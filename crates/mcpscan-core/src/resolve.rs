//! Deriving what a server can do, and which package it runs.

use crate::model::{Capabilities, PackageRef, Registry, ServerSpec};

const DB_HINTS: [&str; 8] = [
    "supabase", "postgres", "mysql", "sqlite", "redis", "mongo", "database", "neon",
];

const FS_HINTS: [&str; 4] = ["filesystem", "file-system", "server-fs", "server-git"];

/// Fill in `pkg` and `capabilities` from the raw config.
pub fn resolve(spec: &mut ServerSpec) {
    spec.pkg = package_ref(spec);
    spec.capabilities = capabilities(spec);
}

/// The package a launcher runs, if it is a package runner.
pub fn package_ref(spec: &ServerSpec) -> Option<PackageRef> {
    let command = spec.command.as_deref()?;
    let base = basename(command);
    match base {
        "npx" | "bunx" => {
            let arg = first_non_flag(&spec.args)?;
            let (name, version) = split_version(arg);
            Some(PackageRef {
                registry: Registry::Npm,
                name,
                version,
            })
        }
        "pnpm" if spec.args.first().map(String::as_str) == Some("dlx") => {
            let arg = first_non_flag(&spec.args[1..])?;
            let (name, version) = split_version(arg);
            Some(PackageRef {
                registry: Registry::Npm,
                name,
                version,
            })
        }
        "uvx" | "pipx" => {
            let skip = if base == "pipx" && spec.args.first().map(String::as_str) == Some("run") {
                1
            } else {
                0
            };
            let arg = first_non_flag(&spec.args[skip..])?;
            let (name, version) = split_version(arg);
            Some(PackageRef {
                registry: Registry::PyPi,
                name,
                version,
            })
        }
        "docker" | "podman" => {
            let idx = spec.args.iter().position(|a| a == "run")?;
            let arg = first_non_flag(&spec.args[idx + 1..])?;
            let (name, version) = split_version(arg);
            Some(PackageRef {
                registry: Registry::Docker,
                name,
                version,
            })
        }
        _ => None,
    }
}

/// What the server can reach or modify, inferred from config only.
pub fn capabilities(spec: &ServerSpec) -> Capabilities {
    let mut caps = Capabilities::default();

    let text_has_scheme = spec
        .args
        .iter()
        .chain(spec.env.values())
        .chain(spec.headers.values())
        .any(|v| v.contains("http://") || v.contains("https://"));
    let port_flag = spec
        .args
        .iter()
        .any(|a| a == "--port" || a.starts_with("--port=") || a == "--host");

    // A package runner downloads its package, but that is not egress the server
    // controls. Count only a url, an http(s) value, or a listening port.
    caps.net_egress = spec.url.is_some() || text_has_scheme || port_flag;
    caps.shell_exec = spec.command.is_some();

    let haystack = format!(
        "{} {} {}",
        spec.pkg.as_ref().map(|p| p.name.as_str()).unwrap_or(""),
        spec.args.join(" "),
        spec.command.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();

    caps.fs_read = spec.args.iter().any(|a| looks_like_path(a))
        || FS_HINTS.iter().any(|h| haystack.contains(h));
    caps.fs_write = spec.args.iter().chain(spec.env.values()).any(|v| {
        matches!(
            v.as_str(),
            "--allow-write" | "--write" | "--rw" | "rw" | "read-write" | "read_write"
        )
    });
    caps.db_read = DB_HINTS.iter().any(|h| haystack.contains(h));
    caps.db_write = spec
        .args
        .iter()
        .chain(spec.declared_scopes.iter())
        .any(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("read-write")
                || v.contains("read_write")
                || v.contains("admin")
                || v == "rw"
                || v == "*"
        });
    caps.secret_in_config = spec
        .env
        .values()
        .chain(spec.headers.values())
        .chain(spec.args.iter())
        .any(|v| crate::rules::secret::looks_like_secret(v).is_some())
        || spec.url.as_deref().is_some_and(|url| {
            url.split_once('?').is_some_and(|(_, query)| {
                crate::rules::secret::looks_like_secret(query).is_some()
                    || query.split('&').any(|pair| {
                        pair.split_once('=').is_some_and(|(_, v)| {
                            crate::rules::secret::looks_like_secret(v).is_some()
                        })
                    })
            })
        });
    caps
}

fn basename(command: &str) -> &str {
    command.rsplit(['/', '\\']).next().unwrap_or(command)
}

fn first_non_flag(args: &[String]) -> Option<&str> {
    args.iter()
        .find(|a| !a.starts_with('-') && !a.is_empty())
        .map(String::as_str)
}

fn split_version(arg: &str) -> (String, Option<String>) {
    if let Some(idx) = arg.rfind('@').filter(|idx| *idx > 0) {
        let (name, version) = arg.split_at(idx);
        return (name.to_string(), Some(version[1..].to_string()));
    }
    if let Some((name, version)) = arg.split_once("==") {
        return (name.to_string(), Some(version.to_string()));
    }
    (arg.to_string(), None)
}

fn looks_like_path(arg: &str) -> bool {
    arg.starts_with('/')
        || arg.starts_with("~/")
        || arg.starts_with("./")
        || arg.starts_with("../")
        || (arg.len() > 2 && arg.as_bytes()[1] == b':' && arg.contains('\\'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Registry, ServerSpec, Source, Transport};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn base() -> ServerSpec {
        ServerSpec {
            id: "id".into(),
            name: "s".into(),
            source: Source {
                file: PathBuf::from("c.json"),
                format: crate::model::ConfigFormat::Json,
                pointer: "/mcpServers/s".into(),
                span: None,
            },
            transport: Transport::Stdio,
            command: None,
            args: vec![],
            env: BTreeMap::new(),
            url: None,
            headers: BTreeMap::new(),
            pkg: None,
            tools: vec![],
            declared_scopes: vec![],
            capabilities: Capabilities::default(),
        }
    }

    fn spec_with(command: &str, args: &[&str]) -> ServerSpec {
        let mut s = base();
        s.command = Some(command.into());
        s.args = args.iter().map(|a| a.to_string()).collect();
        s
    }

    fn spec_with_url(url: &str) -> ServerSpec {
        let mut s = base();
        s.url = Some(url.into());
        s.transport = Transport::Http;
        s
    }

    #[test]
    fn a_package_runner_alone_is_not_egress() {
        let mut s = spec_with(
            "npx",
            &[
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/home/me/docs",
            ],
        );
        resolve(&mut s);
        assert!(s.capabilities.shell_exec);
        assert!(!s.capabilities.net_egress);
        assert!(s.capabilities.fs_read);
    }

    #[test]
    fn url_transport_sets_egress_only() {
        let mut s = spec_with_url("https://api.example.test/mcp");
        resolve(&mut s);
        assert!(s.capabilities.net_egress);
        assert!(!s.capabilities.shell_exec);
        assert!(!s.capabilities.fs_write);
    }

    #[test]
    fn db_packages_infer_read_and_write() {
        let mut s = spec_with("npx", &["-y", "@supabase/mcp-server-supabase@0.4.1"]);
        resolve(&mut s);
        assert!(s.capabilities.db_read);
        assert_eq!(
            s.pkg.as_ref().unwrap().name,
            "@supabase/mcp-server-supabase"
        );
        assert_eq!(s.pkg.as_ref().unwrap().version.as_deref(), Some("0.4.1"));
        assert_eq!(s.pkg.as_ref().unwrap().registry, Registry::Npm);
    }

    #[test]
    fn uvx_and_docker_are_recognized() {
        let uv = package_ref(&spec_with("uvx", &["mcp-server-git==0.6.2"])).unwrap();
        assert_eq!(uv.registry, Registry::PyPi);
        assert_eq!(uv.version.as_deref(), Some("0.6.2"));

        let docker = package_ref(&spec_with(
            "docker",
            &["run", "-i", "--rm", "ghcr.io/x/y@sha256:abc"],
        ))
        .unwrap();
        assert_eq!(docker.registry, Registry::Docker);
        assert_eq!(docker.version.as_deref(), Some("sha256:abc"));
    }

    #[test]
    fn unknown_command_stays_conservative() {
        let mut s = spec_with("./bin/server", &["--port", "9000"]);
        resolve(&mut s);
        assert!(s.capabilities.shell_exec);
        assert!(s.capabilities.net_egress);
        assert!(!s.capabilities.fs_write);
    }

    #[test]
    fn write_flags_are_required_for_fs_write() {
        let mut read = spec_with("npx", &["-y", "server-filesystem", "/data"]);
        resolve(&mut read);
        assert!(read.capabilities.fs_read);
        assert!(!read.capabilities.fs_write);

        let mut write = spec_with(
            "npx",
            &["-y", "server-filesystem", "/data", "--allow-write"],
        );
        resolve(&mut write);
        assert!(write.capabilities.fs_write);
    }

    #[test]
    fn literal_secret_sets_the_exfil_read_leg() {
        let mut s = spec_with("npx", &["-y", "some-server"]);
        s.env.insert(
            "TOKEN".into(),
            "ghp_1234567890abcdefghijklmnopqrstuvwx".into(),
        );
        resolve(&mut s);
        assert!(s.capabilities.secret_in_config);
    }

    #[test]
    fn admin_email_does_not_mean_db_write() {
        let mut s = spec_with("npx", &["-y", "server-postgres"]);
        s.env
            .insert("ADMIN_EMAIL".into(), "ops@example.test".into());
        resolve(&mut s);
        assert!(s.capabilities.db_read);
        assert!(!s.capabilities.db_write);
    }

    #[test]
    fn no_command_and_no_url_is_inert() {
        let mut s = base();
        resolve(&mut s);
        assert!(!s.capabilities.net_egress);
        assert!(!s.capabilities.shell_exec);
    }
}
