//! Composite rule: a server that can reach out, read something sensitive and
//! change something is an exfiltration path, even when each ability is normal.

use crate::model::{Capabilities, Confidence, Finding, Location, ServerSpec, Severity};
use crate::rules::{Rule, RuleCtx};

/// The abilities that make up the path, in a fixed order. `None` when the
/// combination is not an exfiltration path.
pub fn exfil_components(caps: &Capabilities) -> Option<Vec<&'static str>> {
    // A literal secret is not a read: it moves to `mcp-secret-to-network`.
    // `shell_exec` is every stdio server; counting it made this rule fire on
    // every first-party server.
    let read = caps.fs_read || caps.db_read;
    let write = caps.fs_write || caps.db_write;
    if !(caps.net_egress && read && write) {
        return None;
    }
    let mut parts = Vec::new();
    if caps.net_egress {
        parts.push("net_egress");
    }
    if caps.fs_read {
        parts.push("fs_read");
    }
    if caps.db_read {
        parts.push("db_read");
    }
    if caps.fs_write {
        parts.push("fs_write");
    }
    if caps.db_write {
        parts.push("db_write");
    }
    Some(parts)
}

fn run(spec: &ServerSpec, _ctx: &RuleCtx) -> Vec<Finding> {
    let Some(parts) = exfil_components(&spec.capabilities) else {
        return Vec::new();
    };
    vec![Finding::new(
        "mcp-exfil-path",
        Severity::High,
        Confidence::High,
        format!("server combines {}", parts.join(", ")),
        Location {
            file: spec.source.file.clone(),
            pointer: spec.source.pointer.clone(),
            span: spec.source.span,
        },
        None,
        "Split read and write into different servers, or remove network egress from the one that writes.",
    )]
}

fn applies(_spec: &ServerSpec) -> bool {
    true
}

/// Network egress plus read access plus a write or execute path.
pub const fn mcp_exfil_path() -> Rule {
    Rule {
        id: "mcp-exfil-path",
        severity: Severity::High,
        confidence: Confidence::High,
        since: "0.1.0",
        docs: "docs/rules/mcp-exfil-path.md",
        applies_to: applies,
        run,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Capabilities, ConfigFormat, ServerSpec, Source, Transport};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn spec_caps(caps: Capabilities) -> ServerSpec {
        ServerSpec {
            id: "id".into(),
            name: "s".into(),
            source: Source {
                file: PathBuf::from("c.json"),
                format: ConfigFormat::Json,
                pointer: "/mcpServers/s".into(),
                span: None,
            },
            transport: Transport::Stdio,
            command: Some("npx".into()),
            args: vec![],
            env: BTreeMap::new(),
            url: None,
            headers: BTreeMap::new(),
            pkg: None,
            tools: vec![],
            declared_scopes: vec![],
            capabilities: caps,
        }
    }

    fn run(s: &ServerSpec) -> Vec<crate::model::Finding> {
        (mcp_exfil_path().run)(s, &RuleCtx::default())
    }

    #[test]
    fn egress_plus_read_plus_write_fires() {
        let s = spec_caps(Capabilities {
            net_egress: true,
            fs_read: true,
            fs_write: true,
            ..Default::default()
        });
        let f = run(&s);
        assert_eq!(f.len(), 1);
        for part in ["net_egress", "fs_read", "fs_write"] {
            assert!(f[0].message.contains(part), "{}", f[0].message);
        }
    }

    #[test]
    fn a_literal_secret_alone_is_not_an_exfil_path() {
        let s = spec_caps(Capabilities {
            net_egress: true,
            secret_in_config: true,
            ..Default::default()
        });
        assert_eq!(run(&s).len(), 0);
    }

    #[test]
    fn a_command_alone_is_not_a_write_leg() {
        let s = spec_caps(Capabilities {
            net_egress: true,
            fs_read: true,
            shell_exec: true,
            ..Default::default()
        });
        assert_eq!(run(&s).len(), 0);
    }

    #[test]
    fn read_only_server_is_silent() {
        let s = spec_caps(Capabilities {
            fs_read: true,
            db_read: true,
            ..Default::default()
        });
        assert_eq!(run(&s).len(), 0);
    }

    #[test]
    fn one_message_names_every_contributing_capability() {
        let s = spec_caps(Capabilities {
            net_egress: true,
            db_read: true,
            db_write: true,
            shell_exec: true,
            ..Default::default()
        });
        let f = run(&s);
        for part in ["net_egress", "db_read", "db_write"] {
            assert!(f[0].message.contains(part), "{}", f[0].message);
        }
    }

    #[test]
    fn components_are_in_a_fixed_order() {
        let caps = Capabilities {
            net_egress: true,
            shell_exec: true,
            db_write: true,
            db_read: true,
            fs_write: true,
            fs_read: true,
            secret_in_config: true,
        };
        assert_eq!(
            exfil_components(&caps).unwrap(),
            vec!["net_egress", "fs_read", "db_read", "fs_write", "db_write"]
        );
    }
}
