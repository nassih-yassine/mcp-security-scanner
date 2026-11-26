//! Machine-readable report. Output is a contract: `schema_version` changes when
//! the shape does, and nothing time-dependent or machine-dependent is included.
//!
//! Every server value is redacted before it is written. The finding is already
//! redacted, but a raw `env` block would republish the credential the scan found.

use crate::model::{ScanReport, ServerSpec};
use crate::rules::redact;
use crate::rules::secret;
use serde_json::{Value, json};

const SECRET_KEYS: [&str; 6] = ["token", "key", "secret", "password", "apikey", "api_key"];

fn scrub(value: &str) -> String {
    if secret::looks_like_secret(value).is_some() {
        redact(value)
    } else {
        value.to_string()
    }
}

fn scrub_url(url: &str) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let pairs: Vec<String> = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) if SECRET_KEYS.iter().any(|k| key.eq_ignore_ascii_case(k)) => {
                format!("{key}={}", redact(value))
            }
            _ => pair.to_string(),
        })
        .collect();
    format!("{base}?{}", pairs.join("&"))
}

fn server_json(server: &ServerSpec) -> Value {
    let env: std::collections::BTreeMap<&str, String> = server
        .env
        .iter()
        .map(|(k, v)| (k.as_str(), scrub(v)))
        .collect();
    let headers: std::collections::BTreeMap<&str, String> = server
        .headers
        .iter()
        .map(|(k, v)| (k.as_str(), scrub(v)))
        .collect();
    json!({
        "id": server.id,
        "name": server.name,
        "source": server.source,
        "transport": server.transport,
        "command": server.command,
        "args": server.args.iter().map(|a| scrub(a)).collect::<Vec<_>>(),
        "env": env,
        "url": server.url.as_deref().map(scrub_url),
        "headers": headers,
        "pkg": server.pkg,
        "declared_scopes": server.declared_scopes,
        "capabilities": server.capabilities,
    })
}

/// Render the report as stable, pretty-printed JSON with every value redacted.
pub fn render(report: &ScanReport) -> Result<String, serde_json::Error> {
    let servers: Vec<Value> = report.servers.iter().map(server_json).collect();
    let document = json!({
        "schema_version": report.schema_version,
        "servers": servers,
        "findings": report.findings,
        "skipped": report.skipped,
    });
    serde_json::to_string_pretty(&document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Capabilities, ConfigFormat, ServerSpec, Source, Transport};
    use crate::model::{Confidence, Evidence, Finding, Location, ScanReport, Severity};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn server_with_secret(secret: &str) -> ServerSpec {
        let mut env = BTreeMap::new();
        env.insert("GITHUB_TOKEN".to_string(), secret.to_string());
        env.insert("SAFE".to_string(), "us-east-1".to_string());
        ServerSpec {
            id: "id".into(),
            name: "github".into(),
            source: Source {
                file: PathBuf::from("fixtures/demo/.mcp.json"),
                format: ConfigFormat::Json,
                pointer: "/mcpServers/github".into(),
                span: None,
            },
            transport: Transport::Stdio,
            command: Some("npx".into()),
            args: vec!["--token".into(), secret.into()],
            env,
            url: Some(format!("https://api.example.test/mcp?token={secret}")),
            headers: BTreeMap::new(),
            pkg: None,
            tools: vec![],
            declared_scopes: vec![],
            capabilities: Capabilities::default(),
        }
    }

    fn report() -> ScanReport {
        ScanReport {
            schema_version: 1,
            servers: vec![],
            findings: vec![Finding::new(
                "mcp-secret-literal",
                Severity::Critical,
                Confidence::High,
                "literal credential",
                Location {
                    file: PathBuf::from("fixtures/demo/.mcp.json"),
                    pointer: "/mcpServers/github/env/GITHUB_TOKEN".into(),
                    span: None,
                },
                Some(Evidence {
                    kind: "env-value".into(),
                    redacted: "ghp_…uvwx (40)".into(),
                }),
                "rotate it",
            )],
            skipped: vec![],
        }
    }

    #[test]
    fn json_has_schema_version_and_no_timestamps() {
        let out = render(&report()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert!(!out.to_ascii_lowercase().contains("timestamp"));
        assert!(!out.contains("2026-"));
    }

    #[test]
    fn json_is_byte_identical_across_runs() {
        assert_eq!(render(&report()).unwrap(), render(&report()).unwrap());
    }

    #[test]
    fn server_blocks_never_carry_raw_secrets() {
        let secret = "ghp_1234567890abcdefghijklmnopqrstuvwx";
        let mut report = report();
        report.servers = vec![server_with_secret(secret)];
        let out = render(&report).unwrap();
        assert!(!out.contains(secret), "raw secret leaked into json");
        assert!(out.contains("ghp_…uvwx"), "redacted shape missing");
    }

    #[test]
    fn json_carries_no_raw_secret_field() {
        let out = render(&report()).unwrap();
        assert!(out.contains("ghp_…uvwx"));
        assert!(!out.contains("ghp_1234"));
    }
}
