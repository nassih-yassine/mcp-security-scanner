//! A literal credential handed to a server that can reach the network. Normal
//! in practice, so this is a medium-confidence hygiene finding, not an
//! exfiltration verdict.

use crate::model::{Confidence, Evidence, Finding, Location, ServerSpec, Severity};
use crate::rules::{Rule, RuleCtx, redact, secret};

fn first_secret_pointer(spec: &ServerSpec) -> Option<(String, String, String)> {
    let base = spec.source.pointer.as_str();
    for (key, value) in &spec.env {
        if secret::looks_like_secret(value).is_some() {
            return Some((
                format!("{base}/env/{key}"),
                key.clone(),
                secret::strip_scheme(value).to_string(),
            ));
        }
    }
    for (key, value) in &spec.headers {
        if secret::looks_like_secret(value).is_some() {
            return Some((
                format!("{base}/headers/{key}"),
                key.clone(),
                secret::strip_scheme(value).to_string(),
            ));
        }
    }
    for (index, arg) in spec.args.iter().enumerate() {
        if secret::looks_like_secret(arg).is_some() {
            return Some((
                format!("{base}/args/{index}"),
                format!("arg {index}"),
                secret::strip_scheme(arg).to_string(),
            ));
        }
    }
    None
}

fn run(spec: &ServerSpec, _ctx: &RuleCtx) -> Vec<Finding> {
    if !(spec.capabilities.net_egress && spec.capabilities.secret_in_config) {
        return Vec::new();
    }
    let Some((pointer, label, value)) = first_secret_pointer(spec) else {
        return Vec::new();
    };
    vec![Finding::new(
        "mcp-secret-to-network",
        Severity::Medium,
        Confidence::Medium,
        format!("networked server is handed a literal credential ({label})"),
        Location {
            file: spec.source.file.clone(),
            pointer,
            span: spec.source.span,
        },
        Some(Evidence {
            kind: "credential".to_string(),
            redacted: redact(&value),
        }),
        "Reference the credential from the environment and scope it to the least access that works.",
    )]
}

fn applies(spec: &ServerSpec) -> bool {
    spec.capabilities.net_egress
}

/// A literal credential plus network egress on the same server.
pub const fn mcp_secret_to_network() -> Rule {
    Rule {
        id: "mcp-secret-to-network",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        since: "0.1.0",
        docs: "docs/rules/mcp-secret-to-network.md",
        applies_to: applies,
        run,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Capabilities, ConfigFormat, Source, Transport};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn spec(caps: Capabilities, secret: Option<&str>) -> ServerSpec {
        let mut env = BTreeMap::new();
        if let Some(secret) = secret {
            env.insert("TOKEN".to_string(), secret.to_string());
        }
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
            env,
            url: None,
            headers: BTreeMap::new(),
            pkg: None,
            tools: vec![],
            declared_scopes: vec![],
            capabilities: caps,
        }
    }

    fn networked(secret: bool) -> Capabilities {
        Capabilities {
            net_egress: true,
            secret_in_config: secret,
            ..Default::default()
        }
    }

    #[test]
    fn egress_plus_literal_secret_fires_at_medium() {
        let spec = spec(
            networked(true),
            Some("ghp_1234567890abcdefghijklmnopqrstuvwx"),
        );
        let f = (mcp_secret_to_network().run)(&spec, &RuleCtx::default());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].location.pointer.ends_with("/env/TOKEN"));
    }

    #[test]
    fn no_egress_is_silent() {
        let caps = Capabilities {
            secret_in_config: true,
            ..Default::default()
        };
        let spec = spec(caps, Some("ghp_1234567890abcdefghijklmnopqrstuvwx"));
        assert!((mcp_secret_to_network().run)(&spec, &RuleCtx::default()).is_empty());
    }

    #[test]
    fn no_secret_is_silent() {
        let spec = spec(networked(false), None);
        assert!((mcp_secret_to_network().run)(&spec, &RuleCtx::default()).is_empty());
    }
}
