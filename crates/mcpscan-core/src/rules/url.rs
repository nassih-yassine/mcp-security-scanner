//! Remote endpoint sanity: plaintext http, and addresses that should never be
//! reachable from an agent config.

use crate::model::{Confidence, Evidence, Finding, Location, ServerSpec, Severity};
use crate::rules::{Rule, RuleCtx};
use url::Url;

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn suspicious_host(host: &str) -> Option<&'static str> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return None;
        }
        if ip.is_unspecified() {
            return Some("unspecified address");
        }
        if ip.is_loopback() {
            return None;
        }
        match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_link_local() {
                    return Some("link-local address");
                }
                if v4.is_private() {
                    return Some("private address");
                }
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_unique_local() || v6.is_unicast_link_local() {
                    return Some("private address");
                }
            }
        }
        return None;
    }
    if host.eq_ignore_ascii_case("metadata.google.internal") {
        return Some("cloud metadata host");
    }
    None
}

fn run(spec: &ServerSpec, _ctx: &RuleCtx) -> Vec<Finding> {
    let Some(raw) = &spec.url else {
        return Vec::new();
    };
    let parsed = Url::parse(raw).ok();
    let host = parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let scheme = parsed.as_ref().map(|u| u.scheme()).unwrap_or("");

    let mut reason = None;
    if scheme == "http" && !is_loopback_host(&host) {
        reason = Some("plaintext http endpoint");
    }
    if let Some(host_reason) = suspicious_host(&host) {
        reason = Some(host_reason);
    }

    let Some(reason) = reason else {
        return Vec::new();
    };
    vec![Finding::new(
        "mcp-url-untrusted-endpoint",
        Severity::High,
        Confidence::High,
        format!("server endpoint is a {reason}: {scheme}://{host}"),
        Location {
            file: spec.source.file.clone(),
            pointer: format!("{}/url", spec.source.pointer),
            span: spec.source.span,
        },
        Some(Evidence {
            kind: "url-host".to_string(),
            redacted: format!("{scheme}://{host}"),
        }),
        "Use https on a public host, or keep a local server on loopback.",
    )]
}

fn applies(spec: &ServerSpec) -> bool {
    spec.url.is_some()
}

/// Plaintext http or a non-public endpoint.
pub const fn mcp_url_untrusted_endpoint() -> Rule {
    Rule {
        id: "mcp-url-untrusted-endpoint",
        severity: Severity::High,
        confidence: Confidence::High,
        since: "0.1.0",
        docs: "docs/rules/mcp-url-untrusted-endpoint.md",
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

    fn spec_url(url: &str) -> ServerSpec {
        ServerSpec {
            id: "id".into(),
            name: "s".into(),
            source: Source {
                file: PathBuf::from("c.json"),
                format: ConfigFormat::Json,
                pointer: "/mcpServers/s".into(),
                span: None,
            },
            transport: Transport::Http,
            command: None,
            args: vec![],
            env: BTreeMap::new(),
            url: Some(url.into()),
            headers: BTreeMap::new(),
            pkg: None,
            tools: vec![],
            declared_scopes: vec![],
            capabilities: Capabilities::default(),
        }
    }

    fn run(url: &str) -> Vec<crate::model::Finding> {
        (mcp_url_untrusted_endpoint().run)(&spec_url(url), &RuleCtx::default())
    }

    #[test]
    fn plaintext_remote_http_fires() {
        assert_eq!(run("http://example.test/mcp").len(), 1);
    }

    #[test]
    fn link_local_and_private_addresses_fire() {
        for url in [
            "http://169.254.169.254/latest/meta-data",
            "https://10.0.0.5/mcp",
            "https://192.168.1.20/mcp",
            "https://metadata.google.internal/computeMetadata/v1",
        ] {
            assert_eq!(run(url).len(), 1, "{url}");
        }
    }

    #[test]
    fn loopback_and_https_are_allowed() {
        for url in [
            "https://api.example.test/mcp",
            "http://localhost:3000/mcp",
            "http://127.0.0.1:8080/mcp",
            "https://127.0.0.1/mcp",
        ] {
            assert_eq!(run(url).len(), 0, "{url}");
        }
    }

    #[test]
    fn a_stdio_server_is_silent() {
        let mut spec = spec_url("http://example.test/mcp");
        spec.url = None;
        assert_eq!(
            (mcp_url_untrusted_endpoint().run)(&spec, &RuleCtx::default()).len(),
            0
        );
    }
}
