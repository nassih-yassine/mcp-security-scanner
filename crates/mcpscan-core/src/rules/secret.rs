//! Credential exposure: known provider prefixes, and entropy as a fallback.

use crate::model::{Confidence, Evidence, Finding, Location, ServerSpec, Severity};
use crate::rules::{Rule, RuleCtx, redact};
use serde::Deserialize;
use std::sync::OnceLock;

const LITERAL_ID: &str = "mcp-secret-literal";
const ENTROPY_ID: &str = "mcp-secret-entropy";

#[derive(Deserialize)]
struct Prefix {
    id: String,
    prefix: String,
    min_len: usize,
}

fn prefixes() -> &'static [Prefix] {
    static PREFIXES: OnceLock<Vec<Prefix>> = OnceLock::new();
    PREFIXES.get_or_init(|| {
        serde_json::from_str(include_str!("../../data/rules/secret-prefixes.json"))
            .expect("secret-prefixes.json is embedded and valid")
    })
}

fn placeholders() -> &'static [String] {
    static PLACEHOLDERS: OnceLock<Vec<String>> = OnceLock::new();
    PLACEHOLDERS.get_or_init(|| {
        serde_json::from_str(include_str!("../../data/rules/placeholders.json"))
            .expect("placeholders.json is embedded and valid")
    })
}

/// Drop an HTTP auth scheme so `Bearer sk-…` is matched on the token.
pub fn strip_scheme(value: &str) -> &str {
    for scheme in ["Bearer ", "bearer ", "Token ", "token ", "Basic ", "basic "] {
        if let Some(rest) = value.strip_prefix(scheme) {
            return rest.trim();
        }
    }
    value
}

/// The credential family this value matches, if any. Never returns the value.
pub fn looks_like_secret(value: &str) -> Option<&'static str> {
    if is_placeholder(value) {
        return None;
    }
    let token = strip_scheme(value);
    prefixes()
        .iter()
        .find(|p| token.starts_with(p.prefix.as_str()) && token.len() >= p.min_len)
        .map(|p| p.id.as_str())
}

/// True when the value is an intentional reference or a documented dummy.
pub fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    placeholders().iter().any(|p| lower.contains(p.as_str()))
}

struct Candidate<'a> {
    pointer: String,
    value: &'a str,
    kind: &'static str,
}

const SECRET_FLAGS: [&str; 8] = [
    "--token",
    "--api-key",
    "--apikey",
    "--password",
    "--secret",
    "--auth",
    "-token",
    "--access-token",
];

fn candidates(spec: &ServerSpec) -> Vec<Candidate<'_>> {
    let base = spec.source.pointer.as_str();
    let mut out = Vec::new();
    for (key, value) in &spec.env {
        out.push(Candidate {
            pointer: format!("{base}/env/{key}"),
            value,
            kind: "env-value",
        });
    }
    for (key, value) in &spec.headers {
        out.push(Candidate {
            pointer: format!("{base}/headers/{key}"),
            value,
            kind: "header-value",
        });
    }
    let mut prev: Option<&str> = None;
    for (i, arg) in spec.args.iter().enumerate() {
        let flagged = prev.is_some_and(|p| SECRET_FLAGS.contains(&p))
            || arg.starts_with("Authorization:")
            || arg.starts_with("Bearer ");
        if flagged && !arg.starts_with('-') {
            out.push(Candidate {
                pointer: format!("{base}/args/{i}"),
                value: arg,
                kind: "arg-value",
            });
        }
        prev = Some(arg);
    }
    if let Some(query) = spec.url.as_ref().and_then(|url| url.split('?').nth(1)) {
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if ["token", "key", "secret", "password", "apikey", "api_key"]
                .iter()
                .any(|k| key.eq_ignore_ascii_case(k))
            {
                out.push(Candidate {
                    pointer: format!("{base}/url"),
                    value,
                    kind: "url-query",
                });
            }
        }
    }
    out
}

type Meta = (&'static str, Severity, Confidence);

fn finding(
    spec: &ServerSpec,
    (rule_id, severity, confidence): Meta,
    message: String,
    pointer: String,
    kind: &'static str,
    value: &str,
) -> Finding {
    Finding::new(
        rule_id,
        severity,
        confidence,
        message,
        Location {
            file: spec.source.file.clone(),
            pointer,
            span: spec.source.span,
        },
        Some(Evidence {
            kind: kind.to_string(),
            redacted: redact(value),
        }),
        "Move the credential to an environment variable and rotate it.",
    )
}

fn run_literal(spec: &ServerSpec, _ctx: &RuleCtx) -> Vec<Finding> {
    candidates(spec)
        .into_iter()
        .filter_map(|c| {
            let family = looks_like_secret(c.value)?;
            Some(finding(
                spec,
                (LITERAL_ID, Severity::Critical, Confidence::High),
                format!("literal credential ({family}) in {kind}", kind = c.kind),
                c.pointer,
                c.kind,
                strip_scheme(c.value),
            ))
        })
        .collect()
}

fn run_entropy(spec: &ServerSpec, _ctx: &RuleCtx) -> Vec<Finding> {
    candidates(spec)
        .into_iter()
        .filter(|c| looks_like_secret(c.value).is_none())
        .filter(|c| !is_placeholder(c.value))
        .filter(|c| plausible_secret(c.value))
        .map(|c| {
            finding(
                spec,
                (ENTROPY_ID, Severity::High, Confidence::Medium),
                format!("high-entropy value in {kind}", kind = c.kind),
                c.pointer,
                c.kind,
                c.value,
            )
        })
        .collect()
}

/// Length, charset and entropy heuristics that avoid flagging sentences, URLs
/// and paths.
fn plausible_secret(value: &str) -> bool {
    if value.len() < 20 || value.contains(char::is_whitespace) {
        return false;
    }
    if value.contains("://") || value.starts_with('/') || value.starts_with("~/") {
        return false;
    }
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_alpha = value.chars().any(|c| c.is_ascii_alphabetic());
    let has_mixed = value.chars().any(|c| c.is_ascii_uppercase())
        && value.chars().any(|c| c.is_ascii_lowercase());
    has_digit && has_alpha && has_mixed && shannon(value) > 4.0
}

fn shannon(value: &str) -> f64 {
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for byte in value.bytes() {
        counts[byte as usize] += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn applies(_spec: &ServerSpec) -> bool {
    true
}

/// Literal provider credentials anywhere in the config.
pub const fn mcp_secret_literal() -> Rule {
    Rule {
        id: LITERAL_ID,
        severity: Severity::Critical,
        confidence: Confidence::High,
        since: "0.1.0",
        docs: "docs/rules/mcp-secret-literal.md",
        applies_to: applies,
        run: run_literal,
    }
}

/// Credential-shaped values without a known prefix. Medium confidence.
pub const fn mcp_secret_entropy() -> Rule {
    Rule {
        id: ENTROPY_ID,
        severity: Severity::High,
        confidence: Confidence::Medium,
        since: "0.1.0",
        docs: "docs/rules/mcp-secret-entropy.md",
        applies_to: applies,
        run: run_entropy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Capabilities, Confidence, ConfigFormat, ServerSpec, Severity, Source, Transport,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn base() -> ServerSpec {
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
            capabilities: Capabilities::default(),
        }
    }

    fn spec_env(pairs: &[(&str, &str)]) -> ServerSpec {
        let mut s = base();
        for (k, v) in pairs {
            s.env.insert((*k).into(), (*v).into());
        }
        s
    }

    fn spec_header(name: &str, value: &str) -> ServerSpec {
        let mut s = base();
        s.headers.insert(name.into(), value.into());
        s
    }

    fn spec_args(args: &[&str]) -> ServerSpec {
        let mut s = base();
        s.args = args.iter().map(|a| a.to_string()).collect();
        s
    }

    fn run(rule: Rule, s: &ServerSpec) -> Vec<crate::model::Finding> {
        (rule.run)(s, &RuleCtx::default())
    }

    #[test]
    fn provider_prefixes_fire_in_env_headers_and_args() {
        let s = spec_env(&[("GITHUB_TOKEN", "ghp_1234567890abcdefghijklmnopqrstuvwx")]);
        let f = run(mcp_secret_literal(), &s);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);

        let h = spec_header(
            "Authorization",
            "Bearer sk-proj-abcdefghijklmnopqrstuvwxyz1234",
        );
        assert_eq!(run(mcp_secret_literal(), &h).len(), 1);

        let a = spec_args(&["--token", "sk-ant-abcdefghijklmnop1234567890"]);
        assert_eq!(run(mcp_secret_literal(), &a).len(), 1);
    }

    #[test]
    fn placeholders_never_fire() {
        for v in [
            "${GITHUB_TOKEN}",
            "op://vault/item/key",
            "<your-api-key>",
            "YOUR_API_KEY",
            "changeme",
            "xxxxxxxx",
            "sk-xxxx",
            "file:///run/secret",
        ] {
            assert_eq!(
                run(mcp_secret_literal(), &spec_env(&[("TOKEN", v)])).len(),
                0,
                "{v}"
            );
        }
    }

    #[test]
    fn high_entropy_strings_fire_only_at_medium_confidence() {
        let s = spec_env(&[("SOME_VALUE", "Zx9Qm2Lp7Rt4Vb8Nc3Wd6Hk1Js5Gf0Ay")]);
        assert_eq!(run(mcp_secret_literal(), &s).len(), 0);
        let medium = run(mcp_secret_entropy(), &s);
        assert_eq!(medium.len(), 1);
        assert_eq!(medium[0].confidence, Confidence::Medium);
    }

    #[test]
    fn raw_value_never_reaches_the_finding() {
        let secret = "ghp_1234567890abcdefghijklmnopqrstuvwx";
        let f = run(mcp_secret_literal(), &spec_env(&[("TOKEN", secret)]));
        assert!(!serde_json::to_string(&f).unwrap().contains(secret));
    }

    #[test]
    fn location_points_at_the_env_key() {
        let f = run(
            mcp_secret_literal(),
            &spec_env(&[("TOKEN", "ghp_1234567890abcdefghijklmnopqrstuvwx")]),
        );
        assert!(f[0].location.pointer.ends_with("/env/TOKEN"));
    }

    #[test]
    fn url_query_secrets_fire() {
        let mut s = base();
        s.url = Some(
            "https://api.example.test/mcp?token=ghp_1234567890abcdefghijklmnopqrstuvwx".into(),
        );
        let f = run(mcp_secret_literal(), &s);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn entropy_skips_values_with_a_known_prefix() {
        let s = spec_env(&[("TOKEN", "ghp_1234567890abcdefghijklmnopqrstuvwx")]);
        assert_eq!(run(mcp_secret_entropy(), &s).len(), 0);
    }
}
