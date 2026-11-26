//! Scope creep: a server asking for more provider permission than the task needs.

use crate::model::{Confidence, Evidence, Finding, Location, ServerSpec, Severity};
use crate::rules::{Rule, RuleCtx};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

#[derive(Deserialize)]
struct ProviderMap {
    #[serde(default)]
    read_equivalent: BTreeMap<String, String>,
    #[serde(default)]
    admin: Vec<String>,
}

fn maps() -> &'static BTreeMap<String, ProviderMap> {
    static MAPS: OnceLock<BTreeMap<String, ProviderMap>> = OnceLock::new();
    MAPS.get_or_init(|| {
        serde_json::from_str(include_str!("../../data/rules/scope-maps.json"))
            .expect("scope-maps.json is embedded and valid")
    })
}

fn split_scopes(value: &str) -> Vec<String> {
    value
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The provider this server belongs to, and the scopes it declares.
fn provider_and_scopes(spec: &ServerSpec) -> Option<(String, Vec<String>)> {
    for (key, value) in &spec.env {
        if let Some(prefix) = key
            .to_ascii_lowercase()
            .strip_suffix("_scopes")
            .map(str::to_string)
            && maps().contains_key(&prefix)
        {
            return Some((prefix, split_scopes(value)));
        }
    }
    let haystack = format!(
        "{} {}",
        spec.pkg.as_ref().map(|p| p.name.as_str()).unwrap_or(""),
        spec.url.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();
    let provider = maps()
        .iter()
        .find(|(p, _)| haystack.contains(p.as_str()))
        .map(|(p, _)| p)?;
    Some((provider.clone(), spec.declared_scopes.clone()))
}

fn location(spec: &ServerSpec, scope: &str) -> Location {
    Location {
        file: spec.source.file.clone(),
        pointer: format!("{}/scopes/{scope}", spec.source.pointer),
        span: spec.source.span,
    }
}

fn evidence(provider: &str, scope: &str) -> Option<Evidence> {
    Some(Evidence {
        kind: "scope".to_string(),
        redacted: format!("{provider}:{scope}"),
    })
}

fn run_wildcard(spec: &ServerSpec, _ctx: &RuleCtx) -> Vec<Finding> {
    let Some((provider, scopes)) = provider_and_scopes(spec) else {
        return Vec::new();
    };
    scopes
        .iter()
        .filter(|s| s.as_str() == "*")
        .map(|scope| {
            Finding::new(
                "mcp-scope-wildcard",
                Severity::High,
                Confidence::High,
                format!("{provider} server requests the wildcard scope"),
                location(spec, scope),
                evidence(&provider, scope),
                "Replace `*` with the narrowest scopes the task needs.",
            )
        })
        .collect()
}

fn run_write_when_read(spec: &ServerSpec, _ctx: &RuleCtx) -> Vec<Finding> {
    let Some((provider, scopes)) = provider_and_scopes(spec) else {
        return Vec::new();
    };
    let Some(map) = maps().get(&provider) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for scope in &scopes {
        if let Some(read_only) = map.read_equivalent.get(scope) {
            out.push(Finding::new(
                "mcp-scope-write-when-read",
                Severity::Medium,
                Confidence::High,
                format!(
                    "{provider} scope `{scope}` grants write access where a read-only scope exists"
                ),
                location(spec, scope),
                evidence(&provider, scope),
                format!("Use `{read_only}` instead of `{scope}` unless the task writes."),
            ));
        }
    }
    out
}

fn run_admin(spec: &ServerSpec, _ctx: &RuleCtx) -> Vec<Finding> {
    let Some((provider, scopes)) = provider_and_scopes(spec) else {
        return Vec::new();
    };
    let Some(map) = maps().get(&provider) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for scope in &scopes {
        let lower = scope.to_ascii_lowercase();
        let is_admin = map.admin.iter().any(|a| a == scope)
            || lower.contains("admin")
            || lower == "owner"
            || lower == "sudo"
            || lower == "service_role";
        if is_admin {
            out.push(Finding::new(
                "mcp-scope-admin",
                Severity::High,
                Confidence::High,
                format!("{provider} scope `{scope}` grants administrative access"),
                location(spec, scope),
                evidence(&provider, scope),
                "Use the narrowest scope that works; admin belongs to a human, not an agent.",
            ));
        }
    }
    out
}

fn applies(_spec: &ServerSpec) -> bool {
    true
}

/// The wildcard scope.
pub const fn mcp_scope_wildcard() -> Rule {
    Rule {
        id: "mcp-scope-wildcard",
        severity: Severity::High,
        confidence: Confidence::High,
        since: "0.1.0",
        docs: "docs/rules/mcp-scope-wildcard.md",
        applies_to: applies,
        run: run_wildcard,
    }
}

/// A write scope where a read-only scope would do.
pub const fn mcp_scope_write_when_read() -> Rule {
    Rule {
        id: "mcp-scope-write-when-read",
        severity: Severity::Medium,
        confidence: Confidence::High,
        since: "0.1.0",
        docs: "docs/rules/mcp-scope-write-when-read.md",
        applies_to: applies,
        run: run_write_when_read,
    }
}

/// Administrative scopes.
pub const fn mcp_scope_admin() -> Rule {
    Rule {
        id: "mcp-scope-admin",
        severity: Severity::High,
        confidence: Confidence::High,
        since: "0.1.0",
        docs: "docs/rules/mcp-scope-admin.md",
        applies_to: applies,
        run: run_admin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Capabilities, ConfigFormat, ServerSpec, Source, Transport};
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

    fn spec_scopes(provider: &str, scopes: &[&str]) -> ServerSpec {
        let mut s = base();
        s.env.insert(
            format!("{}_SCOPES", provider.to_ascii_uppercase()),
            scopes.join(","),
        );
        s
    }

    fn run(rule: Rule, s: &ServerSpec) -> Vec<crate::model::Finding> {
        (rule.run)(s, &RuleCtx::default())
    }

    #[test]
    fn wildcard_scope_fires() {
        assert_eq!(
            run(mcp_scope_wildcard(), &spec_scopes("github", &["repo", "*"])).len(),
            1
        );
    }

    #[test]
    fn write_scope_without_a_write_reason_fires() {
        let f = run(
            mcp_scope_write_when_read(),
            &spec_scopes("github", &["repo"]),
        );
        assert_eq!(f.len(), 1);
        assert!(
            f[0].remediation.contains("public_repo"),
            "{}",
            f[0].remediation
        );
    }

    #[test]
    fn read_only_equivalent_does_not_fire() {
        for scopes in [vec!["public_repo"], vec!["issues:read", "contents:read"]] {
            let s = spec_scopes("github", &scopes);
            assert_eq!(run(mcp_scope_write_when_read(), &s).len(), 0, "{scopes:?}");
        }
    }

    #[test]
    fn admin_and_sudo_fire_for_every_provider() {
        for (provider, scope) in [
            ("stripe", "admin"),
            ("supabase", "postgres_admin"),
            ("google", "https://www.googleapis.com/auth/cloud-platform"),
        ] {
            let f = run(mcp_scope_admin(), &spec_scopes(provider, &[scope]));
            assert!(!f.is_empty(), "{provider}/{scope}");
        }
    }

    #[test]
    fn unknown_provider_is_silent() {
        assert_eq!(
            run(mcp_scope_wildcard(), &spec_scopes("acme", &["*"])).len(),
            0
        );
    }

    #[test]
    fn scopes_split_on_commas_and_spaces() {
        let f = run(mcp_scope_wildcard(), &spec_scopes("github", &["repo, *"]));
        assert_eq!(f.len(), 1);
    }
}
