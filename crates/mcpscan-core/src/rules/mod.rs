//! The rule registry. Rules are pure functions over one [`ServerSpec`].

pub mod exfil;
pub mod osv;
pub mod scope;
pub mod secret;
pub mod secret_net;
pub mod tool;
pub mod url;

use crate::model::{Confidence, Finding, ServerSpec};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One check. `severity` is what the rule reports at its most severe; a rule
/// may return findings below it when the evidence is weaker.
pub struct Rule {
    /// Kebab-case, family-prefixed, frozen once released.
    pub id: &'static str,
    /// Severity the rule claims.
    pub severity: crate::model::Severity,
    /// Confidence the rule claims. Only `High` ships by default.
    pub confidence: Confidence,
    /// Crate version that introduced the rule.
    pub since: &'static str,
    /// Documentation page path, relative to the repo root.
    pub docs: &'static str,
    /// Cheap pre-check; `false` means `run` is never called.
    pub applies_to: fn(&ServerSpec) -> bool,
    /// Produce findings for one server.
    pub run: fn(&ServerSpec, &RuleCtx) -> Vec<Finding>,
}

/// Per-run context a rule may need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCtx {
    /// Network access is off.
    pub offline: bool,
    /// Directory holding tool schema files.
    pub tools_dir: Option<PathBuf>,
    /// Include medium-confidence rules.
    pub include_medium: bool,
    /// Advisory hits collected by the scan, keyed by `osv::key`.
    pub osv_hits: BTreeMap<String, Vec<crate::osv::OsvHit>>,
}

impl Default for RuleCtx {
    fn default() -> Self {
        Self {
            offline: true,
            tools_dir: None,
            include_medium: false,
            osv_hits: BTreeMap::new(),
        }
    }
}

static RULES: &[Rule] = &[
    exfil::mcp_exfil_path(),
    osv::mcp_osv_vulnerable(),
    scope::mcp_scope_admin(),
    scope::mcp_scope_wildcard(),
    scope::mcp_scope_write_when_read(),
    secret::mcp_secret_entropy(),
    secret::mcp_secret_literal(),
    secret_net::mcp_secret_to_network(),
    tool::mcp_tool_injection(),
    tool::mcp_tool_invisible_text(),
    tool::mcp_tool_schema_mismatch(),
    tool::mcp_tool_shadowing(),
    url::mcp_url_untrusted_endpoint(),
];

/// Every registered rule, in id order.
pub fn registry() -> &'static [Rule] {
    RULES
}

/// Run a specific rule set. Used by the registry, and by tests.
pub fn run_rules(rules: &[Rule], servers: &[ServerSpec], ctx: &RuleCtx) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in rules {
        if rule.confidence == Confidence::Medium && !ctx.include_medium {
            continue;
        }
        for server in servers {
            if !(rule.applies_to)(server) {
                continue;
            }
            findings.extend((rule.run)(server, ctx));
        }
    }
    sort_findings(&mut findings);
    findings
}

/// Run every registered rule.
pub fn run_all(servers: &[ServerSpec], ctx: &RuleCtx) -> Vec<Finding> {
    run_rules(registry(), servers, ctx)
}

/// Sort by severity (worst first), then rule id, file and pointer.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(b.rule_id))
            .then_with(|| a.location.file.cmp(&b.location.file))
            .then_with(|| a.location.pointer.cmp(&b.location.pointer))
    });
}

/// Render a secret as shape only: first four, last four, total length.
pub fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len <= 8 {
        let head: String = chars.iter().take(4).collect();
        return format!("{head}… ({len})");
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(len - 4).collect();
    format!("{head}…{tail} ({len})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, ConfigFormat, Finding, Location, ServerSpec, Severity, Source};
    use std::path::PathBuf;

    fn spec() -> ServerSpec {
        ServerSpec {
            id: "id".into(),
            name: "s".into(),
            source: Source {
                file: PathBuf::from("c.json"),
                format: ConfigFormat::Json,
                pointer: "/mcpServers/s".into(),
                span: None,
            },
            transport: crate::model::Transport::Stdio,
            command: Some("npx".into()),
            args: vec![],
            env: Default::default(),
            url: None,
            headers: Default::default(),
            pkg: None,
            tools: vec![],
            declared_scopes: vec![],
            capabilities: crate::model::Capabilities::default(),
        }
    }

    fn mk(
        id: &'static str,
        confidence: Confidence,
        s: &ServerSpec,
        pointer: &'static str,
    ) -> Vec<Finding> {
        vec![Finding::new(
            id,
            Severity::High,
            confidence,
            "fake",
            Location {
                file: s.source.file.clone(),
                pointer: pointer.into(),
                span: None,
            },
            None,
            "fix",
        )]
    }

    fn run_a(s: &ServerSpec, _: &RuleCtx) -> Vec<Finding> {
        mk("mcp-a", Confidence::High, s, "/a")
    }
    fn run_b(s: &ServerSpec, _: &RuleCtx) -> Vec<Finding> {
        mk("mcp-b", Confidence::High, s, "/b")
    }
    fn run_b_medium(s: &ServerSpec, _: &RuleCtx) -> Vec<Finding> {
        mk("mcp-b", Confidence::Medium, s, "/b")
    }

    fn fake(
        id: &'static str,
        confidence: Confidence,
        run: fn(&ServerSpec, &RuleCtx) -> Vec<Finding>,
    ) -> Rule {
        Rule {
            id,
            severity: Severity::High,
            confidence,
            since: "0.1.0",
            docs: "docs/rules/none.md",
            applies_to: |_| true,
            run,
        }
    }

    #[test]
    fn redact_keeps_shape_only() {
        assert_eq!(redact("sk-abc1234567890wxyz"), "sk-a…wxyz (20)");
        assert_eq!(redact("short"), "shor… (5)");
        assert!(!redact("sk-live-abcdefghijklmnop").contains("abcdefghij"));
    }

    #[test]
    fn medium_confidence_rules_are_opt_in() {
        let rules = [
            fake("mcp-a", Confidence::High, run_a),
            fake("mcp-b", Confidence::Medium, run_b_medium),
        ];
        let default = run_rules(&rules, &[spec()], &RuleCtx::default());
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].rule_id, "mcp-a");

        let with_medium = run_rules(
            &rules,
            &[spec()],
            &RuleCtx {
                include_medium: true,
                ..Default::default()
            },
        );
        assert_eq!(with_medium.len(), 2);
    }

    #[test]
    fn run_output_is_sorted() {
        let rules = [
            fake("mcp-b", Confidence::High, run_b),
            fake("mcp-a", Confidence::High, run_a),
        ];
        let findings = run_rules(&rules, &[spec()], &RuleCtx::default());
        assert_eq!(findings[0].rule_id, "mcp-a");
        assert_eq!(findings[1].rule_id, "mcp-b");
    }

    #[test]
    fn registry_ids_are_kebab_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for rule in registry() {
            assert!(
                rule.id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{}",
                rule.id
            );
            assert!(rule.id.starts_with("mcp-"), "{}", rule.id);
            assert!(seen.insert(rule.id), "duplicate {}", rule.id);
        }
    }

    #[test]
    fn rule_order_is_stable() {
        let ids: Vec<_> = registry().iter().map(|r| r.id).collect();
        let again: Vec<_> = registry().iter().map(|r| r.id).collect();
        assert_eq!(ids, again);
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "registry must be declared in id order");
    }
}
