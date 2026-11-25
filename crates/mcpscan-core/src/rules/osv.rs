//! Known-vulnerable server packages. Offline by default: the lookup happens in
//! `scan`, and this rule only reads what the scan collected.

use crate::model::{Confidence, Evidence, Finding, Location, ServerSpec, Severity};
use crate::osv::{self, OsvHit};
use crate::rules::{Rule, RuleCtx};

fn run(spec: &ServerSpec, ctx: &RuleCtx) -> Vec<Finding> {
    let Some(pkg) = &spec.pkg else {
        return Vec::new();
    };
    if pkg.version.is_none() {
        return Vec::new();
    }
    let Some(hits) = ctx.osv_hits.get(&osv::key(pkg)) else {
        return Vec::new();
    };
    hits.iter()
        .map(|hit: &OsvHit| {
            Finding::new(
                "mcp-osv-vulnerable",
                Severity::High,
                Confidence::High,
                format!(
                    "{}@{} is listed in {}",
                    hit.package,
                    hit.version,
                    hit.ids.join(", ")
                ),
                Location {
                    file: spec.source.file.clone(),
                    pointer: format!("{}/args", spec.source.pointer),
                    span: spec.source.span,
                },
                Some(Evidence {
                    kind: "advisory".to_string(),
                    redacted: hit.ids.join(","),
                }),
                "Upgrade to a version the advisory lists as fixed.",
            )
        })
        .collect()
}

fn applies(spec: &ServerSpec) -> bool {
    spec.pkg.is_some()
}

/// Pinned server package matches an OSV advisory.
pub const fn mcp_osv_vulnerable() -> Rule {
    Rule {
        id: "mcp-osv-vulnerable",
        severity: Severity::High,
        confidence: Confidence::High,
        since: "0.1.0",
        docs: "docs/rules/mcp-osv-vulnerable.md",
        applies_to: applies,
        run,
    }
}
