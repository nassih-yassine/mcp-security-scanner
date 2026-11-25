//! Markdown summary with the `security-score.md` badge content.

use crate::model::{ScanReport, Severity};
use crate::score::{grade, score};

/// Render the score, a findings table and a fix list.
pub fn render(report: &ScanReport) -> String {
    let value = score(&report.findings);
    let grade = grade(value);
    let mut out = String::new();
    out.push_str(&format!(
        "## MCP security score: {} ({}/100)\n\n",
        grade.as_str(),
        value
    ));
    out.push_str(&format!(
        "{} server(s) scanned, {} finding(s).\n\n",
        report.servers.len(),
        report.findings.len()
    ));

    if report.findings.is_empty() {
        out.push_str("No findings.\n");
        return out;
    }

    out.push_str("| Severity | Rule | File | Message |\n");
    out.push_str("|---|---|---|---|\n");
    for finding in &report.findings {
        out.push_str(&format!(
            "| {} | `{}` | `{}` | {} |\n",
            label(finding.severity),
            finding.rule_id,
            finding.location.file.display(),
            finding.message.replace('|', "\\|")
        ));
    }

    out.push_str("\n### How to fix\n\n");
    for finding in &report.findings {
        let evidence = finding
            .evidence
            .as_ref()
            .map(|e| format!(" (evidence: {})", e.redacted))
            .unwrap_or_default();
        out.push_str(&format!(
            "- `{}` at `{}`: {}{}\n",
            finding.rule_id, finding.location.pointer, finding.remediation, evidence
        ));
    }

    if !report.skipped.is_empty() {
        out.push_str("\n### Not scanned\n\n");
        for skipped in &report.skipped {
            out.push_str(&format!(
                "- `{}`: {}\n",
                skipped.file.display(),
                skipped.reason
            ));
        }
    }

    out
}

fn label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Evidence, Finding, Location, ScanReport, Severity};
    use std::path::PathBuf;

    fn f(severity: Severity, rule: &'static str) -> Finding {
        Finding::new(
            rule,
            severity,
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
            "Move the credential to an environment variable and rotate it.",
        )
    }

    fn report() -> ScanReport {
        ScanReport {
            schema_version: 1,
            servers: vec![],
            findings: vec![f(Severity::Critical, "mcp-secret-literal")],
            skipped: vec![],
        }
    }

    #[test]
    fn markdown_has_grade_header_and_table() {
        let out = render(&report());
        assert!(out.starts_with("## MCP security score: "), "{out}");
        assert!(out.contains("| Severity | Rule | File | Message |"));
        assert!(out.contains("mcp-secret-literal"));
        assert!(out.contains("ghp_…uvwx"));
    }

    #[test]
    fn markdown_snapshot() {
        insta::assert_snapshot!(render(&report()));
    }
}
