//! Human-readable terminal report.

use crate::model::{ScanReport, Severity};

/// Render findings grouped by file.
pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "MCP security scan: {} server(s), {} finding(s)\n",
        report.servers.len(),
        report.findings.len()
    ));
    if report.findings.is_empty() {
        if report.skipped.is_empty() {
            out.push_str("No findings.\n");
        } else {
            out.push_str(&format!(
                "No findings, but {} file(s) could not be fully scanned.\n",
                report.skipped.len()
            ));
        }
    }
    let mut current: Option<&std::path::Path> = None;
    for finding in &report.findings {
        if current != Some(finding.location.file.as_path()) {
            out.push_str(&format!("\n{}\n", finding.location.file.display()));
            current = Some(finding.location.file.as_path());
        }
        out.push_str(&format!(
            "  {} {}  {}\n",
            label(finding.severity),
            finding.rule_id,
            finding.message
        ));
        let span = finding
            .location
            .span
            .map(|s| format!(":{}:{}", s.start_line, s.start_col))
            .unwrap_or_default();
        out.push_str(&format!("    at {}{}\n", finding.location.pointer, span));
        if let Some(evidence) = &finding.evidence {
            out.push_str(&format!("    evidence: {}\n", evidence.redacted));
        }
        out.push_str(&format!("    fix: {}\n", finding.remediation));
    }
    for skipped in &report.skipped {
        out.push_str(&format!(
            "\nskipped {}: {}\n",
            skipped.file.display(),
            skipped.reason
        ));
    }
    out
}

fn label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH    ",
        Severity::Medium => "MEDIUM  ",
        Severity::Low => "LOW     ",
    }
}
