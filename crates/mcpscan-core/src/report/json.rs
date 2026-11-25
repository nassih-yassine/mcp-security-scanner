//! Machine-readable report. Output is a contract: `schema_version` changes when
//! the shape does, and nothing time-dependent or machine-dependent is included.

use crate::model::ScanReport;

/// Render the report as stable, pretty-printed JSON.
pub fn render(report: &ScanReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Evidence, Finding, Location, ScanReport, Severity};
    use std::path::PathBuf;

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
    fn json_carries_no_raw_secret_field() {
        let out = render(&report()).unwrap();
        assert!(out.contains("ghp_…uvwx"));
        assert!(!out.contains("ghp_1234"));
    }
}
