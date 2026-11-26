//! SARIF 2.1.0 output, so findings land in GitHub code scanning without a second
//! format of truth. Rule IDs, severities and fingerprints come from the same
//! `Finding` the other reports use.

use crate::model::{ScanReport, Severity};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFORMATION_URI: &str = "https://github.com/nassih-yassine/mcp-security-scanner";

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn kind(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High | Severity::Medium => "fail",
        Severity::Low => "informational",
    }
}

fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
    }
}

fn artifact_uri(file: &std::path::Path) -> String {
    let relative = if file.is_absolute() {
        std::env::current_dir()
            .ok()
            .and_then(|cwd| file.strip_prefix(cwd).ok())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| file.to_path_buf())
    } else {
        file.to_path_buf()
    };
    relative
        .to_string_lossy()
        .replace('\\', "/")
        .replace(' ', "%20")
        .replace('#', "%23")
}

/// Render one SARIF run containing every finding.
pub fn render(report: &ScanReport, version: &str) -> Result<String, serde_json::Error> {
    let rules_by_id: BTreeMap<&str, usize> = {
        let mut ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.into_iter()
            .enumerate()
            .map(|(index, id)| (id, index))
            .collect()
    };

    let rules: Vec<Value> = rules_by_id
        .keys()
        .copied()
        .map(|id| {
            let declared = crate::rules::registry()
                .iter()
                .find(|rule| rule.id == id)
                .map(|rule| level(rule.severity))
                .unwrap_or("warning");
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": id },
                "helpUri": format!("{INFORMATION_URI}/blob/main/docs/rules/{id}.md"),
                "defaultConfiguration": { "level": declared },
            })
        })
        .collect();

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|finding| {
            let mut physical = json!({
                "artifactLocation": { "uri": artifact_uri(&finding.location.file) }
            });
            if let Some(span) = finding.location.span {
                physical["region"] = json!({
                    "startLine": span.start_line,
                    "startColumn": span.start_col,
                    "endLine": span.end_line,
                    "endColumn": span.end_col,
                });
            }
            let mut result = json!({
                "ruleId": finding.rule_id,
                "ruleIndex": rules_by_id.get(finding.rule_id).copied().unwrap_or(0),
                "level": level(finding.severity),
                "kind": kind(finding.severity),
                "message": { "text": finding.message },
                "locations": [ { "physicalLocation": physical } ],
                "partialFingerprints": { "primaryLocationLineHash": finding.fingerprint },
                "properties": {
                    "security-severity": security_severity(finding.severity),
                    "pointer": finding.location.pointer,
                },
            });
            if let Some(evidence) = &finding.evidence {
                result["properties"]["evidence"] = json!(evidence.redacted);
                result["properties"]["evidenceKind"] = json!(evidence.kind);
            }
            result
        })
        .collect();

    let document = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [ {
            "tool": {
                "driver": {
                    "name": "mcpscan",
                    "informationUri": INFORMATION_URI,
                    "version": version,
                    "rules": rules,
                }
            },
            "results": results,
        } ]
    });

    serde_json::to_string_pretty(&document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Evidence, Finding, Location, ScanReport, Severity, Span};
    use std::path::PathBuf;

    fn f(severity: Severity, pointer: &str) -> Finding {
        f_for("mcp-secret-literal", severity, pointer)
    }

    fn f_for(rule: &'static str, severity: Severity, pointer: &str) -> Finding {
        Finding::new(
            rule,
            severity,
            Confidence::High,
            "literal credential",
            Location {
                file: PathBuf::from("fixtures/demo/.mcp.json"),
                pointer: pointer.into(),
                span: Some(Span {
                    start_line: 5,
                    start_col: 7,
                    end_line: 5,
                    end_col: 20,
                }),
            },
            Some(Evidence {
                kind: "env-value".into(),
                redacted: "ghp_…uvwx (40)".into(),
            }),
            "rotate it",
        )
    }

    fn report() -> ScanReport {
        ScanReport {
            schema_version: 1,
            servers: vec![],
            findings: vec![
                f(Severity::Critical, "/mcpServers/s/env/A"),
                f(Severity::High, "/mcpServers/s/env/B"),
            ],
            skipped: vec![],
        }
    }

    fn doc(findings: Vec<Finding>) -> serde_json::Value {
        let report = ScanReport {
            schema_version: 1,
            servers: vec![],
            findings,
            skipped: vec![],
        };
        serde_json::from_str(&render(&report, "0.1.0").unwrap()).unwrap()
    }

    #[test]
    fn sarif_is_valid_against_the_official_schema() {
        let text = render(&report(), "0.1.0").unwrap();
        let document: serde_json::Value = serde_json::from_str(&text).unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../../schemas/sarif-2.1.0.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&document)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{errors:#?}");
    }

    #[test]
    fn levels_follow_severity() {
        let document = doc(vec![
            f(Severity::Critical, "/a"),
            f(Severity::Medium, "/b"),
            f(Severity::Low, "/c"),
        ]);
        let levels: Vec<_> = document["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["level"].as_str().unwrap())
            .collect();
        assert_eq!(levels, ["error", "warning", "note"]);
    }

    #[test]
    fn fingerprints_are_stable_across_runs() {
        assert_eq!(
            render(&report(), "0.1.0").unwrap(),
            render(&report(), "0.1.0").unwrap()
        );
    }

    #[test]
    fn uris_are_repo_relative_with_forward_slashes() {
        let document = doc(vec![f(Severity::High, "/a")]);
        let uri = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(!uri.starts_with('/'));
        assert!(!uri.contains('\\'));
        assert_eq!(uri, "fixtures/demo/.mcp.json");
    }

    #[test]
    fn rules_are_deduplicated_and_indexed() {
        let document = doc(vec![f(Severity::Critical, "/a"), f(Severity::High, "/b")]);
        let rules = document["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "mcp-secret-literal");
        assert_eq!(document["runs"][0]["results"][1]["ruleIndex"], 0);
    }

    #[test]
    fn rule_default_level_follows_the_declared_severity() {
        let document = doc(vec![f_for(
            "mcp-tool-schema-mismatch",
            Severity::Medium,
            "/a",
        )]);
        let rule = &document["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["defaultConfiguration"]["level"], "warning");
    }

    #[test]
    fn security_severity_is_the_github_property() {
        let document = doc(vec![f(Severity::Critical, "/a")]);
        let score = document["runs"][0]["results"][0]["properties"]["security-severity"]
            .as_str()
            .unwrap();
        assert_eq!(score, "9.5");
    }
}
