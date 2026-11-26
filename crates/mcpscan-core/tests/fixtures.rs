//! Every rule must reproduce the findings its fixture claims, and stay silent on
//! the clean one. This is the mechanism that makes false positives cheap.

use mcpscan_core::model::{ConfigFormat, Finding, ServerSpec, ToolSpec};
use mcpscan_core::parse::parse_str;
use mcpscan_core::resolve::resolve;
use mcpscan_core::rules::{self, Rule, RuleCtx};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load(dir: &Path, stem: &str) -> Vec<ServerSpec> {
    let path = dir.join(stem);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let format = if path.extension().and_then(|e| e.to_str()) == Some("toml") {
        ConfigFormat::Toml
    } else {
        ConfigFormat::Json
    };
    let parsed = parse_str(&text, &path, format).unwrap();
    let mut servers = parsed.servers;
    let tools_path = dir.join(format!("{}.tools.json", stem.trim_end_matches(".json")));
    if let Ok(tools_text) = std::fs::read_to_string(&tools_path) {
        let pack: serde_json::Value = serde_json::from_str(&tools_text).unwrap();
        let tools: Vec<ToolSpec> = pack["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| ToolSpec {
                name: t["name"].as_str().unwrap().to_string(),
                description: t["description"].as_str().unwrap_or("").to_string(),
                input_schema: t["inputSchema"].clone(),
            })
            .collect();
        for server in &mut servers {
            server.tools = tools.clone();
        }
    }
    for server in &mut servers {
        resolve(server);
    }
    servers
}

fn ctx_for(rule: &Rule, servers: &[ServerSpec]) -> RuleCtx {
    let mut ctx = RuleCtx {
        include_medium: true,
        ..Default::default()
    };
    if rule.id == "mcp-osv-vulnerable" {
        for server in servers {
            if let Some(pkg) = &server.pkg {
                ctx.osv_hits.insert(
                    mcpscan_core::osv::key(pkg),
                    vec![mcpscan_core::osv::OsvHit {
                        package: pkg.name.clone(),
                        version: pkg.version.clone().unwrap_or_default(),
                        ids: vec!["GHSA-test".to_string()],
                    }],
                );
            }
        }
    }
    ctx
}

fn severity_label(finding: &Finding) -> String {
    serde_json::to_string(&finding.severity)
        .unwrap()
        .trim_matches('"')
        .to_string()
}

fn signatures(rule: &Rule, servers: &[ServerSpec]) -> Vec<String> {
    let ctx = ctx_for(rule, servers);
    let mut out: Vec<String> = servers
        .iter()
        .filter(|s| (rule.applies_to)(s))
        .flat_map(|s| (rule.run)(s, &ctx))
        .map(|f| {
            format!(
                "{}|{}|{}",
                f.rule_id,
                severity_label(&f),
                f.location.pointer
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn every_rule_matches_its_fixtures() {
    let fixtures = root().join("fixtures");
    let mut checked = 0;
    for rule in rules::registry() {
        let dir = fixtures.join(rule.id);
        assert!(dir.is_dir(), "missing fixture dir for {}", rule.id);

        let vulnerable = load(&dir, "vulnerable.json");
        let expected: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).unwrap())
                .unwrap();
        let expected_rows: Vec<String> = expected["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                format!(
                    "{}|{}|{}",
                    f["rule_id"].as_str().unwrap(),
                    f["severity"].as_str().unwrap(),
                    f["pointer"].as_str().unwrap_or("")
                )
            })
            .collect();
        let actual = signatures(rule, &vulnerable);
        assert_eq!(actual.len(), expected_rows.len(), "{}: count", rule.id);
        for (row, expected_row) in actual.iter().zip(expected_rows.iter()) {
            let same = if expected_row.ends_with('|') {
                row.rsplit_once('|').map(|(a, _)| a)
                    == expected_row.rsplit_once('|').map(|(a, _)| a)
            } else {
                row == expected_row
            };
            assert!(same, "{}: got {row}, expected {expected_row}", rule.id);
        }

        let clean = load(&dir, "clean.json");
        assert!(
            signatures(rule, &clean).is_empty(),
            "{} fires on its clean fixture",
            rule.id
        );
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} rules checked");
}
