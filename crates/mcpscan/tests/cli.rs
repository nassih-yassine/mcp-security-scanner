use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;

fn bin() -> Command {
    let mut cmd = Command::cargo_bin("mcpscan").unwrap();
    cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    cmd
}

#[test]
fn clean_repo_exits_zero() {
    bin()
        .args(["scan", "fixtures/_parse/clean"])
        .assert()
        .code(0);
}

#[test]
fn leaked_secret_exits_two_and_redacts() {
    let out = bin().args(["scan", "fixtures/demo"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("mcp-secret-literal"), "{stdout}");
    assert!(!stdout.contains("ghp_1234567890abcdefghijklmnopqrstuvwx"));
}

#[test]
fn missing_path_exits_three() {
    bin()
        .args(["scan", "does/not/exist"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("does/not/exist"));
}

#[cfg(unix)]
#[test]
fn unreadable_file_exits_three_and_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join(".mcp.json");
    std::fs::write(&bad, b"{\"mcpServers\":{}}").unwrap();
    let mut perms = std::fs::metadata(&bad).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o000);
    std::fs::set_permissions(&bad, perms).unwrap();
    bin()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(".mcp.json"));
}

#[test]
fn usage_error_is_three_not_two() {
    bin().args(["scan", "--nope"]).assert().code(3);
}

#[test]
fn allowlist_downgrades_and_demands_a_reason() {
    let ok = bin()
        .args([
            "scan",
            "fixtures/demo",
            "--allow",
            "mcp-secret-literal:fixtures/demo=test fixture",
        ])
        .output()
        .unwrap();
    assert_eq!(ok.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&ok.stdout).contains("test fixture"));

    bin()
        .args([
            "scan",
            "fixtures/demo",
            "--allow",
            "mcp-secret-literal:fixtures/demo",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("reason"));
}

#[test]
fn rules_subcommand_lists_registry() {
    bin()
        .args(["rules", "--format", "json"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("mcp-secret-literal"));
}

#[test]
fn scan_does_not_execute_anything() {
    // A command that would create a file if it were ever run.
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("executed");
    let config = dir.path().join(".mcp.json");
    // serde_json escapes the path, so a Windows backslash cannot break the JSON.
    let document = serde_json::json!({
        "mcpServers": {
            "s": { "command": "sh", "args": ["-c", format!("touch {}", marker.display())] }
        }
    });
    std::fs::write(&config, document.to_string()).unwrap();
    bin()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .code(0);
    assert!(!Path::new(&marker).exists(), "scanned command was executed");
}

#[test]
fn json_output_is_byte_identical_across_runs() {
    let a = bin()
        .args(["scan", "fixtures/demo", "--format", "json"])
        .output()
        .unwrap();
    let b = bin()
        .args(["scan", "fixtures/demo", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(a.status.code(), Some(2));
    assert_eq!(a.stdout, b.stdout);
}

#[test]
fn fail_on_threshold_is_honored() {
    bin()
        .args(["scan", "fixtures/demo", "--fail-on", "high"])
        .assert()
        .code(2);
    bin()
        .args(["scan", "fixtures/demo", "--fail-on", "none"])
        .assert()
        .code(0);
    bin()
        .args(["scan", "fixtures/_parse/clean", "--fail-on", "low"])
        .assert()
        .code(0);
}

#[test]
fn output_file_only_changes_where_the_report_goes() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("report.json");
    bin()
        .args([
            "scan",
            "fixtures/demo",
            "--format",
            "json",
            "--output",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("mcp-secret-literal"));
}

#[test]
fn sarif_format_is_valid_and_keeps_the_exit_code() {
    let out = bin()
        .args(["scan", "fixtures/demo", "--format", "sarif"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stdout);
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["version"], "2.1.0");
    assert_eq!(document["runs"][0]["tool"]["driver"]["name"], "mcpscan");
    assert!(text.contains("mcp-secret-literal"));
}

#[test]
fn markdown_format_reports_a_grade() {
    let out = bin()
        .args(["scan", "fixtures/demo", "--format", "markdown"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("## MCP security score: "));
}

#[test]
fn a_wrong_shaped_container_exits_three() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".mcp.json"), r#"{"mcpServers":[]}"#).unwrap();
    bin()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("mcpServers"));
}

#[cfg(unix)]
#[test]
fn an_unreadable_directory_exits_three() {
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join(".cursor");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("mcp.json"), b"{\"mcpServers\":{}}").unwrap();
    let mut perms = std::fs::metadata(&locked).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o000);
    std::fs::set_permissions(&locked, perms).unwrap();
    let result = bin()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .code(3);
    let mut perms = std::fs::metadata(&locked).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    let _ = std::fs::set_permissions(&locked, perms);
    drop(result);
}

#[cfg(unix)]
#[test]
fn a_dangling_symlink_exits_three() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("missing.json", dir.path().join(".mcp.json")).unwrap();
    bin()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(".mcp.json"));
}

#[test]
fn allow_prefix_respects_a_path_boundary() {
    // fixtures/demo is allowed; fixtures/demo-prod is a different directory.
    bin()
        .args([
            "scan",
            "fixtures/demo",
            "fixtures/demo-prod",
            "--allow",
            "mcp-secret-literal:fixtures/demo=test fixture",
        ])
        .assert()
        .code(2);
}

#[test]
fn invalid_utf8_env_exits_three() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), b"TOKEN=\xff\xfe\n").unwrap();
    bin()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(".env"));
}

#[test]
fn no_raw_secret_in_any_format() {
    let secret = "ghp_1234567890abcdefghijklmnopqrstuvwx";
    for format in ["human", "json", "sarif", "markdown"] {
        let out = bin()
            .args(["scan", "fixtures/demo", "--format", format])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains(secret), "raw secret in --format {format}");
        assert!(text.contains("ghp_…uvwx"), "no redacted shape in {format}");
    }
}
