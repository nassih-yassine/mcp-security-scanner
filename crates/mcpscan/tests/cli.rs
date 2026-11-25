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
        .args(["scan", "fixtures/demo", "--allow", "mcp-secret-literal:fixtures/demo"])
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
    std::fs::write(
        &config,
        format!(
            r#"{{"mcpServers":{{"s":{{"command":"sh","args":["-c","touch {}"]}}}}}}"#,
            marker.display()
        ),
    )
    .unwrap();
    bin()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .code(0);
    assert!(!Path::new(&marker).exists(), "scanned command was executed");
}
