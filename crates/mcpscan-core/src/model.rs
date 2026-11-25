//! Normalized scan model shared by every rule and report.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

/// How bad a finding is.
///
/// Declaration order is ascending significance, so `Critical` compares greater
/// than `High`. Keep it that way: the gate relies on `Ord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Hygiene.
    Low,
    /// Weakens a control without exposing anything by itself.
    Medium,
    /// Real exposure with a plausible path to harm.
    High,
    /// Exploitable now, or a live credential.
    Critical,
}

/// How sure the rule is. Only `High` ships in the default policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Experimental, never in the default policy.
    Low,
    /// Heuristic; expect some noise.
    Medium,
    /// Pattern is specific; false positives are rare.
    High,
}

/// Process exit codes. `2` means findings, `3` means the scan did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExitCode {
    /// Clean, or findings below the fail threshold.
    Clean,
    /// Findings at or above `--fail-on`.
    Findings,
    /// The scan could not be completed.
    Incomplete,
}

impl ExitCode {
    /// The process exit status for this outcome.
    pub fn as_i32(self) -> i32 {
        match self {
            ExitCode::Clean => 0,
            ExitCode::Findings => 2,
            ExitCode::Incomplete => 3,
        }
    }
}

/// How the config reaches the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// Launched locally over stdio.
    Stdio,
    /// Remote streamable HTTP endpoint.
    Http,
    /// Legacy server-sent-events endpoint.
    Sse,
}

/// Syntax of the file a server was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigFormat {
    /// Strict JSON.
    Json,
    /// JSON with comments and trailing commas.
    Jsonc,
    /// TOML.
    Toml,
}

/// Package registry a server package comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Registry {
    /// npm.
    Npm,
    /// PyPI.
    PyPi,
    /// A container image.
    Docker,
}

/// A 1-based source range, used for report line references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    /// First line, 1-based.
    pub start_line: usize,
    /// First column, 1-based.
    pub start_col: usize,
    /// Last line, 1-based.
    pub end_line: usize,
    /// Last column, 1-based.
    pub end_col: usize,
}

/// Where a server definition was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// Config file, relative to the scan root.
    pub file: PathBuf,
    /// Syntax of that file.
    pub format: ConfigFormat,
    /// JSON pointer to the server object.
    pub pointer: String,
    /// Source range when the parser could produce one.
    pub span: Option<Span>,
}

/// A package reference extracted from a launch command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRef {
    /// Registry that serves the package.
    pub registry: Registry,
    /// Package name as published.
    pub name: String,
    /// Exact version or digest when the config pins one.
    pub version: Option<String>,
}

/// Derived abilities of a server, from its command, args, env and url.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Can read local files.
    pub fs_read: bool,
    /// Can write local files.
    pub fs_write: bool,
    /// Can reach the network.
    pub net_egress: bool,
    /// Can run a shell or interpreter.
    pub shell_exec: bool,
    /// Can read a database.
    pub db_read: bool,
    /// Can write a database.
    pub db_write: bool,
    /// Config carries a literal credential.
    pub secret_in_config: bool,
}

/// A tool advertised by a server, when its schema is available locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSpec {
    /// Tool name as the model sees it.
    pub name: String,
    /// Description as the model sees it.
    pub description: String,
    /// JSON Schema for the tool input.
    pub input_schema: serde_json::Value,
}

/// One MCP server, normalized across every editor config shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSpec {
    /// Stable identifier derived from source path and server name.
    pub id: String,
    /// Server name as written in the config.
    pub name: String,
    /// Where the definition lives.
    pub source: Source,
    /// Transport implied by the config.
    pub transport: Transport,
    /// Executable for stdio servers.
    pub command: Option<String>,
    /// Arguments for stdio servers.
    pub args: Vec<String>,
    /// Environment for stdio servers.
    pub env: BTreeMap<String, String>,
    /// Endpoint for remote servers.
    pub url: Option<String>,
    /// Extra headers for remote servers.
    pub headers: BTreeMap<String, String>,
    /// Package reference when the launcher is a package runner.
    pub pkg: Option<PackageRef>,
    /// Tools with locally available schemas.
    pub tools: Vec<ToolSpec>,
    /// Scopes the config declares, when it does.
    pub declared_scopes: Vec<String>,
    /// Derived abilities.
    pub capabilities: Capabilities,
}

/// Where a finding points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// Config file, relative to the scan root.
    pub file: PathBuf,
    /// JSON pointer to the offending value.
    pub pointer: String,
    /// Source range when known.
    pub span: Option<Span>,
}

/// What a finding saw, with the sensitive part removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Kind of evidence, e.g. `env-value` or `url-host`.
    pub kind: String,
    /// Redacted rendering. Never the raw value.
    pub redacted: String,
}

/// One reported problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Rule that produced it. Kebab-case and frozen once released.
    pub rule_id: &'static str,
    /// Severity.
    pub severity: Severity,
    /// Rule confidence.
    pub confidence: Confidence,
    /// One sentence: what is wrong.
    pub message: String,
    /// Where it is.
    pub location: Location,
    /// Redacted evidence.
    pub evidence: Option<Evidence>,
    /// One actionable sentence.
    pub remediation: String,
    /// Stable hash of rule, file, pointer and redacted evidence.
    pub fingerprint: String,
}

impl Finding {
    /// Build a finding and compute its fingerprint.
    pub fn new(
        rule_id: &'static str,
        severity: Severity,
        confidence: Confidence,
        message: impl Into<String>,
        location: Location,
        evidence: Option<Evidence>,
        remediation: impl Into<String>,
    ) -> Self {
        let redacted = evidence.as_ref().map(|e| e.redacted.as_str()).unwrap_or("");
        let fingerprint = fingerprint(rule_id, &location, redacted);
        Self {
            rule_id,
            severity,
            confidence,
            message: message.into(),
            location,
            evidence,
            remediation: remediation.into(),
            fingerprint,
        }
    }
}

fn fingerprint(rule_id: &str, location: &Location, redacted: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(location.file.to_string_lossy().as_bytes());
    hasher.update([0]);
    hasher.update(location.pointer.as_bytes());
    hasher.update([0]);
    hasher.update(redacted.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A file that was found but deliberately not scanned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    /// File that was skipped.
    pub file: PathBuf,
    /// Why.
    pub reason: String,
}

/// The whole result of one scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    /// Wire schema version for `--format json`.
    pub schema_version: u32,
    /// Servers found, in deterministic order.
    pub servers: Vec<ServerSpec>,
    /// Findings, in deterministic order.
    pub findings: Vec<Finding>,
    /// Files found but not scanned.
    pub skipped: Vec<Skipped>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn finding(rule: &'static str, file: &'static str, pointer: &'static str) -> Finding {
        Finding::new(
            rule,
            Severity::High,
            Confidence::High,
            "message",
            Location { file: PathBuf::from(file), pointer: pointer.into(), span: None },
            Some(Evidence { kind: "env".into(), redacted: "sk-…(12)".into() }),
            "fix it",
        )
    }

    fn report() -> ScanReport {
        ScanReport {
            schema_version: 1,
            servers: vec![],
            findings: vec![finding("mcp-secret-literal", "a.json", "/mcpServers/x")],
            skipped: vec![],
        }
    }

    #[test]
    fn severity_orders_critical_first() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn fingerprint_is_stable_and_scoped_to_location() {
        let a = finding("mcp-secret-literal", "a.json", "/mcpServers/x");
        let b = finding("mcp-secret-literal", "a.json", "/mcpServers/x");
        let c = finding("mcp-secret-literal", "b.json", "/mcpServers/x");
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_ne!(a.fingerprint, c.fingerprint);
        assert_eq!(a.fingerprint.len(), 64);
        assert!(a.fingerprint.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn evidence_never_carries_the_raw_value() {
        let f = finding("mcp-secret-literal", "a.json", "/mcpServers/x");
        let raw = "ghp_1234567890abcdefghijklmnopqrstuvwx";
        assert!(!f.evidence.unwrap().redacted.contains(raw));
    }

    #[test]
    fn report_serializes_deterministically() {
        assert_eq!(
            serde_json::to_string(&report()).unwrap(),
            serde_json::to_string(&report()).unwrap()
        );
    }

    #[test]
    fn enum_wire_names_are_kebab_case() {
        assert_eq!(serde_json::to_string(&Severity::Critical).unwrap(), "\"critical\"");
        assert_eq!(serde_json::to_string(&Confidence::Medium).unwrap(), "\"medium\"");
        assert_eq!(serde_json::to_string(&ExitCode::Findings).unwrap(), "\"findings\"");
        assert_eq!(ExitCode::Findings.as_i32(), 2);
        assert_eq!(ExitCode::Incomplete.as_i32(), 3);
    }
}
