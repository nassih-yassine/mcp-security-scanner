//! Orchestration: discover, parse, resolve, run rules, apply allow entries.

use crate::discover::{self, DiscoverOptions, Platform};
use crate::model::{
    Capabilities, ConfigFormat, Finding, ScanReport, ServerSpec, Severity, Skipped, Source, Transport,
};
use crate::parse::{self, ParseError};
use crate::resolve;
use crate::rules::{self, RuleCtx};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One reviewed exception: downgrade a rule for a path prefix, with a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowEntry {
    /// Rule the exception applies to.
    pub rule_id: String,
    /// Path prefix the exception covers.
    pub path_prefix: String,
    /// Why it is acceptable. Required.
    pub reason: String,
}

impl AllowEntry {
    /// Parse `rule-id:path-prefix=reason`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let (head, reason) = raw
            .split_once('=')
            .ok_or_else(|| format!("allow entry needs a reason: expected <rule>:<path>=<reason>, got {raw}"))?;
        if reason.trim().is_empty() {
            return Err(format!("allow entry needs a non-empty reason: {raw}"));
        }
        let (rule_id, path_prefix) = head
            .split_once(':')
            .ok_or_else(|| format!("allow entry needs a path: expected <rule>:<path>=<reason>, got {raw}"))?;
        Ok(Self {
            rule_id: rule_id.to_string(),
            path_prefix: path_prefix.to_string(),
            reason: reason.trim().to_string(),
        })
    }
}

/// What to scan and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOptions {
    /// Directories to scan.
    pub roots: Vec<PathBuf>,
    /// Include per-user config paths.
    pub include_user: bool,
    /// Include shell history.
    pub include_history: bool,
    /// Directory holding tool schema files.
    pub tools_dir: Option<PathBuf>,
    /// Include medium-confidence rules.
    pub include_medium: bool,
    /// Network is off.
    pub offline: bool,
    /// Platform for user paths.
    pub platform: Platform,
    /// Reviewed exceptions.
    pub allow: Vec<AllowEntry>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            roots: vec![PathBuf::from(".")],
            include_user: false,
            include_history: false,
            tools_dir: None,
            include_medium: false,
            offline: true,
            platform: Platform::current(),
            allow: Vec::new(),
        }
    }
}

/// Why a scan could not be completed.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// A requested root does not exist.
    #[error("{0}: no such file or directory")]
    MissingRoot(PathBuf),
    /// An existing file could not be read or parsed.
    #[error("{path}: {message}")]
    Unreadable {
        /// Offending file.
        path: PathBuf,
        /// Parser or IO message.
        message: String,
    },
}

/// Scan every root and return one deterministic report.
pub fn scan(opts: &ScanOptions) -> Result<ScanReport, ScanError> {
    let mut servers = Vec::new();
    let mut skipped = Vec::new();

    for root in &opts.roots {
        if !root.exists() {
            return Err(ScanError::MissingRoot(root.clone()));
        }
        let discovered = discover::candidates(&DiscoverOptions {
            root: root.clone(),
            include_user: opts.include_user,
            include_history: opts.include_history,
        });
        for path in discovered {
            if !path.exists() || path.is_dir() {
                continue;
            }
            if is_env_like(&path) {
                let bytes = std::fs::read(&path).map_err(|e| ScanError::Unreadable {
                    path: path.clone(),
                    message: e.to_string(),
                })?;
                servers.push(kv_server(&path, &String::from_utf8_lossy(&bytes)));
                continue;
            }
            match parse::parse_file(&path) {
                Ok(parsed) => {
                    for mut server in parsed.servers {
                        resolve::resolve(&mut server);
                        servers.push(server);
                    }
                    for unreadable in parsed.unreadable {
                        skipped.push(Skipped {
                            file: unreadable.file,
                            reason: unreadable.reason,
                        });
                    }
                }
                Err(err) => {
                    let message = match err {
                        ParseError::Io { source, .. } => source.to_string(),
                        other => other.to_string(),
                    };
                    return Err(ScanError::Unreadable {
                        path: path.clone(),
                        message,
                    });
                }
            }
        }
    }

    servers.sort_by(|a, b| {
        a.source
            .file
            .cmp(&b.source.file)
            .then_with(|| a.name.cmp(&b.name))
    });
    skipped.sort_by(|a, b| a.file.cmp(&b.file).then_with(|| a.reason.cmp(&b.reason)));

    let ctx = RuleCtx {
        offline: opts.offline,
        tools_dir: opts.tools_dir.clone(),
        include_medium: opts.include_medium,
    };
    let mut findings = rules::run_all(&servers, &ctx);
    apply_allow(&mut findings, &opts.allow);
    rules::sort_findings(&mut findings);

    Ok(ScanReport {
        schema_version: 1,
        servers,
        findings,
        skipped,
    })
}

fn apply_allow(findings: &mut [Finding], allow: &[AllowEntry]) {
    for finding in findings.iter_mut() {
        let file = finding.location.file.to_string_lossy();
        let hit = allow.iter().find(|entry| {
            entry.rule_id == finding.rule_id && file.starts_with(&entry.path_prefix)
        });
        if let Some(entry) = hit {
            finding.severity = Severity::Low;
            finding.message = format!("{} (allowed: {})", finding.message, entry.reason);
        }
    }
}

fn is_env_like(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == ".env" || name.starts_with(".env.") || discover::is_history(path)
}

fn kv_server(path: &Path, text: &str) -> ServerSpec {
    let mut env = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if value.is_empty() {
            continue;
        }
        env.insert(format!("{}#{i}", key.trim()), value.to_string());
    }
    ServerSpec {
        id: path.display().to_string(),
        name: path.display().to_string(),
        source: Source {
            file: path.to_path_buf(),
            format: ConfigFormat::Env,
            pointer: String::new(),
            span: None,
        },
        transport: Transport::Stdio,
        command: None,
        args: Vec::new(),
        env,
        url: None,
        headers: BTreeMap::new(),
        pkg: None,
        tools: Vec::new(),
        declared_scopes: Vec::new(),
        capabilities: Capabilities::default(),
    }
}
