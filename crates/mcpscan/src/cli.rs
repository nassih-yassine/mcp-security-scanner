//! Command surface. Parsing only: no I/O, no exits.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Static security scan for MCP servers, agent configs and tool definitions.
#[derive(Debug, Parser)]
#[command(name = "mcpscan", version, about, disable_help_subcommand = true)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan directories for MCP and agent config issues.
    Scan(ScanArgs),
    /// List the rules in this build.
    Rules(RulesArgs),
}

/// Report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Terminal output.
    Human,
    /// Machine-readable report.
    Json,
    /// SARIF 2.1.0 for code scanning.
    Sarif,
    /// Markdown summary with a score.
    Markdown,
}

/// Severity at which the process fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    /// Fail on any finding.
    Low,
    /// Fail on medium and above.
    Medium,
    /// Fail on high and above.
    High,
    /// Fail on critical only (default).
    Critical,
    /// Never fail on findings.
    None,
}

/// Arguments for `scan`.
#[derive(Debug, clap::Args)]
pub struct ScanArgs {
    /// Directories to scan.
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,
    /// Report format.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
    /// Write the report to a file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Also scan per-user config files.
    #[arg(long)]
    pub user: bool,
    /// Also scan shell history for leaked credentials.
    #[arg(long)]
    pub include_history: bool,
    /// Directory with tool schema JSON files.
    #[arg(long)]
    pub tools_dir: Option<PathBuf>,
    /// Allow network lookups (OSV advisories).
    #[arg(long)]
    pub online: bool,
    /// Severity that makes the process exit 2.
    #[arg(long, value_enum, default_value_t = FailOn::Critical)]
    pub fail_on: FailOn,
    /// Include medium-confidence rules.
    #[arg(long)]
    pub include_medium: bool,
    /// Reviewed exception: rule-id:path-prefix=reason. Repeatable.
    #[arg(long = "allow", value_name = "RULE:PATH=REASON")]
    pub allow: Vec<String>,
}

/// Arguments for `rules`.
#[derive(Debug, clap::Args)]
pub struct RulesArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}
