//! `mcpscan` binary: argv, exit codes and stdout. All logic lives in the core.

mod cli;

use clap::Parser;
use cli::{Cli, Commands, FailOn, Format};
use mcpscan_core::model::{ExitCode, Severity};
use mcpscan_core::report;
use mcpscan_core::rules;
use mcpscan_core::scan::{scan, AllowEntry, ScanOptions};
use std::process::ExitCode as ProcessExitCode;

fn main() -> ProcessExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let is_help = matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let _ = err.print();
            return exit(if is_help { ExitCode::Clean } else { ExitCode::Incomplete });
        }
    };
    match run(cli) {
        Ok(code) => exit(code),
        Err(message) => {
            eprintln!("{message}");
            exit(ExitCode::Incomplete)
        }
    }
}

fn exit(code: ExitCode) -> ProcessExitCode {
    ProcessExitCode::from(code.as_i32() as u8)
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Commands::Scan(args) => run_scan(args),
        Commands::Rules(args) => run_rules(args),
    }
}

fn run_scan(args: cli::ScanArgs) -> Result<ExitCode, String> {
    let allow = args
        .allow
        .iter()
        .map(|raw| AllowEntry::parse(raw))
        .collect::<Result<Vec<_>, _>>()?;
    let options = ScanOptions {
        roots: args.paths,
        include_user: args.user,
        include_history: args.include_history,
        tools_dir: args.tools_dir,
        include_medium: args.include_medium,
        offline: !args.online,
        platform: mcpscan_core::discover::Platform::current(),
        allow,
    };
    let report = scan(&options).map_err(|e| e.to_string())?;

    let rendered = match args.format {
        Format::Human => report::human::render(&report),
        Format::Json => report::json::render(&report).map_err(|e| e.to_string())?,
        other => {
            return Err(format!(
                "--format {} is not implemented in this build",
                format_name(other)
            ));
        }
    };

    match args.output {
        Some(path) => std::fs::write(&path, rendered).map_err(|e| format!("{}: {e}", path.display()))?,
        None => print!("{rendered}"),
    }

    let threshold = threshold(args.fail_on);
    Ok(match threshold {
        Some(threshold) if report.findings.iter().any(|f| f.severity >= threshold) => {
            ExitCode::Findings
        }
        _ => ExitCode::Clean,
    })
}

fn run_rules(args: cli::RulesArgs) -> Result<ExitCode, String> {
    match args.format {
        Format::Human => {
            for rule in rules::registry() {
                println!(
                    "{}  {}  {}  since {}",
                    rule.id,
                    serde_json::to_string(&rule.severity).unwrap_or_default(),
                    serde_json::to_string(&rule.confidence).unwrap_or_default(),
                    rule.since
                );
            }
        }
        Format::Json => {
            let items: Vec<serde_json::Value> = rules::registry()
                .iter()
                .map(|rule| {
                    serde_json::json!({
                        "id": rule.id,
                        "severity": rule.severity,
                        "confidence": rule.confidence,
                        "since": rule.since,
                        "docs": rule.docs,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&items).map_err(|e| e.to_string())?
            );
        }
        other => return Err(format!("rules --format {} is not implemented", format_name(other))),
    }
    Ok(ExitCode::Clean)
}

fn threshold(fail_on: FailOn) -> Option<Severity> {
    match fail_on {
        FailOn::Low => Some(Severity::Low),
        FailOn::Medium => Some(Severity::Medium),
        FailOn::High => Some(Severity::High),
        FailOn::Critical => Some(Severity::Critical),
        FailOn::None => None,
    }
}

fn format_name(format: Format) -> &'static str {
    match format {
        Format::Human => "human",
        Format::Json => "json",
        Format::Sarif => "sarif",
        Format::Markdown => "markdown",
    }
}
