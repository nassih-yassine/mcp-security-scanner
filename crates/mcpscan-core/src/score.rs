//! Scoring and the CI gate. Weights live here and nowhere else.

use crate::model::{Confidence, ExitCode, Finding, Severity};
use std::collections::BTreeSet;

/// What the caller asked the gate to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Fail when a finding is at or above this severity. `None` never fails.
    pub fail_on: Option<Severity>,
    /// Whether medium-confidence rules should run.
    pub include_medium: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            fail_on: Some(Severity::Critical),
            include_medium: false,
        }
    }
}

/// Letter grade derived from the score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    /// 90-100.
    A,
    /// 70-89.
    B,
    /// 50-69.
    C,
    /// 30-49.
    D,
    /// 0-29.
    F,
}

impl Grade {
    /// Single-letter label.
    pub fn as_str(self) -> &'static str {
        match self {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        }
    }
}

fn weight(severity: Severity) -> u32 {
    match severity {
        Severity::Critical => 40,
        Severity::High => 20,
        Severity::Medium => 8,
        Severity::Low => 2,
    }
}

fn multiplier(confidence: Confidence) -> f64 {
    match confidence {
        Confidence::High => 1.0,
        Confidence::Medium => 0.5,
        Confidence::Low => 0.25,
    }
}

/// 100 minus the deduplicated penalty of every finding.
pub fn score(findings: &[Finding]) -> u8 {
    let mut seen = BTreeSet::new();
    let mut penalty = 0.0_f64;
    for finding in findings {
        if !seen.insert(finding.fingerprint.as_str()) {
            continue;
        }
        penalty += f64::from(weight(finding.severity)) * multiplier(finding.confidence);
    }
    (100.0 - penalty).clamp(0.0, 100.0) as u8
}

/// Map a score to a letter grade.
pub fn grade(score: u8) -> Grade {
    match score {
        90..=100 => Grade::A,
        70..=89 => Grade::B,
        50..=69 => Grade::C,
        30..=49 => Grade::D,
        _ => Grade::F,
    }
}

/// The process outcome implied by the findings and the policy.
pub fn gate(findings: &[Finding], policy: &Policy) -> ExitCode {
    match policy.fail_on {
        Some(threshold) if findings.iter().any(|f| f.severity >= threshold) => ExitCode::Findings,
        _ => ExitCode::Clean,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Finding, Location, Severity};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn f(severity: Severity, confidence: Confidence) -> Finding {
        let mut finding = Finding::new(
            "mcp-test",
            severity,
            confidence,
            "m",
            Location {
                file: PathBuf::from("c.json"),
                pointer: "/p".into(),
                span: None,
            },
            None,
            "fix",
        );
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        finding.fingerprint = format!("{severity:?}{confidence:?}{n}");
        finding
    }

    #[test]
    fn score_subtracts_weight_times_confidence() {
        assert_eq!(score(&[]), 100);
        assert_eq!(score(&[f(Severity::Critical, Confidence::High)]), 60);
        assert_eq!(score(&[f(Severity::High, Confidence::High)]), 80);
        assert_eq!(score(&[f(Severity::Medium, Confidence::Medium)]), 96);
        let five: Vec<_> = (0..5).map(|_| f(Severity::Critical, Confidence::High)).collect();
        assert_eq!(score(&five), 0);
    }

    #[test]
    fn duplicate_findings_count_once() {
        let one = f(Severity::High, Confidence::High);
        assert_eq!(score(&[one.clone(), one]), 80);
    }

    #[test]
    fn grades_follow_the_spec_bands() {
        assert_eq!(grade(100), Grade::A);
        assert_eq!(grade(90), Grade::A);
        assert_eq!(grade(89), Grade::B);
        assert_eq!(grade(69), Grade::C);
        assert_eq!(grade(49), Grade::D);
        assert_eq!(grade(29), Grade::F);
    }

    #[test]
    fn gate_defaults_to_critical() {
        let high = vec![f(Severity::High, Confidence::High)];
        let critical = vec![f(Severity::Critical, Confidence::High)];
        assert_eq!(gate(&high, &Policy::default()), ExitCode::Clean);
        assert_eq!(gate(&critical, &Policy::default()), ExitCode::Findings);
        assert_eq!(gate(&[], &Policy::default()), ExitCode::Clean);
        let none = Policy {
            fail_on: None,
            ..Policy::default()
        };
        assert_eq!(gate(&critical, &none), ExitCode::Clean);
        let low = Policy {
            fail_on: Some(Severity::Low),
            ..Policy::default()
        };
        assert_eq!(gate(&high, &low), ExitCode::Findings);
    }
}
