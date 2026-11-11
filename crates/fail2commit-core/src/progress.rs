//! Install review progress (FR-013; coordinator-owned contract, frozen).
//!
//! The npm and pip flows report through a [`Progress`] sink; the CLI decides
//! where it goes (a redrawn stderr line, the Windows progress window, or
//! nowhere). Reporting is best effort and must never change a decision: a sink
//! that fails or is slow only loses progress text. Package names passed here
//! come from untrusted metadata; sinks bound and sanitize them before display.

use crate::protocol::Finding;

/// Review steps, in the order a flow normally runs them. A flow may skip a
/// step; it never goes back to an earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Resolve,
    DownloadVerify,
    PreInstallChecks,
    ScanCode,
    Advisories,
    Scripts,
    ScanOutput,
    Apply,
}

impl Step {
    pub fn label(self) -> &'static str {
        match self {
            Step::Resolve => "Resolving the install plan",
            Step::DownloadVerify => "Downloading and verifying packages",
            Step::PreInstallChecks => "Running pre-install checks",
            Step::ScanCode => "Scanning package code",
            Step::Advisories => "Checking advisories and malware data",
            Step::Scripts => "Running install scripts in the sandbox",
            Step::ScanOutput => "Scanning files the scripts produced",
            Step::Apply => "Applying the install",
        }
    }
}

/// How the review ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum End {
    /// Finished with no findings.
    Clean,
    /// Finished; findings were shown or approved.
    Findings,
    /// Denied, cancelled or failed.
    Stopped,
}

pub trait Progress: Send + Sync {
    /// A new step starts with `total` units (packages, scripts or files; 0 if
    /// unknown).
    fn step(&self, _step: Step, _total: u64) {}
    /// `done` units of the current step are finished; `current` names the
    /// unit being worked on (may be empty).
    fn advance(&self, _done: u64, _current: &str) {}
    /// A finding was produced (already redacted).
    fn finding(&self, _finding: &Finding) {}
    /// Called before any approval prompt or console output from the flow, so
    /// a terminal sink can clear its line.
    fn pause(&self) {}
    /// The review ended; `summary` is one line for the result.
    fn finish(&self, _end: End, _summary: &str) {}
}

/// Reports nothing (tests, `--json`, the api channel).
pub struct Silent;

impl Progress for Silent {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_are_ordered_as_the_flow_runs() {
        assert!(Step::Resolve < Step::DownloadVerify);
        assert!(Step::Scripts < Step::ScanOutput);
        assert!(Step::ScanOutput < Step::Apply);
        let s: &dyn Progress = &Silent;
        s.step(Step::Resolve, 3);
        s.finish(End::Clean, "ok");
    }
}
