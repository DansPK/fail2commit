//! Package-code execution policy (FR-008 / SPEC-008 decision table).
//!
//! Shared by npm, pip and `fail2commit run`, so it lives in the frozen
//! contract. Inputs come from the trusted settings snapshot and the backend
//! probe; nothing here reads repository data.

/// What the package manager adapter found about package-controlled code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptSituation {
    /// Any lifecycle/build script would run for this install.
    pub has_scripts: bool,
    /// At least one script is needed for a working install (native build).
    pub required: bool,
    /// The scanner flagged a script for force-push behavior (hard deny).
    pub flagged: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptDecision {
    /// Script-free install: no sandbox starts.
    NoScripts,
    /// Sandbox on and available: run allowed scripts inside it.
    RunSandboxed,
    /// Sandbox off: skip scripts (install continues without them).
    SkipScripts,
    /// Sandbox off and a required script: needs a separate
    /// `Decision::RunOnHostOnce` approval (ApprovalKind::HostExecution).
    AskHostOnce,
    /// Stop before any package code runs.
    Deny(DenyReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    FlaggedScript,
    /// Sandbox on but unavailable. Never falls back to the host.
    IsolationUnavailable,
}

/// `sandbox_enabled` is the snapshot taken at command start.
/// `isolation_available` is `SandboxBackend::probe().available`.
pub fn script_decision(
    sandbox_enabled: bool,
    isolation_available: bool,
    s: ScriptSituation,
) -> ScriptDecision {
    if s.flagged {
        return ScriptDecision::Deny(DenyReason::FlaggedScript);
    }
    if !s.has_scripts {
        return ScriptDecision::NoScripts;
    }
    match (sandbox_enabled, isolation_available, s.required) {
        (true, true, _) => ScriptDecision::RunSandboxed,
        (true, false, _) => ScriptDecision::Deny(DenyReason::IsolationUnavailable),
        (false, _, false) => ScriptDecision::SkipScripts,
        (false, _, true) => ScriptDecision::AskHostOnce,
    }
}

/// Explicit `fail2commit run` always requires isolation, regardless of the
/// toggle.
pub fn explicit_run_allowed(isolation_available: bool) -> crate::Result<()> {
    if isolation_available {
        Ok(())
    } else {
        Err(crate::Error::isolation_unavailable(
            "no verified sandbox backend; refusing to run",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ScriptDecision::*;

    const fn s(has_scripts: bool, required: bool, flagged: bool) -> ScriptSituation {
        ScriptSituation {
            has_scripts,
            required,
            flagged,
        }
    }

    #[test]
    fn decision_table() {
        assert_eq!(
            script_decision(true, true, s(false, false, false)),
            NoScripts
        );
        assert_eq!(
            script_decision(false, false, s(false, false, false)),
            NoScripts
        );
        assert_eq!(
            script_decision(true, true, s(true, true, false)),
            RunSandboxed
        );
        assert_eq!(
            script_decision(true, false, s(true, false, false)),
            Deny(DenyReason::IsolationUnavailable)
        );
        assert_eq!(
            script_decision(false, true, s(true, false, false)),
            SkipScripts
        );
        assert_eq!(
            script_decision(false, true, s(true, true, false)),
            AskHostOnce
        );
        for on in [true, false] {
            for avail in [true, false] {
                assert_eq!(
                    script_decision(on, avail, s(true, true, true)),
                    Deny(DenyReason::FlaggedScript)
                );
            }
        }
        assert!(explicit_run_allowed(false).is_err());
    }
}
