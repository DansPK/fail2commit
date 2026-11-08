//! T-008 (FR-008, SPEC-008) owns this directory: one shared flow that turns
//! a [`crate::policy::ScriptDecision`] into an authorized execution mode, so
//! npm (T-004) and pip (T-005) behave identically.
//!
//! Frozen API: [`ScriptRun`], [`authorize_scripts`].

use crate::approval::ApprovalCtx;
use crate::approver::{new_request, now_secs, validate_response, Approver};
use crate::digest::Digest;
use crate::isolation::SandboxBackend;
use crate::policy::{script_decision, DenyReason, ScriptDecision, ScriptSituation};
use crate::protocol::{
    ApprovalKind, ApprovalRequest, Decision, Finding, FindingAction, FindingKind,
};

/// How package-controlled code may run for this operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptRun {
    /// Nothing to run; no sandbox was started.
    NoScripts,
    /// Run allowed scripts through `crate::sandbox::run_job`.
    Sandboxed,
    /// Sandbox off: install continues without running scripts.
    Skipped,
    /// The user approved `RunOnHostOnce` for exactly `digest`.
    Host,
}

/// Apply the FR-008 table using `ctx.settings.sandbox.enabled` (the command
/// snapshot) and `backend.probe()`. For `AskHostOnce`, request a separate
/// `ApprovalKind::HostExecution` approval bound to `digest`, stating that the
/// code gains the current user's access. Denials are errors:
/// flagged script -> Rejected, isolation unavailable -> IsolationUnavailable,
/// declined host run -> Rejected. Never falls back to the host.
pub fn authorize_scripts(
    ctx: &ApprovalCtx<'_>,
    backend: &dyn SandboxBackend,
    situation: ScriptSituation,
    summary: &str,
    digest: &Digest,
) -> crate::Result<ScriptRun> {
    authorize(ctx, backend, situation, summary, digest, &|req| {
        crate::approval::approve(ctx, req)
    })
}

/// Same flow with an injectable approval channel (tests, embedders). The
/// reply is checked with [`validate_response`], so it must be bound to the
/// exact request and digest.
pub fn authorize_scripts_with(
    ctx: &ApprovalCtx<'_>,
    backend: &dyn SandboxBackend,
    approver: &dyn Approver,
    situation: ScriptSituation,
    summary: &str,
    digest: &Digest,
) -> crate::Result<ScriptRun> {
    authorize(ctx, backend, situation, summary, digest, &|req| {
        let resp = approver.ask(req)?;
        validate_response(req, &resp, now_secs())
    })
}

fn authorize(
    ctx: &ApprovalCtx<'_>,
    backend: &dyn SandboxBackend,
    situation: ScriptSituation,
    summary: &str,
    digest: &Digest,
    ask: &dyn Fn(&ApprovalRequest) -> crate::Result<Decision>,
) -> crate::Result<ScriptRun> {
    // Nothing to run: no probe, no sandbox.
    if !situation.has_scripts && !situation.flagged {
        return Ok(ScriptRun::NoScripts);
    }
    let available = backend.probe().available;
    match script_decision(ctx.settings.sandbox.enabled, available, situation) {
        ScriptDecision::NoScripts => Ok(ScriptRun::NoScripts),
        ScriptDecision::RunSandboxed => Ok(ScriptRun::Sandboxed),
        ScriptDecision::SkipScripts => Ok(ScriptRun::Skipped),
        ScriptDecision::AskHostOnce => {
            let finding = Finding::new(
                FindingKind::HostExecution,
                FindingAction::Approve,
                "exec.host",
                "package code would run on the host without a sandbox",
            );
            let req = new_request(
                ApprovalKind::HostExecution,
                digest,
                format!(
                    "{summary}
Run on host once: sandbox is off, so package code gains the                      current user's access and does not run in the sandbox."
                ),
                vec!["Runs with the current user's access, outside the sandbox.".into()],
                vec![finding],
                ctx.settings.approval.request_ttl_secs,
                false,
                vec![Decision::RunOnHostOnce],
            )?;
            match ask(&req)? {
                Decision::RunOnHostOnce => Ok(ScriptRun::Host),
                _ => Err(crate::Error::rejected("host execution was not approved")),
            }
        }
        ScriptDecision::Deny(DenyReason::FlaggedScript) => Err(crate::Error::rejected(
            "a flagged script is blocked",
        )
        .with_findings(vec![Finding::new(
            FindingKind::SuspiciousScript,
            FindingAction::Deny,
            "exec.policy",
            "script with Git force-push behavior is blocked in both sandbox modes",
        )])),
        ScriptDecision::Deny(DenyReason::IsolationUnavailable) => Err(
            crate::Error::isolation_unavailable("sandbox is on but isolation is unavailable"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approver::Scripted;
    use crate::isolation::{JobOutcome, JobSpec, ProbeReport};
    use crate::paths::TrustedPaths;
    use crate::settings::Settings;
    use crate::ResultCode;

    struct Fake(bool);
    impl SandboxBackend for Fake {
        fn probe(&self) -> ProbeReport {
            ProbeReport {
                backend: "fake",
                available: self.0,
                detail: String::new(),
                controls: vec![],
            }
        }
        fn run(&self, _: &JobSpec) -> crate::Result<JobOutcome> {
            unreachable!("authorization never runs jobs")
        }
    }

    fn sit(has: bool, req: bool, flagged: bool) -> ScriptSituation {
        ScriptSituation {
            has_scripts: has,
            required: req,
            flagged,
        }
    }

    fn go(on: bool, avail: bool, d: Decision, s: ScriptSituation) -> crate::Result<ScriptRun> {
        let paths = TrustedPaths::under(std::path::Path::new("unused"));
        let mut settings = Settings::default();
        settings.sandbox.enabled = on;
        let ctx = ApprovalCtx {
            paths: &paths,
            settings: &settings,
            choice: crate::approver::ApproverChoice::None,
        };
        let dg = Digest::of("t", &["x"]).unwrap();
        let a = Scripted {
            decision: d,
            password: None,
        };
        authorize_scripts_with(&ctx, &Fake(avail), &a, s, "install x", &dg)
    }

    #[test]
    fn table() {
        use Decision::*;
        assert_eq!(
            go(true, false, Cancel, sit(false, false, false)).unwrap(),
            ScriptRun::NoScripts
        );
        assert_eq!(
            go(true, true, Cancel, sit(true, true, false)).unwrap(),
            ScriptRun::Sandboxed
        );
        assert_eq!(
            go(false, false, Cancel, sit(true, false, false)).unwrap(),
            ScriptRun::Skipped
        );
        assert_eq!(
            go(false, false, RunOnHostOnce, sit(true, true, false)).unwrap(),
            ScriptRun::Host
        );
        for d in [Cancel, ApproveOnce] {
            assert_eq!(
                go(false, true, d, sit(true, true, false)).unwrap_err().code,
                ResultCode::Rejected
            );
        }
        assert_eq!(
            go(true, false, RunOnHostOnce, sit(true, true, false))
                .unwrap_err()
                .code,
            ResultCode::IsolationUnavailable
        );
        for on in [true, false] {
            let e = go(on, true, RunOnHostOnce, sit(true, true, true)).unwrap_err();
            assert_eq!(e.code, ResultCode::Rejected);
            assert_eq!(e.findings[0].kind, FindingKind::SuspiciousScript);
            assert_eq!(e.findings[0].action, FindingAction::Deny);
        }
    }
}
