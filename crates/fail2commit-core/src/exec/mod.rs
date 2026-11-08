//! T-008 (FR-008, SPEC-008) owns this directory: one shared flow that turns
//! a [`crate::policy::ScriptDecision`] into an authorized execution mode, so
//! npm (T-004) and pip (T-005) behave identically.
//!
//! Frozen API: [`ScriptRun`], [`authorize_scripts`].

use crate::approval::ApprovalCtx;
use crate::digest::Digest;
use crate::isolation::SandboxBackend;
use crate::policy::ScriptSituation;

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
    let _ = (ctx, backend, summary, digest);
    if !situation.has_scripts && !situation.flagged {
        return Ok(ScriptRun::NoScripts);
    }
    Err(crate::Error::not_implemented("script authorization"))
}
