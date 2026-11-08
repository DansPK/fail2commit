//! T-002 (FR-002, SPEC-002) owns this directory.
//!
//! Frozen API (keep signatures): [`ApprovalCtx`], [`approve`],
//! [`password_required`]. Everything else here is the worker's choice:
//! terminal prompt, stdio channel, password/recovery state, rate limits.

use crate::approver::ApproverChoice;
use crate::paths::TrustedPaths;
use crate::protocol::{ApprovalRequest, Decision};
use crate::settings::Settings;

pub struct ApprovalCtx<'a> {
    pub paths: &'a TrustedPaths,
    pub settings: &'a Settings,
    pub choice: ApproverChoice,
}

/// Obtain a decision for `req` through the selected channel, then enforce
/// binding ([`crate::approver::validate_response`]), password verification
/// when `req.password_required`, and rate limits. Returns `Cancel` or an
/// offered decision; unreachable channels are `ApprovalUnavailable`.
pub fn approve(ctx: &ApprovalCtx<'_>, req: &ApprovalRequest) -> crate::Result<Decision> {
    let _ = req;
    match ctx.choice {
        ApproverChoice::None => Err(crate::Error::approval_unavailable(
            "approval required but running unattended",
        )),
        _ => Err(crate::Error::approval_unavailable(
            "approval channels are not implemented in this build",
        )),
    }
}

/// Whether the optional force-push password is enabled for this user.
pub fn password_required(paths: &TrustedPaths) -> crate::Result<bool> {
    let _ = paths;
    Ok(false)
}
