//! T-002 (FR-002, SPEC-002) owns this directory.
//!
//! Frozen API (keep signatures): [`ApprovalCtx`], [`approve`],
//! [`password_required`]. Everything else here is the worker's choice:
//! terminal prompt, stdio channel, password/recovery state, rate limits.
//! Threat model and parameters: docs/approval.md.

pub mod console;
pub mod password;

mod channels;
mod replay;
#[cfg(test)]
mod tests;

use crate::approver::{now_secs, session_id, validate_response, Approver, ApproverChoice};
use crate::paths::TrustedPaths;
use crate::protocol::{ApprovalRequest, Decision, PROTOCOL_VERSION};
use crate::settings::Settings;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

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
    let channel: Box<dyn Approver> = match ctx.choice {
        ApproverChoice::None => {
            return Err(crate::Error::approval_unavailable(
                "approval required but running unattended",
            ))
        }
        ApproverChoice::Tray => crate::ipc::tray_approver().ok_or_else(|| {
            crate::Error::approval_unavailable("approval required but the tray is not running")
        })?,
        ApproverChoice::Terminal => Box::new(channels::Terminal),
        ApproverChoice::Stdio => Box::new(channels::Stdio),
        ApproverChoice::Auto => match crate::ipc::tray_approver() {
            Some(tray) => tray,
            None if console::interactive() => Box::new(channels::Terminal),
            None => {
                return Err(crate::Error::approval_unavailable(
                    "approval required but no tray or interactive terminal is available",
                ))
            }
        },
    };
    approve_with(ctx, req, channel.as_ref())
}

/// Whether the optional force-push password is enabled for this user.
///
/// Also records the password generation this process saw, so a request
/// built from this answer cannot be approved after a later reset/change.
pub fn password_required(paths: &TrustedPaths) -> crate::Result<bool> {
    let s = password::load(paths)?;
    observed()
        .lock()
        .map_err(|_| crate::Error::internal("approval state lock poisoned"))?
        .entry(paths.state_dir.clone())
        .or_insert(s.generation);
    Ok(s.enabled())
}

fn observed() -> &'static Mutex<HashMap<PathBuf, u64>> {
    static M: std::sync::OnceLock<Mutex<HashMap<PathBuf, u64>>> = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// Request ids already presented by this process (never prompt twice).
fn asked() -> &'static Mutex<HashSet<String>> {
    static M: std::sync::OnceLock<Mutex<HashSet<String>>> = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// The policy half of [`approve`], with the channel supplied.
pub(crate) fn approve_with(
    ctx: &ApprovalCtx<'_>,
    req: &ApprovalRequest,
    channel: &dyn Approver,
) -> crate::Result<Decision> {
    password::reject_secret_env()?;
    if req.version != PROTOCOL_VERSION {
        return Err(crate::Error::rejected(
            "approval request has an unknown version",
        ));
    }
    if req.session != session_id() {
        return Err(crate::Error::rejected(
            "approval request belongs to another session",
        ));
    }
    if now_secs() > req.expires_at {
        return Err(crate::Error::rejected("approval request expired"));
    }
    if !req.allowed.iter().any(|d| *d != Decision::Cancel) {
        return Ok(Decision::Cancel);
    }
    replay::ensure_unused(ctx.paths, &req.nonce)?;

    let generation = if req.password_required {
        let s = password::load(ctx.paths)?;
        if !s.enabled() {
            return Err(crate::Error::rejected(
                "request requires the force-push password but none is set",
            ));
        }
        let seen = observed()
            .lock()
            .map_err(|_| crate::Error::internal("approval state lock poisoned"))?
            .get(&ctx.paths.state_dir)
            .copied();
        if seen.is_some_and(|g| g != s.generation) {
            return Err(crate::Error::rejected(
                "password state changed after the request was created; retry the operation",
            ));
        }
        Some(s.generation)
    } else {
        None
    };

    let first = asked()
        .lock()
        .map_err(|_| crate::Error::internal("approval state lock poisoned"))?
        .insert(req.request_id.clone());
    if !first {
        return Err(crate::Error::rejected(
            "approval request was already presented",
        ));
    }

    let resp = match channel.ask(req) {
        Ok(r) => r,
        Err(e) if e.code == crate::ResultCode::ApprovalUnavailable => return Err(e),
        // Any other channel failure is a cancel, never an approval.
        Err(_) => channels::reply(req, Decision::Cancel, None),
    };
    let decision = validate_response(req, &resp, now_secs())?;
    replay::consume(ctx.paths, &req.nonce, req.expires_at)?;
    if decision == Decision::Cancel {
        return Ok(Decision::Cancel);
    }
    if let Some(g) = generation {
        password::verify_for_request(ctx.paths, resp.password.as_deref().unwrap_or(""), g)?;
    }
    Ok(decision)
}
