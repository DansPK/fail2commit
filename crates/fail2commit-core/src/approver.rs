//! Approval channel contract (CHORE-001, frozen; SPEC-002 binding rules).
//!
//! Callers build an [`ApprovalRequest`] with [`new_request`], hand it to
//! `crate::approval::approve` (T-002), and act only on the returned
//! decision. [`validate_response`] is the single place that checks a reply
//! is bound to the exact request; every channel (terminal, tray pipe, VS Code
//! stdio) must go through it.

use crate::digest::{ct_eq, random_hex32, Digest};
use crate::protocol::{
    ApprovalKind, ApprovalRequest, ApprovalResponse, Decision, Finding, PROTOCOL_VERSION,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Where an approval may be obtained. Selected by `--approver`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ApproverChoice {
    /// Tray if running (Windows), else terminal if interactive, else none.
    #[default]
    Auto,
    Terminal,
    /// Windows tray named pipe.
    Tray,
    /// Line-delimited JSON over stdin/stdout (`fail2commit api`, VS Code).
    Stdio,
    /// Unattended: anything needing approval fails closed.
    None,
}

/// One interactive channel. Implementations only transport; they must not
/// decide policy.
pub trait Approver {
    fn name(&self) -> &'static str;
    /// Present the request and wait. `Err(ApprovalUnavailable)` if the channel
    /// cannot be reached; a closed/timeout channel is Cancel or unavailable,
    /// never approval.
    fn ask(&self, req: &ApprovalRequest) -> crate::Result<ApprovalResponse>;
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Per-process session id (random, stable for this CLI process).
pub fn session_id() -> &'static str {
    use std::sync::OnceLock;
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| random_hex32().unwrap_or_else(|_| format!("pid-{}", std::process::id())))
}

#[allow(clippy::too_many_arguments)]
pub fn new_request(
    kind: ApprovalKind,
    digest: &Digest,
    summary: impl Into<String>,
    details: Vec<String>,
    findings: Vec<Finding>,
    ttl_secs: u64,
    password_required: bool,
    allowed: Vec<Decision>,
) -> crate::Result<ApprovalRequest> {
    Ok(ApprovalRequest {
        version: PROTOCOL_VERSION,
        request_id: random_hex32()?[..32].to_string(),
        nonce: random_hex32()?,
        digest: digest.as_hex().to_string(),
        session: session_id().to_string(),
        kind,
        summary: summary.into(),
        details,
        findings,
        expires_at: now_secs().saturating_add(ttl_secs),
        password_required,
        allowed,
    })
}

/// Check that `resp` answers exactly `req` and is still valid at `now`.
/// Returns the decision (Cancel on any mismatch is NOT returned: mismatches
/// are errors so callers can log them). Password verification is T-002's
/// job and happens after this succeeds.
pub fn validate_response(
    req: &ApprovalRequest,
    resp: &ApprovalResponse,
    now: u64,
) -> crate::Result<Decision> {
    let bad = |m: &str| {
        Err(crate::Error::rejected(format!(
            "approval response rejected: {m}"
        )))
    };
    if resp.version != PROTOCOL_VERSION {
        return bad("protocol version");
    }
    if !ct_eq(resp.request_id.as_bytes(), req.request_id.as_bytes()) {
        return bad("request id");
    }
    if !ct_eq(resp.nonce.as_bytes(), req.nonce.as_bytes()) {
        return bad("nonce");
    }
    if !ct_eq(resp.digest.as_bytes(), req.digest.as_bytes()) {
        return bad("operation changed");
    }
    if now > req.expires_at {
        return bad("expired");
    }
    if resp.decision != Decision::Cancel && !req.allowed.contains(&resp.decision) {
        return bad("decision not offered");
    }
    if resp.decision != Decision::Cancel
        && req.password_required
        && resp.password.as_deref().unwrap_or("").is_empty()
    {
        return bad("password required");
    }
    Ok(resp.decision)
}

/// Test double: answers every request with a fixed decision. Never use
/// outside tests or fixtures.
pub struct Scripted {
    pub decision: Decision,
    pub password: Option<String>,
}

impl Approver for Scripted {
    fn name(&self) -> &'static str {
        "scripted"
    }
    fn ask(&self, req: &ApprovalRequest) -> crate::Result<ApprovalResponse> {
        Ok(ApprovalResponse {
            version: PROTOCOL_VERSION,
            request_id: req.request_id.clone(),
            nonce: req.nonce.clone(),
            digest: req.digest.clone(),
            decision: self.decision,
            password: self.password.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(pw: bool) -> ApprovalRequest {
        let d = Digest::of("test", &["refs/heads/main", "a", "b"]).unwrap();
        new_request(
            ApprovalKind::Operation,
            &d,
            "push",
            vec![],
            vec![],
            60,
            pw,
            vec![Decision::ApproveOnce],
        )
        .unwrap()
    }

    #[test]
    fn binding_checks() {
        let r = req(false);
        let ok = Scripted {
            decision: Decision::ApproveOnce,
            password: None,
        }
        .ask(&r)
        .unwrap();
        assert_eq!(
            validate_response(&r, &ok, now_secs()).unwrap(),
            Decision::ApproveOnce
        );

        let mut changed = ok.clone();
        changed.digest = Digest::of("test", &["refs/heads/main", "a", "c"])
            .unwrap()
            .to_string();
        assert!(validate_response(&r, &changed, now_secs()).is_err());

        let mut replay = ok.clone();
        replay.nonce = "00".repeat(32);
        assert!(validate_response(&r, &replay, now_secs()).is_err());

        assert!(validate_response(&r, &ok, r.expires_at + 1).is_err());

        let mut host = ok.clone();
        host.decision = Decision::RunOnHostOnce;
        assert!(validate_response(&r, &host, now_secs()).is_err());
    }

    #[test]
    fn password_presence_required() {
        let r = req(true);
        let no_pw = Scripted {
            decision: Decision::ApproveOnce,
            password: None,
        }
        .ask(&r)
        .unwrap();
        assert!(validate_response(&r, &no_pw, now_secs()).is_err());
        let cancel = Scripted {
            decision: Decision::Cancel,
            password: None,
        }
        .ask(&r)
        .unwrap();
        assert_eq!(
            validate_response(&r, &cancel, now_secs()).unwrap(),
            Decision::Cancel
        );
    }
}
