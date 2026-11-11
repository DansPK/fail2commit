//! Versioned JSON wire contract (CHORE-001, frozen).
//!
//! Used by the CLI `--json` output, `fail2commit api` (VS Code), and the
//! Windows tray named-pipe approval channel. Additive fields must be
//! `#[serde(default)]`; anything else bumps [`PROTOCOL_VERSION`].

use serde::{Deserialize, Serialize};
use std::fmt;

/// Version of every message in this module.
pub const PROTOCOL_VERSION: u32 = 1;

/// Stable machine-readable outcome codes. Do not renumber.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ResultCode {
    /// Operation allowed and completed (see `Response::tool_exit`).
    Ok,
    /// Canceled by the user or denied by policy.
    Rejected,
    /// Approval was required but no approver could be reached (non-TTY,
    /// tray closed with no terminal, unattended run). Fails closed.
    ApprovalUnavailable,
    /// A scan could not complete (bounds hit, offline, missing objects).
    IncompleteScan,
    /// Artifact bytes or plan did not match what was reviewed.
    IntegrityFailure,
    /// Required sandbox could not start or cannot enforce policy.
    IsolationUnavailable,
    /// Bad arguments, unsupported input, or untrusted configuration.
    InvalidInput,
    /// Bug or unexpected environment failure.
    Internal,
}

impl ResultCode {
    /// Process exit status for this code. `Ok` is 0, or the delegated tool's
    /// own exit status when one ran (see [`Response::exit_status`]).
    pub fn exit_code(self) -> i32 {
        match self {
            ResultCode::Ok => 0,
            ResultCode::InvalidInput => 2,
            ResultCode::Rejected => 10,
            ResultCode::ApprovalUnavailable => 11,
            ResultCode::IncompleteScan => 12,
            ResultCode::IntegrityFailure => 13,
            ResultCode::IsolationUnavailable => 14,
            ResultCode::Internal => 70,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ResultCode::Ok => "ok",
            ResultCode::Rejected => "rejected",
            ResultCode::ApprovalUnavailable => "approval_unavailable",
            ResultCode::IncompleteScan => "incomplete_scan",
            ResultCode::IntegrityFailure => "integrity_failure",
            ResultCode::IsolationUnavailable => "isolation_unavailable",
            ResultCode::InvalidInput => "invalid_input",
            ResultCode::Internal => "internal",
        }
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Explicit force flag/refspec seen by the shim (FR-001).
    ForceIntent,
    /// Non-fast-forward update of a branch observed by the hook.
    RefRewrite,
    /// Ref deletion.
    RefDeletion,
    /// Existing tag moved to a different object.
    TagReplacement,
    /// Outgoing secret or `.env` file (added or deleted in history).
    Secret,
    /// Known vulnerability advisory for an exact package version.
    Advisory,
    /// Known-malicious package (OpenSSF malicious-packages via OSV `MAL-`).
    Malware,
    /// Lifecycle script with Git force-push evidence.
    SuspiciousScript,
    /// Package code matching a malicious-code heuristic (CR-017); a warning
    /// that needs approval, never a denial on its own.
    SuspiciousCode,
    /// Registry signature missing, unverifiable or invalid for the exact
    /// artifact (CR-018, P-108); a denial.
    SignatureInvalid,
    /// Build provenance absent although an earlier version of the same
    /// package had it (CR-018, P-108); a warning that needs approval.
    ProvenanceMissing,
    /// Artifact hash or plan mismatch.
    IntegrityMismatch,
    /// A scan or advisory lookup did not complete.
    IncompleteScan,
    /// Advisory data is stale or offline.
    StaleData,
    /// Input the guard cannot review (git/url/local deps, sdists, editable).
    UnsupportedInput,
    /// Package code would run on the host without a sandbox (FR-008 Off).
    HostExecution,
    /// A package or script-produced file matched a YARA rule (FR-019, FR-028);
    /// needs approval.
    YaraMatch,
    /// A sandboxed script opened a bait credential or sent a bait value
    /// (FR-024); a denial.
    BaitTouched,
    /// A pre-install risk check hit (FR-025): new install script, maintainer
    /// change, very new version, look-alike name, newly obfuscated code.
    RiskSignal,
    /// What a sandboxed script tried that the sandbox refused, blocked or
    /// limited, and where it connected (FR-026); information only.
    SandboxActivity,
}

/// What a finding requires. `Deny` can never be approved away.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FindingAction {
    /// Pauses for an explicit one-time approval.
    Approve,
    /// Hard denial for the affected artifact/script/ref.
    Deny,
    /// Informational only.
    Info,
}

/// A single policy finding. `evidence` MUST already be redacted
/// (see [`crate::redact`]); secret values never appear in any message.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub action: FindingAction,
    /// Detector or component id, e.g. `git.pre-push`, `osv`, `npm.scripts`.
    pub source: String,
    /// Human-readable, redacted evidence.
    pub evidence: String,
    /// Affected ref (`refs/heads/main`) or package (`npm:left-pad@1.3.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// File path or script name inside the target, when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory_id: Option<String>,
}

impl Finding {
    pub fn new(
        kind: FindingKind,
        action: FindingAction,
        source: &str,
        evidence: impl Into<String>,
    ) -> Self {
        Finding {
            kind,
            action,
            source: source.to_string(),
            evidence: evidence.into(),
            target: None,
            location: None,
            advisory_id: None,
        }
    }

    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    pub fn advisory(mut self, id: impl Into<String>) -> Self {
        self.advisory_id = Some(id.into());
        self
    }
}

/// Request envelope for `fail2commit api` (one JSON object on stdin).
/// `argv` is the argument vector after the program name, routed exactly like
/// a terminal invocation; it is never passed through a shell.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub version: u32,
    pub id: String,
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

/// Final result of any command (`--json` prints exactly one of these last).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Response {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub code: ResultCode,
    pub message: String,
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Exit status of the delegated tool (git/npm/pip/sandboxed program).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_exit: Option<i32>,
    /// Command-specific structured payload (status, plan summary, ...).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub data: serde_json::Value,
}

impl Response {
    /// Exit status: a delegated tool's own status when the guard allowed it,
    /// otherwise the code's stable exit number.
    pub fn exit_status(&self) -> i32 {
        match (self.code, self.tool_exit) {
            (ResultCode::Ok, Some(status)) => status,
            (code, _) => code.exit_code(),
        }
    }
}

/// Decisions an approver may return. Cancel is always the default.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    #[default]
    Cancel,
    /// Approve exactly this operation digest once.
    ApproveOnce,
    /// FR-008: run package code on the host once with the user's access.
    RunOnHostOnce,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// Git force/rewrite/secret or install advisory approval.
    Operation,
    /// Separate host-execution consent (sandbox Off, required script).
    HostExecution,
}

/// Sent by the CLI to an approver (terminal, tray pipe, VS Code stdio).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub version: u32,
    pub request_id: String,
    /// 256-bit random hex; echoed back unchanged.
    pub nonce: String,
    /// [`crate::digest::Digest`] hex of the exact operation being approved.
    pub digest: String,
    /// Originating session id (per CLI process, see `approver::session_id`).
    pub session: String,
    pub kind: ApprovalKind,
    /// One-line summary, e.g. `git push --force origin main`.
    pub summary: String,
    /// Extra redacted detail lines (ref tuples, package list, script path).
    #[serde(default)]
    pub details: Vec<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Unix seconds after which the request is void.
    pub expires_at: u64,
    /// When true the response must carry the force-push password.
    #[serde(default)]
    pub password_required: bool,
    /// Decisions the approver may offer besides Cancel.
    pub allowed: Vec<Decision>,
}

/// Approver reply. The password is only ever carried in this message over
/// stdin / a restricted pipe; it is never logged (Debug redacts it).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ApprovalResponse {
    pub version: u32,
    pub request_id: String,
    pub nonce: String,
    pub digest: String,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl fmt::Debug for ApprovalResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalResponse")
            .field("version", &self.version)
            .field("request_id", &self.request_id)
            .field("nonce", &self.nonce)
            .field("digest", &self.digest)
            .field("decision", &self.decision)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Drop for ApprovalResponse {
    fn drop(&mut self) {
        if let Some(p) = self.password.as_mut() {
            zeroize::Zeroize::zeroize(p);
        }
    }
}

/// Line-delimited JSON messages from the CLI to an interactive client
/// (`fail2commit api` stdout, tray pipe server->client).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Progress { message: String },
    ApprovalRequest(ApprovalRequest),
    Result(Response),
}

/// Line-delimited JSON messages from a client to the CLI.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    ApprovalResponse(ApprovalResponse),
    Cancel { request_id: String },
}

/// Upper bound for one protocol line on any channel (pipe, stdio).
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        let codes = [
            (ResultCode::Ok, 0),
            (ResultCode::InvalidInput, 2),
            (ResultCode::Rejected, 10),
            (ResultCode::ApprovalUnavailable, 11),
            (ResultCode::IncompleteScan, 12),
            (ResultCode::IntegrityFailure, 13),
            (ResultCode::IsolationUnavailable, 14),
            (ResultCode::Internal, 70),
        ];
        for (code, exit) in codes {
            assert_eq!(code.exit_code(), exit);
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
        }
    }

    #[test]
    fn tool_exit_passes_through_only_on_ok() {
        let mut r = Response {
            version: PROTOCOL_VERSION,
            id: None,
            code: ResultCode::Ok,
            message: String::new(),
            findings: vec![],
            tool_exit: Some(1),
            data: serde_json::Value::Null,
        };
        assert_eq!(r.exit_status(), 1);
        r.code = ResultCode::Rejected;
        assert_eq!(r.exit_status(), 10);
    }

    #[test]
    fn response_debug_redacts_password() {
        let resp = ApprovalResponse {
            version: 1,
            request_id: "r".into(),
            nonce: "n".into(),
            digest: "d".into(),
            decision: Decision::ApproveOnce,
            password: Some("hunter2-synthetic".into()),
        };
        assert!(!format!("{resp:?}").contains("hunter2"));
    }

    #[test]
    fn messages_round_trip() {
        let msg = ClientMessage::Cancel {
            request_id: "x".into(),
        };
        let s = serde_json::to_string(&msg).unwrap();
        assert_eq!(s, r#"{"type":"cancel","request_id":"x"}"#);
        assert_eq!(serde_json::from_str::<ClientMessage>(&s).unwrap(), msg);
    }
}
