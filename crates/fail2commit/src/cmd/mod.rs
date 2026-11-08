//! Shared command context and output (CHORE-001, coordinator-owned).

pub mod api;
pub mod git;
pub mod hook;
pub mod npm;
pub mod password;
pub mod pip;
pub mod run;
pub mod sandbox;
pub mod scan;
pub mod secrets;
pub mod server;
pub mod setup;

use fail2commit_core::approval::ApprovalCtx;
use fail2commit_core::approver::ApproverChoice;
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::protocol::{Finding, Response, PROTOCOL_VERSION};
use fail2commit_core::settings::Settings;
use fail2commit_core::Error;

/// Per-invocation context. `settings` is the snapshot taken at start; an
/// in-flight job never re-reads it (FR-008).
// shortcut: allow until worker commands consume every field; drop at T-011 integration.
#[allow(dead_code)]
pub struct Ctx {
    pub json: bool,
    pub approver: ApproverChoice,
    pub paths: TrustedPaths,
    pub settings: Settings,
}

impl Ctx {
    pub fn new(json: bool, approver: ApproverChoice) -> fail2commit_core::Result<Ctx> {
        let paths = TrustedPaths::resolve()?;
        let settings = Settings::load(&paths)?;
        Ok(Ctx {
            json,
            approver,
            paths,
            settings,
        })
    }

    #[allow(dead_code)]
    pub fn approval(&self) -> ApprovalCtx<'_> {
        ApprovalCtx {
            paths: &self.paths,
            settings: &self.settings,
            choice: self.approver,
        }
    }
}

/// Successful command result.
#[derive(Default)]
pub struct Outcome {
    pub message: String,
    pub findings: Vec<Finding>,
    pub tool_exit: Option<i32>,
    pub data: serde_json::Value,
}

impl Outcome {
    pub fn msg(message: impl Into<String>) -> Self {
        Outcome {
            message: message.into(),
            ..Default::default()
        }
    }
}

pub type CmdResult = fail2commit_core::Result<Outcome>;

pub fn error_response(e: Error, id: Option<String>) -> Response {
    Response {
        version: PROTOCOL_VERSION,
        id,
        code: e.code,
        message: e.message,
        findings: e.findings,
        tool_exit: None,
        data: serde_json::Value::Null,
    }
}

/// Text mode writes to stderr so a delegated tool's stdout stays clean.
pub fn print_response(r: &Response, json: bool) {
    if json {
        println!("{}", serde_json::to_string(r).expect("response serializes"));
        return;
    }
    for f in &r.findings {
        let target = f
            .target
            .as_deref()
            .map(|t| format!(" [{t}]"))
            .unwrap_or_default();
        eprintln!(
            "fail2commit: {:?} {:?}{target}: {}",
            f.action, f.kind, f.evidence
        );
    }
    if !r.message.is_empty() {
        if r.code == fail2commit_core::ResultCode::Ok {
            eprintln!("fail2commit: {}", r.message);
        } else {
            eprintln!("fail2commit: {} ({})", r.message, r.code);
        }
    }
}
