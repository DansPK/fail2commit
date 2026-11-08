//! Approval transports (FR-002): terminal and `fail2commit api` stdio.
//! They only carry the request and the reply; policy lives in `approve`.

use super::console::{sanitize, Console};
use crate::approver::{now_secs, Approver};
use crate::protocol::{
    ApprovalRequest, ApprovalResponse, ClientMessage, Decision, ServerMessage, MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
};
use std::io::{BufRead, Read, Write};
use std::sync::mpsc;
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) fn reply(
    req: &ApprovalRequest,
    decision: Decision,
    password: Option<String>,
) -> ApprovalResponse {
    ApprovalResponse {
        version: PROTOCOL_VERSION,
        request_id: req.request_id.clone(),
        nonce: req.nonce.clone(),
        digest: req.digest.clone(),
        decision,
        password,
    }
}

/// Run `f` on a worker thread and wait until the request expires. Timeout,
/// a panic or a dropped channel all mean Cancel.
// shortcut: a timed-out worker stays blocked on its read until the process
// exits (CLI processes are short-lived); upgrade to poll/overlapped I/O if a
// long-lived process ever hosts approvals.
fn until_expiry<T: Send + 'static>(
    req: &ApprovalRequest,
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    let left = req.expires_at.saturating_sub(now_secs());
    rx.recv_timeout(Duration::from_secs(left)).ok().flatten()
}

fn keyword(d: Decision) -> &'static str {
    match d {
        Decision::ApproveOnce => "approve",
        Decision::RunOnHostOnce => "run-on-host",
        Decision::Cancel => "cancel",
    }
}

pub(crate) fn render(req: &ApprovalRequest) -> String {
    let mut s = String::from("\nfail2commit: approval required\n");
    s.push_str(&format!("  {}\n", sanitize(&req.summary)));
    for d in &req.details {
        s.push_str(&format!("    {}\n", sanitize(d)));
    }
    for f in &req.findings {
        let target = f
            .target
            .as_deref()
            .map(|t| format!(" [{}]", sanitize(t)))
            .unwrap_or_default();
        s.push_str(&format!(
            "  {:?} {:?} ({}){}: {}\n",
            f.action,
            f.kind,
            sanitize(&f.source),
            target,
            sanitize(&f.evidence)
        ));
    }
    let left = req.expires_at.saturating_sub(now_secs());
    s.push_str(&format!(
        "  operation {} · expires in {left} s\n",
        &req.digest[..req.digest.len().min(16)]
    ));
    let opts: Vec<String> = req
        .allowed
        .iter()
        .filter(|d| **d != Decision::Cancel)
        .map(|d| format!("\"{}\"", keyword(*d)))
        .collect();
    s.push_str(&format!(
        "Type {} to allow this exact operation once; anything else cancels.\n> ",
        opts.join(" or ")
    ));
    s
}

/// Prompts on the controlling terminal; never reads stdin.
pub(crate) struct Terminal;

impl Approver for Terminal {
    fn name(&self) -> &'static str {
        "terminal"
    }

    fn ask(&self, req: &ApprovalRequest) -> crate::Result<ApprovalResponse> {
        let mut console = Console::open().ok_or_else(|| {
            crate::Error::approval_unavailable("approval required but no interactive terminal")
        })?;
        let text = render(req);
        let allowed = req.allowed.clone();
        let needs_pw = req.password_required;
        let answer = until_expiry(req, move || {
            console.write_str(&text).ok()?;
            let line = console.read_line().ok()??;
            let d = allowed
                .iter()
                .copied()
                .find(|d| *d != Decision::Cancel && line.eq_ignore_ascii_case(keyword(*d)))?;
            if !needs_pw {
                return Some((d, None));
            }
            let pw = rpassword::prompt_password("Force-push password: ")
                .map(Zeroizing::new)
                .ok()?;
            Some((d, Some(pw)))
        });
        Ok(match answer {
            Some((d, pw)) => reply(req, d, pw.map(|p| p.to_string())),
            None => {
                if let Some(mut c) = Console::open() {
                    let _ = c.write_str("fail2commit: canceled\n");
                }
                reply(req, Decision::Cancel, None)
            }
        })
    }
}

/// `fail2commit api`: request as one JSON line on stdout, reply as one
/// `ClientMessage` line on stdin.
pub(crate) struct Stdio;

fn read_message() -> Option<ClientMessage> {
    let mut buf = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(MAX_MESSAGE_BYTES as u64 + 1)
        .read_until(b'\n', &mut buf)
        .ok()?;
    if buf.is_empty() || buf.len() > MAX_MESSAGE_BYTES {
        return None;
    }
    let text = std::str::from_utf8(&buf).ok()?.trim();
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

impl Approver for Stdio {
    fn name(&self) -> &'static str {
        "stdio"
    }

    fn ask(&self, req: &ApprovalRequest) -> crate::Result<ApprovalResponse> {
        let line = serde_json::to_string(&ServerMessage::ApprovalRequest(req.clone()))
            .map_err(|e| crate::Error::internal(format!("serialize approval request: {e}")))?;
        {
            let mut out = std::io::stdout().lock();
            writeln!(out, "{line}")
                .and_then(|_| out.flush())
                .map_err(|_| crate::Error::approval_unavailable("approval client is gone"))?;
        }
        Ok(match until_expiry(req, read_message) {
            Some(ClientMessage::ApprovalResponse(r)) => r,
            // Cancel, EOF, timeout, malformed or oversized input.
            _ => reply(req, Decision::Cancel, None),
        })
    }
}
