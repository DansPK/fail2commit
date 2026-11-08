//! Plain-text rendering of an approval request for the dialog. Pure, so it is
//! unit-tested on every platform. Findings already carry redacted evidence;
//! control characters are stripped again here because the request comes over
//! a pipe and is untrusted input.

use fail2commit_core::protocol::{ApprovalKind, ApprovalRequest, Decision, Finding};

/// Same sanitizer as the terminal prompt: URL credentials, control,
/// zero-width and bidi characters (W1-005).
fn clean(s: &str) -> String {
    fail2commit_core::approval::console::sanitize(s)
}

pub fn title(req: &ApprovalRequest) -> &'static str {
    match req.kind {
        ApprovalKind::Operation => "fail2commit - approve operation",
        ApprovalKind::HostExecution => "fail2commit - run on host?",
    }
}

fn finding_line(f: &Finding) -> String {
    let mut s = format!("[{:?}/{:?}] {}: {}", f.kind, f.action, f.source, f.evidence);
    if let Some(t) = &f.target {
        s.push_str(&format!(" (target {t})"));
    }
    if let Some(l) = &f.location {
        s.push_str(&format!(" (at {l})"));
    }
    clean(&s)
}

/// Multi-line body (CRLF for the Win32 edit control).
pub fn body(req: &ApprovalRequest) -> String {
    let mut lines: Vec<String> = req.details.iter().map(|d| clean(d)).collect();
    if !req.findings.is_empty() {
        lines.push(String::new());
        lines.push("Findings:".into());
        lines.extend(req.findings.iter().map(finding_line));
    }
    if req.kind == ApprovalKind::HostExecution {
        lines.push(String::new());
        lines.push("Host execution runs package code with your full user access.".into());
    }
    lines.join("\r\n")
}

pub fn summary(req: &ApprovalRequest) -> String {
    clean(&req.summary)
}

pub fn offers(req: &ApprovalRequest, d: Decision) -> bool {
    req.allowed.contains(&d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fail2commit_core::protocol::{FindingAction, FindingKind, PROTOCOL_VERSION};

    fn req() -> ApprovalRequest {
        ApprovalRequest {
            version: PROTOCOL_VERSION,
            request_id: "r".into(),
            nonce: "n".into(),
            digest: "d".into(),
            session: "s".into(),
            kind: ApprovalKind::Operation,
            summary: "git push --force\x1b[31m origin main".into(),
            details: vec!["refs/heads/main a..b".into()],
            findings: vec![Finding::new(
                FindingKind::ForceIntent,
                FindingAction::Approve,
                "git.pre-push",
                "force flag",
            )
            .target("refs/heads/main")],
            expires_at: 0,
            password_required: false,
            allowed: vec![Decision::ApproveOnce],
        }
    }

    #[test]
    fn strips_control_characters_and_lists_findings() {
        let r = req();
        assert!(!summary(&r).contains('\x1b'));
        let b = body(&r);
        assert!(b.contains("refs/heads/main a..b"));
        assert!(b.contains("git.pre-push: force flag (target refs/heads/main)"));
    }

    #[test]
    fn escapes_bidi_and_zero_width_controls() {
        let mut r = req();
        for ch in ['\u{202e}', '\u{202a}', '\u{2066}', '\u{2069}', '\u{200b}'] {
            r.summary = format!("push refs/heads/release-{ch}txt");
            r.details = vec![format!("ref {ch}x")];
            assert!(
                !summary(&r).contains(ch),
                "{:x} survived in summary",
                ch as u32
            );
            assert!(!body(&r).contains(ch), "{:x} survived in body", ch as u32);
        }
    }

    #[test]
    fn offers_only_listed_decisions() {
        let r = req();
        assert!(offers(&r, Decision::ApproveOnce));
        assert!(!offers(&r, Decision::RunOnHostOnce));
    }
}
