//! Platform-independent pipe wire rules: bounded line framing and request
//! validation. The tray treats every request as untrusted input.

use crate::protocol::{ApprovalRequest, MAX_MESSAGE_BYTES, PROTOCOL_VERSION};
use std::io::{Read, Write};

/// Longest accepted validity window for a request (the CLI default is 300 s).
pub const MAX_TTL_SECS: u64 = 3600;
const MAX_FIELD: usize = 4096;
const MAX_LINES: usize = 256;

/// Read one `\n`-terminated line of at most [`MAX_MESSAGE_BYTES`].
/// `Ok(None)` is a clean EOF before any byte. Oversized or non-UTF-8 input is
/// an error, never truncated.
pub fn read_line(r: &mut impl Read) -> crate::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) if buf.is_empty() => return Ok(None),
            Ok(0) => return Err(crate::Error::rejected("message ended without newline")),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if buf.len() >= MAX_MESSAGE_BYTES {
                    return Err(crate::Error::rejected("message exceeds size limit"));
                }
                buf.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(crate::Error::approval_unavailable(format!(
                    "pipe read: {e}"
                )))
            }
        }
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| crate::Error::rejected("message is not UTF-8"))
}

pub fn write_line(w: &mut impl Write, line: &str) -> crate::Result<()> {
    if line.len() > MAX_MESSAGE_BYTES {
        return Err(crate::Error::invalid("message exceeds size limit"));
    }
    w.write_all(line.as_bytes())
        .and_then(|_| w.write_all(b"\n"))
        .and_then(|_| w.flush())
        .map_err(|e| crate::Error::approval_unavailable(format!("pipe write: {e}")))
}

fn hex_len(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validate field bounds and the session before showing a request.
pub fn validate_request(req: &ApprovalRequest, now: u64) -> crate::Result<()> {
    let bad = |m: &str| {
        Err(crate::Error::rejected(format!(
            "approval request rejected: {m}"
        )))
    };
    if req.version != PROTOCOL_VERSION {
        return bad("protocol version");
    }
    if req.request_id.is_empty()
        || req.request_id.len() > 64
        || !req
            .request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return bad("request id");
    }
    if !hex_len(&req.nonce, 64) || !hex_len(&req.digest, 64) {
        return bad("nonce or digest format");
    }
    // Session ids are random per CLI process (`pid-N` fallback).
    if req.session.is_empty()
        || req.session.len() > 128
        || !req
            .session
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return bad("session");
    }
    if req.summary.is_empty() || req.summary.len() > MAX_FIELD {
        return bad("summary size");
    }
    if req.details.len() > MAX_LINES
        || req.findings.len() > MAX_LINES
        || req.details.iter().any(|d| d.len() > MAX_FIELD)
        || req.findings.iter().any(|f| {
            f.source.len() > MAX_FIELD
                || f.evidence.len() > MAX_FIELD
                || f.target.as_deref().is_some_and(|t| t.len() > MAX_FIELD)
                || f.location.as_deref().is_some_and(|t| t.len() > MAX_FIELD)
        })
    {
        return bad("too many or too long detail lines");
    }
    if req.allowed.is_empty() || req.allowed.len() > 3 {
        return bad("allowed decisions");
    }
    if req.expires_at <= now || req.expires_at > now.saturating_add(MAX_TTL_SECS) {
        return bad("expiry");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approver::{new_request, now_secs};
    use crate::digest::Digest;
    use crate::protocol::{ApprovalKind, Decision};

    fn req() -> ApprovalRequest {
        let d = Digest::of("t", &["a"]).unwrap();
        new_request(
            ApprovalKind::Operation,
            &d,
            "push",
            vec![],
            vec![],
            60,
            false,
            vec![Decision::ApproveOnce],
        )
        .unwrap()
    }

    #[test]
    fn accepts_well_formed() {
        validate_request(&req(), now_secs()).unwrap();
    }

    #[test]
    fn rejects_bounds_and_session() {
        let now = now_secs();
        let mut r = req();
        r.session = "bad session!".into();
        assert!(validate_request(&r, now).is_err());
        let mut r = req();
        r.details = vec!["x".repeat(MAX_FIELD + 1)];
        assert!(validate_request(&r, now).is_err());
        let mut r = req();
        r.expires_at = now.saturating_sub(1);
        assert!(validate_request(&r, now).is_err());
        let mut r = req();
        r.expires_at = now + MAX_TTL_SECS + 10;
        assert!(validate_request(&r, now).is_err());
        let mut r = req();
        r.allowed.clear();
        assert!(validate_request(&r, now).is_err());
        let mut r = req();
        r.digest = "zz".repeat(32);
        assert!(validate_request(&r, now).is_err());
    }

    #[test]
    fn read_line_is_bounded() {
        let big = vec![b'a'; MAX_MESSAGE_BYTES + 5];
        assert!(read_line(&mut &big[..]).is_err());
        assert_eq!(read_line(&mut &b"hi\n"[..]).unwrap().as_deref(), Some("hi"));
        assert_eq!(read_line(&mut &b""[..]).unwrap(), None);
        assert!(read_line(&mut &b"no newline"[..]).is_err());
        let exact = [vec![b'a'; MAX_MESSAGE_BYTES], vec![b'\n']].concat();
        assert!(read_line(&mut &exact[..]).is_ok());
    }
}
