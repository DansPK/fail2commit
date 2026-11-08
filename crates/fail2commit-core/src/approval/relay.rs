//! CR-010: carry a Git hook's approval through `fail2commit git push`.
//!
//! Git gives the pre-push hook its own stdin and moves its stdout to stderr, so
//! the hook cannot speak the stdio protocol itself. `fail2commit git push`
//! running under the stdio approver hosts a loopback relay instead. The hook
//! sends its request there; the HOST runs the whole [`super::approve`] (stdio
//! to the api client, reply validation, password check against trusted state)
//! and returns only `{request_id, nonce, digest, decision}` authenticated with
//! HMAC-SHA-256 keyed by the relay token. A password never crosses the relay,
//! and the token is never sent: both directions carry a MAC, not the key.
//!
//! The relay serves exactly one authenticated request and then stops
//! listening. Unauthenticated or malformed connections are dropped without
//! using that slot, within a short deadline, up to a small attempt cap.

use crate::digest::{ct_eq, random_hex32};
use crate::protocol::{ApprovalRequest, Decision, MAX_MESSAGE_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `127.0.0.1:<port>/<token>`; set by the relay host for the git child. Only
/// `fail2commit hook pre-push` reads it, and it removes it at once.
pub const ENV: &str = "FAIL2COMMIT_APPROVAL_RELAY";

/// Time a new connection gets to send its authenticated request line.
const PRE_AUTH: Duration = Duration::from_secs(2);
/// Accepted connections before the relay gives up listening.
const MAX_ATTEMPTS: u32 = 16;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The host's complete approval (stdio round trip, validation, password).
pub type Decide = dyn Fn(&ApprovalRequest) -> crate::Result<Decision> + Send + Sync;

pub struct Relay {
    value: String,
    stop: Arc<AtomicBool>,
}

#[derive(Serialize, Deserialize)]
struct Forward {
    /// The request as JSON text; the MAC covers exactly these bytes.
    request: String,
    mac: String,
}

#[derive(Serialize, Deserialize)]
struct Reply {
    request_id: String,
    nonce: String,
    digest: String,
    decision: Decision,
    mac: String,
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> String {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            inner.update([0u8]);
        }
        inner.update(p);
    }
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    hex::encode(outer.finalize())
}

fn request_mac(token: &str, request_json: &str) -> String {
    hmac(
        token.as_bytes(),
        &[b"fail2commit-relay-request", request_json.as_bytes()],
    )
}

fn reply_mac(token: &str, id: &str, nonce: &str, digest: &str, d: Decision) -> String {
    let d = format!("{d:?}");
    hmac(
        token.as_bytes(),
        &[
            id.as_bytes(),
            nonce.as_bytes(),
            digest.as_bytes(),
            d.as_bytes(),
        ],
    )
}

/// One `\n`-terminated line of at most [`MAX_MESSAGE_BYTES`] before `deadline`.
fn read_line(mut conn: &TcpStream, deadline: Instant) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        conn.set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .ok()?;
        let n = conn.read(&mut chunk).ok().filter(|n| *n > 0)?;
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.iter().position(|b| *b == b'\n') {
            buf.truncate(p);
            return (buf.len() <= MAX_MESSAGE_BYTES).then_some(buf);
        }
        if buf.len() > MAX_MESSAGE_BYTES {
            return None;
        }
    }
}

/// Bind a loopback listener; serve one authenticated request through `decide`.
pub fn start(
    decide: impl Fn(&ApprovalRequest) -> crate::Result<Decision> + Send + Sync + 'static,
) -> crate::Result<Relay> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let token = random_hex32()?;
    let stop = Arc::new(AtomicBool::new(false));
    let used = Arc::new(AtomicBool::new(false));
    let decide: Arc<Decide> = Arc::new(decide);
    let (t, s) = (token.clone(), stop.clone());
    std::thread::spawn(move || {
        let mut attempts = 0;
        while !s.load(Ordering::SeqCst) && !used.load(Ordering::SeqCst) && attempts < MAX_ATTEMPTS {
            match listener.accept() {
                Ok((conn, _)) => {
                    attempts += 1;
                    let (t, u, d) = (t.clone(), used.clone(), decide.clone());
                    std::thread::spawn(move || serve(conn, &t, &u, &*d));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        // The listener drops here: nothing accepts after the slot is used.
    });
    Ok(Relay {
        value: format!("127.0.0.1:{port}/{token}"),
        stop,
    })
}

impl Relay {
    /// The value for [`ENV`].
    pub fn env_value(&self) -> &str {
        &self.value
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn serve(conn: TcpStream, token: &str, used: &AtomicBool, decide: &Decide) {
    let _ = conn.set_nonblocking(false);
    let _ = conn.set_write_timeout(Some(WRITE_TIMEOUT));
    let Some(line) = read_line(&conn, Instant::now() + PRE_AUTH) else {
        return;
    };
    let Ok(fwd) = serde_json::from_slice::<Forward>(&line) else {
        return;
    };
    if !ct_eq(
        fwd.mac.as_bytes(),
        request_mac(token, &fwd.request).as_bytes(),
    ) {
        return;
    }
    let Ok(req) = serde_json::from_str::<ApprovalRequest>(&fwd.request) else {
        return;
    };
    // Authenticated: exactly one such request is served.
    if used
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let decision = match decide(&req) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("fail2commit: {e}");
            Decision::Cancel
        }
    };
    let reply = Reply {
        mac: reply_mac(token, &req.request_id, &req.nonce, &req.digest, decision),
        request_id: req.request_id,
        nonce: req.nonce,
        digest: req.digest,
        decision,
    };
    if let Ok(text) = serde_json::to_string(&reply) {
        let mut out = &conn;
        let _ = writeln!(out, "{text}");
    }
}

/// Hook side: forward `req` to the relay host named by `target` and return its
/// authenticated decision. Every failure (bad target, unreachable, timeout, bad
/// MAC, fields that differ from `req`, a decision not offered) is Cancel.
pub fn forward(req: &ApprovalRequest, target: &str) -> Decision {
    ask(req, target).unwrap_or(Decision::Cancel)
}

fn ask(req: &ApprovalRequest, target: &str) -> Option<Decision> {
    let (addr, token) = target.split_once('/')?;
    let addr: SocketAddr = addr.parse().ok().filter(SocketAddr::is_ipv4)?;
    if !addr.ip().is_loopback() || token.is_empty() {
        return None;
    }
    let mut conn = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
    conn.set_write_timeout(Some(WRITE_TIMEOUT)).ok()?;
    let request = serde_json::to_string(req).ok()?;
    let msg = Forward {
        mac: request_mac(token, &request),
        request,
    };
    writeln!(conn, "{}", serde_json::to_string(&msg).ok()?).ok()?;
    let left = req.expires_at.saturating_sub(crate::approver::now_secs()) + 5;
    let line = read_line(&conn, Instant::now() + Duration::from_secs(left))?;
    let r: Reply = serde_json::from_slice(&line).ok()?;
    let same = ct_eq(r.request_id.as_bytes(), req.request_id.as_bytes())
        & ct_eq(r.nonce.as_bytes(), req.nonce.as_bytes())
        & ct_eq(r.digest.as_bytes(), req.digest.as_bytes());
    let mac = reply_mac(token, &r.request_id, &r.nonce, &r.digest, r.decision);
    if !(same & ct_eq(r.mac.as_bytes(), mac.as_bytes())) {
        return None;
    }
    (r.decision == Decision::Cancel || req.allowed.contains(&r.decision)).then_some(r.decision)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 1.
    #[test]
    fn hmac_matches_rfc4231() {
        assert_eq!(
            hmac(&[0x0b; 20], &[b"Hi There"]),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
