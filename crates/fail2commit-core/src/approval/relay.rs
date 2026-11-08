//! CR-008: carry a Git hook's approval request over `fail2commit api`.
//!
//! Git gives the pre-push hook its own stdin and moves its stdout to stderr, so
//! the hook cannot speak the stdio protocol itself. `fail2commit git push`
//! running under the stdio approver hosts a loopback relay instead: the hook
//! sends its request there and the relay forwards it to the api client on the
//! parent's stdout/stdin. The relay is transport only. The hook still builds
//! the request, validates the reply against it and verifies any password, so
//! a relay (or a client) cannot approve anything the hook would not.

use super::channels::{read_message, write_request};
use crate::digest::{ct_eq, random_hex32};
use crate::protocol::{ApprovalRequest, ClientMessage, MAX_MESSAGE_BYTES};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// `127.0.0.1:<port>/<token>`; set by the relay host for its child processes.
pub const ENV: &str = "FAIL2COMMIT_APPROVAL_RELAY";

pub struct Relay {
    value: String,
    stop: Arc<AtomicBool>,
}

/// Bind a loopback listener and serve forwarded requests until dropped.
pub fn start() -> crate::Result<Relay> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let token = random_hex32()?;
    let stop = Arc::new(AtomicBool::new(false));
    let (t, s) = (token.clone(), stop.clone());
    std::thread::spawn(move || {
        while !s.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((conn, _)) => serve(conn, &t),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
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

fn serve(conn: TcpStream, token: &str) {
    let _ = conn.set_nonblocking(false);
    let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(mut out) = conn.try_clone() else {
        return;
    };
    let mut line = Vec::new();
    let read = BufReader::new(&conn)
        .take(MAX_MESSAGE_BYTES as u64 + 1)
        .read_until(b'\n', &mut line);
    if read.is_err() || line.len() > MAX_MESSAGE_BYTES {
        return;
    }
    #[derive(serde::Deserialize)]
    struct Forward {
        token: String,
        request: ApprovalRequest,
    }
    let Ok(fwd) = serde_json::from_slice::<Forward>(&line) else {
        return;
    };
    if !ct_eq(fwd.token.as_bytes(), token.as_bytes()) {
        return;
    }
    // A reply of nothing means Cancel on the hook side.
    let Some(reply) = write_request(&fwd.request).then(|| read_message(&fwd.request)).flatten()
    else {
        return;
    };
    if let Ok(text) = serde_json::to_string(&reply) {
        let _ = writeln!(out, "{text}");
    }
}

/// Hook side: forward `req` through the relay named by [`ENV`] and wait for
/// the client's reply. `None` is Cancel (unreachable relay, EOF, timeout).
pub(crate) fn ask(req: &ApprovalRequest, target: &str) -> Option<ClientMessage> {
    let (addr, token) = target.split_once('/')?;
    let addr: SocketAddr = addr.parse().ok().filter(SocketAddr::is_ipv4)?;
    if !addr.ip().is_loopback() {
        return None;
    }
    let mut conn = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
    let left = req.expires_at.saturating_sub(crate::approver::now_secs()) + 5;
    conn.set_read_timeout(Some(Duration::from_secs(left))).ok()?;
    let msg = serde_json::json!({ "token": token, "request": req });
    writeln!(conn, "{msg}").ok()?;
    let mut line = Vec::new();
    BufReader::new(conn)
        .take(MAX_MESSAGE_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)
        .ok()?;
    if line.is_empty() || line.len() > MAX_MESSAGE_BYTES {
        return None;
    }
    serde_json::from_slice(&line).ok()
}
