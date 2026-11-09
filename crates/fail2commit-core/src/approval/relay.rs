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
//! The relay serves exactly one authenticated request that matches the push
//! the host runs. The listener stays bound until the [`Relay`] drops (RR-001),
//! so no other process can take the port; after the slot is used every
//! connection is accepted and closed. Connections without a valid token or with
//! a request for another push are dropped individually, under a short deadline,
//! and never use the slot (RR-002, RR-003).

use crate::digest::{ct_eq, random_hex32};
use crate::protocol::{ApprovalRequest, Decision, MAX_MESSAGE_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `127.0.0.1:<port>/<token>`; set by the relay host for the git child. Only
/// `fail2commit hook pre-push` reads it, and it removes it at once.
pub const ENV: &str = "FAIL2COMMIT_APPROVAL_RELAY";

/// Time a new connection gets to send its authenticated request line.
const PRE_AUTH: Duration = Duration::from_secs(2);
/// Connections handled at once; extras are closed unread (fails closed).
const MAX_INFLIGHT: usize = 256;
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

/// The push the host itself runs (from its own argv and config). A relayed
/// request that names anything else is dropped without using the slot.
#[derive(Clone)]
pub struct Expected {
    pub remote: String,
    /// The push URL with credentials already redacted.
    pub url: String,
    /// `approval.request_ttl_secs`: the upper bound on a request's lifetime.
    pub ttl_secs: u64,
}

impl Expected {
    /// Check the request and clamp `expires_at` to now plus the host's TTL.
    fn bind(&self, mut req: ApprovalRequest) -> Option<ApprovalRequest> {
        let prefix = format!("git push to {} ({}): ", self.remote, self.url);
        let ok = req.kind == crate::protocol::ApprovalKind::Operation
            && req.summary.starts_with(&prefix)
            && req.allowed == [Decision::ApproveOnce];
        let cap = crate::approver::now_secs().saturating_add(self.ttl_secs);
        req.expires_at = req.expires_at.min(cap);
        ok.then_some(req)
    }
}

/// Loopback listener on an ephemeral port. On Windows the socket is bound with
/// `SO_EXCLUSIVEADDRUSE` and is not inheritable, so no other socket can
/// co-bind the port with `SO_REUSEADDR` and intercept the hook (RR-001).
fn bind_loopback() -> std::io::Result<TcpListener> {
    #[cfg(windows)]
    return exclusive::bind_loopback();
    #[cfg(not(windows))]
    TcpListener::bind(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        0,
    ))
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod exclusive {
    use std::net::TcpListener;
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        bind, closesocket, listen, setsockopt, WSAGetLastError, WSASocketW, WSAStartup, AF_INET,
        INVALID_SOCKET, IN_ADDR, IN_ADDR_0, IPPROTO_TCP, SOCKADDR, SOCKADDR_IN, SOCKET,
        SOCK_STREAM, SOL_SOCKET, SOMAXCONN, SO_EXCLUSIVEADDRUSE, WSADATA,
        WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
    };

    fn last() -> std::io::Error {
        // SAFETY: reads the calling thread's WinSock error code.
        std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    fn close_with(s: SOCKET, e: std::io::Error) -> std::io::Error {
        // SAFETY: `s` is a socket this module created and still owns.
        unsafe { closesocket(s) };
        e
    }

    pub(super) fn loopback(port: u16) -> SOCKADDR_IN {
        SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: port.to_be(),
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                },
            },
            sin_zero: [0; 8],
        }
    }

    /// New non-inheritable TCP socket with `opt` set to 1 at `SOL_SOCKET`.
    pub(super) fn socket_with(opt: i32) -> std::io::Result<SOCKET> {
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        // SAFETY: WSAStartup is reference counted (std calls it too); `data` is a
        // valid out parameter.
        if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
            return Err(last());
        }
        // SAFETY: plain socket creation with no protocol info; result checked.
        let s = unsafe {
            WSASocketW(
                AF_INET as i32,
                SOCK_STREAM,
                IPPROTO_TCP,
                std::ptr::null(),
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        if s == INVALID_SOCKET {
            return Err(last());
        }
        let one: i32 = 1;
        // SAFETY: `s` is valid; the option value is a live 4-byte i32.
        let rc = unsafe {
            setsockopt(
                s,
                SOL_SOCKET,
                opt,
                &one as *const i32 as *const u8,
                std::mem::size_of::<i32>() as i32,
            )
        };
        if rc != 0 {
            return Err(close_with(s, last()));
        }
        Ok(s)
    }

    /// Bind `s` to 127.0.0.1:`port`.
    pub(super) fn bind_to(s: SOCKET, port: u16) -> std::io::Result<()> {
        let addr = loopback(port);
        // SAFETY: `addr` is a valid SOCKADDR_IN that outlives the call.
        let rc = unsafe {
            bind(
                s,
                &addr as *const SOCKADDR_IN as *const SOCKADDR,
                std::mem::size_of::<SOCKADDR_IN>() as i32,
            )
        };
        if rc != 0 {
            Err(last())
        } else {
            Ok(())
        }
    }

    pub(super) fn bind_loopback() -> std::io::Result<TcpListener> {
        let s = socket_with(SO_EXCLUSIVEADDRUSE)?;
        if let Err(e) = bind_to(s, 0) {
            return Err(close_with(s, e));
        }
        // SAFETY: `s` is a bound socket owned here.
        if unsafe { listen(s, SOMAXCONN as i32) } != 0 {
            return Err(close_with(s, last()));
        }
        // SAFETY: ownership of `s` moves into the TcpListener, which closes it.
        Ok(unsafe { TcpListener::from_raw_socket(s as u64) })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::Networking::WinSock::SO_REUSEADDR;

        #[test]
        fn reuseaddr_socket_cannot_cobind_the_relay_port() {
            let listener = bind_loopback().unwrap();
            let port = listener.local_addr().unwrap().port();
            let attacker = socket_with(SO_REUSEADDR).unwrap();
            let res = bind_to(attacker, port);
            // SAFETY: `attacker` is owned by this test.
            unsafe { closesocket(attacker) };
            assert!(
                res.is_err(),
                "a SO_REUSEADDR socket co-bound the relay port"
            );
            // Control: a free port binds fine with the same attacker setup.
            let control = socket_with(SO_REUSEADDR).unwrap();
            let ok = bind_to(control, 0);
            unsafe { closesocket(control) };
            assert!(ok.is_ok(), "control bind failed: {ok:?}");
        }
    }
}

/// Bind a loopback listener; serve one authenticated request for `expected`
/// through `decide`.
pub fn start(
    expected: Expected,
    decide: impl Fn(&ApprovalRequest) -> crate::Result<Decision> + Send + Sync + 'static,
) -> crate::Result<Relay> {
    let listener = bind_loopback()?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let token = random_hex32()?;
    let stop = Arc::new(AtomicBool::new(false));
    let st = Arc::new(State {
        token: token.clone(),
        expected,
        used: AtomicBool::new(false),
        inflight: AtomicUsize::new(0),
        decide: Box::new(decide),
    });
    let s = stop.clone();
    std::thread::spawn(move || {
        // RR-001: the listener lives until the Relay drops, used or not.
        while !s.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((conn, _)) => {
                    let over = st.inflight.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT;
                    if over || st.used.load(Ordering::SeqCst) {
                        st.inflight.fetch_sub(1, Ordering::SeqCst);
                        continue; // dropped: closed at once
                    }
                    let st = st.clone();
                    std::thread::spawn(move || {
                        serve(conn, &st);
                        st.inflight.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    Ok(Relay {
        value: format!("127.0.0.1:{port}/{token}"),
        stop,
    })
}

struct State {
    token: String,
    expected: Expected,
    used: AtomicBool,
    inflight: AtomicUsize,
    decide: Box<Decide>,
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

fn serve(conn: TcpStream, st: &State) {
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
        request_mac(&st.token, &fwd.request).as_bytes(),
    ) {
        return;
    }
    let Ok(req) = serde_json::from_str::<ApprovalRequest>(&fwd.request) else {
        return;
    };
    // Authenticated, and it must describe the push this host runs (RR-003).
    let Some(mut req) = st.expected.bind(req) else {
        return;
    };
    // Only now does the single slot get used.
    if st
        .used
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let decision = match (st.decide)(&req) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("fail2commit: {e}");
            Decision::Cancel
        }
    };
    let reply = Reply {
        mac: reply_mac(
            &st.token,
            &req.request_id,
            &req.nonce,
            &req.digest,
            decision,
        ),
        request_id: std::mem::take(&mut req.request_id),
        nonce: std::mem::take(&mut req.nonce),
        digest: std::mem::take(&mut req.digest),
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
