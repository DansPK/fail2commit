//! Host-side egress proxy (SPEC-013 §4.3; FR-023, FR-024).
//!
//! The sandbox keeps `--unshare-all`, so it has no route to anything. In `internet` mode the only
//! way out is this proxy, reached through the in-sandbox relay over a Unix socket in the job's
//! control directory. Every destination is resolved here, on the host, and judged with the frozen
//! [`crate::sandbox::netpolicy::is_public`]: public unicast only. Bait values seen in a request
//! head, a host name or a plain-HTTP body stop the job (FR-024). The value itself is never logged.

use crate::isolation::ActivityKind;
use crate::sandbox::bait::BaitSet;
pub(crate) use crate::sandbox::egress::Watch;
use crate::sandbox::egress::{
    all_public, content_length, find_head_end, has_bait, resolve, Request,
};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Longest request head the proxy will read.
const MAX_HEAD: usize = 8 * 1024;
/// Longest plain-HTTP body prefix inspected for bait values.
const MAX_BODY: usize = 8 * 1024;
/// Time allowed to send a request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed to reach a destination.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle time before a tunnel is closed.
const IDLE: Duration = Duration::from_secs(60);
/// Concurrent connections; a package cannot exhaust the parent.
const MAX_CONNECTIONS: usize = 64;

/// A running proxy. Dropping it stops accepting and removes the socket.
pub struct Egress {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Egress {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bind the egress socket in `dir` and serve until the returned value is dropped.
pub fn start(dir: &Path, watch: Arc<Watch>, bait: Option<Arc<BaitSet>>) -> crate::Result<Egress> {
    let path = dir.join("egress.sock");
    let listener = UnixListener::bind(&path)?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || accept_loop(listener, stop, watch, bait))
    };
    Ok(Egress {
        path,
        stop,
        thread: Some(thread),
    })
}

fn accept_loop(
    listener: UnixListener,
    stop: Arc<AtomicBool>,
    watch: Arc<Watch>,
    bait: Option<Arc<BaitSet>>,
) {
    let live = Arc::new(Mutex::new(0usize));
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((conn, _)) => {
                let over = {
                    let mut n = live.lock().unwrap_or_else(|e| e.into_inner());
                    *n += 1;
                    *n > MAX_CONNECTIONS
                };
                if over {
                    let mut n = live.lock().unwrap_or_else(|e| e.into_inner());
                    *n -= 1;
                    drop(conn);
                    continue;
                }
                let watch = Arc::clone(&watch);
                let bait = bait.clone();
                let live = Arc::clone(&live);
                thread::spawn(move || {
                    let _ = handle(conn, &watch, bait.as_deref());
                    let mut n = live.lock().unwrap_or_else(|e| e.into_inner());
                    *n -= 1;
                });
            }
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
}
fn connect(targets: &[SocketAddr]) -> std::io::Result<Option<TcpStream>> {
    for a in targets {
        if let Ok(s) = TcpStream::connect_timeout(a, CONNECT_TIMEOUT) {
            return Ok(Some(s));
        }
    }
    Ok(None)
}

/// Read the request head (and, for a plain HTTP request with a body, a bounded body prefix).
fn read_request(conn: &mut UnixStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while head.len() < MAX_HEAD {
        let n = match conn.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        head.extend_from_slice(&chunk[..n]);
        if find_head_end(&head).is_some() {
            break;
        }
    }
    let mut body = Vec::new();
    if let Some(end) = find_head_end(&head) {
        body.extend_from_slice(&head[end..]);
        if let Some(wanted) = content_length(&head[..end]) {
            let wanted = wanted.min(MAX_BODY);
            let mut buf = vec![0u8; wanted];
            let mut have = 0usize;
            while have < wanted {
                match conn.read(&mut buf[have..]) {
                    Ok(0) => break,
                    Ok(n) => have += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            body.extend_from_slice(&buf[..have]);
        }
    }
    Ok((head, body))
}

fn tunnel(a: UnixStream, mut b: TcpStream) -> std::io::Result<()> {
    let _ = a.set_read_timeout(Some(IDLE));
    let _ = a.set_write_timeout(Some(IDLE));
    let _ = b.set_read_timeout(Some(IDLE));
    let _ = b.set_write_timeout(Some(IDLE));
    let (mut a_r, mut a_w) = (a.try_clone()?, a.try_clone()?);
    let mut b_w = b.try_clone()?;
    let up = thread::spawn(move || {
        let _ = std::io::copy(&mut a_r, &mut b_w);
        let _ = b_w.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut b, &mut a_w);
    let _ = a_w.shutdown(Shutdown::Both);
    let _ = up.join();
    Ok(())
}
/// Answer one request: parse, check bait, resolve, apply the destination policy, then tunnel.
fn handle(mut conn: UnixStream, watch: &Watch, bait: Option<&BaitSet>) -> std::io::Result<()> {
    let _ = conn.set_read_timeout(Some(HEAD_TIMEOUT));
    let _ = conn.set_write_timeout(Some(HEAD_TIMEOUT));
    let (head, body) = read_request(&mut conn)?;
    let Some(req) = Request::parse(&head) else {
        watch.record(ActivityKind::NetRefused, "malformed proxy request");
        return refuse(&mut conn, "400 Bad Request", "malformed proxy request");
    };
    let authority = req.authority();
    if has_bait(bait, &head, &body) {
        // The value is bait: never echo or log it, only the destination.
        watch.trip(ActivityKind::Bait, format!("egress: {authority}"));
        return refuse(
            &mut conn,
            "403 Forbidden",
            "blocked by the fail2commit bait policy",
        );
    }
    let Some(targets) = resolve(&req.host, req.port) else {
        watch.record(
            ActivityKind::NetRefused,
            format!("{authority} (unresolved)"),
        );
        return refuse(&mut conn, "403 Forbidden", "destination did not resolve");
    };
    if !all_public(&targets) {
        watch.record(ActivityKind::NetRefused, authority);
        return refuse(
            &mut conn,
            "403 Forbidden",
            "only public internet addresses are allowed",
        );
    }
    let upstream = connect(&targets)?;
    let Some(mut upstream) = upstream else {
        watch.record(
            ActivityKind::NetRefused,
            format!("{} (unreachable)", req.authority()),
        );
        return refuse(&mut conn, "502 Bad Gateway", "destination unreachable");
    };
    watch.record(ActivityKind::NetAllowed, authority);
    if req.method.eq_ignore_ascii_case("CONNECT") {
        conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        return tunnel(conn, upstream);
    }
    upstream.write_all(&head)?;
    if !body.is_empty() {
        upstream.write_all(&body)?;
    }
    tunnel(conn, upstream)
}

fn refuse(conn: &mut UnixStream, status: &str, why: &str) -> std::io::Result<()> {
    let body = format!("fail2commit sandbox egress proxy: {why}\n");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    conn.write_all(response.as_bytes())?;
    let _ = conn.shutdown(Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(s: &str) -> Vec<u8> {
        format!("{s}\r\nHost: x\r\n\r\n").into_bytes()
    }

    #[test]
    fn parses_connect_and_absolute_uris() {
        let c = Request::parse(&head("CONNECT registry.npmjs.org:443 HTTP/1.1")).unwrap();
        assert_eq!(
            (c.host.as_str(), c.port, c.method.as_str()),
            ("registry.npmjs.org", 443, "CONNECT")
        );
        let g = Request::parse(&head("GET http://example.test/a?b=1 HTTP/1.1")).unwrap();
        assert_eq!((g.host.as_str(), g.port), ("example.test", 80));
        let v6 = Request::parse(&head("CONNECT [2001:4860:4860::8888]:443 HTTP/1.1")).unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("2001:4860:4860::8888", 443));
        assert_eq!(v6.authority(), "[2001:4860:4860::8888]:443");
        assert_eq!(g.authority(), "example.test:80");
    }

    #[test]
    fn refuses_origin_form_and_garbage() {
        assert!(Request::parse(&head("GET /path HTTP/1.1")).is_none());
        assert!(Request::parse(b"garbage\r\n\r\n").is_none());
    }

    #[test]
    fn only_public_destinations_are_allowed() {
        let sock = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(all_public(&[sock("104.16.0.35:443")]));
        assert!(all_public(&[sock("[2606:4700::6810:2223]:443")]));
        for bad in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "172.16.0.1:443",
            "192.168.1.1:443",
            "169.254.169.254:80",
            "100.64.0.1:443",
            "[::1]:443",
            "[fd00:ec2::254]:80",
            "[fe80::1]:443",
        ] {
            assert!(!all_public(&[sock(bad)]), "{bad}");
        }
        // A mixed answer is refused: a DNS answer cannot smuggle a local address past the check.
        assert!(!all_public(&[
            sock("104.16.0.35:443"),
            sock("127.0.0.1:443")
        ]));
        assert!(!all_public(&[]));
    }

    #[test]
    fn content_length_is_case_insensitive_and_bounded() {
        assert_eq!(
            content_length(b"POST / HTTP/1.1\r\ncontent-length: 5\r\n\r\n"),
            Some(5)
        );
        assert_eq!(content_length(b"GET / HTTP/1.1\r\n\r\n"), None);
    }
}
