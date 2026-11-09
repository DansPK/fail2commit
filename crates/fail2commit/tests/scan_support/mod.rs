//! Loopback HTTP server and fixture helpers for the scan tests (T-006).
//!
//! Default tests never touch the internet: every OSV request in this suite goes
//! to a `TcpListener` bound to 127.0.0.1 that the test itself drives. The single
//! live-internet smoke test is marked `#[ignore]`.

use fail2commit_core::settings::AdvisorySettings;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub struct Request {
    pub method: String,
    pub path: String,
    pub body: String,
}

pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    pub fn json(body: impl Into<String>) -> Response {
        Response {
            status: 200,
            body: body.into(),
        }
    }

    pub fn with_status(status: u16, body: impl Into<String>) -> Response {
        Response {
            status,
            body: body.into(),
        }
    }
}

pub struct TestServer {
    url: String,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl TestServer {
    pub fn start<F>(handler: F) -> TestServer
    where
        F: Fn(&Request) -> Response + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        {
            let hits = Arc::clone(&hits);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            hits.fetch_add(1, Ordering::SeqCst);
                            serve(stream, handler.as_ref());
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        TestServer {
            url: format!("http://127.0.0.1:{port}"),
            hits,
            stop,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Requests served so far, used to prove a cache hit avoids the network.
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve<F>(mut stream: TcpStream, handler: &F)
where
    F: Fn(&Request) -> Response,
{
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                raw.extend_from_slice(&buf[..read]);
                if let Some(position) = find(&raw, b"\r\n\r\n") {
                    break position + 4;
                }
                if raw.len() > 128 * 1024 {
                    return;
                }
            }
        }
    };
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("").to_string();
    let path = request_line.next().unwrap_or("/").to_string();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    while raw.len() < header_end + content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(read) => raw.extend_from_slice(&buf[..read]),
        }
    }
    let request_body = String::from_utf8_lossy(&raw[header_end..]).to_string();
    let response = handler(&Request {
        method,
        path,
        body: request_body,
    });
    let reason = match response.status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let message = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.status,
        response.body.len(),
        response.body
    );
    let _ = stream.write_all(message.as_bytes());
    let _ = stream.flush();
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn advisory_settings(url: &str) -> AdvisorySettings {
    AdvisorySettings {
        osv_url: url.to_string(),
        offline: false,
        ttl_secs: 3600,
        cache_max_bytes: 8 * 1024 * 1024,
        timeout_secs: 5,
    }
}

/// Directory of the recorded OSV payloads used by the loopback handlers.
pub fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("scan")
}

/// Read one fixture. Synthetic payloads only; no real advisory data or secrets.
pub fn fixture(path: &str) -> String {
    let full = fixture_dir().join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("fixture {}: {e}", full.display()))
}

/// Total bytes currently stored in the advisory cache.
pub fn cache_bytes(paths: &fail2commit_core::paths::TrustedPaths) -> u64 {
    let root = paths.cache_dir.join("osv");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|entry| entry.metadata().ok())
        .map(|meta| meta.len())
        .sum()
}
