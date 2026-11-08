//! Loopback wheel-only staging index.
//!
//! pip is pointed at this server and nowhere else. It serves only wheels the
//! pinned registry lists with a SHA-256, and only after the bytes were
//! downloaded, size-bounded, hash-checked and inspected. Source archives are
//! never listed, so no resolver step can prepare source metadata, and a wheel
//! whose METADATA names a direct reference is withheld before pip reads it.

use super::index::{IndexClient, IndexFile};
use super::interp::normalize;
use super::wheel::{self, WheelError};
use crate::{Error, Finding, FindingAction, FindingKind};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub project: String,
    pub filename: String,
    pub sha256: String,
    pub size: u64,
    pub upstream_url: String,
    pub path: PathBuf,
}

#[derive(Default, Clone, Debug)]
pub struct ProjectStats {
    pub wheels: usize,
    pub sources: usize,
}

struct Entry {
    file: IndexFile,
    project: String,
    verified: Option<Verified>,
}

pub struct Shared {
    client: IndexClient,
    staging: PathBuf,
    token: String,
    max_uncompressed: u64,
    files: Mutex<HashMap<String, Entry>>,
    fetch: Mutex<()>,
    pub findings: Mutex<Vec<Finding>>,
    pub projects: Mutex<BTreeMap<String, ProjectStats>>,
    /// Integrity or limit failure seen while serving: reported by name.
    pub failure: Mutex<Option<Error>>,
    pub requests: Mutex<usize>,
}

pub struct Proxy {
    pub shared: Arc<Shared>,
    addr: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Proxy {
    pub fn start(
        client: IndexClient,
        staging: PathBuf,
        max_uncompressed: u64,
    ) -> crate::Result<Proxy> {
        std::fs::create_dir_all(&staging)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?.to_string();
        let shared = Arc::new(Shared {
            client,
            staging,
            token: crate::digest::random_hex32()?[..32].to_string(),
            max_uncompressed,
            files: Mutex::new(HashMap::new()),
            fetch: Mutex::new(()),
            findings: Mutex::new(Vec::new()),
            projects: Mutex::new(BTreeMap::new()),
            failure: Mutex::new(None),
            requests: Mutex::new(0),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, stop2) = (shared.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let s = s2.clone();
                        std::thread::spawn(move || {
                            let _ = handle(&s, stream);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Ok(Proxy {
            shared,
            addr,
            stop,
            thread: Some(thread),
        })
    }

    /// `--index-url` for pip.
    pub fn index_url(&self) -> String {
        format!("http://{}/{}/simple/", self.addr, self.shared.token)
    }

    fn files_prefix(&self) -> String {
        format!("http://{}/{}/files/", self.addr, self.shared.token)
    }

    /// Map a report URL back to the verified file it must be.
    pub fn lookup(&self, url: &str) -> Option<Verified> {
        let rest = url.strip_prefix(&self.files_prefix())?;
        let (id, name) = rest.split_once('/')?;
        let v = self.shared.ensure(id).ok()?;
        (v.filename == name).then_some(v)
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Shared {
    fn finding(&self, kind: FindingKind, evidence: String, file: &str) {
        self.findings
            .lock()
            .unwrap()
            .push(Finding::new(kind, FindingAction::Deny, "pip.staging", evidence).location(file));
    }

    /// Download, verify and inspect the file registered under `id` once.
    pub fn ensure(&self, id: &str) -> crate::Result<Verified> {
        let _guard = self.fetch.lock().unwrap();
        let (file, project) = {
            let files = self.files.lock().unwrap();
            let e = files
                .get(id)
                .ok_or_else(|| Error::rejected("unknown file"))?;
            if let Some(v) = &e.verified {
                return Ok(v.clone());
            }
            (e.file.clone(), e.project.clone())
        };
        let dir = self.staging.join(id);
        std::fs::create_dir_all(&dir)?;
        let dest = dir.join(&file.filename);
        let fail = |e: Error| {
            let _ = std::fs::remove_file(&dest);
            if matches!(
                e.code,
                crate::ResultCode::IntegrityFailure | crate::ResultCode::Rejected
            ) {
                self.finding(
                    FindingKind::IntegrityMismatch,
                    e.message.clone(),
                    &file.filename,
                );
                self.failure.lock().unwrap().get_or_insert(e.clone());
            }
            e
        };
        let (sha256, size) = self.client.download(&file, &dest).map_err(fail)?;
        match wheel::inspect(&dest, &file.filename, self.max_uncompressed) {
            Ok(_) => {}
            Err(WheelError::DirectReference(r)) => {
                let _ = std::fs::remove_file(&dest);
                self.finding(
                    FindingKind::UnsupportedInput,
                    format!("dependency is a direct reference, not a registry requirement: {r}"),
                    &file.filename,
                );
                return Err(Error::rejected("direct reference in wheel metadata"));
            }
            Err(WheelError::Invalid(m)) => {
                let _ = std::fs::remove_file(&dest);
                self.finding(
                    FindingKind::IntegrityMismatch,
                    format!("invalid wheel: {m}"),
                    &file.filename,
                );
                return Err(Error::integrity(format!(
                    "{} is not a valid wheel: {m}",
                    file.filename
                )));
            }
        }
        let v = Verified {
            project,
            filename: file.filename.clone(),
            sha256,
            size,
            upstream_url: file.url.clone(),
            path: dest,
        };
        if let Some(e) = self.files.lock().unwrap().get_mut(id) {
            e.verified = Some(v.clone());
        }
        Ok(v)
    }

    fn project_page(&self, name: &str) -> crate::Result<String> {
        let name = normalize(name);
        let listed = self.client.project(&name)?;
        let mut stats = ProjectStats::default();
        let mut html = String::from("<!DOCTYPE html><html><body>\n");
        for f in listed {
            let is_wheel = f.filename.ends_with(".whl");
            let parsed = wheel::parse_filename(&f.filename);
            let usable = is_wheel
                && f.sha256.is_some()
                && parsed.as_ref().is_some_and(|(n, _)| *n == name)
                && self.client.policy.allows_file_url(&f.url);
            if !is_wheel {
                stats.sources += 1;
            }
            if !usable {
                continue; // sources and unverifiable files are never offered
            }
            stats.wheels += 1;
            let id = crate::digest::random_hex32()?[..16].to_string();
            let sha = f.sha256.clone().unwrap_or_default();
            let mut attrs = String::new();
            if let Some(rp) = &f.requires_python {
                attrs.push_str(&format!(" data-requires-python=\"{}\"", escape(rp)));
            }
            if f.yanked {
                attrs.push_str(" data-yanked=\"yanked\"");
            }
            html.push_str(&format!(
                "<a href=\"/{}/files/{id}/{}#sha256={sha}\"{attrs}>{}</a><br/>\n",
                self.token,
                escape(&f.filename),
                escape(&f.filename)
            ));
            self.files.lock().unwrap().insert(
                id,
                Entry {
                    file: f,
                    project: name.clone(),
                    verified: None,
                },
            );
        }
        html.push_str("</body></html>\n");
        self.projects.lock().unwrap().insert(name, stats);
        Ok(html)
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn handle(s: &Shared, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 || stream.read(&mut byte)? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
    }
    *s.requests.lock().unwrap() += 1;
    let text = String::from_utf8_lossy(&head);
    let mut parts = text.lines().next().unwrap_or("").split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = target.split(['?', '#']).next().unwrap_or("");
    let respond = |stream: &mut TcpStream,
                   code: &str,
                   ctype: &str,
                   body: &[u8],
                   send_body: bool| {
        let h = format!(
            "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(h.as_bytes())?;
        if send_body {
            stream.write_all(body)?;
        }
        stream.flush()
    };
    if method != "GET" && method != "HEAD" {
        return respond(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain",
            b"",
            false,
        );
    }
    let send_body = method == "GET";
    let prefix = format!("/{}/", s.token);
    let Some(rest) = path.strip_prefix(&prefix) else {
        return respond(
            &mut stream,
            "404 Not Found",
            "text/plain",
            b"not found",
            send_body,
        );
    };
    if let Some(name) = rest.strip_prefix("simple/") {
        let name = name.trim_end_matches('/');
        if name.is_empty() || name.contains('/') {
            return respond(
                &mut stream,
                "404 Not Found",
                "text/plain",
                b"not found",
                send_body,
            );
        }
        return match s.project_page(name) {
            Ok(html) => respond(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                html.as_bytes(),
                send_body,
            ),
            Err(e) => respond(
                &mut stream,
                "502 Bad Gateway",
                "text/plain",
                e.message.as_bytes(),
                send_body,
            ),
        };
    }
    if let Some(f) = rest.strip_prefix("files/") {
        let Some((id, filename)) = f.split_once('/') else {
            return respond(
                &mut stream,
                "404 Not Found",
                "text/plain",
                b"not found",
                send_body,
            );
        };
        return match s.ensure(id) {
            Ok(v) if v.filename == filename => {
                let mut file = std::fs::File::open(&v.path)?;
                let h = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    v.size
                );
                stream.write_all(h.as_bytes())?;
                if send_body {
                    std::io::copy(&mut file, &mut stream)?;
                }
                stream.flush()?;
                let _ = stream.shutdown(Shutdown::Write);
                Ok(())
            }
            _ => respond(
                &mut stream,
                "404 Not Found",
                "text/plain",
                b"withheld",
                send_body,
            ),
        };
    }
    respond(
        &mut stream,
        "404 Not Found",
        "text/plain",
        b"not found",
        send_body,
    )
}
