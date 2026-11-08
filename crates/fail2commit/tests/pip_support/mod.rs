//! Shared helpers for the pip tests: an offline PEP 503 index served over
//! loopback, synthetic wheels built with the zip crate, disposable venvs.
#![allow(dead_code)]

use fail2commit_core::approval::ApprovalCtx;
use fail2commit_core::approver::ApproverChoice;
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::pip::{ApplyHooks, Cancel, IndexPolicy, Seams};
use fail2commit_core::scan::AdvisoryReport;
use fail2commit_core::settings::Settings;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// A tiny but valid wheel: one module plus dist-info.
pub fn build_wheel(name: &str, version: &str, requires: &[&str], tag: &str) -> (String, Vec<u8>) {
    let norm = name.replace('-', "_");
    let dist = format!("{norm}-{version}.dist-info");
    let mut md = format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n");
    for r in requires {
        md.push_str(&format!("Requires-Dist: {r}\n"));
    }
    let mut buf = std::io::Cursor::new(Vec::new());
    let mut z = zip::ZipWriter::new(&mut buf);
    let o = zip::write::SimpleFileOptions::default();
    let files: Vec<(String, String)> = vec![
        (format!("{norm}.py"), format!("VERSION = '{version}'\n")),
        (format!("{dist}/METADATA"), md),
        (
            format!("{dist}/WHEEL"),
            format!("Wheel-Version: 1.0\nGenerator: f2c-test\nRoot-Is-Purelib: true\nTag: {tag}\n"),
        ),
        (format!("{dist}/RECORD"), String::new()),
    ];
    for (n, c) in files {
        z.start_file(n, o).unwrap();
        z.write_all(c.as_bytes()).unwrap();
    }
    z.finish().unwrap();
    (format!("{norm}-{version}-{tag}.whl"), buf.into_inner())
}

#[derive(Clone)]
struct File {
    filename: String,
    bytes: Vec<u8>,
    advertised: String,
}

#[derive(Default)]
struct State {
    projects: BTreeMap<String, Vec<File>>,
    delay: Duration,
}

/// Offline registry: `/simple/<name>/` pages and `/files/<filename>`.
pub struct TestIndex {
    pub addr: String,
    state: Arc<Mutex<State>>,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl TestIndex {
    pub fn start() -> TestIndex {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let state = Arc::new(Mutex::new(State::default()));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (s, r, st) = (state.clone(), requests.clone(), stop.clone());
        std::thread::spawn(move || {
            while !st.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((c, _)) => {
                        let (s, r) = (s.clone(), r.clone());
                        std::thread::spawn(move || {
                            let _ = serve(c, &s, &r);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        TestIndex {
            addr,
            state,
            requests,
            stop,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}/simple", self.addr)
    }

    pub fn policy(&self) -> IndexPolicy {
        IndexPolicy::new(&self.url(), vec![]).unwrap()
    }

    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// Stop answering: later requests fail to connect.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn handle(&self) -> IndexHandle {
        IndexHandle {
            requests: self.requests.clone(),
            stop: self.stop.clone(),
        }
    }

    pub fn set_delay(&self, d: Duration) {
        self.state.lock().unwrap().delay = d;
    }

    pub fn add_wheel(&self, name: &str, version: &str, requires: &[&str]) -> String {
        let (filename, bytes) = build_wheel(name, version, requires, "py3-none-any");
        self.add_raw(name, &filename, bytes.clone(), &sha256_hex(&bytes));
        filename
    }

    pub fn add_wheel_tagged(&self, name: &str, version: &str, tag: &str) {
        let (filename, bytes) = build_wheel(name, version, &[], tag);
        self.add_raw(name, &filename, bytes.clone(), &sha256_hex(&bytes));
    }

    pub fn add_sdist(&self, name: &str, version: &str) {
        let filename = format!("{name}-{version}.tar.gz");
        let bytes = b"not really an sdist".to_vec();
        self.add_raw(name, &filename, bytes.clone(), &sha256_hex(&bytes));
    }

    /// Serve `bytes` while advertising `advertised` as the SHA-256.
    pub fn add_raw(&self, project: &str, filename: &str, bytes: Vec<u8>, advertised: &str) {
        self.state
            .lock()
            .unwrap()
            .projects
            .entry(project.to_ascii_lowercase().replace(['_', '.'], "-"))
            .or_default()
            .push(File {
                filename: filename.to_string(),
                bytes,
                advertised: advertised.to_string(),
            });
    }
}

/// Cloneable view for hooks that must outlive a borrow.
#[derive(Clone)]
pub struct IndexHandle {
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl IndexHandle {
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for TestIndex {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn serve(mut c: TcpStream, state: &Mutex<State>, requests: &AtomicUsize) -> std::io::Result<()> {
    c.set_nonblocking(false)?;
    c.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read(&mut b)? == 0 {
            return Ok(());
        }
        head.push(b[0]);
    }
    requests.fetch_add(1, Ordering::SeqCst);
    let text = String::from_utf8_lossy(&head).to_string();
    let path = text
        .lines()
        .next()
        .unwrap_or("")
        .split(' ')
        .nth(1)
        .unwrap_or("")
        .to_string();
    let (delay, projects) = {
        let s = state.lock().unwrap();
        (s.delay, s.projects.clone())
    };
    let reply = |c: &mut TcpStream, code: &str, ctype: &str, body: &[u8]| {
        let h = format!(
            "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        c.write_all(h.as_bytes())?;
        c.write_all(body)
    };
    if let Some(name) = path.strip_prefix("/simple/") {
        std::thread::sleep(delay);
        let name = name.trim_end_matches('/');
        return match projects.get(name) {
            Some(files) => {
                let mut html = String::from("<html><body>\n");
                for f in files {
                    html.push_str(&format!(
                        "<a href=\"../../files/{0}#sha256={1}\">{0}</a>\n",
                        f.filename, f.advertised
                    ));
                }
                reply(&mut c, "200 OK", "text/html", html.as_bytes())
            }
            None => reply(&mut c, "404 Not Found", "text/plain", b"no such project"),
        };
    }
    if let Some(fname) = path.strip_prefix("/files/") {
        let found = projects.values().flatten().find(|f| f.filename == fname);
        return match found {
            Some(f) => reply(&mut c, "200 OK", "application/octet-stream", &f.bytes),
            None => reply(&mut c, "404 Not Found", "text/plain", b"no such file"),
        };
    }
    reply(&mut c, "404 Not Found", "text/plain", b"")
}

// ---------------------------------------------------------------------
// Python / venv

pub fn host_python() -> String {
    if let Ok(p) = std::env::var("F2C_TEST_PYTHON") {
        return p;
    }
    for c in ["python3", "python", "py"] {
        if Command::new(c)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return c.to_string();
        }
    }
    panic!("no Python found; set F2C_TEST_PYTHON (needs the venv module and pip)");
}

pub fn make_venv(dir: &Path) -> PathBuf {
    let out = Command::new(host_python())
        .args(["-m", "venv"])
        .arg(dir)
        .output()
        .expect("python -m venv");
    assert!(
        out.status.success(),
        "venv creation failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let py = if cfg!(windows) {
        dir.join("Scripts").join("python.exe")
    } else {
        dir.join("bin").join("python")
    };
    assert!(py.is_file(), "venv python missing at {}", py.display());
    py
}

/// `(normalized name, version)` for everything installed in `python`.
/// Runs `-I -S` like the guard does, so a wheel's `.pth` never runs here either.
pub fn installed(python: &Path) -> Vec<(String, String)> {
    // Without `site` a venv is not detected: point sys.prefix at it by hand
    // (python is <venv>/Scripts/python.exe or <venv>/bin/python).
    let root = python.parent().unwrap().parent().unwrap();
    let code = format!(
        "import sys, json\nsys.prefix = sys.exec_prefix = {:?}\nimport sysconfig\n\
         sys.path.extend([sysconfig.get_path('purelib'), sysconfig.get_path('platlib')])\n\
         from importlib import metadata as m\n\
         print(json.dumps(sorted([d.metadata['Name'].lower().replace('_','-'),d.version] for d in m.distributions())))\n",
        root.to_string_lossy()
    );
    let out = Command::new(python)
        .args(["-I", "-S", "-c", &code])
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Every file under `root` (except `__pycache__`) with its SHA-256.
pub fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, String>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if e.file_name() == "__pycache__" {
                continue;
            }
            if p.is_dir() {
                walk(&p, root, out);
            } else if let Ok(b) = std::fs::read(&p) {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                out.insert(rel, sha256_hex(&b));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

pub fn has(python: &Path, name: &str, version: &str) -> bool {
    installed(python)
        .iter()
        .any(|(n, v)| n == name && v == version)
}

pub fn has_name(python: &Path, name: &str) -> bool {
    installed(python).iter().any(|(n, _)| n == name)
}

// ---------------------------------------------------------------------
// Fail2commit environment

pub struct Env {
    pub home: tempfile::TempDir,
    pub paths: TrustedPaths,
    pub settings: Settings,
}

impl Env {
    pub fn new() -> Env {
        let home = tempfile::tempdir().unwrap();
        let paths = TrustedPaths::under(&home.path().join("f2c"));
        let mut settings = Settings::default();
        settings.limits.job_timeout_secs = 240;
        Env {
            home,
            paths,
            settings,
        }
    }

    pub fn ctx(&self) -> ApprovalCtx<'_> {
        ApprovalCtx {
            paths: &self.paths,
            settings: &self.settings,
            choice: ApproverChoice::None,
        }
    }

    pub fn workdir(&self) -> PathBuf {
        let d = self.home.path().join("work");
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Anything left in the run/staging area after a command.
    pub fn leftover_runs(&self) -> usize {
        let d = self.paths.cache_dir.join("pip");
        std::fs::read_dir(d)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().starts_with("run-"))
                    .count()
            })
            .unwrap_or(0)
    }

    /// Bytes of the single pending journal, if any.
    pub fn journal_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read_dir(self.paths.state_dir.join("pip"))
            .ok()?
            .flatten()
            .find(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with("journal-") && n.ends_with(".json")
            })
            .map(|e| std::fs::read(e.path()).unwrap())
    }

    /// Reviewed-wheel directories still on disk.
    pub fn reviewed_dirs(&self) -> usize {
        std::fs::read_dir(self.paths.cache_dir.join("pip").join("reviewed"))
            .map(|d| d.count())
            .unwrap_or(0)
    }

    pub fn journal_exists(&self) -> bool {
        std::fs::read_dir(self.paths.state_dir.join("pip"))
            .map(|rd| {
                rd.filter_map(|e| e.ok()).any(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    n.starts_with("journal-") && n.ends_with(".json")
                })
            })
            .unwrap_or(false)
    }
}

pub fn clean_advisories() -> AdvisoryReport {
    AdvisoryReport {
        findings: vec![],
        complete: true,
    }
}

/// Seams for an offline test: clean advisories, approvals forbidden unless
/// the test supplies its own.
pub fn seams<'a>(index: &TestIndex) -> Seams<'a> {
    Seams {
        advisories: Box::new(|_| clean_advisories()),
        approve: Box::new(|_| panic!("approval must not be requested for a clean install")),
        cancel: Arc::new(AtomicBool::new(false)),
        hooks: ApplyHooks::default(),
        index: Some(index.policy()),
        check_ambient_config: false,
    }
}

pub fn args(v: &[&str]) -> Vec<std::ffi::OsString> {
    v.iter().map(std::ffi::OsString::from).collect()
}

pub fn cancel_flag() -> Cancel {
    Arc::new(AtomicBool::new(false))
}
