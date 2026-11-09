//! Shared helpers for the T-002 approval integration tests (FR-002).
//! Every test gets a disposable `FAIL2COMMIT_HOME`; children run without a
//! console/controlling terminal unless a test asks for one.
#![allow(dead_code)]

use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::protocol::{
    ApprovalRequest, ApprovalResponse, ClientMessage, Decision, Response, ServerMessage,
    PROTOCOL_VERSION,
};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

pub fn pw(tag: &str) -> String {
    format!("{}-{}-{}", "synthetic", "pw", tag)
}

pub struct Home {
    pub dir: tempfile::TempDir,
    pub paths: TrustedPaths,
}

pub fn home() -> Home {
    let dir = tempfile::tempdir().unwrap();
    let paths = TrustedPaths::under(dir.path());
    Home { dir, paths }
}

impl Home {
    /// Enable the password through the library (the CLI needs a console).
    pub fn set_password(&self, p: &str) -> String {
        fail2commit_core::approval::password::set(&self.paths, p)
            .unwrap()
            .expose()
            .to_string()
    }

    pub fn ttl(&self, secs: u64) {
        std::fs::create_dir_all(&self.paths.config_dir).unwrap();
        std::fs::write(
            self.paths.settings_file(),
            format!("[approval]\nrequest_ttl_secs = {secs}\n"),
        )
        .unwrap();
    }

    /// fail2commit with this home, a scrubbed fail2commit environment and
    /// no console (Windows: DETACHED_PROCESS; Unix: new session via setsid).
    pub fn cmd(&self, args: &[&str]) -> Command {
        let bin = env!("CARGO_BIN_EXE_fail2commit");
        #[cfg(unix)]
        let mut c = if std::fs::File::open("/dev/tty").is_ok() {
            let mut c = Command::new("setsid");
            c.arg(bin);
            c
        } else {
            Command::new(bin)
        };
        #[cfg(windows)]
        let mut c = {
            use std::os::windows::process::CommandExt;
            let mut c = Command::new(bin);
            c.creation_flags(0x0000_0008); // DETACHED_PROCESS
            c
        };
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("FAIL2COMMIT_") {
                c.env_remove(k);
            }
        }
        c.env("FAIL2COMMIT_HOME", self.dir.path())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    /// Every byte under the trusted home (state, config).
    pub fn all_state_text(&self) -> String {
        let mut s = String::new();
        for p in walk(self.dir.path()) {
            s.push_str(&String::from_utf8_lossy(&std::fs::read(p).unwrap()));
        }
        s
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run(mut c: Command) -> Run {
    let out = c.stdin(Stdio::null()).output().unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into(),
        stderr: String::from_utf8_lossy(&out.stderr).into(),
    }
}

/// A `fail2commit api` child speaking the stdio approval protocol.
pub struct Api {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    pub transcript: String,
}

impl Api {
    pub fn start(h: &Home, argv: &[&str]) -> Api {
        let mut child = h.cmd(&["api"]).spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let req = serde_json::json!({"version": PROTOCOL_VERSION, "id": "t-1", "argv": argv});
        writeln!(stdin, "{req}").unwrap();
        stdin.flush().unwrap();
        Api {
            child,
            stdin: Some(stdin),
            stdout,
            transcript: String::new(),
        }
    }

    pub fn next(&mut self) -> ServerMessage {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        self.transcript.push_str(&line);
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad line {line:?}: {e}"))
    }

    pub fn approval_request(&mut self) -> ApprovalRequest {
        match self.next() {
            ServerMessage::ApprovalRequest(r) => r,
            other => panic!("expected approval request, got {other:?}"),
        }
    }

    pub fn send(&mut self, msg: &ClientMessage) {
        self.send_raw(&serde_json::to_string(msg).unwrap());
    }

    pub fn send_raw(&mut self, line: &str) {
        // The child may already have stopped reading (cancel, timeout).
        if let Some(s) = self.stdin.as_mut() {
            let _ = writeln!(s, "{line}").and_then(|_| s.flush());
        }
    }

    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Read the final Result, wait for exit, return (response, exit, stderr).
    pub fn finish(mut self) -> (Response, i32, String) {
        self.close_stdin();
        let resp = match self.next() {
            ServerMessage::Result(r) => r,
            other => panic!("expected result, got {other:?}"),
        };
        let out = self.child.wait_with_output().unwrap();
        self.transcript
            .push_str(&String::from_utf8_lossy(&out.stdout));
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        (
            resp,
            out.status.code().unwrap_or(-1),
            stderr + &self.transcript,
        )
    }
}

pub fn answer(req: &ApprovalRequest, decision: Decision, password: Option<&str>) -> ClientMessage {
    ClientMessage::ApprovalResponse(ApprovalResponse {
        version: PROTOCOL_VERSION,
        request_id: req.request_id.clone(),
        nonce: req.nonce.clone(),
        digest: req.digest.clone(),
        decision,
        password: password.map(String::from),
    })
}
