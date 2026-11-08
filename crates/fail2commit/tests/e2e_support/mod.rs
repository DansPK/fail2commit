//! Shared helpers for the end-to-end tests (`tests/e2e_*.rs`): every test runs
//! the built `fail2commit` binary against a disposable home, repository,
//! remote and registry. Synthetic secrets and passwords are built at runtime
//! and never printed.
#![allow(dead_code)]

#[path = "../approval_support/mod.rs"]
pub mod approval;
#[path = "../git_support/mod.rs"]
pub mod git;
#[path = "../npm_support/mod.rs"]
pub mod npm;
#[path = "../scan_support/mod.rs"]
pub mod scan;

pub mod npm_world;

use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::protocol::{
    ApprovalRequest, ClientMessage, Response, ServerMessage, PROTOCOL_VERSION,
};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

pub const BUILT_EXE: &str = env!("CARGO_BIN_EXE_fail2commit");

/// The CLI under test. The Linux bundle (scripts/linux/test.ps1) moves test
/// binaries away from their compile-time paths and points `F2C_BIN` at the CLI.
pub fn exe() -> String {
    std::env::var("F2C_BIN").unwrap_or_else(|_| BUILT_EXE.to_string())
}

/// Disposable Git world plus the trusted-state view of its fail2commit home.
pub struct World {
    pub env: git::Env,
    pub paths: TrustedPaths,
    /// The CLI under test; see [`World::private_exe`].
    pub exe: std::path::PathBuf,
}

impl World {
    pub fn new() -> World {
        let env = git::Env::new();
        std::fs::create_dir_all(&env.f2c_home).unwrap();
        // Windows resolves known folders (the sandbox stage anchors) below the
        // overridden USERPROFILE, so the disposable profile needs them.
        std::fs::create_dir_all(env.home.join("AppData").join("Local")).unwrap();
        std::fs::create_dir_all(env.home.join("AppData").join("Roaming")).unwrap();
        let paths = TrustedPaths::under(&env.f2c_home);
        World {
            env,
            paths,
            exe: exe().into(),
        }
    }

    /// Run a hard link (or copy) of the CLI from a directory of its own. Setup
    /// derives the hook, shim and tray start-up paths from the running binary,
    /// and a tray binary beside it would register a Windows sign-in Run value,
    /// so this proves none can sit next to the tested binary.
    pub fn private_exe(&mut self) {
        let dir = self.env.root.join("installed");
        std::fs::create_dir_all(&dir).unwrap();
        let name = if cfg!(windows) {
            "fail2commit.exe"
        } else {
            "fail2commit"
        };
        let dst = dir.join(name);
        if std::fs::hard_link(exe(), &dst).is_err() {
            std::fs::copy(exe(), &dst).unwrap();
        }
        assert!(!dir.join("fail2commit-tray.exe").exists());
        self.exe = dst;
    }

    /// A configured approval password (the CLI needs a console to set one).
    pub fn set_password(&self, tag: &str) {
        fail2commit_core::approval::password::set(&self.paths, &approval::pw(tag)).unwrap();
    }

    /// The CLI in `cwd` with the disposable environment and no console.
    pub fn cmd(&self, cwd: &Path) -> Command {
        let mut c = Command::new(&self.exe);
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("FAIL2COMMIT_") {
                c.env_remove(k);
            }
        }
        for v in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_PREFIX"] {
            c.env_remove(v);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            c.creation_flags(0x0000_0008); // DETACHED_PROCESS: no console to prompt on
        }
        c.current_dir(cwd)
            .env("HOME", &self.env.home)
            .env("USERPROFILE", &self.env.home)
            .env("GIT_CONFIG_GLOBAL", &self.env.gitcfg)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("FAIL2COMMIT_HOME", &self.env.f2c_home)
            .env("FAIL2COMMIT_PATH_TARGET", &self.env.path_target)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    /// `fail2commit api` for `argv` run in `cwd`.
    pub fn api(&self, cwd: &Path, argv: &[&str]) -> ApiClient {
        let mut c = self.cmd(cwd);
        c.arg("api");
        ApiClient::spawn(c, cwd, argv)
    }

    /// Run `fail2commit <args>` to completion with empty stdin.
    pub fn run(&self, cwd: &Path, args: &[&str]) -> Ran {
        let mut c = self.cmd(cwd);
        c.args(args).stdin(Stdio::null());
        let out = c.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        Ran {
            code: out.status.code().unwrap_or(-1),
            json: stdout
                .lines()
                .rev()
                .find_map(|l| serde_json::from_str(l).ok())
                .unwrap_or(serde_json::Value::Null),
            stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// `fail2commit setup` with the disposable PATH target (never the real one).
    pub fn setup(&self) {
        let r = self.run(&self.env.root, &["setup"]);
        assert_eq!(r.code, 0, "setup failed: {}", r.stderr);
    }
}

pub struct Ran {
    pub code: i32,
    pub json: serde_json::Value,
    pub stdout: String,
    pub stderr: String,
}

/// A `fail2commit api` child with a scriptable client side.
pub struct ApiClient {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    pub transcript: String,
}

impl ApiClient {
    pub fn spawn(mut c: Command, cwd: &Path, argv: &[&str]) -> ApiClient {
        let mut child = c.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let req = serde_json::json!({
            "version": PROTOCOL_VERSION, "id": "e2e-1", "argv": argv,
            "cwd": cwd.to_string_lossy(),
        });
        writeln!(stdin, "{req}").unwrap();
        stdin.flush().unwrap();
        ApiClient {
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
        if let Some(s) = self.stdin.as_mut() {
            let line = serde_json::to_string(msg).unwrap();
            let _ = writeln!(s, "{line}").and_then(|_| s.flush());
        }
    }

    /// The final Result, the exit status and everything the child printed.
    pub fn finish(mut self) -> (Response, i32, String) {
        self.stdin = None;
        let resp = loop {
            match self.next() {
                ServerMessage::Result(r) => break r,
                ServerMessage::ApprovalRequest(r) => {
                    panic!("unexpected approval request: {}", r.summary)
                }
                _ => {}
            }
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
