//! Shared helpers for the FR-008 tests. Disposable state only.
#![allow(dead_code)]

use fail2commit_core::approver::{Approver, Scripted};
use fail2commit_core::isolation::{JobOutcome, JobSpec, ProbeReport, SandboxBackend};
use fail2commit_core::protocol::{ApprovalRequest, ApprovalResponse, Decision};
use std::cell::RefCell;
use std::path::Path;
use std::process::Output;

pub struct FakeBackend {
    pub available: bool,
}

impl SandboxBackend for FakeBackend {
    fn probe(&self) -> ProbeReport {
        ProbeReport {
            backend: "fake",
            available: self.available,
            detail: String::new(),
            controls: vec![],
        }
    }
    fn run(&self, _: &JobSpec) -> fail2commit_core::Result<JobOutcome> {
        panic!("authorization must never launch a job")
    }
}

/// Answers with a fixed decision, records every request, and optionally runs
/// a hook first (to flip the settings file mid-operation).
pub struct Recorder<'a> {
    pub decision: Decision,
    pub asked: RefCell<Vec<ApprovalRequest>>,
    pub hook: Option<Box<dyn Fn() + 'a>>,
}

impl<'a> Recorder<'a> {
    pub fn new(decision: Decision) -> Self {
        Recorder {
            decision,
            asked: RefCell::new(vec![]),
            hook: None,
        }
    }
}

impl Approver for Recorder<'_> {
    fn name(&self) -> &'static str {
        "recorder"
    }
    fn ask(&self, req: &ApprovalRequest) -> fail2commit_core::Result<ApprovalResponse> {
        if let Some(h) = &self.hook {
            h();
        }
        self.asked.borrow_mut().push(req.clone());
        Scripted {
            decision: self.decision,
            password: None,
        }
        .ask(req)
    }
}

/// Run the real binary with a disposable trusted home, from `cwd`.
pub fn cli(home: &Path, cwd: &Path, args: &[&str]) -> Output {
    let global = home.join("gitconfig");
    std::fs::write(&global, "").unwrap();
    std::process::Command::new(env!("CARGO_BIN_EXE_fail2commit"))
        .args(args)
        .current_dir(cwd)
        .env("FAIL2COMMIT_HOME", home)
        .env("GIT_CONFIG_GLOBAL", &global)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
}

pub fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}
