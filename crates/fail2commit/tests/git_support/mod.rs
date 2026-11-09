//! Disposable Git environment for the TC-001 tests.
//!
//! Every process runs with HOME/USERPROFILE/GIT_CONFIG_GLOBAL/FAIL2COMMIT_HOME
//! and the PATH edit target inside one temp directory (with a space in its
//! name on purpose), so nothing touches the real home, global Git config,
//! registry or shell profile.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub const EXE: &str = env!("CARGO_BIN_EXE_fail2commit");

pub struct Env {
    pub _tmp: tempfile::TempDir,
    pub root: PathBuf,
    pub home: PathBuf,
    pub f2c_home: PathBuf,
    pub gitcfg: PathBuf,
    pub path_target: PathBuf,
}

/// Synthetic secrets are assembled at runtime so no realistic literal is
/// committed to this repository.
pub fn aws_key() -> String {
    ["AKIA", "QX7M2K9P4R8T3V6W"].concat()
}

pub fn file_url(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    if s.starts_with('/') {
        format!("file://{s}")
    } else {
        format!("file:///{s}")
    }
}

impl Env {
    pub fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        // Long form: CI runners have an 8.3 TEMP (`RUNNER~1`), which the npm
        // guard rightly refuses when a fixture script embeds the path.
        let long = fail2commit_core::fsutil::plain_path(&tmp.path().canonicalize().unwrap());
        let root = long.join("f2c root");
        let home = root.join("home dir");
        let f2c_home = root.join("f2c state");
        let gitcfg = root.join("gitconfig");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            &gitcfg,
            "[user]\n\tname = Test User\n\temail = test@example.test\n\
             [init]\n\tdefaultBranch = main\n\
             [commit]\n\tgpgsign = false\n\
             [core]\n\tautocrlf = false\n\
             [protocol \"file\"]\n\tallow = always\n",
        )
        .unwrap();
        let path_target = root.join("profile");
        Env {
            _tmp: tmp,
            root,
            home,
            f2c_home,
            gitcfg,
            path_target,
        }
    }

    fn prepare(&self, c: &mut Command, dir: &Path) {
        for v in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_PREFIX",
            "FAIL2COMMIT_PUSH_INTENT",
        ] {
            c.env_remove(v);
        }
        c.current_dir(dir)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("GIT_CONFIG_GLOBAL", &self.gitcfg)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("FAIL2COMMIT_HOME", &self.f2c_home)
            .env("FAIL2COMMIT_PATH_TARGET", &self.path_target)
            // The hook never opens an approval channel (no CONIN$ or
            // /dev/tty): every pause fails closed, so tests run unattended.
            .env("FAIL2COMMIT_HOOK_FAIL_CLOSED", "1")
            .stdin(std::process::Stdio::null());
    }

    pub fn git_cmd(&self, dir: &Path) -> Command {
        let mut c = Command::new("git");
        self.prepare(&mut c, dir);
        c
    }

    pub fn f2c_cmd(&self, dir: &Path) -> Command {
        let mut c = Command::new(EXE);
        self.prepare(&mut c, dir);
        c
    }

    /// Run git, panic with its output on failure, return trimmed stdout.
    pub fn git(&self, dir: &Path, args: &[&str]) -> String {
        let o = self.git_cmd(dir).args(args).output().unwrap();
        assert!(
            o.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    /// Plain `git push` (real git; the global hooksPath runs our hook).
    pub fn push(&self, dir: &Path, args: &[&str]) -> Output {
        self.git_cmd(dir).arg("push").args(args).output().unwrap()
    }

    /// `fail2commit git push ...` (what the PATH shim runs).
    pub fn shim_push(&self, dir: &Path, args: &[&str]) -> Output {
        self.f2c_cmd(dir)
            .args(["git", "push"])
            .args(args)
            .output()
            .unwrap()
    }

    pub fn setup(&self) {
        let o = self.f2c_cmd(&self.root).arg("setup").output().unwrap();
        assert!(
            o.status.success(),
            "setup failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }

    pub fn bare(&self, name: &str) -> PathBuf {
        let p = self.root.join(name);
        std::fs::create_dir_all(&p).unwrap();
        self.git(&p, &["init", "-q", "--bare"]);
        p
    }

    /// A working repo with `origin` pointing at a fresh bare remote and one
    /// pushed commit on `main` (pushed with plain git before setup runs).
    pub fn repo_with_remote(&self, name: &str) -> (PathBuf, PathBuf) {
        let remote = self.bare(&format!("{name}-remote.git"));
        let work = self.root.join(name);
        std::fs::create_dir_all(&work).unwrap();
        self.git(&work, &["init", "-q"]);
        self.git(&work, &["remote", "add", "origin", &file_url(&remote)]);
        self.commit(&work, "README", "hello\n", "initial");
        self.git(&work, &["push", "-q", "-u", "origin", "main"]);
        (work, remote)
    }

    pub fn commit(&self, dir: &Path, file: &str, content: &str, msg: &str) -> String {
        let p = dir.join(file);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content).unwrap();
        self.git(dir, &["add", "-A"]);
        self.git(dir, &["commit", "-q", "-m", msg]);
        self.git(dir, &["rev-parse", "HEAD"])
    }

    pub fn head_of(&self, repo: &Path, refname: &str) -> String {
        self.git(repo, &["rev-parse", refname])
    }

    pub fn ref_exists(&self, repo: &Path, refname: &str) -> bool {
        self.git_cmd(repo)
            .args(["rev-parse", "--verify", "-q", refname])
            .output()
            .unwrap()
            .status
            .success()
    }
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A push that was stopped by fail2commit: non-zero and findings printed.
pub fn assert_blocked(o: &Output, kind: &str) {
    let err = stderr(o);
    assert!(!o.status.success(), "push should be blocked: {err}");
    assert!(err.contains(kind), "expected {kind} in: {err}");
}
