//! Disposable bare remote + client fixture for TC-003 (FR-003).
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub const BIN: &str = env!("CARGO_BIN_EXE_fail2commit");

pub struct Fx {
    pub tmp: tempfile::TempDir,
    pub remote: PathBuf,
    pub state: PathBuf,
    pub work: PathBuf,
    gitcfg: PathBuf,
}

pub fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn file_url(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    if s.starts_with('/') {
        format!("file://{s}")
    } else {
        format!("file:///{s}")
    }
}

impl Fx {
    /// Remote with the hook installed, protecting `protect`; client clone
    /// with one pushed commit on `main`. No local hooks exist on the client.
    pub fn new(protect: &str) -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let gitcfg = tmp.path().join("gitconfig");
        std::fs::write(
            &gitcfg,
            "[user]\n\tname = T\n\temail = t@example.invalid\n[init]\n\tdefaultBranch = main\n[core]\n\tautocrlf = false\n",
        )
        .unwrap();
        let fx = Fx {
            remote: tmp.path().join("remote.git"),
            state: tmp.path().join("state"),
            work: tmp.path().join("work"),
            gitcfg,
            tmp,
        };
        std::fs::create_dir(&fx.work).unwrap();
        fx.git_ok(&fx.work, &["init", "-q"], None);
        fx.git_ok(fx.tmp.path(), &["init", "-q", "--bare", "remote.git"], None);
        let out = Command::new(BIN)
            .args(["server", "install"])
            .arg(&fx.remote)
            .arg("--state")
            .arg(&fx.state)
            .args(["--protect", protect])
            .envs(fx.env_pairs())
            .output()
            .unwrap();
        assert!(out.status.success(), "install: {}", text(&out));
        fx.git_ok(&fx.work, &["remote", "add", "origin", &fx.url()], None);
        fx.commit("a.txt", "one");
        fx.git_ok(&fx.work, &["push", "-q", "origin", "main"], None);
        fx
    }

    fn env_pairs(&self) -> Vec<(&'static str, PathBuf)> {
        vec![
            ("GIT_CONFIG_GLOBAL", self.gitcfg.clone()),
            ("FAIL2COMMIT_HOME", self.tmp.path().join("home")),
        ]
    }

    pub fn url(&self) -> String {
        file_url(&self.remote)
    }

    pub fn cmd(&self, dir: &Path, args: &[&str], actor: Option<&str>) -> Command {
        let mut c = Command::new("git");
        c.args(args)
            .current_dir(dir)
            .envs(self.env_pairs())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("FAIL2COMMIT_ACTOR")
            .stdin(Stdio::null());
        if let Some(a) = actor {
            c.env("FAIL2COMMIT_ACTOR", a);
        }
        c
    }

    pub fn git(&self, dir: &Path, args: &[&str], actor: Option<&str>) -> Output {
        self.cmd(dir, args, actor).output().unwrap()
    }

    pub fn git_ok(&self, dir: &Path, args: &[&str], actor: Option<&str>) -> String {
        let o = self.git(dir, args, actor);
        assert!(o.status.success(), "git {args:?}: {}", text(&o));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    /// Write `file` and commit it on the client; returns the new commit id.
    pub fn commit(&self, file: &str, content: &str) -> String {
        std::fs::write(self.work.join(file), content).unwrap();
        self.git_ok(&self.work, &["add", "-A"], None);
        self.git_ok(&self.work, &["commit", "-q", "-m", content], None);
        self.rev(&self.work, "HEAD")
    }

    pub fn rev(&self, dir: &Path, rev: &str) -> String {
        self.git_ok(dir, &["rev-parse", rev], None)
    }

    pub fn remote_ref(&self, name: &str) -> String {
        self.rev(&self.remote, name)
    }

    /// Rewrite the client's `main` (amend). Returns `(old, new)` ids.
    pub fn rewrite(&self) -> (String, String) {
        let old = self.remote_ref("refs/heads/main");
        self.git_ok(
            &self.work,
            &["commit", "-q", "--amend", "-m", "rewritten"],
            None,
        );
        (old, self.rev(&self.work, "HEAD"))
    }

    /// Maintainer-side issuer; returns the printed token.
    pub fn approve(&self, actor: &str, refname: &str, old: &str, new: &str, ttl: u64) -> String {
        let out = Command::new(BIN)
            .args(["server", "approve", "--repo"])
            .arg(&self.remote)
            .arg("--state")
            .arg(&self.state)
            .args(["--actor", actor, "--ttl", &ttl.to_string()])
            .args(["--update", &format!("{refname}:{old}:{new}")])
            .envs(self.env_pairs())
            .output()
            .unwrap();
        assert!(out.status.success(), "approve: {}", text(&out));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Force push `main`, optionally with an approval token.
    pub fn force_push_cmd(&self, token: Option<&str>, actor: Option<&str>) -> Command {
        let opt = token.map(|t| format!("f2c-approval={t}"));
        let mut args = vec!["push", "--force"];
        if let Some(o) = &opt {
            args.extend(["-o", o]);
        }
        args.extend(["origin", "main"]);
        self.cmd(&self.work, &args, actor)
    }

    pub fn force_push(&self, token: Option<&str>, actor: Option<&str>) -> Output {
        self.force_push_cmd(token, actor).output().unwrap()
    }
}
