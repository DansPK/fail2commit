//! `fail2commit secret-scan [REMOTE]`: what would pushing the current
//! branch publish? Nothing is pushed and nothing leaves the machine.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::git::{scan_outgoing, RefUpdate};
use fail2commit_core::protocol::FindingKind;
use fail2commit_core::toolpath::find_real;
use fail2commit_core::Error;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Remote to compare against (default: the branch's push remote, else origin).
    pub remote: Option<String>,
    /// Ask the remote for its current branch value (network) instead of
    /// scanning all local history.
    #[arg(long = "remote")]
    pub query_remote: bool,
}

fn git_out(git: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new(git)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let git = find_real("git", Some(&ctx.paths.bin_dir))?;
    let repo = std::env::current_dir()?;
    let head = git_out(&git, &["symbolic-ref", "-q", "HEAD"])
        .ok_or_else(|| Error::invalid("HEAD is detached; check out a branch to scan its push"))?;
    let branch = head
        .strip_prefix("refs/heads/")
        .unwrap_or(&head)
        .to_string();
    let new = git_out(&git, &["rev-parse", "--verify", "HEAD"])
        .ok_or_else(|| Error::invalid("the current branch has no commits"))?;
    let remote = args
        .remote
        .or_else(|| {
            git_out(
                &git,
                &["config", "--get", &format!("branch.{branch}.pushRemote")],
            )
        })
        .or_else(|| git_out(&git, &["config", "--get", "remote.pushDefault"]))
        .or_else(|| {
            git_out(
                &git,
                &["config", "--get", &format!("branch.{branch}.remote")],
            )
        })
        .unwrap_or_else(|| "origin".to_string());
    // refs/remotes/** is repository-controlled and proves nothing about the
    // remote (R1-003). Default: scan everything reachable from HEAD. Only an
    // explicit --remote asks the remote itself, over the network.
    let zero = "0".repeat(new.len());
    let old = if args.query_remote {
        let o = Command::new(&git)
            .args(["ls-remote", "--", &remote, &head])
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if !o.status.success() {
            return Err(Error::invalid(
                "could not query the remote; run without --remote to scan all local history",
            ));
        }
        // An empty answer means the branch does not exist on the remote.
        String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .next()
            .filter(|o| o.len() == new.len())
            .map(str::to_string)
            .unwrap_or(zero)
    } else {
        zero
    };
    let mode = if args.query_remote {
        "compared with the remote's current value from git ls-remote"
    } else {
        "local-only: scanned all history reachable from HEAD, not just unpublished commits (use --remote to compare with the remote)"
    };
    let updates = [RefUpdate {
        refname: head,
        old,
        new,
    }];
    let findings = scan_outgoing(&git, &repo, &updates, Some(&remote), &ctx.settings.limits)?;
    if findings.is_empty() {
        let mut o = Outcome::msg(format!(
            "no secrets found in what pushing {branch} to {remote} would publish ({mode})"
        ));
        o.data = serde_json::json!({ "remote": remote, "branch": branch, "mode": mode });
        return Ok(o);
    }
    let only_incomplete = findings
        .iter()
        .all(|f| f.kind == FindingKind::IncompleteScan);
    let msg = format!(
        "{} finding(s) in what pushing {branch} to {remote} would publish",
        findings.len()
    );
    Err(if only_incomplete {
        Error::incomplete(msg)
    } else {
        Error::rejected(msg)
    }
    .with_findings(findings))
}
