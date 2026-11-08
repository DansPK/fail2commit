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
    // The remote-tracking ref is the last state we saw; it avoids the network.
    let old = git_out(
        &git,
        &[
            "rev-parse",
            "--verify",
            "-q",
            &format!("refs/remotes/{remote}/{branch}"),
        ],
    )
    .unwrap_or_else(|| "0".repeat(new.len()));
    let updates = [RefUpdate {
        refname: head,
        old,
        new,
    }];
    let findings = scan_outgoing(&git, &repo, &updates, Some(&remote), &ctx.settings.limits)?;
    if findings.is_empty() {
        let mut o = Outcome::msg(format!(
            "no secrets found in what pushing {branch} to {remote} would publish"
        ));
        o.data = serde_json::json!({ "remote": remote, "branch": branch });
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
