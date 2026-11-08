//! Private Git hook entry points: `fail2commit hook pre-push <remote> <url>`
//! (FR-001, SPEC-001). Git feeds the proposed ref tuples on stdin; any
//! non-Ok result makes the hook exit non-zero and Git aborts the push.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::approval;
use fail2commit_core::git::prepush;
use fail2commit_core::protocol::{ApprovalRequest, Decision};
use fail2commit_core::toolpath::find_real;
use fail2commit_core::Error;
use std::ffi::OsString;
use std::io::Read;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// `pre-push <remote> <url>`
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<OsString>,
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let a: Vec<String> = args
        .args
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    match a.as_slice() {
        [name, remote, url] if name == "pre-push" => {
            pre_push(ctx, remote, url, std::io::stdin().lock(), &|req| {
                approval::approve(&ctx.approval(), req)
            })
        }
        _ => Err(Error::invalid("usage: hook pre-push <remote> <url>")),
    }
}

/// The whole pre-push policy. `decide` is the approval channel, injectable
/// so tests can script answers without any real prompt.
pub fn pre_push(
    ctx: &Ctx,
    remote: &str,
    url: &str,
    input: impl Read,
    decide: &dyn Fn(&ApprovalRequest) -> fail2commit_core::Result<Decision>,
) -> CmdResult {
    let git = find_real("git", Some(&ctx.paths.bin_dir))?;
    let repo = std::env::current_dir()?;
    let updates = prepush::parse_hook_input(input)?;
    if updates.is_empty() {
        return Ok(Outcome::default());
    }
    let intent = prepush::intent_from_env();
    let findings = prepush::review(&git, &repo, remote, &updates, &intent, &ctx.settings.limits)?;
    if findings.is_empty() {
        return Ok(Outcome::default());
    }
    let password = prepush::needs_password(&findings) && approval::password_required(&ctx.paths)?;
    let req = prepush::build_request(
        remote,
        url,
        &updates,
        &findings,
        &intent,
        ctx.settings.approval.request_ttl_secs,
        password,
    )?;
    match decide(&req).map_err(|e| e.with_findings(findings.clone()))? {
        Decision::ApproveOnce => Ok(Outcome::msg("push approved")),
        _ => Err(Error::rejected("push canceled; nothing was sent").with_findings(findings)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fail2commit_core::approver::{Approver, Scripted};
    use std::process::Command;

    fn git(dir: &std::path::Path, args: &[&str]) -> String {
        let o = Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", dir.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}");
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    fn ctx(home: &std::path::Path) -> Ctx {
        Ctx {
            json: false,
            approver: fail2commit_core::approver::ApproverChoice::None,
            paths: fail2commit_core::paths::TrustedPaths::under(home),
            settings: Default::default(),
        }
    }

    /// Three commits where the last two share a divergent history.
    fn rewrite_setup() -> (tempfile::TempDir, String, String) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        git(p, &["init", "-q", "-b", "main", "."]);
        git(p, &["config", "user.email", "t@example.test"]);
        git(p, &["config", "user.name", "t"]);
        std::fs::write(p.join("a"), "1").unwrap();
        git(p, &["add", "-A"]);
        git(p, &["commit", "-qm", "one"]);
        let old = git(p, &["rev-parse", "HEAD"]);
        git(p, &["commit", "-q", "--amend", "-m", "rewritten"]);
        let new = git(p, &["rev-parse", "HEAD"]);
        (d, old, new)
    }

    fn run_hook(
        d: &tempfile::TempDir,
        old: &str,
        new: &str,
        decision: Decision,
    ) -> (fail2commit_core::Result<Outcome>, std::cell::Cell<u32>) {
        let home = tempfile::tempdir().unwrap();
        let c = ctx(home.path());
        let asked = std::cell::Cell::new(0);
        let scripted = Scripted {
            decision,
            password: None,
        };
        let input = format!("refs/heads/main {new} refs/heads/main {old}\n");
        std::env::set_current_dir(d.path()).unwrap();
        let r = pre_push(&c, "origin", "file:///x", input.as_bytes(), &|req| {
            asked.set(asked.get() + 1);
            let resp = scripted.ask(req)?;
            fail2commit_core::approver::validate_response(
                req,
                &resp,
                fail2commit_core::approver::now_secs(),
            )
        });
        (r, asked)
    }

    // One test: it changes the process cwd, which other tests must not race.
    #[test]
    fn rewrite_prompts_once_and_cancel_aborts() {
        let (d, old, new) = rewrite_setup();
        let (r, asked) = run_hook(&d, &old, &new, Decision::ApproveOnce);
        assert!(r.is_ok());
        assert_eq!(asked.get(), 1);
        let (r, asked) = run_hook(&d, &old, &new, Decision::Cancel);
        let e = r.err().expect("canceled");
        assert_eq!(e.code, fail2commit_core::ResultCode::Rejected);
        assert_eq!(asked.get(), 1);
        assert!(!e.findings.is_empty());
        // fast-forward needs no prompt at all
        let (r, asked) = run_hook(&d, &new, &new, Decision::Cancel);
        assert!(r.is_ok());
        assert_eq!(asked.get(), 0);
    }
}
