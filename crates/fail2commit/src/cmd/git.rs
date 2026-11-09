//! `fail2commit git <args...>`: the `git` shim target (FR-001, SPEC-001).
//!
//! Every command goes to the real git with inherited stdio and its exact
//! exit status. For `push` the shim also records explicit force intent and
//! makes sure the fail2commit pre-push hook runs, even in repositories with
//! their own `core.hooksPath`; the hook then asks once for the whole plan.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::approval::{self, relay};
use fail2commit_core::approver::ApproverChoice;
use fail2commit_core::git::intent::{
    config_overrides, is_forced_refspec, push_intent, subcommand_index,
};
use fail2commit_core::git::{hooks_dir, prepush::INTENT_ENV};
use fail2commit_core::toolpath::find_real;
use std::ffi::OsString;
use std::path::Path;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Arguments passed to git unchanged.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<OsString>,
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let real = find_real("git", Some(&ctx.paths.bin_dir))?;
    let lossy: Vec<String> = args
        .args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let mut cmd = fail2commit_core::winenv::command(&real);
    cmd.env_remove(INTENT_ENV).env_remove(relay::ENV);
    // CR-008: under `fail2commit api` the pre-push hook asks through this relay.
    let mut _relay = None;

    match subcommand_index(&lossy) {
        Some(i) => {
            let (globals, rest) = (&args.args[..i], &args.args[i..]);
            let push_rest = push_arguments(&real, &lossy[..i], globals, &lossy[i..], rest);
            match push_rest {
                Some(push_args) => {
                    let dir = hooks_dir(&ctx.paths);
                    if !dir.is_dir() {
                        return Err(fail2commit_core::Error::invalid(
                            "fail2commit hooks are not installed; run `fail2commit setup`",
                        ));
                    }
                    let strs: Vec<String> = push_args
                        .iter()
                        .map(|a| a.to_string_lossy().into_owned())
                        .collect();
                    let reasons = force_reasons(&real, &lossy[..i], &strs);
                    cmd.args(globals)
                        .arg("-c")
                        .arg(format!(
                            "core.hooksPath={}",
                            dir.to_string_lossy().replace('\\', "/")
                        ))
                        .arg("push")
                        .args(&push_args);
                    if ctx.approver == ApproverChoice::None {
                        // `--approver none` must reach the hook, which would
                        // otherwise prompt on a console it finds.
                        cmd.env(super::hook::FAIL_CLOSED_ENV, "1");
                    }
                    if ctx.approver == ApproverChoice::Stdio {
                        // Record the password generation before git runs, as the
                        // hook-side check used to; the host verifies the password.
                        let _ = approval::password_required(&ctx.paths);
                        let (paths, settings) = (ctx.paths.clone(), ctx.settings.clone());
                        let expected = expected_push(
                            &real,
                            &lossy[..i],
                            &strs,
                            ctx.settings.approval.request_ttl_secs,
                        );
                        let r = relay::start(expected, move |req| {
                            approval::approve_relayed(
                                &approval::ApprovalCtx {
                                    paths: &paths,
                                    settings: &settings,
                                    choice: ApproverChoice::Stdio,
                                },
                                req,
                            )
                        })?;
                        cmd.env(relay::ENV, r.env_value());
                        _relay = Some(r);
                    }
                    if !reasons.is_empty() {
                        cmd.env(
                            INTENT_ENV,
                            serde_json::to_string(&reasons).expect("strings serialize"),
                        );
                    }
                }
                None => {
                    cmd.args(&args.args);
                }
            }
        }
        None => {
            cmd.args(&args.args);
        }
    }

    let status = cmd
        .status()
        .map_err(|e| fail2commit_core::Error::internal(format!("cannot run git: {e}")))?;
    Ok(Outcome {
        tool_exit: Some(exit_status(&status)),
        ..Default::default()
    })
}

/// Arguments after `push` if this is a push (directly or through a simple
/// alias such as `alias.p = push`); otherwise None.
fn push_arguments(
    real: &Path,
    global_strs: &[String],
    globals: &[OsString],
    sub_strs: &[String],
    sub: &[OsString],
) -> Option<Vec<OsString>> {
    if sub_strs[0] == "push" {
        return Some(sub[1..].to_vec());
    }
    let alias = git_config(
        real,
        global_strs,
        &["--get", &format!("alias.{}", sub_strs[0])],
    )?;
    if alias.starts_with('!') {
        return None;
    }
    let mut words = alias.split_whitespace();
    if words.next() != Some("push") {
        return None;
    }
    let _ = globals;
    let mut out: Vec<OsString> = words.map(OsString::from).collect();
    out.extend_from_slice(&sub[1..]);
    Some(out)
}

fn git_config(real: &Path, globals: &[String], args: &[&str]) -> Option<String> {
    git_out(real, globals, "config", args)
}

fn git_out(real: &Path, globals: &[String], sub: &str, args: &[&str]) -> Option<String> {
    let out = fail2commit_core::winenv::command(real)
        .args(globals)
        .arg(sub)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// RR-003: the remote name and (credential-free) push URL this host's own argv
/// and config select, which is what Git hands the hook. Unresolvable input
/// yields an expectation nothing matches, so the relay fails closed.
fn expected_push(
    real: &Path,
    globals: &[String],
    push_args: &[String],
    ttl_secs: u64,
) -> relay::Expected {
    let remote = push_intent(push_args).repository.or_else(|| {
        let branch = git_out(real, globals, "symbolic-ref", &["--short", "-q", "HEAD"]);
        let key = |k: &str| {
            branch
                .as_ref()
                .and_then(|b| git_config(real, globals, &["--get", &format!("branch.{b}.{k}")]))
        };
        key("pushRemote")
            .or_else(|| git_config(real, globals, &["--get", "remote.pushDefault"]))
            .or_else(|| key("remote"))
            .or_else(|| Some("origin".to_string()))
    });
    let url = remote.as_ref().map(|r| {
        git_out(real, globals, "remote", &["get-url", "--push", r]).unwrap_or_else(|| r.clone())
    });
    relay::Expected {
        remote: remote.unwrap_or_default(),
        url: fail2commit_core::redact::redact_url_credentials(&url.unwrap_or_default()),
        ttl_secs,
    }
}

/// Command-line force flags plus forced configured push refspecs.
fn force_reasons(real: &Path, globals: &[String], push_args: &[String]) -> Vec<String> {
    let intent = push_intent(push_args);
    let mut reasons = intent.reasons.clone();
    if !intent.explicit_refspecs {
        // Explicit refspecs override remote.<n>.push, so look only otherwise.
        let mut configured: Vec<(String, String)> = config_overrides(globals);
        if let Some(text) = git_config(real, globals, &["--get-regexp", r"^remote\..*\.push$"]) {
            configured.extend(text.lines().filter_map(|l| {
                let (k, v) = l.split_once(' ')?;
                Some((k.to_ascii_lowercase(), v.to_string()))
            }));
        }
        for (k, v) in configured {
            let remote_key = k
                .strip_prefix("remote.")
                .and_then(|r| r.strip_suffix(".push"));
            let Some(name) = remote_key else { continue };
            let relevant = match &intent.repository {
                Some(r) => r.eq_ignore_ascii_case(name),
                None => true,
            };
            if relevant && is_forced_refspec(&v) {
                reasons.push(format!("configured forced push refspec for {name}"));
            }
        }
    }
    reasons.dedup();
    reasons
}

#[cfg(unix)]
fn exit_status(s: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
}

#[cfg(not(unix))]
fn exit_status(s: &std::process::ExitStatus) -> i32 {
    s.code().unwrap_or(1)
}
