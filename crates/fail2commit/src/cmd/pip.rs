//! Guarded pip (FR-005, T-005).
//!
//! `fail2commit pip [--python <interpreter>] install <names | -r file>` is
//! also what the `pip`/`pip3` shims run. It is the guarded replacement for
//! `python -m pip` / `py -m pip`: a shim cannot intercept arbitrary
//! interpreter invocations. Anything other than `install` and a few
//! read-only commands is refused instead of reaching an unguarded pip.
//! `fail2commit pip [--python <interpreter>] recover [--discard]` finishes
//! (after a fresh approval) or drops an unfinished install.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::pip;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Interpreter whose environment is resolved for and installed into.
    /// Defaults to the Python next to the real `pip` on PATH.
    #[arg(long, value_name = "INTERPRETER")]
    pub python: Option<PathBuf>,
    /// `install <requirements | -r file>`, `recover [--discard]`, or a
    /// read-only pip command.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<OsString>,
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let python = match args.python {
        Some(p) => std::path::absolute(&p)
            .map_err(|e| fail2commit_core::Error::invalid(format!("--python: {e}")))?,
        None => pip::default_python(&ctx.paths)?,
    };
    let mut rest = args.args.into_iter();
    let Some(sub) = rest.next() else {
        return Err(fail2commit_core::Error::invalid(
            "usage: fail2commit pip [--python <interpreter>] install <requirements>",
        ));
    };
    let rest: Vec<OsString> = rest.collect();
    if sub == "recover" {
        return recover(ctx, &python, &rest);
    }
    if sub != "install" {
        let all: Vec<OsString> = std::iter::once(sub).chain(rest).collect();
        let actx = ctx.approval();
        let (code, out) = pip::passthrough(&actx, &python, &all, ctx.json)?;
        return Ok(Outcome {
            tool_exit: Some(code),
            data: serde_json::json!({ "stdout": String::from_utf8_lossy(&out) }),
            ..Default::default()
        });
    }
    let cwd = std::env::current_dir()?;
    let actx = ctx.approval();
    let seams = pip::Seams::production(&actx, Arc::new(AtomicBool::new(false)));
    let r = pip::install(&actx, &python, &rest, &cwd, &seams)?;
    let message = if r.packages.is_empty() {
        "nothing to install; requirements already satisfied".to_string()
    } else {
        format!(
            "installed {} wheel(s) into {}: {}",
            r.packages.len(),
            fail2commit_core::fsutil::plain_path(std::path::Path::new(&r.interpreter)).display(),
            r.packages
                .iter()
                .map(|w| format!("{}=={}", w.name, w.version))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let data = serde_json::json!({
        "interpreter": r.interpreter,
        "index": r.index,
        "digest": r.digest,
        "approved": r.approved,
        "packages": r.packages.iter().map(|w| serde_json::json!({
            "name": w.name, "version": w.version, "filename": w.filename, "sha256": w.sha256,
        })).collect::<Vec<_>>(),
    });
    Ok(Outcome {
        message,
        findings: r.findings,
        tool_exit: Some(0),
        data,
    })
}

fn recover(ctx: &Ctx, python: &std::path::Path, rest: &[OsString]) -> CmdResult {
    let discard = match rest {
        [] => false,
        [a] if a == "--discard" => true,
        _ => {
            return Err(fail2commit_core::Error::invalid(
                "usage: fail2commit pip [--python <interpreter>] recover [--discard]",
            ))
        }
    };
    let actx = ctx.approval();
    let seams = pip::Seams::production(&actx, Arc::new(AtomicBool::new(false)));
    let r = pip::recover(&actx, python, discard, &seams)?;
    let names = |v: &[pip::PlanWheel]| {
        v.iter()
            .map(|w| format!("{}=={}", w.name, w.version))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let message = if r.discarded {
        format!(
            "discarded the unfinished install for {}; already installed: [{}]; not installed: [{}]",
            r.interpreter,
            names(&r.already_installed),
            names(&r.pending)
        )
    } else {
        format!(
            "finished the unfinished install into {}: installed {}",
            r.interpreter,
            names(&r.pending)
        )
    };
    let list = |v: &[pip::PlanWheel]| {
        v.iter()
            .map(
                |w| serde_json::json!({ "name": w.name, "version": w.version, "sha256": w.sha256 }),
            )
            .collect::<Vec<_>>()
    };
    Ok(Outcome {
        message,
        findings: r.findings.clone(),
        tool_exit: Some(0),
        data: serde_json::json!({
            "interpreter": r.interpreter,
            "digest": r.digest,
            "approved": r.approved,
            "discarded": r.discarded,
            "already_installed": list(&r.already_installed),
            "pending": list(&r.pending),
        }),
    })
}
