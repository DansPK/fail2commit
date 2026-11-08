//! T-005 (FR-005, SPEC-005): guarded pip installs.
//!
//! Frozen API: [`integration`]. Flow of [`install`]:
//! 1. reject unreviewable input and untrusted index configuration;
//! 2. bind to the selected interpreter (tags, platform, venv);
//! 3. resolve with pip's `--dry-run --report` through a loopback wheel-only
//!    staging index that fronts the pinned registry (no sdist is ever
//!    offered, every wheel is hash-checked and inspected before pip sees it);
//! 4. check advisories, ask for approval bound to a digest of the exact plan;
//! 5. apply offline from the reviewed wheels, journaled, then verify.
//!
//! Every interpreter is started `-I -S` (see `interp::BOOT`): wheel-supplied
//! `*.pth`, `sitecustomize` and `usercustomize` never run inside the guard.
//! Wheels that install such files need an explicit approval naming them,
//! because they run whenever the user next starts Python (FR-005, CR-001).
//! An unfinished journal blocks guarded installs for its interpreter until
//! [`recover`] completes it after a fresh approval or discards it (CR-002).

mod apply;
mod index;
mod interp;
mod plan;
mod proxy;
mod request;
mod shim;
mod wheel;

pub use apply::ApplyHooks;
pub use index::{IndexPolicy, DEFAULT_INDEX};
pub use interp::{Cancel, Interpreter};
pub use plan::PlanWheel;

use crate::approval::ApprovalCtx;
use crate::integration::Integration;
use crate::protocol::{ApprovalKind, ApprovalRequest, Decision};
use crate::scan::{AdvisoryReport, PackageId};
use crate::{Error, Finding, FindingAction, FindingKind, ResultCode};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// pip shim integration for `fail2commit setup`.
pub fn integration() -> Option<Box<dyn Integration>> {
    Some(Box::new(shim::PipShim))
}

type AdvisoryFn<'a> = Box<dyn Fn(&[PackageId]) -> AdvisoryReport + 'a>;
type ApproveFn<'a> = Box<dyn Fn(&ApprovalRequest) -> crate::Result<Decision> + 'a>;

/// Everything a test needs to replace. [`Seams::production`] wires the
/// real approval channel and advisory scanner.
pub struct Seams<'a> {
    pub advisories: AdvisoryFn<'a>,
    pub approve: ApproveFn<'a>,
    pub cancel: Cancel,
    pub hooks: ApplyHooks,
    /// `None` reads the pinned index from trusted settings.
    pub index: Option<IndexPolicy>,
    /// Reject `PIP_*` and pip config files (tests disable only the host scan).
    pub check_ambient_config: bool,
}

impl<'a> Seams<'a> {
    pub fn production(ctx: &'a ApprovalCtx<'a>, cancel: Cancel) -> Seams<'a> {
        Seams {
            advisories: Box::new(move |pkgs| {
                crate::scan::check_advisories(ctx.paths, &ctx.settings.advisories, pkgs)
            }),
            approve: Box::new(move |req| crate::approval::approve(ctx, req)),
            cancel,
            hooks: ApplyHooks::default(),
            index: None,
            check_ambient_config: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstallReport {
    pub interpreter: String,
    pub index: String,
    pub digest: String,
    pub approved: bool,
    /// Wheels installed, in apply order. Empty when everything was present.
    pub packages: Vec<PlanWheel>,
    pub findings: Vec<Finding>,
}

/// Result of `fail2commit pip recover`.
#[derive(Debug, Clone)]
pub struct RecoverReport {
    pub interpreter: String,
    /// Digest the fresh approval was bound to; empty when none was needed.
    pub digest: String,
    pub approved: bool,
    pub discarded: bool,
    /// Wheels the journal recorded as installed before recovery.
    pub already_installed: Vec<PlanWheel>,
    /// Wheels that were still to install: now installed, or (discard) dropped.
    pub pending: Vec<PlanWheel>,
    pub findings: Vec<Finding>,
}

/// Removes the per-run work directory on every exit path.
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The interpreter `pip` would use when no `--python` is given: the one
/// next to the real `pip` outside our shims, else `python3`/`python`.
pub fn default_python(paths: &crate::paths::TrustedPaths) -> crate::Result<PathBuf> {
    let py = if cfg!(windows) { "python" } else { "python3" };
    if let Ok(pip) = crate::toolpath::find_real("pip", Some(&paths.bin_dir)) {
        if let Some(dir) = pip.parent() {
            for n in [py, "python"] {
                let cand = dir.join(if cfg!(windows) {
                    format!("{n}.exe")
                } else {
                    n.to_string()
                });
                if cand.is_file() {
                    return Ok(cand);
                }
            }
        }
    }
    crate::toolpath::find_real(py, Some(&paths.bin_dir))
        .or_else(|_| crate::toolpath::find_real("python", Some(&paths.bin_dir)))
}

/// Guarded `pip install`. `args` is everything after the word `install`.
pub fn install(
    ctx: &ApprovalCtx<'_>,
    python: &Path,
    args: &[OsString],
    cwd: &Path,
    seams: &Seams<'_>,
) -> crate::Result<InstallReport> {
    let limits = interp::RunLimits::from_settings(&ctx.settings.limits);
    let policy = match &seams.index {
        Some(p) => p.clone(),
        None => IndexPolicy::load(ctx.paths)?,
    };

    // 1. nothing is resolved or fetched until the input is acceptable
    let req = request::parse_args(args, cwd)?;
    if seams.check_ambient_config {
        interp::check_env(std::env::vars(), DEFAULT_INDEX)?;
    }

    // 2. bind to the selected interpreter
    let interp = Interpreter::probe(python, &limits, &seams.cancel)?;
    if seams.check_ambient_config {
        interp::check_config_files(&interp::config_file_candidates(&interp.prefix), &policy.url)?;
    }

    let cx = apply::ApplyCtx {
        paths: ctx.paths,
        interp: &interp,
        limits: &limits,
        cancel: &seams.cancel,
        hooks: &seams.hooks,
    };
    // An unfinished plan is never rolled forward from here.
    if let Some(j) = apply::read_journal(ctx.paths, &interp.executable)? {
        return Err(apply::pending_error(&j));
    }

    // 3. wheel-only staging index + pip's dry-run report
    let run_dir = ctx
        .paths
        .cache_dir
        .join("pip")
        .join(format!("run-{}", &crate::digest::random_hex32()?[..16]));
    crate::fsutil::ensure_private_dir(&run_dir)?;
    let _scratch = Scratch(run_dir.clone());
    let client = index::IndexClient::new(
        policy.clone(),
        Duration::from_secs(ctx.settings.advisories.timeout_secs.max(5) * 4),
        ctx.settings.limits.artifact_max_bytes,
    );
    let proxy = proxy::Proxy::start(
        client,
        run_dir.join("staging"),
        ctx.settings.limits.artifact_max_bytes,
    )?;
    let report_path = run_dir.join("report.json");
    std::fs::write(run_dir.join("requirements.txt"), req.requirements_txt())?;
    let mut cmd = interp.pip();
    cmd.args([
        "install",
        "--dry-run",
        "--quiet",
        "--only-binary=:all:",
        "--no-cache-dir",
        "--report",
    ])
    .arg(&report_path)
    .arg("--index-url")
    .arg(proxy.index_url())
    .arg("-r")
    .arg(run_dir.join("requirements.txt"));
    if !req.constraints.is_empty() {
        std::fs::write(run_dir.join("constraints.txt"), req.constraints_txt())?;
        cmd.arg("-c").arg(run_dir.join("constraints.txt"));
    }
    if req.upgrade {
        cmd.arg("--upgrade");
    }
    if req.pre {
        cmd.arg("--pre");
    }
    let out = interp::run(&mut cmd, &limits, &seams.cancel)?;
    if out.status != Some(0) {
        return Err(resolution_failure(&proxy, &out));
    }
    let report =
        std::fs::read(&report_path).map_err(|_| Error::internal("pip produced no report"))?;
    let staged = plan::from_report(&report, &proxy)?;
    if let Some(e) = proxy.shared.failure.lock().unwrap().clone() {
        return Err(e);
    }
    proxy.stop(); // from here on nothing can reach the network

    let wheels: Vec<PlanWheel> = staged.iter().map(|(w, _)| w.clone()).collect();
    check_pins(&req, &wheels)?;
    let digest = plan::plan_digest(&interp, &policy.url, &req.canonical(), &wheels)?;
    if wheels.is_empty() {
        return Ok(InstallReport {
            interpreter: interp.executable,
            index: policy.url,
            digest: digest.to_string(),
            approved: false,
            packages: vec![],
            findings: vec![],
        });
    }

    // 4. review: advisories, approval bound to the exact wheel set
    let reviewed = apply::materialize(ctx.paths, &staged)?;
    let result = review_and_apply(
        ctx, &cx, seams, &digest, &wheels, &reviewed, &interp, &policy,
    );
    let journal_pending = apply::read_journal(ctx.paths, &interp.executable)
        .ok()
        .flatten()
        .is_some();
    if !journal_pending {
        let _ = std::fs::remove_dir_all(&reviewed);
    }
    let (findings, approved) = result?;
    Ok(InstallReport {
        interpreter: interp.executable.clone(),
        index: policy.url,
        digest: digest.to_string(),
        approved,
        packages: wheels,
        findings,
    })
}

/// One `pip.startup` approval finding per interpreter-startup file the
/// wheels would install, read from the reviewed copies.
fn startup_findings(dir: &Path, wheels: &[PlanWheel]) -> crate::Result<Vec<Finding>> {
    let mut out = Vec::new();
    for w in wheels {
        let files = wheel::startup_files(&dir.join(&w.filename))
            .map_err(|e| Error::integrity(format!("{}: {e:?}", w.filename)))?;
        for f in files {
            out.push(
                Finding::new(
                    FindingKind::HostExecution,
                    FindingAction::Approve,
                    "pip.startup",
                    format!(
                        "{} installs {} ({}): package code that runs on the host, outside fail2commit, whenever Python starts in this environment",
                        w.filename, f.entry, f.why
                    ),
                )
                .target(w.package().display())
                .location(&f.entry),
            );
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn review_and_apply(
    ctx: &ApprovalCtx<'_>,
    cx: &apply::ApplyCtx<'_>,
    seams: &Seams<'_>,
    digest: &crate::digest::Digest,
    wheels: &[PlanWheel],
    reviewed: &Path,
    interp: &Interpreter,
    policy: &IndexPolicy,
) -> crate::Result<(Vec<Finding>, bool)> {
    let pkgs: Vec<PackageId> = wheels.iter().map(PlanWheel::package).collect();
    let adv = (seams.advisories)(&pkgs);
    if adv.findings.iter().any(|f| f.action == FindingAction::Deny) {
        return Err(
            Error::rejected("blocked by a deny finding; nothing was installed")
                .with_findings(adv.findings),
        );
    }
    // Startup files in the reviewed copies need approval, not denial (CR-001).
    let startup = startup_findings(reviewed, wheels)?;
    let mut findings = adv.findings.clone();
    findings.extend(startup.iter().cloned());
    let needs_approval =
        !adv.complete || findings.iter().any(|f| f.action == FindingAction::Approve);
    let mut approved = false;
    if needs_approval {
        let details: Vec<String> = std::iter::once(format!(
            "interpreter {} ({}, {}) index {}",
            interp.executable, interp.python_version, interp.platform, policy.url
        ))
        .chain(
            wheels
                .iter()
                .map(|w| format!("{}=={} sha256:{}", w.name, w.version, &w.sha256[..16])),
        )
        .chain(
            startup
                .iter()
                .map(|f| format!("startup code: {}", f.evidence)),
        )
        .collect();
        let req = crate::approver::new_request(
            ApprovalKind::Operation,
            digest,
            format!(
                "pip install {} wheel(s) into {}",
                wheels.len(),
                interp.prefix
            ),
            details,
            findings.clone(),
            ctx.settings.approval.request_ttl_secs,
            false,
            vec![Decision::ApproveOnce],
        )?;
        match (seams.approve)(&req)? {
            Decision::ApproveOnce => approved = true,
            _ => {
                return Err(
                    Error::rejected("canceled; nothing was installed").with_findings(findings)
                )
            }
        }
    }
    // The plan must still be exactly what was reviewed.
    apply::verify_reviewed(reviewed, wheels)?;
    // `has_scripts` is about code the guard itself would run. Installing a
    // wheel runs none: pip only unpacks it, and every interpreter we start
    // skips `site`, so `*.pth`/`sitecustomize` files the wheel ships do not run
    // here. Those files are reported above as `pip.startup` approvals because
    // they run later, when the user starts Python outside this command.
    crate::exec::authorize_scripts(
        ctx,
        &*crate::sandbox::platform_backend(),
        crate::policy::ScriptSituation {
            has_scripts: false,
            required: false,
            flagged: false,
        },
        "pip wheel install (no guard-run package code; interpreters start without site)",
        digest,
    )?;
    if seams.cancel.load(Ordering::SeqCst) {
        return Err(Error::rejected("canceled; nothing was installed"));
    }
    apply::apply(cx, digest.as_hex(), reviewed, wheels)?;
    Ok((findings, approved))
}

/// `fail2commit pip recover [--discard]`: finish or drop an unfinished apply.
///
/// Completing shows the remaining plan and asks a fresh approval bound to a
/// digest over the interpreter and the remaining wheels; canceling changes
/// nothing and keeps the journal. `discard` removes the journal and the
/// reviewed copies; wheels already installed stay installed.
pub fn recover(
    ctx: &ApprovalCtx<'_>,
    python: &Path,
    discard: bool,
    seams: &Seams<'_>,
) -> crate::Result<RecoverReport> {
    let limits = interp::RunLimits::from_settings(&ctx.settings.limits);
    let interp = Interpreter::probe(python, &limits, &seams.cancel)?;
    let cx = apply::ApplyCtx {
        paths: ctx.paths,
        interp: &interp,
        limits: &limits,
        cancel: &seams.cancel,
        hooks: &seams.hooks,
    };
    let jp = apply::journal_path(ctx.paths, &interp.executable);
    crate::fsutil::with_lock(&jp, || recover_locked(ctx, &cx, &interp, discard, seams))
}

fn recover_locked(
    ctx: &ApprovalCtx<'_>,
    cx: &apply::ApplyCtx<'_>,
    interp: &Interpreter,
    discard: bool,
    seams: &Seams<'_>,
) -> crate::Result<RecoverReport> {
    let Some(j) = apply::read_journal(ctx.paths, &interp.executable)? else {
        return Err(Error::invalid(format!(
            "no unfinished pip install is recorded for {}",
            interp.executable
        )));
    };
    let (done, left) = j.wheels.split_at(j.done);
    let (done, left) = (done.to_vec(), left.to_vec());
    let mut report = RecoverReport {
        interpreter: interp.executable.clone(),
        digest: String::new(),
        approved: false,
        discarded: discard,
        already_installed: done.clone(),
        pending: left.clone(),
        findings: vec![],
    };
    if discard {
        apply::discard(ctx.paths, &j);
        return Ok(report);
    }
    apply::verify_pending(cx, &j)?;
    if left.is_empty() {
        // Everything was installed; only the final check was missing.
        apply::resume(cx, j)?;
        return Ok(report);
    }
    let pkgs: Vec<PackageId> = left.iter().map(PlanWheel::package).collect();
    let adv = (seams.advisories)(&pkgs);
    if adv.findings.iter().any(|f| f.action == FindingAction::Deny) {
        return Err(
            Error::rejected("blocked by a deny finding; nothing was installed")
                .with_findings(adv.findings),
        );
    }
    let startup = startup_findings(&j.reviewed, &left)?;
    let mut findings = adv.findings.clone();
    findings.extend(startup.iter().cloned());
    let digest = plan::recover_digest(interp, &left)?;
    let details: Vec<String> = std::iter::once(format!(
        "interpreter {} ({}, {}); finishing an unfinished plan: {} of {} wheel(s) already installed",
        interp.executable,
        interp.python_version,
        interp.platform,
        done.len(),
        j.wheels.len()
    ))
    .chain(left.iter().map(|w| {
        format!(
            "to install: {}=={} sha256:{}",
            w.name,
            w.version,
            &w.sha256[..16]
        )
    }))
    .chain(
        startup
            .iter()
            .map(|f| format!("startup code: {}", f.evidence)),
    )
    .collect();
    let req = crate::approver::new_request(
        ApprovalKind::Operation,
        &digest,
        format!(
            "finish unfinished pip install: {} remaining wheel(s) into {}",
            left.len(),
            interp.prefix
        ),
        details,
        findings.clone(),
        ctx.settings.approval.request_ttl_secs,
        false,
        vec![Decision::ApproveOnce],
    )?;
    match (seams.approve)(&req)? {
        Decision::ApproveOnce => {}
        _ => return Err(Error::rejected("canceled; nothing was changed").with_findings(findings)),
    }
    if seams.cancel.load(Ordering::SeqCst) {
        return Err(Error::rejected("canceled; nothing was changed"));
    }
    report.digest = digest.to_string();
    report.approved = true;
    report.findings = findings;
    apply::resume(cx, j)?;
    Ok(report)
}

fn check_pins(req: &request::InstallRequest, wheels: &[PlanWheel]) -> crate::Result<()> {
    for r in req.requirements.iter().filter(|r| !r.hashes.is_empty()) {
        let name = interp::normalize(&r.name);
        if let Some(w) = wheels.iter().find(|w| w.name == name) {
            if !r.hashes.contains(&w.sha256) {
                return Err(Error::integrity(format!(
                    "{} does not match the --hash pinned for {}",
                    w.filename, r.name
                ))
                .with_findings(vec![Finding::new(
                    FindingKind::IntegrityMismatch,
                    FindingAction::Deny,
                    "pip.hash",
                    format!("{} differs from the pinned hash", w.filename),
                )
                .target(w.package().display())]));
            }
        }
    }
    Ok(())
}

/// Explain why resolution failed: integrity problems and unsupported
/// (source-only or direct-reference) packages first.
fn resolution_failure(proxy: &proxy::Proxy, out: &interp::RunOutput) -> Error {
    if let Some(e) = proxy.shared.failure.lock().unwrap().clone() {
        let mut e = e;
        e.findings
            .extend(proxy.shared.findings.lock().unwrap().clone());
        return e;
    }
    let mut findings: Vec<Finding> = proxy.shared.findings.lock().unwrap().clone();
    for (name, st) in proxy.shared.projects.lock().unwrap().iter() {
        if st.wheels == 0 && st.sources > 0 {
            findings.push(
                Finding::new(
                    FindingKind::UnsupportedInput,
                    FindingAction::Deny,
                    "pip.staging",
                    format!("{name} publishes only source distributions; sdists are never built or installed"),
                )
                .target(format!("PyPI:{name}")),
            );
        }
    }
    let msg = format!(
        "could not resolve a wheel-only install: {}",
        interp::tail(&out.stderr)
    );
    if findings.is_empty() {
        Error::new(ResultCode::InvalidInput, msg)
    } else {
        Error::new(ResultCode::InvalidInput, msg).with_findings(findings)
    }
}

/// Subcommands that cannot fetch or build packages run through unchanged
/// (isolated); everything else must be `install` or is refused, so the
/// shim never hands arguments to an unguarded manager path.
/// With `capture` the output is returned instead of inherited (JSON mode).
pub fn passthrough(
    python: &Path,
    args: &[OsString],
    capture: bool,
) -> crate::Result<(i32, Vec<u8>)> {
    const SAFE: [&str; 8] = [
        "list",
        "show",
        "freeze",
        "check",
        "inspect",
        "uninstall",
        "help",
        "debug",
    ];
    const NETWORK: [&str; 12] = [
        "-o",
        "--outdated",
        "-u",
        "--uptodate",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "--proxy",
        "--cert",
        "--trusted-host",
    ];
    let sub = args.first().and_then(|a| a.to_str()).unwrap_or("");
    let version = matches!(sub, "--version" | "-V");
    if !version && !SAFE.contains(&sub) {
        return Err(Error::invalid(format!(
            "`pip {sub}` is not available through fail2commit; only guarded `install` and read-only commands are"
        )));
    }
    for a in args {
        let a = a.to_string_lossy();
        let flag = a.split('=').next().unwrap_or("");
        if NETWORK.contains(&flag) {
            return Err(Error::invalid(format!(
                "{flag} is not allowed through fail2commit pip"
            )));
        }
    }
    let mut cmd = interp::pip_command(python, &["--isolated", "--disable-pip-version-check"]);
    cmd.args(args);
    interp::scrub_env(&mut cmd);
    let start_err =
        |e: std::io::Error| Error::invalid(format!("cannot start {}: {e}", python.display()));
    if capture {
        let out = cmd.output().map_err(start_err)?;
        let mut text = out.stdout;
        text.truncate(1024 * 1024);
        return Ok((out.status.code().unwrap_or(1), text));
    }
    let status = cmd.status().map_err(start_err)?;
    Ok((status.code().unwrap_or(1), Vec::new()))
}
