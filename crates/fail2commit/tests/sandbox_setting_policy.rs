//! FR-008 / TC-008: script authorization guarantees.

mod sandbox_setting_support;
use fail2commit_core::approval::ApprovalCtx;
use fail2commit_core::approver::ApproverChoice;
use fail2commit_core::digest::Digest;
use fail2commit_core::exec::{authorize_scripts, authorize_scripts_with, ScriptRun};
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::policy::{explicit_run_allowed, ScriptSituation};
use fail2commit_core::protocol::{ApprovalKind, Decision, FindingAction, FindingKind};
use fail2commit_core::settings::Settings;
use fail2commit_core::ResultCode;
use sandbox_setting_support::{FakeBackend, Recorder};

const fn sit(has_scripts: bool, required: bool, flagged: bool) -> ScriptSituation {
    ScriptSituation {
        has_scripts,
        required,
        flagged,
    }
}
const NONE: ScriptSituation = sit(false, false, false);
const OPTIONAL: ScriptSituation = sit(true, false, false);
const REQUIRED: ScriptSituation = sit(true, true, false);
const FLAGGED: ScriptSituation = sit(true, true, true);

fn digest() -> Digest {
    Digest::of("test", &["npm", "ci"]).unwrap()
}

fn run(
    paths: &TrustedPaths,
    settings: &Settings,
    available: bool,
    rec: &Recorder,
    s: ScriptSituation,
) -> fail2commit_core::Result<ScriptRun> {
    let ctx = ApprovalCtx {
        paths,
        settings,
        choice: ApproverChoice::None,
    };
    authorize_scripts_with(
        &ctx,
        &FakeBackend { available },
        rec,
        s,
        "npm ci",
        &digest(),
    )
}

fn home(enabled: bool) -> (tempfile::TempDir, TrustedPaths, Settings) {
    let d = tempfile::tempdir().unwrap();
    let p = TrustedPaths::under(d.path());
    let s = Settings::update(&p, |s| s.sandbox.enabled = enabled).unwrap();
    (d, p, s)
}

#[test]
fn no_scripts_needs_no_sandbox_and_no_approval() {
    for on in [true, false] {
        let (_d, p, s) = home(on);
        let rec = Recorder::new(Decision::RunOnHostOnce);
        // An unavailable backend would deny if probed; no scripts, no sandbox.
        assert_eq!(
            run(&p, &s, false, &rec, NONE).unwrap(),
            ScriptRun::NoScripts
        );
        assert!(rec.asked.borrow().is_empty());
    }
}

#[test]
fn on_runs_sandboxed_and_fails_closed_without_backend() {
    let (_d, p, s) = home(true);
    let rec = Recorder::new(Decision::RunOnHostOnce);
    assert_eq!(
        run(&p, &s, true, &rec, REQUIRED).unwrap(),
        ScriptRun::Sandboxed
    );
    for situation in [OPTIONAL, REQUIRED] {
        let e = run(&p, &s, false, &rec, situation).unwrap_err();
        assert_eq!(e.code, ResultCode::IsolationUnavailable);
    }
    // Never offers the host as a fallback, even if the user would say yes.
    assert!(rec.asked.borrow().is_empty());
}

#[test]
fn off_skips_unless_separately_approved() {
    let (_d, p, s) = home(false);
    let rec = Recorder::new(Decision::RunOnHostOnce);
    assert_eq!(
        run(&p, &s, true, &rec, OPTIONAL).unwrap(),
        ScriptRun::Skipped
    );
    assert!(rec.asked.borrow().is_empty());

    assert_eq!(run(&p, &s, false, &rec, REQUIRED).unwrap(), ScriptRun::Host);
    let asked = rec.asked.borrow();
    assert_eq!(asked.len(), 1);
    let r = &asked[0];
    assert_eq!(r.kind, ApprovalKind::HostExecution);
    assert_eq!(r.allowed, vec![Decision::RunOnHostOnce]);
    assert_eq!(r.digest, digest().as_hex());
    assert!(
        r.summary.contains("current user's access") && r.summary.contains("not run in the sandbox")
    );
    assert_eq!(r.findings[0].kind, FindingKind::HostExecution);
}

#[test]
fn declined_host_run_is_rejected() {
    let (_d, p, s) = home(false);
    for d in [Decision::Cancel, Decision::ApproveOnce] {
        let rec = Recorder::new(d);
        let e = run(&p, &s, true, &rec, REQUIRED).unwrap_err();
        // ApproveOnce is not an offered decision, so the binding check or the
        // decision match rejects it; either way it is a denial.
        assert_eq!(e.code, ResultCode::Rejected, "{d:?}");
    }
}

#[test]
fn unreachable_approval_never_runs_on_host() {
    // The frozen entry point goes through approval::approve.
    let (_d, p, s) = home(false);
    let ctx = ApprovalCtx {
        paths: &p,
        settings: &s,
        choice: ApproverChoice::None,
    };
    let backend = FakeBackend { available: true };
    let e = authorize_scripts(&ctx, &backend, REQUIRED, "npm ci", &digest()).unwrap_err();
    assert_eq!(e.code, ResultCode::ApprovalUnavailable);
}

#[test]
fn flagged_scripts_are_blocked_in_both_modes() {
    for on in [true, false] {
        let (_d, p, s) = home(on);
        let rec = Recorder::new(Decision::RunOnHostOnce);
        let e = run(&p, &s, true, &rec, FLAGGED).unwrap_err();
        assert_eq!(e.code, ResultCode::Rejected);
        assert_eq!(e.findings[0].kind, FindingKind::SuspiciousScript);
        assert_eq!(e.findings[0].action, FindingAction::Deny);
        assert!(rec.asked.borrow().is_empty());
    }
}

#[test]
fn snapshot_cannot_be_weakened_mid_flight() {
    // On at command start; the file is flipped Off before authorization.
    let (_d, p, snapshot) = home(true);
    Settings::update(&p, |s| s.sandbox.enabled = false).unwrap();
    let rec = Recorder::new(Decision::RunOnHostOnce);
    assert_eq!(
        run(&p, &snapshot, true, &rec, REQUIRED).unwrap(),
        ScriptRun::Sandboxed
    );
    assert_eq!(
        run(&p, &snapshot, false, &rec, REQUIRED).unwrap_err().code,
        ResultCode::IsolationUnavailable
    );
    assert!(rec.asked.borrow().is_empty());
}

#[test]
fn snapshot_holds_while_approval_is_pending() {
    // Off at start; flipped On while the prompt is open. The snapshot decision
    // stands for this job, and the file keeps the newer value for the next one.
    let (_d, p, snapshot) = home(false);
    let mut rec = Recorder::new(Decision::RunOnHostOnce);
    rec.hook = Some(Box::new(|| {
        Settings::update(&p, |s| s.sandbox.enabled = true).unwrap();
    }));
    assert_eq!(
        run(&p, &snapshot, true, &rec, REQUIRED).unwrap(),
        ScriptRun::Host
    );
    assert!(Settings::load(&p).unwrap().sandbox.enabled);
}

#[test]
fn explicit_run_always_requires_isolation_in_both_modes() {
    // `fail2commit run` consults policy::explicit_run_allowed, not the toggle.
    for on in [true, false] {
        let (_d, _p, s) = home(on);
        assert_eq!(s.sandbox.enabled, on);
        assert!(explicit_run_allowed(false).is_err());
        assert!(explicit_run_allowed(true).is_ok());
    }
}
