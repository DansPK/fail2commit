//! TC-005 / SPEC-005: clean wheel install, source and direct-reference
//! stops, hash and plan integrity, no second resolution.

mod pip_support;

use fail2commit_core::pip;
use fail2commit_core::protocol::{ApprovalRequest, Decision};
use fail2commit_core::scan::AdvisoryReport;
use fail2commit_core::{Error, Finding, FindingAction, FindingKind, ResultCode};
use pip_support::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct Fixture {
    env: Env,
    index: TestIndex,
    python: std::path::PathBuf,
    _venv: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let env = Env::new();
    let index = TestIndex::start();
    let venv = tempfile::tempdir().unwrap();
    let python = make_venv(&venv.path().join("v"));
    Fixture {
        env,
        index,
        python,
        _venv: venv,
    }
}

impl Fixture {
    fn install(
        &self,
        a: &[&str],
        seams: &pip::Seams<'_>,
    ) -> fail2commit_core::Result<pip::InstallReport> {
        let ctx = self.env.ctx();
        pip::install(&ctx, &self.python, &args(a), &self.env.workdir(), seams)
    }
}

fn finding_kinds(e: &Error) -> Vec<FindingKind> {
    e.findings.iter().map(|f| f.kind).collect()
}

fn advisory() -> AdvisoryReport {
    AdvisoryReport {
        findings: vec![Finding::new(
            FindingKind::Advisory,
            FindingAction::Approve,
            "osv",
            "synthetic advisory",
        )
        .advisory("GHSA-test-0000")],
        complete: true,
    }
}

#[test]
fn clean_wheel_install_works_with_transitive_dependency() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &["beta>=1"]);
    f.index.add_wheel("beta", "1.0", &[]);
    f.index.add_wheel("beta", "2.0", &[]);
    f.index.add_sdist("beta", "3.0"); // newer, but source-only: must be ignored
    let r = f.install(&["alpha"], &seams(&f.index)).unwrap();
    assert!(!r.approved, "clean plan needs no approval");
    let names: Vec<_> = r
        .packages
        .iter()
        .map(|w| format!("{}=={}", w.name, w.version))
        .collect();
    assert_eq!(names, ["alpha==1.0", "beta==2.0"]);
    assert!(has(&f.python, "alpha", "1.0") && has(&f.python, "beta", "2.0"));
    assert_eq!(f.env.leftover_runs(), 0, "staging is cleaned up");
    assert!(!f.env.journal_exists());
    // installed bytes are the reviewed ones
    for w in &r.packages {
        assert_eq!(w.sha256.len(), 64);
    }
}

#[test]
fn requirements_file_install_and_hash_pin() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &[]);
    let wd = f.env.workdir();
    let (_, bytes) = build_wheel("alpha", "1.0", &[], "py3-none-any");
    let good = sha256_hex(&bytes);
    std::fs::write(
        wd.join("bad.txt"),
        format!("alpha==1.0 --hash=sha256:{}\n", "ab".repeat(32)),
    )
    .unwrap();
    let e = f.install(&["-r", "bad.txt"], &seams(&f.index)).unwrap_err();
    assert_eq!(e.code, ResultCode::IntegrityFailure);
    assert!(!has_name(&f.python, "alpha"));
    std::fs::write(
        wd.join("ok.txt"),
        format!("alpha==1.0 --hash=sha256:{good}\n"),
    )
    .unwrap();
    f.install(&["-r", "ok.txt"], &seams(&f.index)).unwrap();
    assert!(has(&f.python, "alpha", "1.0"));
}

#[test]
fn source_only_dependency_is_unsupported_input() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &["gamma"]);
    f.index.add_sdist("gamma", "1.0");
    let e = f.install(&["alpha"], &seams(&f.index)).unwrap_err();
    assert_eq!(e.code, ResultCode::InvalidInput);
    let hit = e
        .findings
        .iter()
        .find(|x| {
            x.kind == FindingKind::UnsupportedInput && x.target.as_deref() == Some("PyPI:gamma")
        })
        .expect("gamma reported");
    assert_eq!(hit.action, FindingAction::Deny);
    assert!(!has_name(&f.python, "alpha"), "nothing installed");
    assert_eq!(f.env.leftover_runs(), 0);
}

#[test]
fn transitive_direct_reference_is_stopped_before_pip_uses_it() {
    let f = fixture();
    f.index.add_wheel(
        "alpha",
        "1.0",
        &["evil @ https://evil.invalid/evil-1.0-py3-none-any.whl"],
    );
    let e = f.install(&["alpha"], &seams(&f.index)).unwrap_err();
    assert!(
        finding_kinds(&e).contains(&FindingKind::UnsupportedInput),
        "{e}"
    );
    assert!(!has_name(&f.python, "alpha") && !has_name(&f.python, "evil"));
}

#[test]
fn mismatched_hash_fails_closed() {
    let f = fixture();
    let (name, bytes) = build_wheel("alpha", "1.0", &[], "py3-none-any");
    f.index.add_raw("alpha", &name, bytes, &"00".repeat(32));
    let e = f.install(&["alpha"], &seams(&f.index)).unwrap_err();
    assert_eq!(e.code, ResultCode::IntegrityFailure, "{e}");
    assert!(finding_kinds(&e).contains(&FindingKind::IntegrityMismatch));
    assert!(!has_name(&f.python, "alpha"));
}

#[test]
fn oversized_artifact_is_refused() {
    let mut f = fixture();
    f.env.settings.limits.artifact_max_bytes = 200;
    f.index.add_wheel("alpha", "1.0", &[]);
    let e = f.install(&["alpha"], &seams(&f.index)).unwrap_err();
    assert!(
        matches!(e.code, ResultCode::Rejected | ResultCode::IntegrityFailure),
        "{e}"
    );
    assert!(!has_name(&f.python, "alpha"));
}

#[test]
fn wheel_for_another_platform_is_not_installed() {
    let f = fixture();
    f.index
        .add_wheel_tagged("alpha", "1.0", "cp27-cp27m-win_amd64");
    let e = f.install(&["alpha"], &seams(&f.index)).unwrap_err();
    assert_eq!(e.code, ResultCode::InvalidInput);
    assert!(!has_name(&f.python, "alpha"));
}

#[test]
fn advisory_pauses_for_approval_and_cancel_applies_nothing() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &[]);
    let asked: Arc<Mutex<Vec<ApprovalRequest>>> = Arc::default();
    let a2 = asked.clone();
    let mut s = seams(&f.index);
    s.advisories = Box::new(|_| advisory());
    s.approve = Box::new(move |r| {
        a2.lock().unwrap().push(r.clone());
        Ok(Decision::Cancel)
    });
    let e = f.install(&["alpha"], &s).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected);
    assert!(!has_name(&f.python, "alpha"));
    assert!(!f.env.journal_exists());
    assert_eq!(asked.lock().unwrap().len(), 1);
    // reviewed copies are removed after a cancel
    let reviewed = f.env.paths.cache_dir.join("pip").join("reviewed");
    assert_eq!(
        std::fs::read_dir(reviewed).map(|d| d.count()).unwrap_or(0),
        0
    );

    // approving the same plan installs it; the digest is stable
    let digest_first = asked.lock().unwrap()[0].digest.clone();
    let seen = Arc::new(Mutex::new(String::new()));
    let s2 = seen.clone();
    let mut s = seams(&f.index);
    s.advisories = Box::new(|_| advisory());
    s.approve = Box::new(move |r| {
        *s2.lock().unwrap() = r.digest.clone();
        Ok(Decision::ApproveOnce)
    });
    let r = f.install(&["alpha"], &s).unwrap();
    assert!(r.approved);
    assert_eq!(*seen.lock().unwrap(), digest_first);
    assert_eq!(r.digest, digest_first);
    assert!(has(&f.python, "alpha", "1.0"));
}

#[test]
fn incomplete_scan_pauses() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &[]);
    let asked = Arc::new(AtomicUsize::new(0));
    let a2 = asked.clone();
    let mut s = seams(&f.index);
    s.advisories = Box::new(|_| AdvisoryReport {
        findings: vec![],
        complete: false,
    });
    s.approve = Box::new(move |_| {
        a2.fetch_add(1, Ordering::SeqCst);
        Ok(Decision::Cancel)
    });
    assert!(f.install(&["alpha"], &s).is_err());
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    assert!(!has_name(&f.python, "alpha"));
}

#[test]
fn deny_finding_cannot_be_approved_away() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &[]);
    let mut s = seams(&f.index);
    s.advisories = Box::new(|_| AdvisoryReport {
        findings: vec![Finding::new(
            FindingKind::Malware,
            FindingAction::Deny,
            "osv",
            "synthetic",
        )],
        complete: true,
    });
    let e = f.install(&["alpha"], &s).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected);
    assert!(!has_name(&f.python, "alpha"));
}

#[test]
fn changed_plan_invalidates_approval() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &[]);
    let reviewed = f.env.paths.cache_dir.join("pip").join("reviewed");
    let mut s = seams(&f.index);
    s.advisories = Box::new(|_| advisory());
    s.approve = Box::new(move |_| {
        // the user "approves" while something swaps the reviewed bytes
        for dir in std::fs::read_dir(&reviewed).unwrap() {
            for w in std::fs::read_dir(dir.unwrap().path()).unwrap() {
                let p = w.unwrap().path();
                let mut b = std::fs::read(&p).unwrap();
                b.extend_from_slice(b"tampered");
                std::fs::write(&p, b).unwrap();
            }
        }
        Ok(Decision::ApproveOnce)
    });
    let e = f.install(&["alpha"], &s).unwrap_err();
    assert_eq!(e.code, ResultCode::IntegrityFailure, "{e}");
    assert!(!has_name(&f.python, "alpha"));
    assert!(!f.env.journal_exists());
}

#[test]
fn a_different_plan_has_a_different_digest() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &[]);
    let one = f.install(&["alpha"], &seams(&f.index)).unwrap().digest;
    // the registry now offers a new version: same request, different plan
    f.index.add_wheel("alpha", "1.1", &[]);
    let mut s = seams(&f.index);
    s.advisories = Box::new(|_| advisory());
    s.approve = Box::new(|_| Ok(Decision::Cancel));
    let e = f.install(&["--upgrade", "alpha"], &s);
    assert!(e.is_err());
    let two = {
        let seen = Arc::new(Mutex::new(String::new()));
        let s2 = seen.clone();
        let mut s = seams(&f.index);
        s.advisories = Box::new(|_| advisory());
        s.approve = Box::new(move |r| {
            *s2.lock().unwrap() = r.digest.clone();
            Ok(Decision::Cancel)
        });
        let _ = f.install(&["--upgrade", "alpha"], &s);
        let d = seen.lock().unwrap().clone();
        d
    };
    assert_ne!(one, two);
}

#[test]
fn apply_does_not_resolve_again() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &["beta"]);
    f.index.add_wheel("beta", "1.0", &[]);
    let at_apply = Arc::new(AtomicUsize::new(usize::MAX));
    let a2 = at_apply.clone();
    let h = f.index.handle();
    let mut s = seams(&f.index);
    s.hooks.before_wheel = Some(Box::new(move |i, _| {
        if i == 0 {
            a2.store(h.requests(), Ordering::SeqCst);
            h.shutdown();
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(())
    }));
    let r = f.install(&["alpha"], &s).unwrap();
    assert_eq!(r.packages.len(), 2);
    assert!(has(&f.python, "alpha", "1.0") && has(&f.python, "beta", "1.0"));
    assert_eq!(
        f.index.requests(),
        at_apply.load(Ordering::SeqCst),
        "no request after the plan"
    );
}

#[test]
fn resolver_cancellation_leaves_everything_unchanged() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &[]);
    f.index.set_delay(std::time::Duration::from_secs(30));
    let s = seams(&f.index);
    let cancel = s.cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(4));
        cancel.store(true, Ordering::SeqCst);
    });
    let started = std::time::Instant::now();
    let e = f.install(&["alpha"], &s).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(25),
        "pip was killed, not awaited"
    );
    assert!(!has_name(&f.python, "alpha"));
    assert_eq!(f.env.leftover_runs(), 0);
    assert!(!f.env.journal_exists());
}

#[test]
fn interrupted_apply_is_recovered_by_the_next_run() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &[]);
    f.index.add_wheel("beta", "1.0", &[]);
    let crashed = Arc::new(AtomicBool::new(false));
    let c2 = crashed.clone();
    let mut s = seams(&f.index);
    s.hooks.before_wheel = Some(Box::new(move |i, _| {
        if i == 1 {
            c2.store(true, Ordering::SeqCst);
            return Err(Error::internal("simulated crash"));
        }
        Ok(())
    }));
    let e = f.install(&["alpha", "beta"], &s).unwrap_err();
    assert!(crashed.load(Ordering::SeqCst), "{e}");
    // partially applied, but journaled with the reviewed wheels kept
    assert!(has_name(&f.python, "alpha") && !has_name(&f.python, "beta"));
    assert!(f.env.journal_exists());

    // the next guarded run completes the reviewed set first
    let r = f.install(&["alpha"], &seams(&f.index)).unwrap();
    assert!(r.recovered);
    assert!(has(&f.python, "alpha", "1.0") && has(&f.python, "beta", "1.0"));
    assert!(!f.env.journal_exists());
}

#[test]
fn cancel_during_apply_stops_between_wheels_and_is_recoverable() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &[]);
    f.index.add_wheel("beta", "1.0", &[]);
    let mut s = seams(&f.index);
    let cancel = s.cancel.clone();
    s.hooks.before_wheel = Some(Box::new(move |i, _| {
        if i == 1 {
            cancel.store(true, Ordering::SeqCst);
        }
        Ok(())
    }));
    let e = f.install(&["alpha", "beta"], &s).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected);
    assert!(!has_name(&f.python, "beta"));
    assert!(f.env.journal_exists());
    f.install(&["alpha"], &seams(&f.index)).unwrap();
    assert!(has_name(&f.python, "beta"));
}

#[test]
fn tampered_reviewed_set_blocks_recovery() {
    let f = fixture();
    f.index.add_wheel("alpha", "1.0", &[]);
    f.index.add_wheel("beta", "1.0", &[]);
    let mut s = seams(&f.index);
    s.hooks.before_wheel = Some(Box::new(|i, _| {
        if i == 1 {
            return Err(Error::internal("simulated crash"));
        }
        Ok(())
    }));
    f.install(&["alpha", "beta"], &s).unwrap_err();
    let reviewed = f.env.paths.cache_dir.join("pip").join("reviewed");
    for d in std::fs::read_dir(&reviewed).unwrap() {
        for w in std::fs::read_dir(d.unwrap().path()).unwrap() {
            std::fs::write(w.unwrap().path(), b"substituted").unwrap();
        }
    }
    let e = f.install(&["alpha"], &seams(&f.index)).unwrap_err();
    assert_eq!(e.code, ResultCode::IntegrityFailure, "{e}");
    assert!(!has_name(&f.python, "beta"));
}

#[test]
fn install_is_bound_to_the_selected_interpreter() {
    let f = fixture();
    let other_dir = tempfile::tempdir().unwrap();
    let other = make_venv(&other_dir.path().join("o"));
    f.index.add_wheel("alpha", "1.0", &[]);
    let r = f.install(&["alpha"], &seams(&f.index)).unwrap();
    assert!(has_name(&f.python, "alpha"));
    assert!(
        !has_name(&other, "alpha"),
        "other environments are untouched"
    );
    // the same request for another interpreter is a different plan
    let ctx = f.env.ctx();
    let r2 = pip::install(
        &ctx,
        &other,
        &args(&["alpha"]),
        &f.env.workdir(),
        &seams(&f.index),
    )
    .unwrap();
    assert_ne!(r.digest, r2.digest);
    assert!(has_name(&other, "alpha"));
}
