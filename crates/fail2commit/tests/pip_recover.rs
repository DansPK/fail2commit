//! FR-005 / CR-002 (review W2-002): a canceled or interrupted apply is never
//! rolled forward implicitly; `recover` completes it after a fresh approval
//! or discards it.

mod pip_support;

use fail2commit_core::pip;
use fail2commit_core::protocol::{ApprovalRequest, Decision};
use fail2commit_core::scan::AdvisoryReport;
use fail2commit_core::{Error, Finding, FindingAction, FindingKind, ResultCode};
use pip_support::*;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

struct Fixture {
    env: Env,
    index: TestIndex,
    python: std::path::PathBuf,
    venv: std::path::PathBuf,
    _venv: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let env = Env::new();
    let index = TestIndex::start();
    let dir = tempfile::tempdir().unwrap();
    let python = make_venv(&dir.path().join("v"));
    index.add_wheel("alpha", "1.0", &[]);
    index.add_wheel("beta", "1.0", &[]);
    index.add_wheel("gamma", "1.0", &[]);
    Fixture {
        env,
        index,
        python,
        venv: dir.path().join("v"),
        _venv: dir,
    }
}

impl Fixture {
    fn install(
        &self,
        a: &[&str],
        seams: &pip::Seams<'_>,
    ) -> fail2commit_core::Result<pip::InstallReport> {
        pip::install(
            &self.env.ctx(),
            &self.python,
            &args(a),
            &self.env.workdir(),
            seams,
        )
    }

    fn recover(
        &self,
        discard: bool,
        seams: &pip::Seams<'_>,
    ) -> fail2commit_core::Result<pip::RecoverReport> {
        pip::recover(&self.env.ctx(), &self.python, discard, seams)
    }

    /// alpha is installed, beta is not: canceled between the two wheels.
    fn cancel_after_first_wheel(&self) -> Error {
        let mut s = seams(&self.index);
        let cancel = s.cancel.clone();
        s.hooks.before_wheel = Some(Box::new(move |i, _| {
            if i == 0 {
                cancel.store(true, Ordering::SeqCst); // arrives while wheel 0 installs
            }
            Ok(())
        }));
        self.install(&["alpha", "beta"], &s).unwrap_err()
    }

    /// Seams for `recover`: records the request and answers `decision`.
    fn answering(
        &self,
        decision: Decision,
    ) -> (pip::Seams<'static>, Arc<Mutex<Vec<ApprovalRequest>>>) {
        let asked: Arc<Mutex<Vec<ApprovalRequest>>> = Arc::default();
        let a2 = asked.clone();
        let mut s = seams(&self.index);
        s.approve = Box::new(move |r| {
            a2.lock().unwrap().push(r.clone());
            Ok(decision)
        });
        (s, asked)
    }
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
fn cancel_before_apply_leaves_the_venv_byte_identical() {
    let f = fixture();
    let before = snapshot(&f.venv);
    let mut s = seams(&f.index);
    s.advisories = Box::new(|_| advisory());
    let cancel = s.cancel.clone();
    // the user approves, but a cancel lands before apply starts
    s.approve = Box::new(move |_| {
        cancel.store(true, Ordering::SeqCst);
        Ok(Decision::ApproveOnce)
    });
    let e = f.install(&["alpha", "beta"], &s).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    assert_eq!(snapshot(&f.venv), before, "environment untouched");
    assert!(!f.env.journal_exists());
    assert_eq!(f.env.reviewed_dirs(), 0);

    // a cancel seen at the first wheel boundary also changes nothing
    let mut s = seams(&f.index);
    let cancel = s.cancel.clone();
    s.hooks.before_wheel = Some(Box::new(|_, _| panic!("no wheel may start")));
    cancel.store(true, Ordering::SeqCst);
    let e = f.install(&["alpha", "beta"], &s).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    assert_eq!(snapshot(&f.venv), before);
    assert!(!f.env.journal_exists());
}

#[test]
fn cancel_mid_apply_keeps_a_cancelled_journal_and_blocks_other_installs() {
    let f = fixture();
    let e = f.cancel_after_first_wheel();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    assert!(has_name(&f.python, "alpha") && !has_name(&f.python, "beta"));
    let journal = String::from_utf8(f.env.journal_bytes().expect("journal kept")).unwrap();
    assert!(journal.contains("\"cancelled\":true"), "{journal}");

    // an unrelated install never finishes the old plan
    let before = snapshot(&f.venv);
    let e = f.install(&["gamma"], &seams(&f.index)).unwrap_err();
    assert_eq!(e.code, ResultCode::InvalidInput, "{e}");
    assert!(e.message.contains("recover"), "{e}");
    assert!(!has_name(&f.python, "beta") && !has_name(&f.python, "gamma"));
    assert_eq!(snapshot(&f.venv), before);
}

#[test]
fn recover_with_approval_completes_the_remaining_wheels() {
    let f = fixture();
    let first = Arc::new(Mutex::new(String::new()));
    {
        let f2 = first.clone();
        let mut s = seams(&f.index);
        s.advisories = Box::new(|_| advisory());
        let cancel = s.cancel.clone();
        s.approve = Box::new(move |r| {
            *f2.lock().unwrap() = r.digest.clone();
            Ok(Decision::ApproveOnce)
        });
        s.hooks.before_wheel = Some(Box::new(move |i, _| {
            if i == 0 {
                cancel.store(true, Ordering::SeqCst);
            }
            Ok(())
        }));
        f.install(&["alpha", "beta"], &s).unwrap_err();
    }
    assert!(!has_name(&f.python, "beta"));

    let (s, asked) = f.answering(Decision::ApproveOnce);
    let r = f.recover(false, &s).unwrap();
    let asked = asked.lock().unwrap();
    assert_eq!(asked.len(), 1, "a fresh approval was requested");
    assert_ne!(asked[0].digest, *first.lock().unwrap(), "new digest");
    assert_eq!(asked[0].digest, r.digest);
    let details = asked[0].details.join("\n");
    assert!(details.contains("beta==1.0"), "{details}");
    assert!(!details.contains("to install: alpha"), "{details}");
    assert!(r.approved && !r.discarded);
    let names = |v: &[pip::PlanWheel]| v.iter().map(|w| w.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&r.already_installed), ["alpha"]);
    assert_eq!(names(&r.pending), ["beta"]);
    assert!(has(&f.python, "alpha", "1.0") && has(&f.python, "beta", "1.0"));
    assert!(!f.env.journal_exists());
    assert_eq!(f.env.reviewed_dirs(), 0);

    // guarded installs work again
    f.install(&["gamma"], &seams(&f.index)).unwrap();
    assert!(has_name(&f.python, "gamma"));
}

#[test]
fn recover_that_is_canceled_changes_nothing() {
    let f = fixture();
    f.cancel_after_first_wheel();
    let journal = f.env.journal_bytes().unwrap();
    let before = snapshot(&f.venv);

    let (s, asked) = f.answering(Decision::Cancel);
    let e = f.recover(false, &s).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    assert_eq!(asked.lock().unwrap().len(), 1);

    // approving while a cancel is pending also applies nothing
    let (mut s, _) = f.answering(Decision::ApproveOnce);
    let cancel = s.cancel.clone();
    s.approve = Box::new(move |_| {
        cancel.store(true, Ordering::SeqCst);
        Ok(Decision::ApproveOnce)
    });
    let e = f.recover(false, &s).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");

    assert_eq!(snapshot(&f.venv), before, "environment untouched");
    assert_eq!(f.env.journal_bytes().unwrap(), journal, "journal untouched");
    assert!(!has_name(&f.python, "beta"));
}

#[test]
fn discard_drops_the_journal_and_reports_what_was_installed() {
    let f = fixture();
    f.cancel_after_first_wheel();
    // no approval is needed to discard
    let r = f.recover(true, &seams(&f.index)).unwrap();
    assert!(r.discarded && !r.approved);
    let names = |v: &[pip::PlanWheel]| v.iter().map(|w| w.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&r.already_installed), ["alpha"]);
    assert_eq!(names(&r.pending), ["beta"]);
    assert!(!f.env.journal_exists());
    assert_eq!(f.env.reviewed_dirs(), 0);
    assert!(has_name(&f.python, "alpha") && !has_name(&f.python, "beta"));

    f.install(&["gamma"], &seams(&f.index)).unwrap();
    assert!(has_name(&f.python, "gamma"));
    // nothing left to discard
    let e = f.recover(true, &seams(&f.index)).unwrap_err();
    assert_eq!(e.code, ResultCode::InvalidInput, "{e}");
}

#[test]
fn a_crashed_apply_also_blocks_and_a_tampered_set_cannot_be_recovered() {
    let f = fixture();
    let mut s = seams(&f.index);
    s.hooks.before_wheel = Some(Box::new(|i, _| {
        if i == 1 {
            return Err(Error::internal("simulated crash"));
        }
        Ok(())
    }));
    f.install(&["alpha", "beta"], &s).unwrap_err();
    assert!(has_name(&f.python, "alpha") && !has_name(&f.python, "beta"));
    let e = f.install(&["gamma"], &seams(&f.index)).unwrap_err();
    assert_eq!(e.code, ResultCode::InvalidInput, "{e}");

    let reviewed = f.env.paths.cache_dir.join("pip").join("reviewed");
    for d in std::fs::read_dir(&reviewed).unwrap() {
        for w in std::fs::read_dir(d.unwrap().path()).unwrap() {
            std::fs::write(w.unwrap().path(), b"substituted").unwrap();
        }
    }
    let e = f.recover(false, &seams(&f.index)).unwrap_err();
    assert_eq!(e.code, ResultCode::IntegrityFailure, "{e}");
    assert!(!has_name(&f.python, "beta"));
    assert!(f.env.journal_exists(), "evidence kept");
}

#[test]
fn recover_without_a_journal_is_invalid_input() {
    let f = fixture();
    let e = f.recover(false, &seams(&f.index)).unwrap_err();
    assert_eq!(e.code, ResultCode::InvalidInput, "{e}");
}
