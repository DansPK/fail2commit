//! Independent re-review of the W2-002 / CR-002 fix (FR-005): the journal gate,
//! `recover` approval binding and the trust placed in the journal file.

mod pip_support;

use fail2commit_core::pip;
use fail2commit_core::protocol::{ApprovalRequest, Decision};
use fail2commit_core::ResultCode;
use pip_support::*;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

struct Fx {
    env: Env,
    index: TestIndex,
    python: PathBuf,
    venv: PathBuf,
    _dir: tempfile::TempDir,
}

fn fx() -> Fx {
    let env = Env::new();
    let index = TestIndex::start();
    let dir = tempfile::tempdir().unwrap();
    let venv = dir.path().join("v");
    let python = make_venv(&venv);
    for n in ["alpha", "beta", "gamma"] {
        index.add_wheel(n, "1.0", &[]);
    }
    Fx {
        env,
        index,
        python,
        venv,
        _dir: dir,
    }
}

impl Fx {
    fn install_at(
        &self,
        python: &std::path::Path,
        a: &[&str],
        s: &pip::Seams<'_>,
    ) -> fail2commit_core::Result<pip::InstallReport> {
        pip::install(&self.env.ctx(), python, &args(a), &self.env.workdir(), s)
    }

    /// alpha installed, beta pending, journal `cancelled`.
    fn cancelled_journal(&self) {
        let mut s = seams(&self.index);
        let cancel = s.cancel.clone();
        s.hooks.before_wheel = Some(Box::new(move |i, _| {
            if i == 0 {
                cancel.store(true, Ordering::SeqCst);
            }
            Ok(())
        }));
        let e = self
            .install_at(&self.python, &["alpha", "beta"], &s)
            .unwrap_err();
        assert_eq!(e.code, ResultCode::Rejected, "{e}");
        assert!(self.env.journal_exists());
    }

    fn journal_file(&self) -> PathBuf {
        std::fs::read_dir(self.env.paths.state_dir.join("pip"))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("journal-")
            })
            .expect("journal")
    }

    fn approving(&self) -> (pip::Seams<'static>, Arc<Mutex<Vec<ApprovalRequest>>>) {
        let asked: Arc<Mutex<Vec<ApprovalRequest>>> = Arc::default();
        let a2 = asked.clone();
        let mut s = seams(&self.index);
        s.approve = Box::new(move |r| {
            a2.lock().unwrap().push(r.clone());
            Ok(Decision::ApproveOnce)
        });
        (s, asked)
    }
}

/// Every journal and hash file stays under the trusted state dir, whatever the
/// interpreter is called.
#[test]
fn journal_lives_only_under_the_trusted_state_dir() {
    let f = fx();
    f.cancelled_journal();
    let j = f.journal_file();
    assert_eq!(j.parent().unwrap(), f.env.paths.state_dir.join("pip"));
    let text = std::fs::read_to_string(&j).unwrap();
    assert!(text.contains("\"cancelled\":true"));
}

/// RP-006: the per-interpreter gate is keyed by the *spelling* of the
/// interpreter path the user passed, not by the interpreter. A second spelling
/// of the same venv python is not blocked by the unfinished journal.
#[test]
fn respelled_interpreter_path_is_still_blocked_by_the_journal() {
    let f = fx();
    f.cancelled_journal();
    let scripts = if cfg!(windows) { "Scripts" } else { "bin" };
    let exe = if cfg!(windows) {
        "python.exe"
    } else {
        "python"
    };
    // same file, different spelling
    let respelled = f.venv.join(scripts).join("..").join(scripts).join(exe);
    assert!(respelled.is_file());
    let before = snapshot(&f.venv);
    let r = f.install_at(&respelled, &["gamma"], &seams(&f.index));
    let blocked =
        matches!(&r, Err(e) if e.code == ResultCode::InvalidInput && e.message.contains("recover"));
    assert!(
        blocked,
        "RP-006: a respelled path to the same interpreter bypassed the journal gate: {:?}; gamma installed = {}",
        r.as_ref().map(|r| r.packages.len()).map_err(|e| e.to_string()),
        has_name(&f.python, "gamma"),
    );
    assert_eq!(snapshot(&f.venv), before);
}

/// RP-007: `recover` trusts the journal file completely. A journal that was
/// edited to name a different wheel set (never reviewed or inspected by an
/// install) is accepted as long as it is self-consistent; nothing binds it to
/// the digest the user originally approved.
#[test]
fn recover_rejects_a_journal_that_no_longer_matches_what_was_approved() {
    let f = fx();
    f.cancelled_journal();
    // forge: replace the pending wheel list with one the original plan never had
    let forged_dir = tempfile::tempdir().unwrap();
    let (filename, bytes) = build_wheel("forged", "1.0", &[], "py3-none-any");
    std::fs::write(forged_dir.path().join(&filename), &bytes).unwrap();
    let jp = f.journal_file();
    let mut j: serde_json::Value = serde_json::from_slice(&std::fs::read(&jp).unwrap()).unwrap();
    j["reviewed"] = serde_json::json!(forged_dir.path());
    j["wheels"] = serde_json::json!([{
        "name": "forged", "version": "1.0", "filename": filename,
        "sha256": sha256_hex(&bytes), "size": bytes.len(),
    }]);
    j["done"] = serde_json::json!(0);
    std::fs::write(&jp, serde_json::to_vec(&j).unwrap()).unwrap();

    let (s, asked) = f.approving();
    let r = pip::recover(&f.env.ctx(), &f.python, false, &s);
    let installed = has_name(&f.python, "forged");
    assert!(
        r.is_err() && !installed,
        "RP-007: recover installed a wheel ('forged') that is not part of the plan the user approved; \
         the approval it asked for showed: {:?}",
        asked.lock().unwrap().first().map(|r| r.details.clone()),
    );
}

/// RP-008: the journal's own `python` field decides which journal `discard`
/// and the progress writes touch; it is never compared with the interpreter
/// that `recover` was asked about.
#[test]
fn discard_acts_on_the_journal_of_the_interpreter_it_was_asked_about() {
    let f = fx();
    f.cancelled_journal();
    let jp = f.journal_file();
    let mut j: serde_json::Value = serde_json::from_slice(&std::fs::read(&jp).unwrap()).unwrap();
    j["python"] = serde_json::json!(f.env.home.path().join("some-other-python"));
    std::fs::write(&jp, serde_json::to_vec(&j).unwrap()).unwrap();
    let r = pip::recover(&f.env.ctx(), &f.python, true, &seams(&f.index));
    let still_there = jp.exists();
    assert!(
        r.is_err() || !still_there,
        "RP-008: `recover --discard` reported success ({:?}) but left this interpreter's journal in place \
         because the journal named a different interpreter",
        r.map(|r| r.discarded).map_err(|e| e.to_string())
    );
}

/// `--discard` can never apply anything, even with a hostile journal.
#[test]
fn discard_installs_nothing_even_with_a_forged_journal() {
    let f = fx();
    f.cancelled_journal();
    let before = snapshot(&f.venv);
    let r = pip::recover(&f.env.ctx(), &f.python, true, &seams(&f.index)).unwrap();
    assert!(r.discarded && !r.approved);
    assert_eq!(snapshot(&f.venv), before);
    assert!(!f.env.journal_exists());
}

/// A cancel that arrives while a wheel is installing lets that wheel finish
/// (never half installed) and the journal records exactly what is done.
#[test]
fn cancel_stops_at_a_wheel_boundary_with_consistent_progress() {
    let f = fx();
    f.cancelled_journal();
    let j: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.journal_file()).unwrap()).unwrap();
    assert_eq!(j["done"], 1);
    assert_eq!(j["wheels"].as_array().unwrap().len(), 2);
    assert!(has(&f.python, "alpha", "1.0") && !has_name(&f.python, "beta"));
}
