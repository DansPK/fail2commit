//! Independent wave-2 security-review reproduction.
//!
//! `python -I` alone still imports `site` and executes `.pth` import lines from
//! the target environment (the first test pins that premise). `pip::interp`
//! therefore starts every interpreter with `-I -S`, and the second test is the
//! W2-001 regression: the guard's process chain never runs the `.pth`, and the
//! wheel needs an approval naming it.

use std::path::{Path, PathBuf};
use std::process::Command;

fn python() -> Option<Command> {
    for (program, args) in [
        ("py", &["-3"][..]),
        ("python", &[][..]),
        ("python3", &[][..]),
    ] {
        let mut cmd = Command::new(program);
        cmd.args(args);
        if cmd
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            let mut cmd = Command::new(program);
            cmd.args(args);
            return Some(cmd);
        }
    }
    None
}

fn venv_python(root: &Path) -> PathBuf {
    if cfg!(windows) {
        root.join("Scripts/python.exe")
    } else {
        root.join("bin/python")
    }
}

#[test]
fn isolated_python_still_executes_target_pth_files() {
    let Some(mut create) = python() else {
        eprintln!("Python is unavailable; reproduction not exercised");
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let venv = temp.path().join("venv");
    assert!(create
        .args(["-m", "venv"])
        .arg(&venv)
        .status()
        .unwrap()
        .success());

    let python = venv_python(&venv);
    let purelib = Command::new(&python)
        .args([
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ])
        .output()
        .unwrap();
    assert!(purelib.status.success());
    let purelib = PathBuf::from(String::from_utf8(purelib.stdout).unwrap().trim());
    let marker = temp.path().join("pth-ran");
    let marker_literal = format!("{:?}", marker.to_string_lossy());
    std::fs::write(
        purelib.join("fail2commit_review.pth"),
        format!("import pathlib; pathlib.Path({marker_literal}).write_text('ran')\n"),
    )
    .unwrap();

    let status = Command::new(&python)
        .args(["-I", "-c", "pass"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        marker.is_file(),
        "python -I executed the target environment's .pth import line"
    );
}
// ---------------------------------------------------------------------------
// W2-001, end to end: a wheel may ship a top-level `.pth` file, and the wheel
// spec installs it into purelib. Fixed (CR-001): the guard starts every
// interpreter with `-I -S`, and the wheel is flagged for approval by name.
// ---------------------------------------------------------------------------

mod pip_support;

use fail2commit_core::pip;
use fail2commit_core::protocol::{ApprovalRequest, Decision};
use fail2commit_core::{FindingAction, FindingKind};
use pip_support::*;
use std::io::Write;
use std::sync::{Arc, Mutex};

/// A valid wheel whose top level also carries a `.pth` file that writes
/// `marker` when any interpreter for the environment starts.
fn build_pth_wheel(marker: &Path) -> (String, Vec<u8>) {
    let marker = marker.to_string_lossy().replace('\\', "/");
    let pth = format!("import pathlib; pathlib.Path(\"{marker}\").write_text('ran')\n");
    let files = [
        ("evilpth.py", "VERSION = '1.0'\n".to_string()),
        (
            "evilpth-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: evilpth\nVersion: 1.0\n".to_string(),
        ),
        (
            "evilpth-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: f2c-review\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                .to_string(),
        ),
        ("evilpth-1.0.dist-info/RECORD", String::new()),
        ("f2c_review_marker.pth", pth),
    ];
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let o = zip::write::SimpleFileOptions::default();
        for (name, body) in files {
            z.start_file(name, o).unwrap();
            z.write_all(body.as_bytes()).unwrap();
        }
        z.finish().unwrap();
    }
    ("evilpth-1.0-py3-none-any.whl".to_string(), buf.into_inner())
}

fn has_pip(python: &Path) -> bool {
    Command::new(python)
        .args(["-I", "-c", "import pip"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// W2-001 / CR-001 regression: the guard's own process chain (probe, dry-run
/// resolution, apply, verify) starts every interpreter without `site`, so the
/// wheel's `.pth` never runs inside the guard; the wheel needs an approval that
/// names the file.
#[test]
fn guarded_install_never_runs_wheel_startup_code_and_asks_approval_naming_it() {
    let env = Env::new();
    let index = TestIndex::start();
    let venv = tempfile::tempdir().unwrap();
    let python = make_venv(&venv.path().join("v"));
    if !has_pip(&python) {
        eprintln!(
            "{} has no pip; reproduction not exercised",
            python.display()
        );
        return;
    }
    let marker = env.home.path().join("wheel-code-ran");
    let (filename, bytes) = build_pth_wheel(&marker);
    index.add_raw("evilpth", &filename, bytes.clone(), &sha256_hex(&bytes));
    index.add_wheel("other", "1.0", &[]);

    let asked: Arc<Mutex<Vec<ApprovalRequest>>> = Arc::default();
    let a2 = asked.clone();
    let mut s = seams(&index);
    s.approve = Box::new(move |r| {
        a2.lock().unwrap().push(r.clone());
        Ok(Decision::ApproveOnce)
    });
    let report = pip::install(&env.ctx(), &python, &args(&["evilpth"]), &env.workdir(), &s)
        .expect("an approved wheel install succeeds");
    assert!(
        !marker.exists(),
        "W2-001: the guarded install executed wheel code on the host"
    );
    assert!(report.approved, "startup code needs an approval");
    assert!(has(&python, "evilpth", "1.0"), "the wheel is installed");

    let asked = asked.lock().unwrap();
    assert_eq!(asked.len(), 1);
    let f = asked[0]
        .findings
        .iter()
        .find(|f| f.source == "pip.startup")
        .expect("a pip.startup finding");
    assert_eq!(f.kind, FindingKind::HostExecution);
    assert_eq!(f.action, FindingAction::Approve);
    assert_eq!(f.location.as_deref(), Some("f2c_review_marker.pth"));
    assert!(f.evidence.contains(&filename), "{}", f.evidence);
    assert!(
        asked[0]
            .details
            .iter()
            .any(|d| d.contains("f2c_review_marker.pth") && d.contains(&filename)),
        "{:?}",
        asked[0].details
    );
    assert!(report.findings.iter().any(|f| f.source == "pip.startup"));
    drop(asked);

    // The .pth is now installed. A later guarded run (probe, dry run, apply,
    // verify against that environment) still must not execute it.
    let r = pip::install(
        &env.ctx(),
        &python,
        &args(&["other"]),
        &env.workdir(),
        &seams(&index),
    )
    .unwrap();
    assert!(!r.approved, "a clean wheel asks nothing");
    assert!(has(&python, "other", "1.0"));
    assert!(
        !marker.exists(),
        "W2-001: a later guarded run executed the installed .pth"
    );
}

#[test]
fn declining_the_startup_approval_installs_nothing() {
    let env = Env::new();
    let index = TestIndex::start();
    let venv = tempfile::tempdir().unwrap();
    let python = make_venv(&venv.path().join("v"));
    if !has_pip(&python) {
        return;
    }
    let marker = env.home.path().join("wheel-code-ran");
    let (filename, bytes) = build_pth_wheel(&marker);
    index.add_raw("evilpth", &filename, bytes.clone(), &sha256_hex(&bytes));
    let mut s = seams(&index);
    s.approve = Box::new(|_| Ok(Decision::Cancel));
    let e = pip::install(&env.ctx(), &python, &args(&["evilpth"]), &env.workdir(), &s).unwrap_err();
    assert_eq!(e.code, fail2commit_core::ResultCode::Rejected, "{e}");
    assert!(!has_name(&python, "evilpth"));
    assert!(!marker.exists());
    assert!(!env.journal_exists());
}
