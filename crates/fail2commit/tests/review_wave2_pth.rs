//! Independent wave-2 security-review reproduction.
//!
//! `pip::interp` treats `python -I` as a code-free probe/apply boundary, but
//! isolated mode still imports `site` and executes `.pth` import lines from the
//! target environment. A wheel installed by one apply process can therefore
//! execute host code when fail2commit starts its next interpreter process.

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
// spec installs it into purelib. `pip::install` then runs the interpreter again
// (verify_installed) inside the same guarded command, so the wheel's code runs
// on the host with no sandbox and no `exec::authorize_scripts`.
// ---------------------------------------------------------------------------

mod pip_support;

use fail2commit_core::pip;
use pip_support::*;
use std::io::Write;

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

#[test]
fn reviewed_pip_install_runs_wheel_code_on_the_host() {
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

    let report = pip::install(
        &env.ctx(),
        &python,
        &args(&["evilpth"]),
        &env.workdir(),
        &seams(&index),
    )
    .expect("a clean, hash-verified wheel install is expected to succeed");
    assert!(!report.approved, "a clean plan asks for no approval");
    assert!(has(&python, "evilpth", "1.0"), "the wheel is installed");
    assert!(
        !marker.exists(),
        "W2-001: the guarded install executed wheel code on the host"
    );
}
