//! Independent re-review of the W2-001 / CR-001 fix (FR-005, FR-008).
//!
//! Every test here is an attempt to defeat the `-I -S` bootstrap
//! (`pip::interp::BOOT`) or the `pip.startup` approval finding. A test fails
//! when the attempt works; the failure message carries the RP-### id used in
//! `docs/verify/REREVIEW-2026-11-09-pip.md`. All state is disposable and the
//! only network is the loopback fixture index.

mod pip_support;

use fail2commit_core::pip;
use fail2commit_core::protocol::{ApprovalRequest, Decision};
use pip_support::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};

/// Tests below touch process environment variables; run them one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn has_pip(python: &Path) -> bool {
    Command::new(python)
        .args(["-I", "-c", "import pip"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// `purelib` of the venv, relative to the venv root (e.g. `Lib/site-packages`).
fn purelib_rel(python: &Path, root: &Path) -> String {
    let out = Command::new(python)
        .args([
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ])
        .output()
        .unwrap();
    let abs = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
    abs.strip_prefix(root)
        .unwrap_or_else(|_| panic!("{} not under {}", abs.display(), root.display()))
        .to_string_lossy()
        .replace('\\', "/")
}

/// A valid wheel for `name` 1.0 plus arbitrary extra zip entries.
fn wheel_with(name: &str, extra: &[(&str, Vec<u8>)]) -> (String, Vec<u8>) {
    let dist = format!("{name}-1.0.dist-info");
    let mut files: Vec<(String, Vec<u8>)> = vec![
        (format!("{name}.py"), b"VERSION = '1.0'\n".to_vec()),
        (
            format!("{dist}/METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n").into_bytes(),
        ),
        (
            format!("{dist}/WHEEL"),
            b"Wheel-Version: 1.0\nGenerator: f2c-rereview\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                .to_vec(),
        ),
        (format!("{dist}/RECORD"), Vec::new()),
    ];
    files.extend(extra.iter().map(|(n, b)| (n.to_string(), b.clone())));
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let o = zip::write::SimpleFileOptions::default();
        for (n, b) in files {
            z.start_file(n, o).unwrap();
            z.write_all(&b).unwrap();
        }
        z.finish().unwrap();
    }
    (format!("{name}-1.0-py3-none-any.whl"), buf.into_inner())
}

struct Lab {
    env: Env,
    index: TestIndex,
    python: PathBuf,
    root: PathBuf,
    _dir: tempfile::TempDir,
}

fn lab() -> Option<Lab> {
    let env = Env::new();
    let index = TestIndex::start();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("v");
    let python = make_venv(&root);
    if !has_pip(&python) {
        eprintln!("{} has no pip; not exercised", python.display());
        return None;
    }
    Some(Lab {
        env,
        index,
        python,
        root,
        _dir: dir,
    })
}

impl Lab {
    fn publish(&self, name: &str, extra: &[(&str, Vec<u8>)]) {
        let (filename, bytes) = wheel_with(name, extra);
        self.index
            .add_raw(name, &filename, bytes.clone(), &sha256_hex(&bytes));
    }

    /// Guarded install that approves anything and records every request.
    fn install(
        &self,
        specs: &[&str],
    ) -> (
        fail2commit_core::Result<pip::InstallReport>,
        Vec<ApprovalRequest>,
    ) {
        let asked: Arc<Mutex<Vec<ApprovalRequest>>> = Arc::default();
        let a2 = asked.clone();
        let mut s = seams(&self.index);
        s.approve = Box::new(move |r| {
            a2.lock().unwrap().push(r.clone());
            Ok(Decision::ApproveOnce)
        });
        let r = pip::install(
            &self.env.ctx(),
            &self.python,
            &args(specs),
            &self.env.workdir(),
            &s,
        );
        let asked = asked.lock().unwrap().clone();
        (r, asked)
    }

    /// Start the venv python the way a user would (full `site` processing).
    fn plain_python(&self) {
        let _ = Command::new(&self.python).args(["-c", "pass"]).output();
    }

    fn marker(&self, n: &str) -> PathBuf {
        self.env.home.path().join(n)
    }
}

fn writes(marker: &Path) -> String {
    format!(
        "import pathlib; pathlib.Path({:?}).write_text('ran')",
        marker.to_string_lossy().replace('\\', "/")
    )
}

/// The startup-code finding must name every file that site would run.
fn assert_named(asked: &[ApprovalRequest], what: &str, id: &str) {
    let named = asked.iter().any(|r| {
        r.findings.iter().any(|f| f.source == "pip.startup")
            && r.details.iter().any(|d| d.starts_with("startup code:"))
    });
    assert!(
        named,
        "{id}: {what} runs at every Python start but no pip.startup finding / approval detail names it (asked {} time(s))",
        asked.len()
    );
}

// ---------------------------------------------------------------------------
// Startup-code finding completeness (CR-001: "names every import-bearing .pth
// and the customize modules")
// ---------------------------------------------------------------------------

/// Install a wheel carrying `entry` => `content`, then start python plainly.
/// If the file ran, the finding had to name it.
fn startup_variant(
    entry: impl Fn(&Lab) -> String,
    content: impl Fn(&Path) -> Vec<u8>,
    what: &str,
    id: &str,
) {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("startup-ran");
    let e = entry(&l);
    l.publish("evil", &[(e.as_str(), content(&marker))]);
    let (r, asked) = l.install(&["evil"]);
    r.expect("install of the wheel itself succeeds");
    l.plain_python();
    if !marker.exists() {
        eprintln!("{id}: {what} did not run on this interpreter; not a bypass here");
        return;
    }
    assert!(
        !asked.is_empty(),
        "{id}: {what} ran with NO approval at all"
    );
    assert_named(&asked, what, id);
}

#[test]
fn rp_pth_with_cr_line_separator_is_named() {
    startup_variant(
        |_| "evil_cr.pth".into(),
        |m| format!("# padding\rimport {}\n", &writes(m)["import ".len()..]).into_bytes(),
        ".pth whose import line follows a bare CR",
        "RP-001",
    );
}

#[test]
fn rp_pth_with_utf8_bom_is_named() {
    startup_variant(
        |_| "evil_bom.pth".into(),
        |m| {
            let mut v = vec![0xEF, 0xBB, 0xBF];
            v.extend_from_slice(format!("{}\n", writes(m)).as_bytes());
            v
        },
        ".pth with a UTF-8 BOM",
        "RP-001",
    );
}

#[test]
fn rp_pth_through_data_scheme_is_named() {
    startup_variant(
        |l| {
            format!(
                "evil-1.0.data/data/{}/evil_data.pth",
                purelib_rel(&l.python, &l.root)
            )
        },
        |m| format!("{}\n", writes(m)).into_bytes(),
        ".pth installed through the wheel's .data/data scheme",
        "RP-002",
    );
}

#[test]
fn rp_sitecustomize_through_data_scheme_is_named() {
    startup_variant(
        |l| {
            format!(
                "evil-1.0.data/data/{}/sitecustomize.py",
                purelib_rel(&l.python, &l.root)
            )
        },
        |m| format!("{}\n", writes(m)).into_bytes(),
        "sitecustomize.py installed through the wheel's .data/data scheme",
        "RP-002",
    );
}

#[test]
fn control_plain_top_level_pth_is_named() {
    // The case the fix was written for; must keep working.
    startup_variant(
        |_| "evil_plain.pth".into(),
        |m| format!("{}\n", writes(m)).into_bytes(),
        "a plain top-level .pth",
        "control",
    );
}

// ---------------------------------------------------------------------------
// Defeating the bootstrap itself: files a wheel may legitimately install that
// the next `python -I -S` run will load.
// ---------------------------------------------------------------------------

/// A wheel that overlays `pip` (or ships a `pyvenv.cfg` in the scripts dir) gets
/// its code run by the guard's own next interpreter start.
fn guard_run_executes(l: &Lab, marker: &Path) -> bool {
    // First command installs the wheel; the next guarded command starts the
    // interpreter again (probe imports `pip`). Either may fail; only the
    // marker matters.
    let a = l.install(&["evil"]).0;
    l.publish("other", &[]);
    let b = l.install(&["other"]).0;
    eprintln!(
        "diag: install evil = {:?}; install other = {:?}",
        a.map(|r| r.packages.len()).map_err(|e| e.to_string()),
        b.map(|r| r.packages.len()).map_err(|e| e.to_string())
    );
    marker.exists()
}

#[test]
fn rp_wheel_overlaying_pip_runs_code_in_the_next_guarded_start() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("pip-overlay-ran");
    let site = purelib_rel(&l.python, &l.root);
    let _ = site;
    l.publish(
        "evil",
        &[(
            "pip/__init__.py",
            format!("{}\n", writes(&marker)).into_bytes(),
        )],
    );
    assert!(
        !guard_run_executes(&l, &marker),
        "RP-003: a wheel that installs pip/__init__.py had its code executed by the guard's own interpreter, unsandboxed, with no approval naming it"
    );
}

#[test]
fn rp_scripts_dir_pyvenv_cfg_redirects_the_bootstrap_prefix() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("pyvenv-redirect-ran");
    let rel = purelib_rel(&l.python, &l.root);
    // BOOT trusts `<dir of sys.executable>/pyvenv.cfg` before the real one and
    // `.data/scripts` installs into exactly that directory.
    let pip_init = format!("evil-1.0.data/scripts/{rel}/pip/__init__.py");
    // a copy of the venv's own config, so the interpreter still starts
    let real_cfg = std::fs::read(l.root.join("pyvenv.cfg")).unwrap();
    l.publish(
        "evil",
        &[
            ("evil-1.0.data/scripts/pyvenv.cfg", real_cfg.clone()),
            (
                pip_init.as_str(),
                format!("{}\n", writes(&marker)).into_bytes(),
            ),
        ],
    );
    let ran = guard_run_executes(&l, &marker);
    let scripts = l.python.parent().unwrap();
    eprintln!(
        "diag: {}/pyvenv.cfg exists = {}, planted pip = {}",
        scripts.display(),
        scripts.join("pyvenv.cfg").exists(),
        scripts.join(&rel).join("pip/__init__.py").exists()
    );
    assert!(
        scripts.join("pyvenv.cfg").exists(),
        "fixture is vacuous: the wheel's scripts-dir pyvenv.cfg was not installed (or was refused)"
    );
    assert!(
        !ran,
        "RP-004: a wheel's .data/scripts/pyvenv.cfg moved sys.prefix for the guard's bootstrap and the guard imported the wheel's pip"
    );
}

#[test]
fn stdlib_modules_cannot_be_shadowed_from_site_packages() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("shadow-ran");
    let body = format!("{}\n", writes(&marker)).into_bytes();
    // Everything the bootstrap, the probe, the lister and pip's runner import
    // first. Appended site-packages must lose to the stdlib for all of them.
    let names = [
        "runpy.py",
        "json.py",
        "platform.py",
        "sysconfig.py",
        "site.py",
        "os.py",
        "importlib/__init__.py",
        "encodings/__init__.py",
        "sitecustomize.py",
        "usercustomize.py",
        "sys.py",
    ];
    let extra: Vec<(&str, Vec<u8>)> = names.iter().map(|n| (*n, body.clone())).collect();
    l.publish("evil", &extra);
    // also hostile environment: PYTHON* variables are ignored by -I and scrubbed
    let poison = l.env.home.path().join("poison");
    std::fs::create_dir_all(&poison).unwrap();
    std::fs::write(poison.join("json.py"), format!("{}\n", writes(&marker))).unwrap();
    std::fs::write(poison.join("startup.py"), format!("{}\n", writes(&marker))).unwrap();
    std::env::set_var("PYTHONPATH", &poison);
    std::env::set_var("PYTHONSTARTUP", poison.join("startup.py"));
    let ran = guard_run_executes(&l, &marker);
    std::env::remove_var("PYTHONPATH");
    std::env::remove_var("PYTHONSTARTUP");
    // the install itself legitimately asked for approval (startup file names)
    assert!(
        !ran,
        "stdlib shadowing or PYTHON* variables executed code inside the guard"
    );
}

#[test]
fn system_site_packages_venv_and_planted_startup_files_never_run_in_the_guard() {
    let _g = serial();
    let env = Env::new();
    let index = TestIndex::start();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("v");
    let out = Command::new(host_python())
        .args(["-m", "venv", "--system-site-packages"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(out.status.success());
    let python = if cfg!(windows) {
        root.join("Scripts/python.exe")
    } else {
        root.join("bin/python")
    };
    if !has_pip(&python) {
        return;
    }
    let cfg = std::fs::read_to_string(root.join("pyvenv.cfg")).unwrap();
    assert!(cfg
        .to_ascii_lowercase()
        .contains("include-system-site-packages = true"));
    let marker = env.home.path().join("planted-ran");
    let rel = purelib_rel(&python, &root);
    let site = root.join(&rel);
    std::fs::write(site.join("planted.pth"), format!("{}\n", writes(&marker))).unwrap();
    std::fs::write(
        site.join("sitecustomize.py"),
        format!("{}\n", writes(&marker)),
    )
    .unwrap();
    std::fs::write(
        site.join("usercustomize.py"),
        format!("{}\n", writes(&marker)),
    )
    .unwrap();
    index.add_wheel("fine", "1.0", &[]);
    let r = pip::install(
        &env.ctx(),
        &python,
        &args(&["fine"]),
        &env.workdir(),
        &seams(&index),
    )
    .expect("clean wheel installs in a system-site-packages venv");
    assert!(!r.approved);
    assert!(has(&python, "fine", "1.0"));
    assert!(
        !marker.exists(),
        "a planted startup file ran inside the guard"
    );
    // the control: plain python does run it, so the fixture is meaningful
    let _ = Command::new(&python).args(["-c", "pass"]).output();
    assert!(
        marker.exists(),
        "control: the planted .pth must run under plain python"
    );
}
