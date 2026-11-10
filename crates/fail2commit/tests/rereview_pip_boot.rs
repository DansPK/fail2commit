//! Independent re-review of the W2-001 / CR-001 fix (FR-005, FR-008).
//!
//! Every test here is an attempt to defeat the `-I -S` bootstrap
//! (`pip::interp::BOOT`) or the `pip.startup` approval finding. A test fails
//! when the attempt works; the failure message carries the RP-### id used in
//! `docs/verify/reviews/REREVIEW-2026-11-09-pip.md`. All state is disposable and the
//! only network is the loopback fixture index.
//!
//! Fixed (FR-005): these are now regression tests that assert the secure
//! outcome. RP-001 wheels are approved with the file named; RP-002/003/004
//! wheels are refused with a hard `pip.layout` deny; the guard runs pip from a
//! hash-verified snapshot and never imports anything from the environment.

mod pip_support;

use fail2commit_core::pip;
use fail2commit_core::protocol::{ApprovalRequest, Decision};
use fail2commit_core::{FindingAction, FindingKind, ResultCode};
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

/// The install must be refused with a hard `pip.layout` deny that nobody is
/// asked to approve, and the venv must be byte-identical afterwards.
fn assert_layout_denied(l: &Lab, specs: &[&str], id: &str, what: &str) -> fail2commit_core::Error {
    let before = snapshot(&l.root);
    let (r, asked) = l.install(specs);
    let e = r.expect_err(&format!("{id}: {what} was installed"));
    assert_eq!(e.code, ResultCode::InvalidInput, "{id}: {e}");
    assert!(
        e.findings.iter().any(|f| f.source == "pip.layout"
            && f.kind == FindingKind::UnsupportedInput
            && f.action == FindingAction::Deny),
        "{id}: {what}: no pip.layout deny finding: {e} / {:?}",
        e.findings
    );
    assert!(asked.is_empty(), "{id}: a hard deny must not be approvable");
    assert_eq!(snapshot(&l.root), before, "{id}: the venv changed");
    assert!(!l.env.journal_exists(), "{id}: a journal was written");
    e
}

#[test]
fn rp_pth_through_data_scheme_is_denied() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("startup-ran");
    let entry = format!(
        "evil-1.0.data/data/{}/evil_data.pth",
        purelib_rel(&l.python, &l.root)
    );
    l.publish(
        "evil",
        &[(
            entry.as_str(),
            format!("{}\n", writes(&marker)).into_bytes(),
        )],
    );
    assert_layout_denied(&l, &["evil"], "RP-002", ".pth through .data/data");
    l.plain_python();
    assert!(!marker.exists());
}

#[test]
fn rp_sitecustomize_through_data_scheme_is_denied() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("startup-ran");
    let rel = purelib_rel(&l.python, &l.root);
    // both into the site directory and into an otherwise allowed data folder
    for (i, entry) in [
        format!("evil-1.0.data/data/{rel}/sitecustomize.py"),
        "evil-1.0.data/data/share/usercustomize.py".to_string(),
        "evil-1.0.data/data/share/x.pth".to_string(),
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("evil{i}");
        l.publish(
            &name,
            &[(
                entry.as_str(),
                format!("{}\n", writes(&marker)).into_bytes(),
            )],
        );
        assert_layout_denied(&l, &[name.as_str()], "RP-002", &entry);
    }
    l.plain_python();
    assert!(!marker.exists());
}

/// Control: data-scheme files outside the interpreter layout still install.
#[test]
fn control_ordinary_data_scheme_file_still_installs() {
    let _g = serial();
    let Some(l) = lab() else { return };
    l.publish(
        "evil",
        &[("evil-1.0.data/data/share/f2c/readme.txt", b"hello".to_vec())],
    );
    let (r, asked) = l.install(&["evil"]);
    r.expect("an ordinary data file is allowed");
    assert!(asked.is_empty());
    assert_eq!(
        std::fs::read(l.root.join("share/f2c/readme.txt")).unwrap(),
        b"hello"
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
fn rp_wheel_overlaying_pip_is_denied_and_runs_nothing() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("pip-overlay-ran");
    let site = purelib_rel(&l.python, &l.root);
    // every way a wheel can put a file into pip's tree or its metadata
    for (i, entry) in [
        "pip/__init__.py".to_string(),
        "pip/_internal/cli/main.py".to_string(),
        "evil-1.0.data/purelib/pip/__init__.py".to_string(),
        "evil-1.0.data/platlib/pip/__main__.py".to_string(),
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("evil{i}");
        l.publish(
            &name,
            &[(
                entry.as_str(),
                format!("{}\n", writes(&marker)).into_bytes(),
            )],
        );
        assert_layout_denied(&l, &[name.as_str()], "RP-003", &entry);
    }
    let _ = site;
    l.publish(
        "evil",
        &[(
            "pip/__init__.py",
            format!("{}\n", writes(&marker)).into_bytes(),
        )],
    );
    // the next guarded commands still run, and nothing of the wheel ran
    assert!(
        !guard_run_executes(&l, &marker),
        "RP-003: a wheel that installs pip/__init__.py had its code executed by the guard's own interpreter"
    );
}

#[test]
fn upgrading_pip_through_the_guard_is_denied_and_says_so() {
    let _g = serial();
    let Some(l) = lab() else { return };
    l.publish(
        "pip",
        &[("pip/__init__.py", b"__version__ = '1.0'\n".to_vec())],
    );
    let e = assert_layout_denied(&l, &["pip==1.0"], "RP-003", "a wheel for pip itself");
    assert!(
        e.findings.iter().any(|f| f
            .evidence
            .contains("upgrading pip through fail2commit is not supported")),
        "{:?}",
        e.findings
    );
}

/// The core of RP-003: the guard's pip is its private snapshot. Planting code in
/// the environment's own pip, or in modules pip might optionally import
/// (`keyring`, `brotli`, ...), changes nothing the guard runs.
#[test]
fn rp_guard_runs_pip_from_its_snapshot_not_from_the_environment() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("env-code-ran");
    l.index.add_wheel("first", "1.0", &[]);
    l.index.add_wheel("second", "1.0", &[]);
    l.install(&["first"]).0.expect("first install");
    // out of band, after the snapshot exists: overwrite the environment's pip
    // and plant optional-import modules
    let site = l.root.join(purelib_rel(&l.python, &l.root));
    let code = format!("{}\n", writes(&marker));
    for rel in [
        "pip/__init__.py",
        "pip/__main__.py",
        "pip/_internal/cli/main.py",
    ] {
        let p = site.join(rel);
        let old = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, format!("{code}{old}")).unwrap();
    }
    for module in ["keyring.py", "brotli.py", "truststore.py", "socks.py"] {
        std::fs::write(site.join(module), &code).unwrap();
    }
    let (r, _) = l.install(&["second"]);
    r.expect("the guard still installs, from its own pip");
    assert!(has(&l.python, "second", "1.0"));
    assert!(
        !marker.exists(),
        "RP-003: code planted in the environment ran inside the guard"
    );
}

/// The snapshot is private and checked before every launch.
#[test]
fn rp_tampered_snapshot_is_an_integrity_failure_and_nothing_runs() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("snapshot-code-ran");
    l.index.add_wheel("first", "1.0", &[]);
    l.index.add_wheel("second", "1.0", &[]);
    l.install(&["first"]).0.expect("first install");
    let guard_root = l.env.paths.cache_dir.join("pip").join("guard");
    let snap = std::fs::read_dir(&guard_root)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.join("manifest.json").is_file())
        .expect("a snapshot under cache_dir/pip/guard");
    assert!(snap.join("site").join("pip").join("__init__.py").is_file());
    let init = snap.join("site").join("pip").join("__init__.py");
    let old = std::fs::read_to_string(&init).unwrap();
    std::fs::write(&init, format!("{}\n{old}", writes(&marker))).unwrap();
    let before = snapshot(&l.root);
    let (r, asked) = l.install(&["second"]);
    let e = r.expect_err("a changed snapshot must stop the command");
    assert_eq!(e.code, ResultCode::IntegrityFailure, "{e}");
    assert!(asked.is_empty());
    assert!(!marker.exists(), "the tampered snapshot was executed");
    assert_eq!(snapshot(&l.root), before);
    // an added or removed file is caught as well
    std::fs::write(&init, old).unwrap();
    std::fs::write(snap.join("site").join("pip").join("extra.py"), "x = 1\n").unwrap();
    let e = l.install(&["second"]).0.expect_err("added file");
    assert_eq!(e.code, ResultCode::IntegrityFailure, "{e}");
    std::fs::remove_file(snap.join("site").join("pip").join("extra.py")).unwrap();
    l.install(&["second"]).0.expect("intact again");
}

/// pip must still see what is installed, even though it cannot import from the
/// environment: already-satisfied requirements are a no-op and an upgrade
/// replaces the old version instead of leaving it behind.
#[test]
fn guard_pip_still_sees_installed_distributions() {
    let _g = serial();
    let Some(l) = lab() else { return };
    l.index.add_wheel("alpha", "1.0", &[]);
    l.install(&["alpha"]).0.expect("install");
    let (again, _) = l.install(&["alpha"]);
    assert!(again.unwrap().packages.is_empty(), "already satisfied");
    l.index.add_wheel("alpha", "1.1", &[]);
    l.install(&["alpha", "--upgrade"]).0.expect("upgrade");
    assert!(has(&l.python, "alpha", "1.1"));
    assert!(!has(&l.python, "alpha", "1.0"), "old version left behind");
}

#[test]
fn rp_scripts_dir_pyvenv_cfg_and_interpreter_names_are_denied() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("pyvenv-redirect-ran");
    let rel = purelib_rel(&l.python, &l.root);
    let real_cfg = std::fs::read(l.root.join("pyvenv.cfg")).unwrap();
    // the exact RP-004 reproduction, now refused
    let pip_init = format!("evil-1.0.data/scripts/{rel}/pip/__init__.py");
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
    assert_layout_denied(&l, &["evil"], "RP-004", "scripts/pyvenv.cfg");
    let scripts = l.python.parent().unwrap();
    assert_eq!(
        std::fs::read(l.root.join("pyvenv.cfg")).unwrap(),
        real_cfg,
        "venv config untouched"
    );
    assert!(!scripts.join("pyvenv.cfg").exists());
    assert!(!guard_run_executes(&l, &marker));
    // each way to replace the interpreter or its pip launcher, and each data root
    let exe = l.python.file_name().unwrap().to_string_lossy().into_owned();
    for (i, entry) in [
        format!("evil-1.0.data/scripts/{exe}"),
        "evil-1.0.data/scripts/python3".to_string(),
        "evil-1.0.data/scripts/pip".to_string(),
        "evil-1.0.data/scripts/pip3.exe".to_string(),
        "evil-1.0.data/scripts/nested/tool".to_string(),
        "evil-1.0.data/data/pyvenv.cfg".to_string(),
        "evil-1.0.data/data/Lib/site-packages/x.py".to_string(),
        "evil-1.0.data/data/lib/python3.12/site-packages/x.py".to_string(),
        "evil-1.0.data/data/lib64/x".to_string(),
        "evil-1.0.data/data/include/x.h".to_string(),
        "evil-1.0.data/data/bin/python".to_string(),
        "evil-1.0.data/data/Scripts/python.exe".to_string(),
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("tool{i}");
        l.publish(&name, &[(entry.as_str(), b"x".to_vec())]);
        assert_layout_denied(&l, &[name.as_str()], "RP-004", &entry);
    }
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
