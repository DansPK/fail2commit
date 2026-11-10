//! Independent review of the coordinator's fixes 8773c1b (relay), a8a0cc3 and
//! 5ea0dd1 (pip layout denial). Every test fails when the attempt works; the
//! failure message carries the CF-### id used in
//! `docs/verify/reviews/REVIEW-2026-11-09-coordinator-fixes.md`. Disposable venvs, the
//! loopback fixture index only. Product code is not modified.

// The lab helpers mirror rereview2_pip.rs; not every one is used here.
#![allow(dead_code)]

mod pip_support;

use fail2commit_core::pip;
use fail2commit_core::protocol::{ApprovalRequest, Decision};
use pip_support::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};

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
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

fn wheel_with(name: &str, extra: &[(&str, Vec<u8>)]) -> (String, Vec<u8>) {
    let dist = format!("{name}-1.0.dist-info");
    let mut files: Vec<(String, Vec<u8>)> = vec![
        (format!("{name}.py"), b"VERSION = '1.0'\ndef main():\n    pass\n".to_vec()),
        (
            format!("{dist}/METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n").into_bytes(),
        ),
        (
            format!("{dist}/WHEEL"),
            b"Wheel-Version: 1.0\nGenerator: f2c-rereview2\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
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

    fn plain_python(&self) {
        let _ = Command::new(&self.python).args(["-c", "pass"]).output();
    }

    fn scripts_dir(&self) -> PathBuf {
        self.python.parent().unwrap().to_path_buf()
    }

    fn marker(&self, n: &str) -> PathBuf {
        self.env.home.path().join(n)
    }

    fn site(&self) -> PathBuf {
        self.root.join(purelib_rel(&self.python, &self.root))
    }
}

fn dir_listing(d: &Path) -> std::collections::BTreeMap<String, String> {
    snapshot(d)
}

/// Install one wheel whose only extra file is an `entry_points.txt` with `text`.
/// Returns whether the install was refused and which launcher files in
/// `Scripts`/`bin` changed or appeared.
fn install_entry_points(l: &Lab, pkg: &str, text: &str) -> (bool, Vec<String>) {
    let before = dir_listing(&l.scripts_dir());
    let dist_ep = format!("{pkg}-1.0.dist-info/entry_points.txt");
    l.publish(pkg, &[(dist_ep.as_str(), text.as_bytes().to_vec())]);
    let (r, _) = l.install(&[pkg]);
    let after = dir_listing(&l.scripts_dir());
    let changed = after
        .iter()
        .filter(|(k, v)| before.get(*k) != Some(*v))
        .map(|(k, _)| k.clone())
        .collect();
    (r.is_err(), changed)
}

fn pip_changed(changed: &[String]) -> Vec<&String> {
    changed
        .iter()
        .filter(|k| k.to_ascii_lowercase().starts_with("pip"))
        .collect()
}

/// CF-001: `console_script_names` splits with Rust `str::lines` (LF, CRLF);
/// `importlib.metadata` (pip's backend on 3.11+) and `pkg_resources` split with
/// `str.splitlines` (CR, FF, VT, FS/GS/RS, NEL, LS, PS too), and treat a line
/// that starts with `[` but does not end with `]` as an ordinary key/value line.
#[test]
fn cf_001_entry_points_text_that_python_splits_differently_replaces_pip() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let variants: [(&str, &str); 5] = [
        ("cr", "[console_scripts]\rpip = {p}:main\n"),
        ("ls", "[console_scripts]\u{2028}pip = {p}:main\n"),
        ("ff", "[console_scripts]\x0cpip = {p}:main\n"),
        ("comment-cr", "# note\r[console_scripts]\rpip = {p}:main\n"),
        (
            "bracket-line",
            "[console_scripts]\n[a = b\npip = {p}:main\n",
        ),
    ];
    let mut hit = Vec::new();
    for (i, (label, text)) in variants.iter().enumerate() {
        let pkg = format!("cfsep{i}");
        let (refused, changed) = install_entry_points(&l, &pkg, &text.replace("{p}", &pkg));
        if !refused && !pip_changed(&changed).is_empty() {
            hit.push(format!("{label}: {:?}", pip_changed(&changed)));
        }
    }
    assert!(
        hit.is_empty(),
        "CF-001: entry_points.txt spellings the guard does not parse replaced the venv's pip launchers: {hit:?}"
    );
}

/// CF-002: an entry-point name is not a file name. pip/distlib joins it onto the
/// scripts directory, so `../x` writes outside `Scripts`/`bin` (here: the venv
/// root, where `pyvenv.cfg` lives). `bad_script` sees `../x`, whose first
/// `.`-separated piece is empty, and allows it.
#[test]
fn cf_002_entry_point_name_with_separators_escapes_the_scripts_directory() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let (refused, _) = install_entry_points(
        &l,
        "cfescape",
        "[console_scripts]\n../escaped-by-ep = cfescape:main\n",
    );
    let escaped: Vec<String> = std::fs::read_dir(&l.root)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("escaped-by-ep"))
        .collect();
    assert!(
        refused || escaped.is_empty(),
        "CF-002: the install was accepted and wrote outside the scripts directory: {escaped:?}"
    );
}

/// CF-003 (Windows, 8.3 names enabled on the volume): `pip3.12.exe` is not an
/// 8.3 name, so NTFS also knows it as `PIP312~1.EXE`. `bad_script` folds case
/// and dots only; `pip312~1` is neither `pip` nor `pip<digits>`.
#[test]
fn cf_003_short_name_of_the_versioned_pip_launcher_replaces_it() {
    let _g = serial();
    let Some(l) = lab() else { return };
    if !cfg!(windows) {
        eprintln!("CF-003: 8.3 aliases are an NTFS rule; nothing to show here");
        return;
    }
    let scripts = l.scripts_dir();
    let long = std::fs::read_dir(&scripts)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| {
            let b = n.to_ascii_lowercase();
            b.starts_with("pip3.") && b.ends_with(".exe")
        });
    let Some(long) = long else {
        eprintln!(
            "CF-003: no pip3.N.exe in {}; not exercised",
            scripts.display()
        );
        return;
    };
    let stem = long
        .trim_end_matches(".exe")
        .replace('.', "")
        .to_ascii_uppercase();
    let short = format!("{}~1.EXE", &stem[..6.min(stem.len())]);
    let before = std::fs::read(scripts.join(&long)).unwrap();
    let entry = format!("cfshort-1.0.data/scripts/{short}");
    l.publish("cfshort", &[(entry.as_str(), b"REPLACED-VIA-8.3".to_vec())]);
    let (r, _) = l.install(&["cfshort"]);
    let after = std::fs::read(scripts.join(&long)).unwrap();
    assert!(
        r.is_err() || after == before,
        "CF-003: {entry:?} was accepted and {long} now holds {:?} (install: {:?})",
        String::from_utf8_lossy(&after[..after.len().min(32)]),
        r.map(|x| x.packages.len()).map_err(|e| e.to_string())
    );
}
