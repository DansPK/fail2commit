//! Second independent re-review of the pip guard (CR-005, RP-001..RP-008; FR-005, FR-008).
//!
//! Every test is an attempt to make the guard run code a wheel controls, or to
//! install a layout the guard says it denies. A test fails when the attempt
//! works; the failure message carries the RP2-### id used in
//! `docs/dev/verify/reviews/REREVIEW2-2026-11-09-pip.md`. State is disposable; the only
//! network is the loopback fixture index. Several tests are only meaningful on
//! Windows (name aliasing); they pass trivially elsewhere and say so.

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

fn writes(marker: &Path) -> String {
    format!(
        "import pathlib; pathlib.Path({:?}).write_text('ran')",
        marker.to_string_lossy().replace('\\', "/")
    )
}

fn dir_listing(d: &Path) -> std::collections::BTreeMap<String, String> {
    snapshot(d)
}

// ---------------------------------------------------------------------------
// RP2-001: the layout/startup checks compare literal strings; Windows resolves
// trailing dots and spaces in a path component to the same file.
// ---------------------------------------------------------------------------

/// `.data/scripts/pyvenv.cfg.` is not `pyvenv.cfg` to the guard, but on Windows
/// pip writes `Scripts\pyvenv.cfg`, which CPython 3.11+ reads before the venv's
/// own `..\pyvenv.cfg` (it picks `home`, hence the stdlib).
#[test]
fn rp2_001_scripts_pyvenv_cfg_alias_is_denied() {
    let _g = serial();
    let Some(l) = lab() else { return };
    if !cfg!(windows) {
        eprintln!("RP2-001: trailing-dot aliasing is a Windows path rule; nothing to show here");
        return;
    }
    for (i, alias) in ["pyvenv.cfg.", "pyvenv.cfg ", "PyVenv.CFG."]
        .iter()
        .enumerate()
    {
        let name = format!("alias{i}");
        let entry = format!("{name}-1.0.data/scripts/{alias}");
        l.publish(&name, &[(entry.as_str(), b"home = C:\\nowhere\n".to_vec())]);
        let (r, _) = l.install(&[name.as_str()]);
        let landed = l.scripts_dir().join("pyvenv.cfg").exists();
        assert!(
            r.is_err() && !landed,
            "RP2-001: {entry:?} was accepted and Scripts\\pyvenv.cfg exists={landed} (install: {:?})",
            r.map(|x| x.packages.len()).map_err(|e| e.to_string())
        );
    }
}

/// The same alias through the data scheme replaces the venv's own `pyvenv.cfg`
/// (`home =` picks the interpreter the Windows launcher starts and the stdlib).
#[test]
fn rp2_001_data_pyvenv_cfg_alias_does_not_replace_the_venv_cfg() {
    let _g = serial();
    let Some(l) = lab() else { return };
    if !cfg!(windows) {
        eprintln!("RP2-001: trailing-dot aliasing is a Windows path rule; nothing to show here");
        return;
    }
    let cfg = l.root.join("pyvenv.cfg");
    let before = std::fs::read(&cfg).unwrap();
    for (i, alias) in ["pyvenv.cfg.", "pyvenv.cfg "].iter().enumerate() {
        let name = format!("cfgalias{i}");
        let entry = format!("{name}-1.0.data/data/{alias}");
        l.publish(
            &name,
            &[(
                entry.as_str(),
                format!("home = {}\r\n", l.root.join("evil_std").display()).into_bytes(),
            )],
        );
        let (r, _) = l.install(&[name.as_str()]);
        let now = std::fs::read(&cfg).unwrap();
        assert!(
            r.is_err() && now == before,
            "RP2-001: {entry:?} was accepted; venv pyvenv.cfg replaced={} (install ok={})",
            now != before,
            r.is_ok()
        );
    }
}

/// `.pth.`/`.pth ` is not `.pth` to `wheel::scan`, but Windows creates `x.pth`.
#[test]
fn rp2_001_pth_alias_is_named_as_startup_code() {
    let _g = serial();
    let Some(l) = lab() else { return };
    if !cfg!(windows) {
        eprintln!("RP2-001: Windows-only aliasing");
        return;
    }
    let marker = l.marker("alias-pth-ran");
    // CR-001: a startup hook that was named in the approval and then approved
    // may run; only an alias that slips in unnamed is a bypass.
    let mut approved_named = false;
    for (i, alias) in ["alias_a.pth.", "alias_b.pth ", "alias_c.pth::$DATA"]
        .iter()
        .enumerate()
    {
        let name = format!("pthalias{i}");
        l.publish(
            &name,
            &[(*alias, format!("{}\n", writes(&marker)).into_bytes())],
        );
        let (r, asked) = l.install(&[name.as_str()]);
        if r.is_err() {
            continue; // refused outright is fine
        }
        let named = asked
            .iter()
            .any(|a| a.findings.iter().any(|f| f.source == "pip.startup"));
        let ran_file = std::fs::read_dir(l.site()).unwrap().flatten().any(|e| {
            e.file_name().to_string_lossy().ends_with(".pth")
                && e.file_name().to_string_lossy().starts_with("alias_")
        });
        assert!(
            named || !ran_file,
            "RP2-001: {alias:?} became a *.pth in site-packages with no pip.startup finding"
        );
        approved_named |= named;
    }
    l.plain_python();
    assert!(
        approved_named || !marker.exists(),
        "RP2-001: an alias .pth ran at the next Python start without being named in the approval"
    );
}

/// `.data/data/Lib./site-packages/x.pth`: DATA_RESERVED compares `lib.` literally.
#[test]
fn rp2_001_data_scheme_reserved_dir_alias_is_denied() {
    let _g = serial();
    let Some(l) = lab() else { return };
    if !cfg!(windows) {
        eprintln!("RP2-001: Windows-only aliasing");
        return;
    }
    let marker = l.marker("alias-data-ran");
    l.publish(
        "dataalias",
        &[(
            "dataalias-1.0.data/data/Lib./site-packages/dataalias_x.pth",
            format!("{}\n", writes(&marker)).into_bytes(),
        )],
    );
    let (r, _asked) = l.install(&["dataalias"]);
    let landed = l.site().join("dataalias_x.pth").exists();
    l.plain_python();
    assert!(
        r.is_err() && !landed && !marker.exists(),
        "RP2-001: data/Lib./site-packages/x.pth was accepted (landed={landed}, ran={}, install ok={})",
        marker.exists(),
        r.is_ok()
    );
}

// ---------------------------------------------------------------------------
// RP2-002: console scripts come from entry_points.txt, not only from
// `.data/scripts`; nothing inspects them.
// ---------------------------------------------------------------------------

#[test]
fn rp2_002_entry_point_console_scripts_cannot_replace_python_or_pip() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let scripts = l.scripts_dir();
    let before = dir_listing(&scripts);
    let interp_stem = l
        .python
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .to_ascii_lowercase();
    let mut names = vec!["pip", "pip3", "python", "python3", "activate", "pyvenv.cfg"];
    names.push(Box::leak(interp_stem.into_boxed_str()));
    let mut hit: Vec<String> = Vec::new();
    for (i, n) in names.iter().enumerate() {
        let pkg = format!("ep{i}");
        let ep = format!("[console_scripts]\n{n} = {pkg}:main\n");
        let dist_ep = format!("{pkg}-1.0.dist-info/entry_points.txt");
        l.publish(&pkg, &[(dist_ep.as_str(), ep.into_bytes())]);
        let (r, _) = l.install(&[pkg.as_str()]);
        let after = dir_listing(&scripts);
        let changed: Vec<&String> = after
            .iter()
            .filter(|(k, v)| {
                let kl = k.to_ascii_lowercase();
                let stem = kl.split('.').next().unwrap_or("");
                let reserved = stem == n.to_ascii_lowercase().split('.').next().unwrap_or("")
                    || kl.starts_with(&n.to_ascii_lowercase());
                reserved && before.get(*k) != Some(*v)
            })
            .map(|(k, _)| k)
            .collect();
        if r.is_ok() && !changed.is_empty() {
            hit.push(format!("{n} -> {changed:?}"));
        }
    }
    assert!(
        hit.is_empty(),
        "RP2-002: entry_points.txt console scripts replaced reserved files with no layout deny: {hit:?}"
    );
}

// ---------------------------------------------------------------------------
// RP2-003: .pth differential. One wheel, many .pth files; every one that
// CPython's site.addsitedir executes must have been named by a pip.startup
// finding.
// ---------------------------------------------------------------------------

fn pth_corpus(marker_of: &dyn Fn(&str) -> PathBuf) -> Vec<(String, Vec<u8>)> {
    let line = |id: &str| writes(&marker_of(id));
    let mk = |id: &str, pre: &[u8], sep: &[u8], post: &[u8]| -> (String, Vec<u8>) {
        let mut v = pre.to_vec();
        v.extend_from_slice(sep);
        v.extend_from_slice(line(id).as_bytes());
        v.extend_from_slice(post);
        (format!("c_{id}.pth"), v)
    };
    vec![
        mk("plain", b"", b"", b"\n"),
        mk("cr", b"# pad", b"\r", b"\n"),
        mk("crlf", b"/d", b"\r\n", b"\n"),
        mk("bom", b"\xef\xbb\xbf", b"", b"\n"),
        mk("bom_cmt", b"\xef\xbb\xbf# x", b"\n", b"\n"),
        mk("nel", b"# pad", "\u{85}".as_bytes(), b"\n"),
        mk("vt", b"# pad", b"\x0b", b"\n"),
        mk("ff", b"# pad", b"\x0c", b"\n"),
        mk("fs", b"# pad", b"\x1c", b"\n"),
        mk("gs", b"# pad", b"\x1d", b"\n"),
        mk("rs", b"# pad", b"\x1e", b"\n"),
        mk("ls", b"# pad", "\u{2028}".as_bytes(), b"\n"),
        mk("ps", b"# pad", "\u{2029}".as_bytes(), b"\n"),
        mk("nul_prefix", b"\x00", b"", b"\n"),
        mk("latin1_pad", b"\xe9\n", b"", b"\n"),
        mk("no_trailing_nl", b"", b"", b""),
        mk("tab_form", b"", b"", b"\n").clone(),
        ("c_utf16.pth".into(), {
            let mut v = vec![0xff, 0xfe];
            for u in format!("{}\n", line("utf16")).encode_utf16() {
                v.extend_from_slice(&u.to_le_bytes());
            }
            v
        }),
        (
            "c_comment_only.pth".into(),
            b"# import os\n/some/dir\n".to_vec(),
        ),
        (
            "c_space_lead.pth".into(),
            format!(" {}\n", line("space_lead")).into_bytes(),
        ),
    ]
}

#[test]
fn rp2_003_every_pth_cpython_executes_is_named_at_install() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker_of = |id: &str| l.marker(&format!("pth-{id}"));
    let corpus = pth_corpus(&marker_of);
    let extra: Vec<(&str, Vec<u8>)> = corpus
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    l.publish("pthcorpus", &extra);
    let (r, asked) = l.install(&["pthcorpus"]);
    r.expect("the corpus wheel installs (approvals are auto-granted)");
    // what the guard told the user it would run
    let named: Vec<String> = asked
        .iter()
        .flat_map(|a| a.findings.iter())
        .filter(|f| f.source == "pip.startup")
        .filter_map(|f| f.location.clone())
        .collect();
    l.plain_python();
    let mut unnamed = Vec::new();
    for (n, _) in &corpus {
        let id = n.trim_start_matches("c_").trim_end_matches(".pth");
        if marker_of(id).exists() && !named.iter().any(|x| x == n) {
            unnamed.push(n.clone());
        }
    }
    assert!(
        unnamed.is_empty(),
        "RP2-003: .pth files CPython ran at the next start but no pip.startup finding named: {unnamed:?} (named: {named:?})"
    );
}

// ---------------------------------------------------------------------------
// RP2-004: nothing planted in the environment is importable by the guard.
// ---------------------------------------------------------------------------

#[test]
fn rp2_004_planted_modules_never_import_during_any_guarded_command() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("planted-ran");
    l.index.add_wheel("first", "1.0", &[]);
    l.index.add_wheel("second", "1.0", &[]);
    l.install(&["first"]).0.expect("first");
    let site = l.site();
    let code = format!("{}\n", writes(&marker));
    // top-level names pip or its vendored libraries try to import optionally,
    // stdlib names, pth/customize hooks, and the distutils/setuptools hacks
    let names = [
        "keyring",
        "brotli",
        "brotlicffi",
        "zstandard",
        "truststore",
        "socks",
        "OpenSSL",
        "cryptography",
        "idna",
        "chardet",
        "charset_normalizer",
        "certifi",
        "colorama",
        "typing_extensions",
        "tomli",
        "pkg_resources",
        "setuptools",
        "distutils",
        "_distutils_hack",
        "wheel",
        "sitecustomize",
        "usercustomize",
        "readline",
        "_ctypes_test",
        "six",
        "simplejson",
        "ujson",
        "orjson",
        "yaml",
        "lxml",
        "_cffi_backend",
        "certifi_win32",
        "pip_system_certs",
        "win_inet_pton",
        "ntlm",
        "requests_kerberos",
        "dummy_threading",
        "zoneinfo",
        "tzdata",
        "pytz",
        "rich",
        "pygments",
        "webencodings",
        "msgpack",
        "cachecontrol",
        "pyproject_hooks",
        "distro",
        "platformdirs",
        "tenacity",
        "resolvelib",
        "packaging",
        "ssl",
        "_ssl",
        "json",
        "encodings",
        "site",
        "os",
        "abc",
        "codecs",
        "io",
        "enum",
        "typing",
        "runpy",
        "sysconfig",
        "platform",
        "importlib",
        "zipfile",
        "email",
        "ctypes",
        "locale",
        "_bootlocale",
        "pathlib",
        "tempfile",
        "shutil",
        "subprocess",
        "logging",
        "_sysconfigdata",
    ];
    for n in names {
        std::fs::write(site.join(format!("{n}.py")), &code).unwrap();
        let d = site.join(format!("{n}_pkg_{}", n.len()));
        let _ = d; // single-file shadows are enough; packages below for the dangerous ones
    }
    for n in [
        "pkg_resources",
        "setuptools",
        "distutils",
        "keyring",
        "wheel",
        "certifi",
    ] {
        let d = site.join(n);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("__init__.py"), &code).unwrap();
    }
    std::fs::write(
        site.join("zz-planted.pth"),
        format!("{}\n", writes(&marker)),
    )
    .unwrap();
    // a metadata directory that names an entry point and a "pip" of its own
    let di = site.join("pip-99.0.dist-info");
    std::fs::create_dir_all(&di).unwrap();
    std::fs::write(
        di.join("METADATA"),
        "Metadata-Version: 2.1\nName: pip\nVersion: 99.0\n",
    )
    .unwrap();
    std::fs::write(
        di.join("entry_points.txt"),
        "[console_scripts]\npip = keyring:main\n",
    )
    .unwrap();
    let (r, _) = l.install(&["second"]);
    r.expect("install still works from the snapshot");
    // every pass-through command and a dry resolution as well
    let mut s = seams(&l.index);
    s.approve = Box::new(|_| Ok(Decision::ApproveOnce));
    for cmd in [
        &["list"][..],
        &["list", "--format=json"],
        &["show", "first"],
        &["freeze"],
        &["check"],
        &["inspect"],
        &["debug"],
        &["help"],
        &["--version"],
    ] {
        let a = args(cmd);
        let _ = pip::passthrough(&l.env.ctx(), &l.python, &a, true);
    }
    let _ = pip::passthrough(
        &l.env.ctx(),
        &l.python,
        &args(&["uninstall", "-y", "second"]),
        true,
    );
    assert!(
        !marker.exists(),
        "RP2-004: module planted in the environment ran inside the guard"
    );
}

// ---------------------------------------------------------------------------
// RP2-005: the snapshot manifest lives next to the snapshot it protects.
// This documents a residual (same principal can rewrite both); ignored by
// default because no in-process fix exists.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "documents the same-principal residual RP2-005; run with --ignored"]
fn rp2_005_consistently_rewritten_snapshot_and_manifest_run() {
    let _g = serial();
    let Some(l) = lab() else { return };
    let marker = l.marker("snapshot-rewritten-ran");
    l.index.add_wheel("first", "1.0", &[]);
    l.index.add_wheel("second", "1.0", &[]);
    l.install(&["first"]).0.expect("first install");
    let root = l.env.paths.cache_dir.join("pip").join("guard");
    let snap = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.join("manifest.json").is_file())
        .unwrap();
    let init = snap.join("site").join("pip").join("__init__.py");
    let old = std::fs::read_to_string(&init).unwrap();
    std::fs::write(&init, format!("{}\n{old}", writes(&marker))).unwrap();
    let mf = snap.join("manifest.json");
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&mf).unwrap()).unwrap();
    m["files"]["pip/__init__.py"] =
        serde_json::Value::String(sha256_hex(&std::fs::read(&init).unwrap()));
    std::fs::write(&mf, serde_json::to_vec(&m).unwrap()).unwrap();
    let _ = l.install(&["second"]);
    assert!(
        !marker.exists(),
        "RP2-005: a snapshot plus manifest rewritten together ran unverified"
    );
}

// ---------------------------------------------------------------------------
// RP2-006: permissions of what the guard trusts.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn rp2_006_snapshot_tree_is_not_writable_by_group_or_other() {
    use std::os::unix::fs::PermissionsExt;
    let _g = serial();
    let Some(l) = lab() else { return };
    l.index.add_wheel("first", "1.0", &[]);
    l.install(&["first"]).0.expect("first");
    let root = l.env.paths.cache_dir.join("pip").join("guard");
    let mut bad = Vec::new();
    fn walk(p: &Path, bad: &mut Vec<String>) {
        let m = std::fs::symlink_metadata(p).unwrap();
        if m.permissions().mode() & 0o022 != 0 {
            bad.push(format!(
                "{} {:o}",
                p.display(),
                m.permissions().mode() & 0o7777
            ));
        }
        if m.is_dir() {
            for e in std::fs::read_dir(p).unwrap().flatten() {
                walk(&e.path(), bad);
            }
        }
    }
    walk(&root, &mut bad);
    let top = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
    eprintln!("guard root mode {top:o}");
    assert!(bad.is_empty(), "RP2-006: group/other-writable: {bad:?}");
    assert_eq!(top & 0o077, 0, "guard root must be owner-only, was {top:o}");
}
