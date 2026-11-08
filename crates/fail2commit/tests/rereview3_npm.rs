//! Third re-review of the npm guard after CR-008 (review the tree npm extracts)
//! (FR-004, FR-006). Offline fixtures only; real npm 12.2.0 extracts every
//! fixture. Every test asserts the *safe* behaviour. `control_*` tests pin
//! behaviour that already holds; `rn3_*` tests are reproductions that fail
//! until the finding is fixed. See docs/verify/REREVIEW3-2026-11-09-npm.md.

mod npm_support;

use base64::Engine;
use fail2commit_core::npm;
use fail2commit_core::protocol::{Finding, FindingAction, FindingKind};
use fail2commit_core::scan::inspect_scripts;
use npm_support::*;
use sha2::Digest;
use std::io::Write;
use std::sync::{Arc, Mutex};

const HOSTILE: &str = "#!/bin/sh\ngit push --force origin main\n";
const HOSTILE_BAT: &str = "@echo off\r\ngit push --force origin main\r\n";

fn sri(b: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(b))
    )
}

/// `(path, bytes, unix mode)`; paths are written verbatim.
fn tar_gz(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (path, data, mode) in entries {
        let mut h = tar::Header::new_gnu();
        let n = path.as_bytes();
        h.as_old_mut().name[..n.len()].copy_from_slice(n);
        h.set_size(data.len() as u64);
        h.set_mode(*mode);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append(&h, *data).unwrap();
    }
    let raw = b.into_inner().unwrap();
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(&raw).unwrap();
    e.finish().unwrap()
}

fn manifest(scripts: &str) -> Vec<u8> {
    format!(r#"{{"name":"scripty","version":"1.0.0","scripts":{{{scripts}}}}}"#).into_bytes()
}

/// Staged project dir while the review runs (npm extracted it there).
fn staged_root(cache: &std::path::Path) -> std::path::PathBuf {
    for d in std::fs::read_dir(cache.join("npm-staging"))
        .unwrap()
        .flatten()
    {
        let p = d.path().join("proj");
        if p.join("node_modules").is_dir() {
            return p;
        }
    }
    panic!("no staged tree");
}

struct Outcome {
    result: Result<(), String>,
    /// Every referenced file the inspector was shown.
    seen: Vec<(String, Vec<u8>)>,
    env: Env,
    jobs: Vec<fail2commit_core::isolation::JobSpec>,
    digests: Vec<String>,
    data: serde_json::Value,
}

type Seen = Vec<(String, Vec<u8>)>;
type Hook = Box<dyn Fn(&std::path::Path) + Send + Sync>;

/// One-package `npm ci` against a registry that serves `bytes`.
/// `approve_hook` runs inside the approval call (after the review, before
/// anything runs); the inspector raises one Approve finding when
/// `want_approval` so that an approval happens.
fn run(bytes: Vec<u8>, execute: bool, want_approval: bool, approve_hook: Option<Hook>) -> Outcome {
    require_node();
    let reg = Registry::start();
    let pkg = Pkg::new("scripty", "1.0.0");
    let url = reg.url.clone();
    reg.publish_bytes(&pkg, &url, &bytes, &bytes);
    let pjson = r#"{"name":"clean-app","version":"1.0.0","private":true,"dependencies":{"scripty":"^1.0.0"}}"#;
    let env = Env::new(&reg, pjson);
    let lock = reg
        .lockfile(&["scripty"], &[&pkg])
        .replace(&sri(&pkg.tarball()), &sri(&bytes));
    std::fs::write(env.project.join("package-lock.json"), lock).unwrap();
    let backend = FakeBackend::new(true, execute);
    let rn = Run::new(&env, &backend);
    let seen: Arc<Mutex<Seen>> = Default::default();
    let log = seen.clone();
    let cache = env.paths.cache_dir.clone();
    let b = Behavior {
        inspect: Box::new(move |id, scripts, files| {
            log.lock()
                .unwrap()
                .extend(files.iter().map(|f| (f.path.clone(), f.bytes.clone())));
            let mut f = inspect_scripts(id, scripts, files);
            if want_approval {
                f.push(Finding::new(
                    FindingKind::IncompleteScan,
                    FindingAction::Approve,
                    "test",
                    "force an approval",
                ));
            }
            f
        }),
        on_approval: Box::new(move |_| {
            if let Some(h) = &approve_hook {
                h(&staged_root(&cache));
            }
        }),
        ..Default::default()
    };
    let mut data = serde_json::Value::Null;
    let result = match npm::execute(&rn.deps(b), &env.request(&["ci"])) {
        Ok(o) => {
            data = o.data;
            Ok(())
        }
        Err(e) => Err(format!(
            "{} {:?}",
            e.message,
            e.findings
                .iter()
                .map(|f| f.evidence.clone())
                .collect::<Vec<_>>()
        )),
    };
    let seen = seen.lock().unwrap().clone();
    let digests = rn
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.digest.clone())
        .collect();
    let jobs = backend.jobs();
    drop(rn);
    Outcome {
        result,
        seen,
        env,
        jobs,
        digests,
        data,
    }
}

fn committed(o: &Outcome, rel: &str) -> bool {
    o.env.project.join("node_modules").join(rel).exists()
}

// ------------------------------------------------------------ 1: no code runs

/// Every install-time and prepare-time lifecycle event plus an implicit
/// `binding.gyp` build: none may run while npm extracts the tree.
#[test]
fn control_extraction_runs_no_package_code() {
    let dir = tempfile::tempdir().unwrap();
    let mark = |n: &str| dir.path().join(n).to_string_lossy().replace('\\', "/");
    let js = |n: &str| {
        format!(
            "node -e \\\"require('fs').writeFileSync('{}','x')\\\"",
            mark(n)
        )
    };
    let scripts = [
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "prepublish",
        "prepack",
    ]
    .iter()
    .map(|e| format!("\"{e}\":\"{}\"", js(e)))
    .collect::<Vec<_>>()
    .join(",");
    let bytes = tar_gz(&[
        ("package/package.json", &manifest(&scripts), 0o644),
        ("package/binding.gyp", b"{}", 0o644),
    ]);
    // The fake sandbox does not execute: anything that wrote a marker came
    // from npm's own extraction.
    let o = run(bytes, false, false, None);
    let marks: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
    assert!(
        marks.is_empty(),
        "package code ran during extraction: {marks:?}"
    );
    assert!(o.result.is_ok(), "{:?}", o.result);
    assert!(
        o.jobs.iter().all(|j| !j
            .args
            .iter()
            .any(|a| a.to_string_lossy().contains("prepare"))),
        "prepare must never be scheduled for a registry dependency"
    );
}

// --------------------------------------------------------- 3: tree completeness

#[test]
fn control_tarball_shipped_node_modules_is_denied() {
    for extra in [
        "package/node_modules/evil/package.json",
        "package/node_modules/.hidden/package.json",
        "package/node_modules/evil/x.js",
    ] {
        let bytes = tar_gz(&[
            (
                "package/package.json",
                &manifest(r#""postinstall":"true""#),
                0o644,
            ),
            (extra, b"{\"name\":\"evil\",\"version\":\"1.0.0\"}", 0o644),
        ]);
        let o = run(bytes, false, false, None);
        assert!(o.result.is_err(), "{extra} was accepted");
    }
}

/// std must report a Windows junction as a link, or `deny_links` is blind to it.
#[cfg(windows)]
#[test]
fn control_windows_junction_is_a_link_for_std() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("real")).unwrap();
    let st = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(d.path().join("j"))
        .arg(d.path().join("real"))
        .output()
        .unwrap();
    assert!(st.status.success());
    assert!(std::fs::read_dir(d.path())
        .unwrap()
        .flatten()
        .find(|e| e.file_name() == "j")
        .unwrap()
        .file_type()
        .unwrap()
        .is_symlink());
}

/// RN3-001: a package ships its own `node_modules/.bin/node` (mode 0755; on
/// Windows `node.cmd`). `.bin` is skipped by the tree walk and by the link
/// check, is first on the lifecycle PATH of the package (and of every
/// package above it), and is never read by the review. The reviewed
/// `postinstall` is `node setup.js`; the program that runs is the shipped one.
#[test]
fn rn3_001_shipped_bin_shadow_of_a_command_is_not_reviewed() {
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"node setup.js""#),
            0o644,
        ),
        ("package/setup.js", b"console.log('benign')", 0o644),
        ("package/node_modules/.bin/node", HOSTILE.as_bytes(), 0o755),
        (
            "package/node_modules/.bin/node.cmd",
            HOSTILE_BAT.as_bytes(),
            0o755,
        ),
    ]);
    let o = run(bytes, false, false, None);
    let blocked = o.result.is_err();
    let reviewed = o
        .seen
        .iter()
        .any(|(_, b)| b.starts_with(b"#!/bin/sh") || b.starts_with(b"@echo"));
    assert!(
        blocked || reviewed,
        "install proceeded; the inspector saw {:?}; the shipped .bin/node shadows `node` unreviewed",
        o.seen.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>()
    );
}

/// RN3-002 (Windows): cmd.exe resolves `.\setup` through PATHEXT, so
/// `setup.bat` runs. The review lists `setup`, `setup.js`, ... but not
/// `.bat/.cmd/.exe/.com/.ps1`.
#[cfg(windows)]
#[test]
fn rn3_002_pathext_batch_file_behind_a_bare_command_is_not_reviewed() {
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":".\\\\setup""#),
            0o644,
        ),
        ("package/setup.bat", HOSTILE_BAT.as_bytes(), 0o644),
    ]);
    let o = run(bytes, false, false, None);
    let reviewed = o.seen.iter().any(|(p, _)| p == "setup.bat");
    assert!(
        o.result.is_err() || reviewed,
        "install proceeded with .\\setup -> setup.bat unreviewed; saw {:?}",
        o.seen.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>()
    );
}

// ------------------------------------------------------ 2: reviewed == committed

/// Approval hook edits a referenced file after the review: `recheck` must stop it.
#[test]
fn control_referenced_file_changed_after_review_is_stopped() {
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"node setup.js""#),
            0o644,
        ),
        ("package/setup.js", b"console.log('benign')", 0o644),
    ]);
    let hook: Hook = Box::new(|root| {
        std::fs::write(root.join("node_modules/scripty/setup.js"), b"evil()").unwrap();
    });
    let o = run(bytes, true, true, Some(hook));
    assert!(o.result.is_err(), "changed script ran");
    assert!(!committed(&o, "scripty"), "nothing may be committed");
}

#[test]
fn control_manifest_changed_after_review_is_stopped() {
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"node setup.js""#),
            0o644,
        ),
        ("package/setup.js", b"console.log('benign')", 0o644),
    ]);
    let hook: Hook = Box::new(|root| {
        std::fs::write(
            root.join("node_modules/scripty/package.json"),
            manifest(r#""postinstall":"git push --force""#),
        )
        .unwrap();
    });
    let o = run(bytes, true, true, Some(hook));
    assert!(o.result.is_err() && !committed(&o, "scripty"));
}

/// RN3-003: only the manifest and referenced files are hashed. A file that is
/// not named by a lifecycle command can change between the review and the
/// move into the project, and the changed bytes are committed.
#[test]
fn rn3_003_unreferenced_file_changed_after_review_is_committed() {
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"node setup.js""#),
            0o644,
        ),
        ("package/setup.js", b"console.log('benign')", 0o644),
        ("package/index.js", b"module.exports = 1", 0o644),
    ]);
    let hook: Hook = Box::new(|root| {
        std::fs::write(root.join("node_modules/scripty/index.js"), b"TAMPERED").unwrap();
    });
    let o = run(bytes, false, true, Some(hook));
    let landed = std::fs::read(o.env.project.join("node_modules/scripty/index.js")).ok();
    assert!(
        o.result.is_err() || landed.as_deref() != Some(b"TAMPERED".as_slice()),
        "a file edited after the review was committed: {landed:?}"
    );
}

/// RN3-004: after the (approved, sandboxed) scripts ran, the tree is moved
/// into the project without `verify_tree`/`deny_links` again. A script can
/// add a package directory that is not in the lockfile, or a link.
#[test]
fn rn3_004_post_script_tree_is_not_reverified() {
    let setup = b"const fs=require('fs');\
fs.mkdirSync('../zz');fs.writeFileSync('../zz/package.json','{\"name\":\"zz\",\"version\":\"9.9.9\"}');\
try{fs.symlinkSync('../../..','../lnk','junction')}catch(e){}";
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"node setup.js""#),
            0o644,
        ),
        ("package/setup.js", setup, 0o644),
    ]);
    let o = run(bytes, true, false, None);
    let stray = committed(&o, "zz");
    let link = std::fs::symlink_metadata(o.env.project.join("node_modules/lnk")).is_ok();
    assert!(
        o.result.is_err() || (!stray && !link),
        "stray package dir committed: {stray}; link committed: {link}"
    );
}

// ---------------------------------------------------------------- 4: digest

/// The approval digest changes when a reviewed on-disk file changes (here the
/// tarball differs too, so this is a smoke check; the `tree` term of
/// `ArtifactDigest` is verified by reading `npm/mod.rs`).
#[test]
fn control_approval_digest_changes_with_a_referenced_file() {
    let mk = |body: &[u8]| {
        tar_gz(&[
            (
                "package/package.json",
                &manifest(r#""postinstall":"node setup.js""#),
                0o644,
            ),
            ("package/setup.js", body, 0o644),
        ])
    };
    let digest = |bytes: Vec<u8>| {
        let o = run(bytes, false, true, None);
        assert!(o.result.is_ok(), "{:?}", o.result);
        o.digests[0].clone()
    };
    assert_ne!(digest(mk(b"console.log(1)")), digest(mk(b"console.log(2)")));
}

// ------------------------------------------------- coordinator decisions (CR-008 round 3)

fn denied_with(o: &Outcome, needle: &str) -> bool {
    matches!(&o.result, Err(e) if e.contains(needle))
}

/// Decision 1: any shipped `.bin` entry named like an interpreter or core
/// tool is denied, in any case and with any Windows extension.
#[test]
fn d1_shadowing_bin_names_are_denied() {
    for name in ["NODE.EXE", "Npm.cmd", "python3", "node-gyp.ps1", "sh"] {
        let bytes = tar_gz(&[
            (
                "package/package.json",
                &manifest(r#""postinstall":"true""#),
                0o644,
            ),
            (
                &format!("package/node_modules/.bin/{name}"),
                HOSTILE.as_bytes(),
                0o755,
            ),
        ]);
        let o = run(bytes, false, false, None);
        assert!(denied_with(&o, "shadows"), "{name}: {:?}", o.result);
        assert!(!committed(&o, "scripty"), "{name}");
    }
}

/// Decision 1: another `.bin` command invoked as the first word has its target
/// reviewed like a referenced script.
#[test]
fn d1_other_bin_command_target_is_reviewed() {
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"mytool --go""#),
            0o644,
        ),
        (
            "package/node_modules/.bin/mytool",
            HOSTILE.as_bytes(),
            0o755,
        ),
        (
            "package/node_modules/.bin/mytool.cmd",
            HOSTILE_BAT.as_bytes(),
            0o755,
        ),
    ]);
    let o = run(bytes, false, false, None);
    let reviewed = o
        .seen
        .iter()
        .any(|(_, b)| b.starts_with(b"#!/bin/sh") || b.starts_with(b"@echo"));
    assert!(
        reviewed,
        "inspector saw {:?}",
        o.seen.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>()
    );
    assert!(
        o.result.is_err(),
        "force-push evidence in the target must deny"
    );
}

/// Decision 2: a referenced candidate that is a binary (PE header) is an
/// incomplete-scan denial; so is NUL content in a node-style candidate.
#[test]
fn d2_binary_or_nul_candidate_is_denied() {
    let mut exe = b"MZ".to_vec();
    exe.extend_from_slice(&[0x90, 0, 3, 0]);
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"node setup.js""#),
            0o644,
        ),
        ("package/setup.js", &exe, 0o644),
    ]);
    let o = run(bytes, false, false, None);
    assert!(denied_with(&o, "cannot be inspected"), "{:?}", o.result);
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"node setup.js""#),
            0o644,
        ),
        ("package/setup.js", b"console.log(1)\0", 0o644),
    ]);
    assert!(denied_with(
        &run(bytes, false, false, None),
        "cannot be inspected"
    ));
}

/// Decision 2 (Windows): `.\setup` runs `setup.exe` or `setup.cmd`; both are
/// reviewed (the binary denied, the batch file read).
#[cfg(windows)]
#[test]
fn d2_pathext_candidates_are_reviewed_on_windows() {
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":".\\setup""#),
            0o644,
        ),
        ("package/setup.exe", b"MZ\x90\0", 0o644),
    ]);
    assert!(denied_with(
        &run(bytes, false, false, None),
        "cannot be inspected"
    ));
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"setup""#),
            0o644,
        ),
        ("package/setup.cmd", HOSTILE_BAT.as_bytes(), 0o644),
    ]);
    let o = run(bytes, false, false, None);
    assert!(
        o.seen.iter().any(|(p, _)| p == "setup.cmd") && o.result.is_err(),
        "{:?}",
        o.result
    );
}

/// Decision 3: the approval digest binds files no lifecycle command names.
#[test]
fn d3_digest_binds_unreferenced_files() {
    let mk = |body: &[u8]| {
        tar_gz(&[
            (
                "package/package.json",
                &manifest(r#""postinstall":"node setup.js""#),
                0o644,
            ),
            ("package/setup.js", b"console.log(1)", 0o644),
            ("package/index.js", body, 0o644),
        ])
    };
    let digest = |b: Vec<u8>| run(b, false, true, None).digests[0].clone();
    assert_ne!(
        digest(mk(b"module.exports=1")),
        digest(mk(b"module.exports=2"))
    );
}

/// Decision 3: the change is an integrity failure and nothing is committed.
#[test]
fn d3_tampered_file_is_an_integrity_failure_and_not_committed() {
    let bytes = tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"true""#),
            0o644,
        ),
        ("package/index.js", b"module.exports = 1", 0o644),
    ]);
    let hook: Hook = Box::new(|root| {
        std::fs::write(root.join("node_modules/scripty/index.js"), b"TAMPERED").unwrap();
    });
    let o = run(bytes, false, true, Some(hook));
    assert!(
        denied_with(&o, "changed after it was reviewed"),
        "{:?}",
        o.result
    );
    assert!(!committed(&o, "scripty"));
}

fn script_pkg(body: &str) -> Vec<u8> {
    tar_gz(&[
        (
            "package/package.json",
            &manifest(r#""postinstall":"node setup.js""#),
            0o644,
        ),
        ("package/setup.js", body.as_bytes(), 0o644),
        ("package/index.js", b"module.exports = 1", 0o644),
    ])
}

/// Decision 4: build output inside the package's own directory is allowed and
/// listed in the outcome data.
#[test]
fn d4_build_output_in_the_package_dir_is_allowed_and_listed() {
    let o = run(
        script_pkg("require('fs').writeFileSync('built.txt','x');require('fs').writeFileSync('index.js','2')"),
        true,
        false,
        None,
    );
    assert!(o.result.is_ok(), "{:?}", o.result);
    assert!(committed(&o, "scripty/built.txt"));
    let out: Vec<String> = serde_json::from_value(o.data["build_output"].clone()).unwrap();
    assert!(
        out.contains(&"node_modules/scripty/built.txt".to_string()),
        "{out:?}"
    );
    assert!(
        out.contains(&"node_modules/scripty/index.js".to_string()),
        "{out:?}"
    );
}

/// Decision 4: a script that rewrites a `package.json`, writes outside its
/// package dir, or rewrites its own reviewed script fails the install.
#[test]
fn d4_script_violations_fail_the_install() {
    for body in [
        "require('fs').appendFileSync('package.json',' ')",
        "require('fs').writeFileSync('../stray.txt','x')",
        "require('fs').mkdirSync('../.bin',{recursive:true});require('fs').writeFileSync('../.bin/x','x')",
        "require('fs').writeFileSync('../.package-lock.json','{}')",
        "require('fs').appendFileSync('setup.js','//')",
    ] {
        let o = run(script_pkg(body), true, false, None);
        assert!(o.result.is_err(), "{body} was accepted");
        assert!(!committed(&o, "scripty"), "{body}");
    }
}
