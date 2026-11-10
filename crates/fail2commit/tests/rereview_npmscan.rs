//! Regression tests for the re-review findings RN-001..RN-008 on the npm and
//! scanner fixes (W2-003/004/005/007/008, CR-003/CR-004). Offline fixtures only.
//!
//! Every test asserts the *safe* behaviour. They began as the reviewer's
//! failing reproductions and now guard the fixes; tests marked "control"
//! document what already held. See docs/verify/reviews/REREVIEW-2026-11-09-npmscan.md.

mod npm_support;
#[allow(dead_code)]
mod scan_support;

use fail2commit_core::npm;
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::protocol::{FindingAction, FindingKind};
use fail2commit_core::scan::{self, inspect_scripts, Ecosystem, PackageId, ScriptFile};
use npm_support::*;
use scan_support::{advisory_settings, fixture, Response, TestServer};

const HOSTILE: &str = "#!/bin/sh\ngit push --force origin main\n";

/// Run `npm ci` for a one-package lockfile with the *real* script inspector.
/// Returns true when the install was blocked by a Deny finding.
fn denied(pkg: Pkg) -> bool {
    outcome(pkg).iter().any(|f| f.action == FindingAction::Deny)
}

/// Findings that blocked the install; empty when it proceeded.
fn outcome(pkg: Pkg) -> Vec<fail2commit_core::protocol::Finding> {
    require_node();
    let reg = Registry::start();
    reg.publish(&pkg);
    let pj = format!(
        r#"{{"name":"clean-app","version":"1.0.0","private":true,"dependencies":{{"{}":"^1.0.0"}}}}"#,
        pkg.name
    );
    let env = Env::new(&reg, &pj);
    std::fs::write(
        env.project.join("package-lock.json"),
        reg.lockfile(&[&pkg.name], &[&pkg]),
    )
    .unwrap();
    let backend = FakeBackend::new(true, false);
    let run = Run::new(&env, &backend);
    let b = Behavior {
        inspect: Box::new(inspect_scripts),
        ..Default::default()
    };
    let result = npm::execute(&run.deps(b), &env.request(&["ci"]));
    match result {
        Ok(_) => {
            eprintln!("OUTCOME: install proceeded");
            vec![]
        }
        Err(e) => {
            eprintln!("OUTCOME: blocked: {} {:?}", e.message, e.findings);
            e.findings
        }
    }
}

fn has(pkg: Pkg, kind: FindingKind) -> bool {
    outcome(pkg)
        .iter()
        .any(|f| f.kind == kind && f.action == FindingAction::Deny)
}

fn scripted(cmd: &str) -> Pkg {
    Pkg::new("scripty", "1.0.0").script("postinstall", cmd)
}

fn pkg() -> PackageId {
    PackageId {
        ecosystem: Ecosystem::Npm,
        name: "demo".into(),
        version: "1.0.0".into(),
    }
}

// ---------------------------------------------------------------- W2-003

#[test]
fn control_sh_dot_slash_extensionless_is_denied() {
    assert!(denied(scripted("sh ./run").file("run", HOSTILE)));
}

#[test]
fn control_oversized_referenced_file_is_denied() {
    let mut big = HOSTILE.as_bytes().to_vec();
    big.resize(300 * 1024, b'\n');
    let mut p = scripted("sh ./run");
    p.files.push(("run".into(), big));
    assert!(denied(p));
}

#[test]
fn control_utf16_script_is_denied_as_undecodable() {
    // Node does not run UTF-16 sources and `sh` does not either; PowerShell
    // does. Every ASCII char carries a NUL, so the NUL rule denies it.
    let mut b = vec![0xFF, 0xFE];
    for u in "git push --force origin main\r\n".encode_utf16() {
        b.extend_from_slice(&u.to_le_bytes());
    }
    let f = ScriptFile {
        path: "x.ps1".into(),
        bytes: b,
    };
    let out = inspect_scripts(
        &pkg(),
        &[("postinstall".into(), "pwsh ./x.ps1".into())],
        &[f],
    );
    assert!(out
        .iter()
        .any(|f| f.kind == FindingKind::IncompleteScan && f.action == FindingAction::Deny));
}

/// RN-001: `sh` (and bash) silently ignore NUL bytes after the first line, so
/// `git pu<NUL>sh --force` runs as a force push. The NUL check only looks at
/// the first 8192 bytes and the rules then match against text containing NUL.
#[test]
fn nul_inside_the_command_past_8k_is_not_a_clean_scan() {
    let mut bytes = b"#!/bin/sh\n".to_vec();
    while bytes.len() < 9000 {
        bytes.extend_from_slice(b"# padding padding padding padding\n");
    }
    bytes.extend_from_slice(b"git pu\0sh --force origin main\n");
    let f = ScriptFile {
        path: "run".into(),
        bytes,
    };
    let out = inspect_scripts(&pkg(), &[("postinstall".into(), "sh ./run".into())], &[f]);
    assert!(
        out.iter().any(|f| f.action == FindingAction::Deny),
        "NUL-split force push scanned clean: {out:?}"
    );
}

// ---------------------------------------------------------------- W2-004

/// RN-002: node resolves `./setup` to `setup.js` (and `.` / `./lib` to an
/// index file); the token never equals an archive entry name.
#[test]
fn node_extension_resolution_is_a_candidate() {
    assert!(denied(scripted("node ./setup").file("setup.js", HOSTILE)));
}

/// RN-003: a quoted path containing a space is split at the space.
#[test]
fn quoted_path_with_a_space_is_a_candidate() {
    assert!(denied(
        scripted("sh \"./my script\"").file("my script", HOSTILE)
    ));
}

/// RN-003: `.//run` and `./a/../run` are only trimmed lexically at the front.
#[test]
fn double_slash_is_a_candidate() {
    assert!(denied(scripted("sh .//run").file("run", HOSTILE)));
}

#[test]
fn inner_dotdot_is_a_candidate() {
    assert!(denied(
        scripted("sh ./a/../run")
            .file("run", HOSTILE)
            .file("a/keep", "x")
    ));
}

/// RN-003: a variable or command-substitution prefix hides the path.
#[test]
fn variable_prefixed_path_is_a_candidate() {
    assert!(denied(scripted("sh $PWD/run").file("run", HOSTILE)));
}

/// RN-004: `npm run <script>` executes a non-lifecycle `scripts` entry that
/// the archive layer never passes to the inspector.
#[test]
fn npm_run_chain_to_a_non_lifecycle_script_is_inspected() {
    let p = scripted("npm run build").script("build", "git push --force origin main");
    assert!(denied(p));
}

// ---------------------------------------------------------------- W2-005

/// RN-005: NTFS folds non-ASCII case (verified with node-tar on this host:
/// `Ü.js` and `ü.js` extract to one file). `fold` is ASCII only.
#[test]
fn non_ascii_case_collision_is_rejected() {
    let mut p = scripted("sh ./ü.js").file("ü.js", "echo ok\n");
    p.raw_entries.push(("package/Ü.js".into(), HOSTILE.into()));
    assert!(denied(p), "collision on NTFS must be rejected");
}

/// RN-005: a single `Ü.js` is what `./ü.js` resolves to on Windows, but the
/// candidate set only matches the ASCII-folded name.
#[test]
fn non_ascii_case_variant_is_a_candidate() {
    assert!(denied(scripted("sh ./ü.js").file("Ü.js", HOSTILE)));
}

/// RN-006: `./package.json` is dropped by `normalize` (the leading `.` is
/// treated as the package directory), but node-tar `strip:1` extracts it to
/// the root `package.json`, overwriting the reviewed one.
#[test]
fn dot_slash_package_json_is_not_skipped() {
    let mut p = Pkg::new("scripty", "1.0.0");
    let hostile = br#"{"name":"scripty","version":"1.0.0","scripts":{"postinstall":"git push --force origin main"}}"#;
    p.raw_entries
        .push(("./package.json".into(), hostile.to_vec()));
    assert!(denied(p));
}

/// RN-007: Windows 8.3 short names (default on NTFS system volumes) address
/// the long-named file with a token that matches no archive entry.
#[test]
fn short_name_alias_is_a_candidate() {
    assert!(denied(
        scripted("sh ./BUILDH~1.JS").file("buildhelper.js", HOSTILE)
    ));
}

/// RN-006 against npm's own extractor: the `./package.json` entry really
/// replaces the root manifest under `strip: 1`, and the guard denies it.
#[test]
fn dot_slash_package_json_overlay_matches_npm_tar_and_is_denied() {
    require_node();
    let hostile = br#"{"name":"scripty","version":"1.0.0","scripts":{"postinstall":"git push --force origin main"}}"#;
    let benign = br#"{"name":"scripty","version":"1.0.0"}"#;
    let archive = tgz(&[
        ("package/package.json", benign),
        ("./package.json", hostile),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("p.tgz");
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    std::fs::write(&file, &archive).unwrap();
    let probe = dir.path().join("probe.js");
    std::fs::write(
        &probe,
        r#"const path = require('path');
const roots = [
  path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'node_modules'),
  '/usr/share/nodejs', '/usr/lib/node_modules/npm/node_modules',
  '/usr/local/lib/node_modules/npm/node_modules',
];
let tar;
for (const r of roots) { try { tar = require(path.join(r, 'tar')); break; } catch (e) {} }
if (!tar) { console.error('npm tar module not found'); process.exit(3); }
tar.x({ file: process.argv[2], cwd: process.argv[3], strip: 1, sync: true });
"#,
    )
    .unwrap();
    let run = std::process::Command::new("node")
        .arg(&probe)
        .arg(&file)
        .arg(&out)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        std::fs::read(out.join("package.json")).unwrap(),
        hostile.to_vec(),
        "npm tar lets ./package.json win"
    );

    let mut p = Pkg::new("scripty", "1.0.0");
    p.raw_entries
        .push(("./package.json".into(), hostile.to_vec()));
    assert!(has(p, FindingKind::IntegrityMismatch));
}

/// RN-006: `package//x/./run` collapses like npm's tar, so it collides.
#[test]
fn entries_that_normalize_alike_collide() {
    let mut p = scripted("sh ./x/run").file("x/run", "echo ok\n");
    p.raw_entries
        .push(("package//x/./run".into(), HOSTILE.into()));
    assert!(has(p, FindingKind::IntegrityMismatch));
}

/// RN-007: an entry whose own name has an 8.3 shape is refused outright.
#[test]
fn short_name_shaped_entry_is_denied() {
    let mut p = scripted("sh ./run").file("run", "echo ok\n");
    p.raw_entries
        .push(("package/BUILD~1.JS".into(), HOSTILE.into()));
    assert!(has(p, FindingKind::UnsupportedInput));
}

/// RN-002: a directory resolves through its `package.json` `main`.
#[test]
fn node_directory_main_is_a_candidate() {
    let p = scripted("node ./lib")
        .file("lib/package.json", r#"{"main":"entry"}"#)
        .file("lib/entry.js", HOSTILE);
    assert!(denied(p));
    assert!(denied(scripted("node ./lib").file("lib/index.js", HOSTILE)));
    assert!(denied(scripted("node .").file("index.js", HOSTILE)));
}

/// RN-003: a path that leaves the package is refused, not guessed at.
#[test]
fn path_escaping_the_package_is_unsupported() {
    assert!(has(
        scripted("sh ../outside"),
        FindingKind::UnsupportedInput
    ));
    assert!(has(
        scripted("sh $PWD/../outside"),
        FindingKind::UnsupportedInput
    ));
}

/// RN-004: a chain that cannot be followed, or that nests past the bound.
#[test]
fn unfollowable_run_chain_is_incomplete() {
    assert!(has(
        scripted("npm run -w other build").script("build", "echo ok"),
        FindingKind::IncompleteScan
    ));
    let mut p = scripted("npm run s0");
    for i in 0..12 {
        p = p.script(&format!("s{i}"), &format!("npm run s{}", i + 1));
    }
    assert!(has(p.script("s12", "echo ok"), FindingKind::IncompleteScan));
}

/// RN-004: a chain through `yarn`/`pnpm` reaches `pre`/`post` hooks too.
#[test]
fn chain_hooks_are_inspected() {
    let p = scripted("yarn build")
        .script("build", "echo ok")
        .script("postbuild", "git push --force origin main");
    assert!(denied(p));
}

/// Control: benign chains and extension resolution stay installable.
#[test]
fn control_benign_chain_and_resolution_proceed() {
    let p = scripted("npm run build && node ./setup")
        .script("build", "node ./b.js")
        .file("setup.js", "console.log(1)\n")
        .file("b.js", "console.log(2)\n");
    assert!(outcome(p).is_empty());
}

// ---------------------------------------------------------------- W2-007/8

fn home() -> (tempfile::TempDir, TrustedPaths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = TrustedPaths::under(dir.path());
    paths.ensure().unwrap();
    (dir, paths)
}

fn report_for(ids: Vec<String>, openssf: Option<&'static str>) -> scan::AdvisoryReport {
    let vulns: Vec<serde_json::Value> =
        ids.iter().map(|i| serde_json::json!({ "id": i })).collect();
    let body = serde_json::json!({ "results": [{ "vulns": vulns }] }).to_string();
    let server = TestServer::start(move |request| match (request.path.as_str(), openssf) {
        ("/v1/querybatch", _) => Response::json(body.clone()),
        (p, Some(id)) if p == format!("/v1/vulns/{id}") => {
            Response::json(fixture("osv/vuln-openssf.json"))
        }
        _ => Response::with_status(404, "{}"),
    });
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    scan::check_advisories(&paths, &settings, &[pkg()])
}

/// RN-008: the sort key is the `MAL-` prefix only, but `is_malware` also
/// classifies by record content (OpenSSF source) and case-insensitively. A
/// malware record that is not `MAL-`-prefixed can be truncated away, leaving
/// only an approvable IncompleteScan.
#[test]
fn truncation_never_drops_a_content_classified_malware_record() {
    let mut ids: Vec<String> = (0..130).map(|i| format!("CVE-2024-{i:04}")).collect();
    ids.push("GHSA-1111-2222-3333".into());
    let report = report_for(ids, Some("GHSA-1111-2222-3333"));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::Malware && f.action == FindingAction::Deny),
        "malware record dropped by truncation: {} findings",
        report.findings.len()
    );
}

#[test]
fn truncation_never_drops_a_lowercase_mal_id() {
    let mut ids: Vec<String> = (0..130).map(|i| format!("CVE-2024-{i:04}")).collect();
    ids.push("mal-2024-0001".into());
    let report = report_for(ids, None);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::Malware && f.action == FindingAction::Deny),
        "lowercase mal- id dropped by truncation"
    );
}
