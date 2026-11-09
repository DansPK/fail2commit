//! Second re-review of the npm archive integrity fixes RN-005/006/007 (FR-004).
//! Offline fixtures only. Every test asserts the *safe* behaviour: the install
//! is blocked, or the bytes npm will extract are the bytes that were reviewed.
//!
//! "npm's extractor" below means `pacote.extract` of npm 12.2.0 on this host
//! (bundled `tar` 7.5.22, `strip: 1`, links dropped, `.gitignore` renamed),
//! probed on 2026-11-09. Tests named `control_*` document inputs that already
//! behave safely; `rn2_*` tests are reproductions and fail until fixed.
//! See docs/verify/REREVIEW2-2026-11-09-npm.md.

mod npm_support;

use base64::Engine;
use fail2commit_core::npm;
use fail2commit_core::scan::inspect_scripts;
use npm_support::*;
use sha2::Digest;
use std::io::Write;

const HOSTILE: &str = "#!/bin/sh\ngit push --force origin main\n";

// ---------------------------------------------------------------- raw tar

fn pj(extra: &str) -> Vec<u8> {
    format!(r#"{{"name":"scripty","version":"1.0.0"{extra}}}"#).into_bytes()
}

fn hostile_pj() -> Vec<u8> {
    pj(r#","scripts":{"postinstall":"git push --force origin main"}"#)
}

fn header(name: &str, size: u64, ty: u8) -> Vec<u8> {
    let mut h = tar::Header::new_gnu();
    let n = name.as_bytes();
    h.as_old_mut().name[..n.len()].copy_from_slice(n);
    h.set_entry_type(tar::EntryType::new(ty));
    h.set_size(size);
    h.set_mode(0o644);
    h.set_mtime(0);
    h.set_cksum();
    h.as_bytes().to_vec()
}

fn pad(mut b: Vec<u8>) -> Vec<u8> {
    b.resize(b.len().div_ceil(512) * 512, 0);
    b
}

/// A well-formed entry: header, body, padding.
fn ent(name: &str, body: &[u8]) -> Vec<u8> {
    [header(name, body.len() as u64, b'0'), pad(body.to_vec())].concat()
}

/// An entry whose header claims `size` while `body` follows verbatim.
fn raw(name: &str, size: u64, ty: u8, body: &[u8]) -> Vec<u8> {
    [header(name, size, ty), body.to_vec()].concat()
}

fn pax(path: &str) -> Vec<u8> {
    let rec = format!(" path={path}\n");
    let mut len = rec.len();
    while len != rec.len() + len.to_string().len() {
        len = rec.len() + len.to_string().len();
    }
    let body = format!("{len}{rec}");
    [
        header("PaxHeader/x", body.len() as u64, b'x'),
        pad(body.into_bytes()),
    ]
    .concat()
}

fn gnu_long(name: &str) -> Vec<u8> {
    let mut b = name.as_bytes().to_vec();
    b.push(0);
    [header("././@LongLink", b.len() as u64, b'L'), pad(b)].concat()
}

fn eof() -> Vec<u8> {
    vec![0; 1024]
}

fn gz(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

fn sri(b: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(b))
    )
}

// ---------------------------------------------------------------- harness

/// What the inspector was shown for one package: lifecycle scripts and the
/// referenced files (path, bytes).
type Seen = Vec<(Vec<(String, String)>, Vec<(String, Vec<u8>)>)>;

/// `<rel>` of `name` in the staging tree npm extracted. The tree exists while
/// the review runs, which is when the inspector calls this.
fn staged(cache: &std::path::Path, name: &str, rel: &str) -> Vec<u8> {
    for d in std::fs::read_dir(cache.join("sandbox-stage"))
        .unwrap()
        .flatten()
    {
        let p = d.path().join("proj/node_modules").join(name).join(rel);
        if p.is_file() {
            return std::fs::read(p).unwrap();
        }
    }
    panic!("`{name}/{rel}` is not in the staged tree");
}

/// Run `npm ci` for a one-package lockfile whose registry serves exactly
/// `bytes`, with the real script inspector. `Ok` means the install proceeded.
/// Whatever the inspector is shown is checked against the bytes npm wrote to
/// the staging tree (CR-008): reviewed == extracted.
fn run_seen(pkg: Pkg, bytes: Vec<u8>) -> (Result<(), String>, Seen) {
    require_node();
    let reg = Registry::start();
    let url = reg.url.clone();
    reg.publish_bytes(&pkg, &url, &bytes, &bytes);
    let pjson = format!(
        r#"{{"name":"clean-app","version":"1.0.0","private":true,"dependencies":{{"{}":"^1.0.0"}}}}"#,
        pkg.name
    );
    let env = Env::new(&reg, &pjson);
    let lock = reg
        .lockfile(&[&pkg.name], &[&pkg])
        .replace(&sri(&pkg.tarball()), &sri(&bytes));
    std::fs::write(env.project.join("package-lock.json"), lock).unwrap();
    let backend = FakeBackend::new(true, false);
    let run = Run::new(&env, &backend);
    let seen: std::sync::Arc<std::sync::Mutex<Seen>> = Default::default();
    let (log, cache, name) = (seen.clone(), env.paths.cache_dir.clone(), pkg.name.clone());
    let b = Behavior {
        inspect: Box::new(move |id, scripts, files| {
            let on_disk: serde_json::Value =
                serde_json::from_slice(&staged(&cache, &name, "package.json")).unwrap();
            for (event, cmd) in scripts.iter().filter(|(e, _)| e.ends_with("install")) {
                if event != "install" || cmd != "node-gyp rebuild" {
                    assert_eq!(
                        on_disk["scripts"][event], *cmd,
                        "reviewed {event} != extracted"
                    );
                }
            }
            for f in files.iter().filter(|f| f.path != "binding.gyp") {
                assert_eq!(
                    staged(&cache, &name, &f.path),
                    f.bytes,
                    "reviewed {} != extracted",
                    f.path
                );
            }
            log.lock().unwrap().push((
                scripts.to_vec(),
                files
                    .iter()
                    .map(|f| (f.path.clone(), f.bytes.clone()))
                    .collect(),
            ));
            inspect_scripts(id, scripts, files)
        }),
        ..Default::default()
    };
    let result = match npm::execute(&run.deps(b), &env.request(&["ci"])) {
        Ok(_) => Ok(()),
        Err(e) => {
            let f: Vec<String> = e.findings.iter().map(|f| format!("{:?}", f)).collect();
            Err(format!("{} {}", e.message, f.join(" ")))
        }
    };
    let seen = seen.lock().unwrap().clone();
    (result, seen)
}

fn run_bytes(pkg: Pkg, bytes: Vec<u8>) -> Result<(), String> {
    run_seen(pkg, bytes).0
}

/// The inspector was shown the hostile manifest's script, i.e. the manifest
/// npm extracted and not the benign one a different reader would have seen.
#[track_caller]
fn assert_saw_hostile_script(seen: &Seen) {
    let hostile: serde_json::Value = serde_json::from_slice(&hostile_pj()).unwrap();
    let cmd = hostile["scripts"]["postinstall"].as_str().unwrap();
    assert!(
        seen.iter().any(|(s, _)| s.iter().any(|(_, c)| c == cmd)),
        "the reviewed manifest is not the one npm extracted: {seen:?}"
    );
}

fn run_pkg(pkg: Pkg) -> Result<(), String> {
    let bytes = pkg.tarball();
    run_bytes(pkg, bytes)
}

fn scripty() -> Pkg {
    Pkg::new("scripty", "1.0.0")
}

#[track_caller]
fn assert_blocked(r: Result<(), String>, why: &str) {
    assert!(r.is_err(), "install proceeded: {why}");
}

/// Archive = benign manifest + `hostile` entries + end marker.
fn with_benign(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut v = ent("package/package.json", &pj(""));
    for p in parts {
        v.extend_from_slice(p);
    }
    gz(&[v, eof()].concat())
}

// ---------------------------------------------------------------- controls

#[test]
fn control_benign_archive_installs() {
    assert_eq!(run_bytes(scripty(), with_benign(&[])), Ok(()));
}

/// npm's extractor needs two zero blocks to stop, but so does the extra
/// entry here: a *double* zero block hides the tail from both readers.
#[test]
fn control_two_zero_blocks_end_both_readers() {
    let tail = ent("package/package.json", &hostile_pj());
    let v = gz(&[ent("package/package.json", &pj("")), eof(), tail, eof()].concat());
    assert_eq!(run_bytes(scripty(), v), Ok(()));
}

/// RN-006 fix: every name that npm's `strip: 1` maps onto the manifest.
#[test]
fn control_names_that_land_on_package_json_collide() {
    for name in [
        "./package.json",
        ".//package.json",
        "other/package.json",
        "package//package.json",
        "package/./package.json",
        "x/./package.json",
    ] {
        let v = with_benign(&[ent(name, &hostile_pj())]);
        assert_blocked(run_bytes(scripty(), v), name);
    }
}

#[test]
fn control_unsafe_names_are_rejected() {
    for name in [
        "../package.json",
        "/package.json",
        "//package/package.json",
        "package\\package.json",
        "C:package.json",
        "package/C:x.js",
        "package/../package.json",
        "package/a/../package.json",
    ] {
        let v = with_benign(&[ent(name, &hostile_pj())]);
        assert_blocked(run_bytes(scripty(), v), name);
    }
}

#[test]
fn control_pax_and_gnu_long_names_are_resolved_like_npm() {
    for hdr in [
        pax("./package.json"),
        pax("package/package.json"),
        gnu_long("./package.json"),
        gnu_long("package/package.json"),
    ] {
        let v = with_benign(&[hdr, ent("package/zzz", &hostile_pj())]);
        assert_blocked(run_bytes(scripty(), v), "pax/gnu name override");
    }
}

#[test]
fn control_link_entries_are_rejected() {
    for ty in *b"12" {
        let v = with_benign(&[raw("package/l", 0, ty, b"")]);
        assert_blocked(run_bytes(scripty(), v), "link entry");
    }
}

/// RN-005: NTFS folds BMP simple case. Probed: `Ü`/`ü` and fullwidth `Ａ`/`ａ`
/// share one file; Kelvin, long s, dotless i, `ß`, NFC/NFD do not (the Rust
/// fold over-approximates, which only denies more).
#[test]
fn control_ntfs_case_pairs_collide() {
    for (a, b) in [
        ("\u{dc}.js", "\u{fc}.js"),
        ("\u{ff21}.js", "\u{ff41}.js"),
        ("A.js", "a.js"),
        ("a.js.", "a.js"),
        ("a.js ", "a.js"),
        ("\u{3a3}.js", "\u{3c3}.js"),
    ] {
        let v = with_benign(&[
            ent(&format!("package/{a}"), b"1"),
            ent(&format!("package/{b}"), b"2"),
        ]);
        assert_blocked(run_bytes(scripty(), v), a);
    }
}

#[test]
fn control_short_name_entries_are_rejected_first() {
    // No manifest follows, yet the error must be the name, not "no package.json".
    let v = gz(&[ent("package/BUILDH~1.JS", b"x"), eof()].concat());
    let e = run_bytes(scripty(), v).unwrap_err();
    assert!(e.contains("8.3"), "{e}");
}

#[test]
fn control_collision_is_reported_before_a_missing_manifest() {
    let v = gz(&[ent("package/A.js", b"1"), ent("package/a.js", b"2"), eof()].concat());
    let e = run_bytes(scripty(), v).unwrap_err();
    assert!(e.contains("collide"), "{e}");
}

#[test]
fn control_gitignore_token_names_nothing_npm_extracted() {
    let p = scripty()
        .script("postinstall", "sh ./.gitignore")
        .file(".gitignore", HOSTILE);
    // npm extracted no `.gitignore` (it is `.npmignore` on disk), so the script
    // opens nothing that exists; the extracted tree is what is reviewed (CR-008).
    // A local command path with no file on disk is named for approval as not
    // inspected (CR-012); the hostile bytes are never presented as reviewed.
    let bytes = p.tarball();
    let (_, seen) = run_seen(p, bytes);
    assert!(
        !seen
            .iter()
            .flat_map(|(_, files)| files)
            .any(|(path, _)| path.contains("gitignore")),
        "the renamed .gitignore was offered as reviewed content: {seen:?}"
    );
}

// ---------------------------------------------------------------- RN2 repros

/// RN2-001: npm's `tar` decodes every concatenated gzip member; `flate2`'s
/// `GzDecoder` stops after the first. The second member replaces the reviewed
/// manifest with one that force-pushes.
#[test]
fn rn2_001_second_gzip_member_is_not_hidden() {
    let first = ent("package/package.json", &pj("")); // no end marker: stream continues
    let second = [ent("package/package.json", &hostile_pj()), eof()].concat();
    let v = [gz(&first), gz(&second)].concat();
    // The archive pre-check reads every member and sees the duplicate manifest
    // before npm runs; if it ever did not, the review would see the hostile one.
    let (r, seen) = run_seen(scripty(), v);
    if !seen.is_empty() {
        assert_saw_hostile_script(&seen);
    }
    let e = r.expect_err("second gzip member never reviewed");
    assert!(
        seen.is_empty() && e.contains("collide") || !seen.is_empty(),
        "{e}"
    );
}

/// RN2-001b: a file that only the second gzip member carries is still
/// extracted by npm, so it is reviewed from the extracted tree.
#[test]
fn rn2_001b_file_in_second_gzip_member_is_reviewed_from_disk() {
    let first = ent(
        "package/package.json",
        &pj(r#","scripts":{"postinstall":"sh ./setup.sh"}"#),
    );
    let second = [ent("package/setup.sh", HOSTILE.as_bytes()), eof()].concat();
    let v = [gz(&first), gz(&second)].concat();
    let (r, seen) = run_seen(scripty(), v);
    assert!(
        seen.iter().any(|(_, f)| f
            .iter()
            .any(|(n, b)| n == "setup.sh" && b == HOSTILE.as_bytes())),
        "{seen:?}"
    );
    assert_blocked(r, "script from the second gzip member");
}

/// RN2-002: `tar-rs` ends at the first all-zero block; npm's `tar` needs two
/// in a row and keeps extracting after a single one.
#[test]
fn rn2_002_single_zero_block_does_not_end_the_archive() {
    let v = gz(&[
        ent("package/package.json", &pj("")),
        vec![0; 512],
        ent("package/package.json", &hostile_pj()),
        eof(),
    ]
    .concat());
    let (r, seen) = run_seen(scripty(), v);
    assert_saw_hostile_script(&seen);
    assert_blocked(r, "entries after a lone zero block");
}

/// RN2-003: npm's `tar` turns a type-`0` entry whose name ends in `/` into a
/// directory with size 0, so the entry's body is parsed as the next headers.
/// `tar-rs` sees a regular file and skips the body.
#[test]
fn rn2_003_trailing_slash_file_body_is_parsed_by_npm() {
    let inner = ent("package/package.json", &hostile_pj());
    let v = with_benign(&[raw("package/x/", inner.len() as u64, b'0', &inner)]);
    let (r, seen) = run_seen(scripty(), v);
    assert_saw_hostile_script(&seen);
    assert_blocked(r, "smuggled entry in a `x/` body");
}

/// RN2-003b: same for a real directory entry (type `5`) with a non-zero size.
#[test]
fn rn2_003b_directory_with_size_body_is_parsed_by_npm() {
    let inner = ent("package/package.json", &hostile_pj());
    let v = with_benign(&[raw("package/d", inner.len() as u64, b'5', &inner)]);
    let (r, seen) = run_seen(scripty(), v);
    assert_saw_hostile_script(&seen);
    assert_blocked(r, "smuggled entry in a directory body");
}

/// RN2-004: pacote renames every `.gitignore` to `.npmignore` (unless a
/// `.npmignore` exists). `sh ./.npmignore` runs the bytes of `.gitignore`,
/// but the review looks for an archive entry named `.npmignore`.
#[test]
fn rn2_004_gitignore_is_extracted_as_npmignore() {
    let p = scripty()
        .script("postinstall", "sh ./.npmignore")
        .file(".gitignore", HOSTILE);
    let bytes = p.tarball();
    let (r, seen) = run_seen(p, bytes);
    assert!(
        seen.iter().any(|(_, f)| f
            .iter()
            .any(|(n, b)| n == ".npmignore" && b == HOSTILE.as_bytes())),
        "the renamed file was not reviewed: {seen:?}"
    );
    assert_blocked(r, "`.npmignore` token resolves to `.gitignore` bytes");
}

/// Control: on NTFS `file::$DATA` opens the default stream of `file`
/// (probed: `node setup.js::$DATA` runs `setup.js`). The `$` makes the word
/// an unknowable expansion, so the review already denies it.
#[test]
fn control_default_stream_suffix_is_denied() {
    let p = scripty()
        .script("postinstall", "node ./setup.js::$DATA")
        .file("setup.js", HOSTILE);
    assert_blocked(run_pkg(p), "`::$DATA` alias of a file");
}

/// RN2-006: a `main` that is an 8.3 alias is added as a candidate verbatim, so
/// `node .` runs `buildhelper.js` unreviewed on NTFS volumes with 8.3 names.
#[test]
fn rn2_006_main_field_short_name_alias_is_denied() {
    let manifest = pj(r#","main":"BUILDH~1.JS","scripts":{"postinstall":"node ."}"#);
    let v = gz(&[
        ent("package/package.json", &manifest),
        ent("package/buildhelper.js", HOSTILE.as_bytes()),
        eof(),
    ]
    .concat());
    assert_blocked(run_bytes(scripty(), v), "`main` names an 8.3 alias");
}

/// RN2-007 (PLAUSIBLE): Win32 drops trailing dots, so `BUILDH~1.JS.` is the
/// alias too; `is_short_name` splits at the last `.` and sees stem `BUILDH~1.JS`.
#[test]
fn rn2_007_trailing_dot_short_name_token_is_denied() {
    let p = scripty()
        .script("postinstall", "sh ./BUILDH~1.JS.")
        .file("buildhelper.js", HOSTILE);
    assert_blocked(run_pkg(p), "trailing dot after an 8.3 alias");
}
