//! Second re-review reproductions for the Git secret scan (R2-###). Each test
//! asserts the SECURE behavior; a failing test is a confirmed finding.
//! Offline, disposable repositories, synthetic secrets only.

use fail2commit_core::git::{scan_outgoing, RefUpdate};
use fail2commit_core::protocol::{Finding, FindingKind};
use fail2commit_core::settings::Limits;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn git_in(repo: &Path, config: &Path, args: &[&str], stdin: Option<&[u8]>) -> String {
    use std::io::Write;
    let mut c = Command::new("git");
    c.current_dir(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", config)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().expect("run git");
    if let Some(b) = stdin {
        child.stdin.take().unwrap().write_all(b).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn repo() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    let config = tmp.path().join("gitconfig");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(
        &config,
        "[user]\n\tname = Review\n\temail = review@example.invalid\n[core]\n\tautocrlf = false\n",
    )
    .unwrap();
    git_in(&root, &config, &["init", "-q", "-b", "main"], None);
    (tmp, root, config)
}

fn commit_file(root: &Path, config: &Path, name: &str, contents: &[u8]) -> String {
    std::fs::write(root.join(name), contents).unwrap();
    git_in(root, config, &["add", name], None);
    git_in(root, config, &["commit", "-qm", name], None);
    git_in(root, config, &["rev-parse", "HEAD"], None)
}

fn real_git() -> PathBuf {
    fail2commit_core::toolpath::find_real("git", None).unwrap()
}

fn aws() -> String {
    ["AKIA", "QX7M2K9P4R8T3V6W"].concat()
}

fn has(f: &[Finding], k: FindingKind) -> bool {
    f.iter().any(|f| f.kind == k)
}

fn scan_main(root: &Path, head: String) -> Vec<Finding> {
    scan_outgoing(
        &real_git(),
        root,
        &[RefUpdate {
            refname: "refs/heads/main".into(),
            old: "0".repeat(head.len()),
            new: head,
        }],
        Some("origin"),
        &Limits::default(),
    )
    .unwrap()
}

fn caught(f: &[Finding]) -> bool {
    has(f, FindingKind::Secret) || has(f, FindingKind::IncompleteScan)
}

/// R2-001: BOM-less UTF-16LE text diluted with non-ASCII characters (few NUL
/// bytes) is neither decoded nor reported incomplete.
#[test]
fn r2_001_bomless_utf16_diluted_with_cjk_must_not_be_clean() {
    let mut text = format!("aws_key={}\n", aws());
    text.push_str(&"\u{3042}".repeat(400)); // 2 bytes, no NUL
    let bytes: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let (_tmp, root, config) = repo();
    let head = commit_file(&root, &config, "k.txt", &bytes);
    let f = scan_main(&root, head);
    assert!(caught(&f), "diluted BOM-less UTF-16 reported clean: {f:?}");
}

/// R2-002: BOM-less UTF-32LE ASCII text (three NULs in four) is neither
/// decoded nor reported incomplete.
#[test]
fn r2_002_bomless_utf32_must_not_be_clean() {
    let bytes: Vec<u8> = format!("aws_key={}\n", aws())
        .chars()
        .flat_map(|c| (c as u32).to_le_bytes())
        .collect();
    let (_tmp, root, config) = repo();
    let head = commit_file(&root, &config, "k.txt", &bytes);
    let f = scan_main(&root, head);
    assert!(caught(&f), "BOM-less UTF-32 reported clean: {f:?}");
}

/// R2-003: `secret-scan` reads HEAD with an unhardened `git rev-parse`; a
/// replace ref on the HEAD commit must not change which commit is scanned.
#[test]
fn r2_003_secret_scan_head_must_not_follow_replace_ref() {
    let (tmp, root, config) = repo();
    commit_file(&root, &config, "a.txt", b"1\n");
    let head = commit_file(
        &root,
        &config,
        "credentials.txt",
        format!("aws_key={}\n", aws()).as_bytes(),
    );
    // A clean commit (same tree as the first one) to stand in for HEAD.
    let clean = git_in(&root, &config, &["rev-parse", "HEAD~1"], None);
    git_in(&root, &config, &["replace", &head, &clean], None);
    let shown = git_in(&root, &config, &["rev-parse", "--verify", "HEAD"], None);
    assert_eq!(shown, head, "precondition: rev-parse HEAD is not replaced");
    let out = Command::new(env!("CARGO_BIN_EXE_fail2commit"))
        .current_dir(&root)
        .args(["secret-scan", "origin"])
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("FAIL2COMMIT_HOME", tmp.path().join("f2c"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "secret-scan clean with a replace ref on HEAD: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// R2-004: repository config `log.showSignature` + `gpg.program` makes the
/// scanner's `git log` execute a repository-named program on a signed commit.
#[test]
fn r2_004_scan_must_not_run_repository_named_gpg_program() {
    let (tmp, root, config) = repo();
    let marker = tmp.path().join("executed.txt");
    let prog = tmp.path().join("fakegpg.sh");
    std::fs::write(
        &prog,
        format!(
            "#!/bin/sh\necho ran > '{}'\nexit 1\n",
            marker.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    let head = commit_file(&root, &config, "a.txt", b"1\n");
    // Re-create HEAD with a fake gpgsig header so `log` tries to verify it.
    let raw = git_in(&root, &config, &["cat-file", "commit", &head], None);
    let (hdr, msg) = raw.split_once("\n\n").unwrap();
    let signed = format!("{hdr}\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n x\n -----END PGP SIGNATURE-----\n\n{msg}\n");
    let signed_oid = git_in(
        &root,
        &config,
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        Some(signed.as_bytes()),
    );
    git_in(
        &root,
        &config,
        &["update-ref", "refs/heads/main", &signed_oid],
        None,
    );
    git_in(
        &root,
        &config,
        &["config", "log.showSignature", "true"],
        None,
    );
    git_in(
        &root,
        &config,
        &[
            "config",
            "gpg.program",
            &prog.to_string_lossy().replace('\\', "/"),
        ],
        None,
    );
    let _ = scan_outgoing(
        &real_git(),
        &root,
        &[RefUpdate {
            refname: "refs/heads/main".into(),
            old: "0".repeat(signed_oid.len()),
            new: signed_oid,
        }],
        Some("origin"),
        &Limits::default(),
    );
    assert!(
        !marker.exists(),
        "the scanner executed the repository-configured gpg.program"
    );
}
