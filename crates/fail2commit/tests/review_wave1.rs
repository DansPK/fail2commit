//! Regression tests for the independent wave-1 security review
//! (W1-001..W1-003, FR-001/FR-002). They failed on the reviewed candidate and
//! now assert the fixed behavior. Everything is offline and unattended.

use fail2commit_core::git::{classify_updates, prepush, scan_outgoing, RefUpdate};
use fail2commit_core::protocol::{Finding, FindingAction, FindingKind};
use fail2commit_core::settings::Limits;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(repo: &Path, config: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", config)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("run git");
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
    git(&root, &config, &["init", "-q", "-b", "main"]);
    (tmp, root, config)
}

fn update(new: String) -> RefUpdate {
    RefUpdate {
        refname: "refs/heads/main".into(),
        old: "0".repeat(new.len()),
        new,
    }
}

fn real_git() -> PathBuf {
    fail2commit_core::toolpath::find_real("git", None).unwrap()
}

fn commit_file(root: &Path, config: &Path, name: &str, contents: &[u8]) -> String {
    std::fs::write(root.join(name), contents).unwrap();
    git(root, config, &["add", name]);
    git(root, config, &["commit", "-qm", name]);
    git(root, config, &["rev-parse", "HEAD"])
}

fn scan(root: &Path, new: String, limits: &Limits) -> Vec<Finding> {
    scan_outgoing(&real_git(), root, &[update(new)], Some("origin"), limits).unwrap()
}

fn has(f: &[Finding], k: FindingKind) -> bool {
    f.iter().any(|f| f.kind == k)
}

fn aws() -> String {
    ["AKIA", "QX7M2K9P4R8T3V6W"].concat()
}

// ---- W1-001 -------------------------------------------------------------

#[test]
fn repository_controlled_remote_tracking_ref_must_not_hide_outgoing_secret() {
    let (_tmp, root, config) = repo();
    let head = commit_file(
        &root,
        &config,
        "credentials.txt",
        format!("aws_key={}\n", aws()).as_bytes(),
    );
    git(
        &root,
        &config,
        &["remote", "add", "origin", "file:///does-not-exist"],
    );
    git(
        &root,
        &config,
        &["update-ref", "refs/remotes/origin/attacker", &head],
    );
    let findings = scan(&root, head, &Limits::default());
    assert!(
        has(&findings, FindingKind::Secret),
        "a local remote-tracking ref hid the outgoing secret: {findings:?}"
    );
}

#[test]
fn only_the_remote_reported_old_oid_excludes_history() {
    let (_tmp, root, config) = repo();
    let old = commit_file(&root, &config, "a.txt", format!("k={}\n", aws()).as_bytes());
    let new = commit_file(&root, &config, "b.txt", b"clean\n");
    git(&root, &config, &["remote", "add", "origin", "file:///x"]);
    // The remote reported `old`: its secret is already published, not outgoing.
    let u = RefUpdate {
        refname: "refs/heads/main".into(),
        old,
        new: new.clone(),
    };
    let f = scan_outgoing(&real_git(), &root, &[u], Some("origin"), &Limits::default()).unwrap();
    assert!(f.is_empty(), "{f:?}");
    // A zero old oid (new branch) excludes nothing.
    assert!(has(
        &scan(&root, new, &Limits::default()),
        FindingKind::Secret
    ));
}

#[test]
fn missing_old_object_scans_everything_and_requires_the_password() {
    let (_tmp, root, config) = repo();
    let head = commit_file(&root, &config, "a.txt", format!("k={}\n", aws()).as_bytes());
    let u = RefUpdate {
        refname: "refs/heads/main".into(),
        old: "1".repeat(head.len()),
        new: head,
    };
    let git = real_git();
    let mut f = classify_updates(&git, &root, std::slice::from_ref(&u)).unwrap();
    assert!(has(&f, FindingKind::IncompleteScan) && has(&f, FindingKind::RefRewrite));
    assert!(prepush::needs_password(&f));
    f.extend(scan_outgoing(&git, &root, &[u], Some("origin"), &Limits::default()).unwrap());
    assert!(
        has(&f, FindingKind::Secret),
        "unknown old must not hide history"
    );
}

// ---- W1-002 -------------------------------------------------------------

fn finding(kind: FindingKind) -> Finding {
    Finding::new(kind, FindingAction::Approve, "git.pre-push", "x")
}

#[test]
fn tag_replacement_must_require_the_configured_force_push_password() {
    for k in [
        FindingKind::TagReplacement,
        FindingKind::RefDeletion,
        FindingKind::RefRewrite,
        FindingKind::ForceIntent,
    ] {
        assert!(prepush::needs_password(&[finding(k)]), "{k:?}");
    }
    for k in [FindingKind::Secret, FindingKind::IncompleteScan] {
        assert!(!prepush::needs_password(&[finding(k)]), "{k:?}");
    }
}

// ---- W1-003 -------------------------------------------------------------

#[test]
fn blob_past_the_old_4mib_prefix_is_scanned() {
    let (_tmp, root, config) = repo();
    let mut contents = vec![b'a'; 4 * 1024 * 1024];
    contents.push(b'\n');
    contents.extend_from_slice(format!("aws_key={}\n", aws()).as_bytes());
    let head = commit_file(&root, &config, "large.txt", &contents);
    let f = scan(&root, head, &Limits::default());
    assert!(has(&f, FindingKind::Secret), "{f:?}");
}

#[test]
fn blob_over_the_single_file_limit_is_incomplete_not_clean() {
    let (_tmp, root, config) = repo();
    let head = commit_file(&root, &config, "huge.txt", &vec![b'a'; 33 * 1024 * 1024]);
    let f = scan(&root, head, &Limits::default());
    assert!(has(&f, FindingKind::IncompleteScan), "{f:?}");
}

#[test]
fn full_object_size_is_charged_against_the_budget() {
    let (_tmp, root, config) = repo();
    let head = commit_file(&root, &config, "a.txt", &vec![b'a'; 100_000]);
    let limits = Limits {
        scan_max_bytes: 50_000,
        ..Limits::default()
    };
    assert!(has(
        &scan(&root, head.clone(), &limits),
        FindingKind::IncompleteScan
    ));
    let ok = Limits {
        scan_max_bytes: 100_000,
        ..Limits::default()
    };
    assert!(scan(&root, head, &ok).is_empty());
}

#[test]
fn missing_blob_is_incomplete_not_clean() {
    let (_tmp, root, config) = repo();
    let head = commit_file(&root, &config, "a.txt", b"payload\n");
    let blob = git(&root, &config, &["rev-parse", "HEAD:a.txt"]);
    let loose = root.join(".git/objects").join(&blob[..2]).join(&blob[2..]);
    let mut perm = std::fs::metadata(&loose).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perm.set_readonly(false);
    std::fs::set_permissions(&loose, perm).unwrap();
    std::fs::remove_file(&loose).unwrap();
    let f = scan(&root, head, &Limits::default());
    assert!(has(&f, FindingKind::IncompleteScan), "{f:?}");
}

#[test]
fn binary_blob_is_scanned_not_skipped_and_env_names_still_match() {
    let (_tmp, root, config) = repo();
    let mut bin = vec![0u8; 64];
    bin.extend_from_slice(format!(" aws_key={} ", aws()).as_bytes());
    commit_file(&root, &config, "blob.bin", &bin);
    commit_file(&root, &config, ".env", &[0u8, 1, 2, 3]);
    let head = git(&root, &config, &["rev-parse", "HEAD"]);
    let f = scan(&root, head, &Limits::default());
    let ev: Vec<&str> = f.iter().map(|f| f.evidence.as_str()).collect();
    assert!(ev.iter().any(|e| e.contains("aws-access-key")), "{f:?}");
    assert!(
        ev.iter().any(|e| e.contains("environment file .env")),
        "{f:?}"
    );
}

#[test]
fn secret_inside_an_overlong_line_is_found() {
    let (_tmp, root, config) = repo();
    let line = format!(
        "{}aws_key={}{}\n",
        "x ".repeat(10_000),
        aws(),
        " y".repeat(10_000)
    );
    let head = commit_file(&root, &config, "min.js", line.as_bytes());
    let f = scan(&root, head, &Limits::default());
    assert!(has(&f, FindingKind::Secret), "{f:?}");
}
