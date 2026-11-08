//! Independent wave-1 security review reproductions.
//!
//! These tests intentionally fail on the reviewed candidate. They document
//! approval and secret-scan bypasses that must be fixed before integration.

use fail2commit_core::git::{prepush, scan_outgoing, RefUpdate};
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

#[test]
fn repository_controlled_remote_tracking_ref_must_not_hide_outgoing_secret() {
    let (_tmp, root, config) = repo();
    let secret = ["AKIA", "QX7M2K9P4R8T3V6W"].concat();
    std::fs::write(root.join("credentials.txt"), format!("aws_key={secret}\n")).unwrap();
    git(&root, &config, &["add", "credentials.txt"]);
    git(&root, &config, &["commit", "-qm", "secret"]);
    let head = git(&root, &config, &["rev-parse", "HEAD"]);

    // This ref is local, repository-controlled state. It is not evidence that
    // the remote has the commit, but the candidate passes --remotes=origin to
    // rev-list and therefore excludes HEAD from the scan.
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

    let real_git = fail2commit_core::toolpath::find_real("git", None).unwrap();
    let findings = scan_outgoing(
        &real_git,
        &root,
        &[update(head)],
        Some("origin"),
        &Limits::default(),
    )
    .unwrap();
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::Secret),
        "a local remote-tracking ref hid the outgoing secret: {findings:?}"
    );
}

#[test]
fn large_blob_truncation_must_not_report_a_clean_scan() {
    let (_tmp, root, config) = repo();
    let secret = ["AKIA", "QX7M2K9P4R8T3V6W"].concat();
    let mut contents = vec![b'a'; 4 * 1024 * 1024];
    contents.push(b'\n');
    contents.extend_from_slice(format!("aws_key={secret}\n").as_bytes());
    std::fs::write(root.join("large.txt"), contents).unwrap();
    git(&root, &config, &["add", "large.txt"]);
    git(&root, &config, &["commit", "-qm", "large"]);
    let head = git(&root, &config, &["rev-parse", "HEAD"]);

    let real_git = fail2commit_core::toolpath::find_real("git", None).unwrap();
    let findings =
        scan_outgoing(&real_git, &root, &[update(head)], None, &Limits::default()).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| { matches!(f.kind, FindingKind::Secret | FindingKind::IncompleteScan) }),
        "content beyond the 4 MiB prefix was skipped without an incomplete finding: {findings:?}"
    );
}

#[test]
fn tag_replacement_must_require_the_configured_force_push_password() {
    let findings = vec![Finding::new(
        FindingKind::TagReplacement,
        FindingAction::Approve,
        "git.pre-push",
        "existing tag moved",
    )];
    assert!(
        prepush::needs_password(&findings),
        "a tag replacement is an actual rewrite and must require the configured password"
    );
}
