//! Re-review reproductions for wave 1 (R1-001..R1-003). Each test asserts the
//! SECURE behavior and fails on candidate d163faa. Offline, unattended, with
//! disposable repositories and synthetic secrets only.

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

fn create(refname: &str, new: String) -> RefUpdate {
    RefUpdate {
        refname: refname.into(),
        old: "0".repeat(new.len()),
        new,
    }
}

/// R1-001: a local `refs/replace/<blob>` ref swaps the secret blob for a
/// clean one in the scanner's view, while push still sends the real object.
#[test]
fn r1_001_replace_ref_must_not_hide_secret_blob() {
    let (_tmp, root, config) = repo();
    let head = commit_file(
        &root,
        &config,
        "credentials.txt",
        format!("aws_key={}\n", aws()).as_bytes(),
    );
    let secret_blob = git_in(&root, &config, &["rev-parse", "HEAD:credentials.txt"], None);
    let clean_blob = git_in(
        &root,
        &config,
        &["hash-object", "-w", "--stdin"],
        Some(b"nothing to see\n"),
    );
    git_in(
        &root,
        &config,
        &["replace", &secret_blob, &clean_blob],
        None,
    );
    let f = scan_outgoing(
        &real_git(),
        &root,
        &[create("refs/heads/main", head)],
        Some("origin"),
        &Limits::default(),
    )
    .unwrap();
    assert!(
        has(&f, FindingKind::Secret),
        "replace ref hid the outgoing secret blob: {f:?}"
    );
}

/// R1-002: a tag (or any ref) whose new value is a non-commit object is never
/// walked: `git log <blob>` exits 0 with no output, so the scan is silently empty.
#[test]
fn r1_002_tag_to_blob_or_tree_must_not_be_unscanned() {
    let (_tmp, root, config) = repo();
    commit_file(&root, &config, "a.txt", b"1\n");
    let blob = git_in(
        &root,
        &config,
        &["hash-object", "-w", "--stdin"],
        Some(format!("aws_key={}\n", aws()).as_bytes()),
    );
    let tree = git_in(
        &root,
        &config,
        &["mktree"],
        Some(format!("100644 blob {blob}\tcredentials.txt\n").as_bytes()),
    );
    for (what, oid) in [("blob", blob), ("tree", tree)] {
        let f = scan_outgoing(
            &real_git(),
            &root,
            &[create("refs/tags/leak", oid)],
            Some("origin"),
            &Limits::default(),
        )
        .unwrap();
        assert!(
            has(&f, FindingKind::Secret) || has(&f, FindingKind::IncompleteScan),
            "tag to {what} was treated as clean: {f:?}"
        );
    }
}

/// R1-003: `secret-scan` feeds the repository-controlled
/// `refs/remotes/<remote>/<branch>` as the "remote's old OID".
#[test]
fn r1_003_secret_scan_command_must_not_trust_remote_tracking_ref() {
    let (tmp, root, config) = repo();
    let head = commit_file(
        &root,
        &config,
        "credentials.txt",
        format!("aws_key={}\n", aws()).as_bytes(),
    );
    git_in(
        &root,
        &config,
        &["remote", "add", "origin", "file:///does-not-exist"],
        None,
    );
    git_in(
        &root,
        &config,
        &["update-ref", "refs/remotes/origin/main", &head],
        None,
    );
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
        "secret-scan reported clean because refs/remotes/origin/main = HEAD: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
