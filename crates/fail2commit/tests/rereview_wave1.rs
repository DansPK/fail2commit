//! Re-review regression tests for wave 1 (R1-001..R1-003, R1-005). Each test
//! asserts the SECURE behavior and failed on candidate d163faa. Offline,
//! unattended, with disposable repositories and synthetic secrets only.

mod server_support;

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

fn scan_tag(root: &Path, oid: String) -> Vec<Finding> {
    scan_outgoing(
        &real_git(),
        root,
        &[create("refs/tags/leak", oid)],
        Some("origin"),
        &Limits::default(),
    )
    .unwrap()
}

fn secret_blob_and_tree(root: &Path, config: &Path, content: &[u8]) -> (String, String) {
    let blob = git_in(
        root,
        config,
        &["hash-object", "-w", "--stdin"],
        Some(content),
    );
    let tree = git_in(
        root,
        config,
        &["mktree"],
        Some(format!("100644 blob {blob}\tdir.txt\n").as_bytes()),
    );
    (blob, tree)
}

/// R1-002: annotated tags to a tree, and a tag of a tag of a tree/blob, are
/// peeled and their blobs scanned.
#[test]
fn r1_002_annotated_and_nested_tags_are_peeled() {
    let (_tmp, root, config) = repo();
    commit_file(&root, &config, "a.txt", b"1\n");
    let (blob, tree) =
        secret_blob_and_tree(&root, &config, format!("aws_key={}\n", aws()).as_bytes());
    for (what, target) in [("tree", &tree), ("blob", &blob)] {
        git_in(
            &root,
            &config,
            &["tag", "-a", "-m", "inner", &format!("inner-{what}"), target],
            None,
        );
        let inner = git_in(
            &root,
            &config,
            &["rev-parse", &format!("inner-{what}")],
            None,
        );
        git_in(
            &root,
            &config,
            &["tag", "-a", "-m", "outer", &format!("outer-{what}"), &inner],
            None,
        );
        for name in [format!("inner-{what}"), format!("outer-{what}")] {
            let tag = git_in(&root, &config, &["rev-parse", &name], None);
            let f = scan_tag(&root, tag);
            assert!(
                has(&f, FindingKind::Secret),
                "annotated tag {name} to {what} hid the secret: {f:?}"
            );
        }
    }
}

/// R1-002: a tip whose object is absent fails closed.
#[test]
fn r1_002_unresolvable_tip_is_incomplete() {
    let (_tmp, root, config) = repo();
    commit_file(&root, &config, "a.txt", b"1\n");
    let f = scan_tag(&root, "1".repeat(40));
    assert!(has(&f, FindingKind::IncompleteScan), "{f:?}");
}

/// R1-005: a UTF-16 file (BOM and BOM-less, LE and BE) is decoded and scanned.
#[test]
fn r1_005_utf16_secret_is_found() {
    let text = format!("aws_key={}\n", aws());
    let le: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let be: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    let mut le_bom = vec![0xFF, 0xFE];
    le_bom.extend(&le);
    let mut be_bom = vec![0xFE, 0xFF];
    be_bom.extend(&be);
    for (what, bytes) in [
        ("le", le),
        ("be", be),
        ("le-bom", le_bom),
        ("be-bom", be_bom),
    ] {
        let (_tmp, root, config) = repo();
        let head = commit_file(&root, &config, "k.txt", &bytes);
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
            "UTF-16 {what} not scanned: {f:?}"
        );
    }
}

/// R1-005: UTF-32 (BOM) cannot be decoded here, so it is never reported clean.
#[test]
fn r1_005_utf32_is_incomplete_not_clean() {
    let (_tmp, root, config) = repo();
    let mut bytes = vec![0xFF, 0xFE, 0, 0];
    bytes.extend(
        format!("aws_key={}\n", aws())
            .chars()
            .flat_map(|c| (c as u32).to_le_bytes()),
    );
    let head = commit_file(&root, &config, "k.txt", &bytes);
    let f = scan_outgoing(
        &real_git(),
        &root,
        &[create("refs/heads/main", head)],
        Some("origin"),
        &Limits::default(),
    )
    .unwrap();
    assert!(has(&f, FindingKind::IncompleteScan), "{f:?}");
}

/// R1-001 on the server path: a pusher plants `refs/replace/<secret>` in the
/// unprotected namespace first, then pushes the secret to the protected branch.
#[test]
fn r1_001_server_replace_ref_must_not_defeat_secret_policy() {
    use server_support::{text, Fx};
    let fx = Fx::new("refs/heads/main");
    let cfg = std::fs::read_to_string(fx.state.join("server.toml")).unwrap();
    std::fs::write(
        fx.state.join("server.toml"),
        cfg.replace("secret_policy = false", "secret_policy = true"),
    )
    .unwrap();
    let secret = aws();
    fx.commit("cfg.txt", &format!("aws_key = {secret}\n"));
    let secret_blob = fx.rev(&fx.work, "HEAD:cfg.txt");
    let clean = fx.git_ok(&fx.work, &["hash-object", "-w", "--stdin"], None);
    let _ = clean; // stdin is null: empty blob, which is clean content too
    fx.git_ok(&fx.work, &["replace", &secret_blob, &clean], None);
    let rr = format!("refs/replace/{secret_blob}");
    let planted = fx.git(&fx.work, &["push", "origin", &format!("{rr}:{rr}")], None);
    assert!(planted.status.success(), "{}", text(&planted));
    let out = fx.git(&fx.work, &["push", "origin", "main"], Some("alice"));
    assert!(
        !out.status.success(),
        "replace ref hid the secret: {}",
        text(&out)
    );
    assert!(!text(&out).contains(&secret), "secret leaked");
}
