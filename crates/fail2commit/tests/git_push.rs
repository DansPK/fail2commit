//! TC-001: real `git push` through the installed pre-push hook against
//! disposable bare remotes (FR-001, SPEC-001). Approval channels are not
//! available in this build, so every pause ends the push (fail closed); the
//! approved path is covered by unit tests with a scripted approver.

mod git_support;
use git_support::*;

fn setup_pair(name: &str) -> (Env, std::path::PathBuf, std::path::PathBuf) {
    let env = Env::new();
    let (work, remote) = env.repo_with_remote(name);
    env.setup();
    (env, work, remote)
}

#[test]
fn fast_forward_passes() {
    let (env, work, remote) = setup_pair("ff");
    let c = env.commit(&work, "a.txt", "one\n", "second");
    let o = env.push(&work, &["origin", "main"]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(env.head_of(&remote, "main"), c);
}

#[test]
fn first_branch_clean_passes_and_secret_env_pauses() {
    let (env, work, remote) = setup_pair("first");
    env.git(&work, &["checkout", "-q", "-b", "feature"]);
    env.commit(&work, "src/lib.txt", "code\n", "feature work");
    env.commit(&work, ".env.example", "TOKEN=\n", "template is fine");
    let o = env.push(&work, &["-u", "origin", "feature"]);
    assert!(o.status.success(), "{}", stderr(&o));

    env.git(&work, &["checkout", "-q", "-b", "leaky"]);
    env.commit(&work, "app/.env", "A=1\n", "oops");
    let o = env.push(&work, &["origin", "leaky"]);
    assert_blocked(&o, "Secret");
    assert!(!env.ref_exists(&remote, "refs/heads/leaky"));
}

#[test]
fn rewrite_blocked_for_force_and_both_lease_styles() {
    let (env, work, remote) = setup_pair("rw");
    let before = env.head_of(&remote, "main");
    env.git(&work, &["commit", "-q", "--amend", "-m", "rewritten"]);
    for args in [
        vec!["--force", "origin", "main"],
        vec!["-f", "origin", "main"],
        vec!["--force-with-lease", "origin", "main"],
        vec![
            "--force-with-lease=main:BEFORE",
            "--force-if-includes",
            "origin",
            "main",
        ],
        vec!["origin", "+main"],
    ] {
        let args: Vec<String> = args.iter().map(|a| a.replace("BEFORE", &before)).collect();
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = env.push(&work, &refs);
        assert_blocked(&o, "RefRewrite");
        assert_eq!(env.head_of(&remote, "main"), before, "{args:?}");
    }
}

#[test]
fn shim_force_intent_needs_confirmation_even_without_rewrite() {
    let (env, work, remote) = setup_pair("intent");
    let c = env.commit(&work, "a.txt", "one\n", "plain fast-forward");
    for args in [
        vec!["--force", "origin", "main"],
        vec!["-f", "origin", "main"],
        vec!["-fu", "origin", "main"],
        vec!["--force-with-lease", "origin", "main"],
        vec!["origin", "+main"],
        vec!["origin", "+refs/heads/*:refs/heads/*"],
    ] {
        let o = env.shim_push(&work, &args);
        assert_blocked(&o, "ForceIntent");
        assert_ne!(env.head_of(&remote, "main"), c, "{args:?}");
    }
    // Without force intent the same push goes through the shim untouched.
    let o = env.shim_push(&work, &["origin", "main"]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(env.head_of(&remote, "main"), c);
}

#[test]
fn configured_forced_refspec_and_mirror_are_intent() {
    let (env, work, remote) = setup_pair("cfg");
    let c = env.commit(&work, "a.txt", "one\n", "next");
    env.git(
        &work,
        &["config", "remote.origin.push", "+refs/heads/*:refs/heads/*"],
    );
    let o = env.shim_push(&work, &["origin"]);
    assert_blocked(&o, "ForceIntent");
    assert_ne!(env.head_of(&remote, "main"), c);
    // explicit unforced refspec overrides the configured one
    let o = env.shim_push(&work, &["origin", "main"]);
    assert!(o.status.success(), "{}", stderr(&o));
    env.git(&work, &["config", "--unset", "remote.origin.push"]);

    env.commit(&work, "b.txt", "two\n", "after mirror setup");
    let o = env.shim_push(&work, &["--mirror", "origin"]);
    assert_blocked(&o, "ForceIntent");
}

#[test]
fn multiple_refs_are_reviewed_in_one_plan() {
    let (env, work, remote) = setup_pair("multi");
    env.git(&work, &["checkout", "-q", "-b", "topic"]);
    env.commit(&work, "t.txt", "t\n", "topic");
    env.git(&work, &["push", "-q", "origin", "topic"]);
    let topic_before = env.head_of(&remote, "topic");
    env.git(&work, &["commit", "-q", "--amend", "-m", "topic rewritten"]);
    env.git(&work, &["checkout", "-q", "main"]);
    let main_new = env.commit(&work, "m.txt", "m\n", "main moves on");
    let o = env.push(&work, &["origin", "main", "+topic"]);
    assert_blocked(&o, "RefRewrite");
    let err = stderr(&o);
    assert!(err.contains("refs/heads/topic"), "{err}");
    assert!(!err.contains("target: refs/heads/main"), "{err}");
    assert_eq!(env.head_of(&remote, "topic"), topic_before);
    assert_ne!(env.head_of(&remote, "main"), main_new, "nothing is sent");
}

#[test]
fn tag_replacement_and_deletion_are_separate_findings() {
    let (env, work, remote) = setup_pair("tag");
    env.git(&work, &["tag", "v1"]);
    env.git(&work, &["push", "-q", "origin", "v1"]);
    env.commit(&work, "a.txt", "one\n", "later");
    env.git(&work, &["tag", "-f", "v1"]);
    let o = env.push(&work, &["origin", "+refs/tags/v1"]);
    assert_blocked(&o, "TagReplacement");

    env.git(&work, &["push", "-q", "origin", "main:refs/heads/doomed"]);
    for args in [
        vec!["origin", ":doomed"],
        vec!["--delete", "origin", "doomed"],
    ] {
        let o = env.push(&work, &args);
        assert_blocked(&o, "RefDeletion");
        assert!(env.ref_exists(&remote, "refs/heads/doomed"));
    }
}

#[test]
fn missing_old_object_is_a_finding_not_safe() {
    let (env, work, remote) = setup_pair("shallow");
    let other = env.root.join("other");
    env.git(
        &env.root,
        &["clone", "-q", &file_url(&remote), other.to_str().unwrap()],
    );
    env.commit(&other, "o.txt", "o\n", "from someone else");
    env.git(&other, &["push", "-q", "origin", "main"]);
    // `work` never fetched that commit; its view of the remote is stale.
    env.commit(&work, "w.txt", "w\n", "diverging");
    let o = env.push(&work, &["--force", "origin", "main"]);
    assert_blocked(&o, "IncompleteScan");
}

#[test]
fn sha256_repositories_are_supported() {
    let env = Env::new();
    let remote = env.root.join("s256.git");
    std::fs::create_dir_all(&remote).unwrap();
    let init = env
        .git_cmd(&remote)
        .args(["init", "-q", "--bare", "--object-format=sha256"])
        .output()
        .unwrap();
    if !init.status.success() {
        eprintln!("PENDING: git cannot init sha256 repositories here");
        return;
    }
    let work = env.root.join("s256");
    std::fs::create_dir_all(&work).unwrap();
    env.git(&work, &["init", "-q", "--object-format=sha256"]);
    env.git(&work, &["remote", "add", "origin", &file_url(&remote)]);
    env.commit(&work, "a", "1\n", "one");
    env.git(&work, &["push", "-q", "origin", "main"]);
    env.setup();
    let c = env.commit(&work, "b", "2\n", "two");
    let o = env.push(&work, &["origin", "main"]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(env.head_of(&remote, "main"), c);
    env.commit(&work, ".env", "X=1\n", "env");
    assert_blocked(&env.push(&work, &["origin", "main"]), "Secret");
    env.git(&work, &["reset", "-q", "--hard", "HEAD~1"]);
    env.git(&work, &["commit", "-q", "--amend", "-m", "again"]);
    assert_blocked(&env.push(&work, &["-f", "origin", "main"]), "RefRewrite");
}

#[test]
fn secrets_in_content_and_add_delete_history_are_found_and_redacted() {
    let (env, work, remote) = setup_pair("sec");
    let key = aws_key();
    env.commit(
        &work,
        "config/app.txt",
        &format!("key = {key}\n"),
        "add key",
    );
    env.commit(&work, "config/app.txt", "key = removed\n", "remove key");
    let o = env.push(&work, &["origin", "main"]);
    assert_blocked(&o, "Secret");
    let err = stderr(&o);
    assert!(err.contains("aws-access-key"), "{err}");
    assert!(!err.contains(&key), "secret value leaked: {err}");
    let before = env.head_of(&remote, "main");
    assert_ne!(env.head_of(&work, "HEAD"), before);

    // a deleted .env in outgoing history pauses too
    let (env, work, _remote) = setup_pair("sec2");
    env.commit(&work, ".env", "A=1\n", "add env");
    env.git(&work, &["rm", "-q", ".env"]);
    env.git(&work, &["commit", "-q", "-m", "drop env"]);
    let o = env.push(&work, &["origin", "main"]);
    assert_blocked(&o, "Secret");
    assert!(stderr(&o).contains(".env"));
}

#[test]
fn bounds_report_incomplete_scan() {
    let (env, work, _remote) = setup_pair("bounds");
    std::fs::create_dir_all(env.f2c_home.join("config")).unwrap();
    std::fs::write(
        env.f2c_home.join("config").join("settings.toml"),
        "[limits]\ngraph_max_nodes = 2\n",
    )
    .unwrap();
    for i in 0..4 {
        env.commit(&work, "f.txt", &format!("{i}\n"), "c");
    }
    assert_blocked(&env.push(&work, &["origin", "main"]), "IncompleteScan");

    std::fs::write(
        env.f2c_home.join("config").join("settings.toml"),
        "[limits]\nscan_max_bytes = 10\n",
    )
    .unwrap();
    env.commit(
        &work,
        "big.txt",
        &"line of text
"
        .repeat(20),
        "big",
    );
    assert_blocked(&env.push(&work, &["origin", "main"]), "IncompleteScan");
}

#[cfg(unix)]
#[test]
fn non_utf8_and_newline_filenames_are_handled() {
    use std::os::unix::ffi::OsStrExt;
    let (env, work, _remote) = setup_pair("bytes");
    let name = std::ffi::OsStr::from_bytes(b"dir\xffname\n/.env");
    let p = work.join(name);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, "A=1\n").unwrap();
    env.git(&work, &["add", "-A"]);
    env.git(&work, &["commit", "-q", "-m", "weird"]);
    assert_blocked(&env.push(&work, &["origin", "main"]), "Secret");
}

#[test]
fn non_push_commands_pass_through_with_exact_status() {
    let (env, work, _remote) = setup_pair("pass");
    let o = env
        .f2c_cmd(&env.root)
        .args(["git", "-C", work.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(o.status.success());
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        env.head_of(&work, "HEAD")
    );
    let o = env
        .f2c_cmd(&work)
        .args(["git", "rev-parse", "--verify", "no-such-ref"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(128));
    let o = env
        .f2c_cmd(&work)
        .args(["git", "--version"])
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("git version"));
}

#[test]
fn secret_scan_command_reports_without_pushing() {
    let (env, work, remote) = setup_pair("scancmd");
    let o = env.f2c_cmd(&work).arg("secret-scan").output().unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    env.commit(&work, ".env.local", "A=1\n", "env");
    let o = env.f2c_cmd(&work).arg("secret-scan").output().unwrap();
    assert_eq!(o.status.code(), Some(10));
    assert!(stderr(&o).contains("Secret"));
    let o = env
        .f2c_cmd(&work)
        .args(["--json", "secret-scan"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["code"], "rejected");
    assert_eq!(v["findings"][0]["kind"], "secret");
    assert_ne!(env.head_of(&remote, "main"), env.head_of(&work, "HEAD"));
}
