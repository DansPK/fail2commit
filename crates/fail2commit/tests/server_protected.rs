//! TC-003 (FR-003, SPEC-003): protected remote updates against disposable
//! bare repositories with the real installed pre-receive hook.

mod server_support;
use server_support::{text, Fx};

const MAIN: &str = "refs/heads/main";

#[test]
fn direct_force_push_without_local_hooks_is_rejected() {
    let fx = Fx::new(MAIN);
    let before = fx.remote_ref(MAIN);
    fx.rewrite();
    let out = fx.force_push(None, Some("alice"));
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("protected ref"), "{}", text(&out));
    assert_eq!(fx.remote_ref(MAIN), before);
    // The client skipping its hooks changes nothing server-side.
    let mut out = fx.cmd(
        &fx.work,
        &["push", "--no-verify", "--force", "origin", "main"],
        Some("alice"),
    );
    assert!(!out.output().unwrap().status.success());
    assert_eq!(fx.remote_ref(MAIN), before);
}

#[test]
fn approved_rewrite_succeeds() {
    let fx = Fx::new(MAIN);
    let (old, new) = fx.rewrite();
    let token = fx.approve("alice", MAIN, &old, &new, 60);
    let stored = std::fs::read_to_string(fx.state.join("approvals.json")).unwrap();
    assert!(!stored.contains(&token), "only a verifier may be stored");
    let out = fx.force_push(Some(&token), Some("alice"));
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(fx.remote_ref(MAIN), new);
}

#[test]
fn replayed_token_fails() {
    let fx = Fx::new(MAIN);
    let (old, new) = fx.rewrite();
    let token = fx.approve("alice", MAIN, &old, &new, 60);
    assert!(fx.force_push(Some(&token), Some("alice")).status.success());
    // Maintainer resets the remote to the same starting point; same tuples.
    fx.git_ok(&fx.remote, &["update-ref", MAIN, &old], None);
    let out = fx.force_push(Some(&token), Some("alice"));
    assert!(!out.status.success(), "{}", text(&out));
    assert_eq!(fx.remote_ref(MAIN), old);
}

#[test]
fn concurrent_pushes_with_one_token_allow_exactly_one() {
    let fx = Fx::new(MAIN);
    let (old, new) = fx.rewrite();
    let token = fx.approve("alice", MAIN, &old, &new, 60);
    let kids: Vec<_> = (0..2)
        .map(|_| {
            fx.force_push_cmd(Some(&token), Some("alice"))
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let ok = kids
        .into_iter()
        .map(|k| k.wait_with_output().unwrap())
        .filter(|o| o.status.success())
        .count();
    assert_eq!(ok, 1);
    assert_eq!(fx.remote_ref(MAIN), new);
}

#[test]
fn token_for_other_tuples_actor_or_expired_fails() {
    let fx = Fx::new(MAIN);
    let (old, new) = fx.rewrite();
    let other_new = fx.commit("b.txt", "other"); // a different target commit
    fx.git_ok(&fx.work, &["reset", "-q", "--hard", &new], None);

    let wrong_tuple = fx.approve("alice", MAIN, &old, &other_new, 60);
    let out = fx.force_push(Some(&wrong_tuple), Some("alice"));
    assert!(!out.status.success(), "{}", text(&out));

    let wrong_actor = fx.approve("alice", MAIN, &old, &new, 60);
    let out = fx.force_push(Some(&wrong_actor), Some("mallory"));
    assert!(!out.status.success(), "{}", text(&out));
    // A failed attempt burned it: the rightful actor now needs fresh approval.
    assert!(!fx
        .force_push(Some(&wrong_actor), Some("alice"))
        .status
        .success());

    let expiring = fx.approve("alice", MAIN, &old, &new, 1);
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let out = fx.force_push(Some(&expiring), Some("alice"));
    assert!(!out.status.success(), "{}", text(&out));

    let junk = fx.force_push(Some("f2ca-not-a-real-token"), Some("alice"));
    assert!(!junk.status.success());
    let no_actor = fx.approve("alice", MAIN, &old, &new, 60);
    assert!(!fx.force_push(Some(&no_actor), None).status.success());
    assert_eq!(fx.remote_ref(MAIN), old);
}

#[test]
fn fast_forward_and_unprotected_refs_pass() {
    let fx = Fx::new(MAIN);
    fx.commit("a.txt", "two");
    let out = fx.git(&fx.work, &["push", "origin", "main"], Some("alice"));
    assert!(out.status.success(), "ff on protected: {}", text(&out));

    fx.git_ok(
        &fx.work,
        &["push", "-q", "origin", "main:refs/heads/feature"],
        None,
    );
    fx.git_ok(&fx.work, &["commit", "-q", "--amend", "-m", "again"], None);
    let out = fx.git(
        &fx.work,
        &["push", "--force", "origin", "main:refs/heads/feature"],
        None,
    );
    assert!(
        out.status.success(),
        "rewrite of unprotected: {}",
        text(&out)
    );
}

#[test]
fn deleting_protected_ref_is_denied_without_approval() {
    let fx = Fx::new("refs/heads/*");
    // Not the remote's HEAD branch, which Git itself refuses to delete.
    let rel = "refs/heads/rel";
    fx.git_ok(
        &fx.work,
        &["push", "-q", "origin", "main:refs/heads/rel"],
        None,
    );
    let before = fx.remote_ref(rel);
    let del = format!(":{rel}");
    let out = fx.git(&fx.work, &["push", "origin", &del], Some("alice"));
    assert!(!out.status.success(), "{}", text(&out));
    assert_eq!(fx.remote_ref(rel), before);

    // With approval bound to the exact deletion tuple it is allowed.
    let zero = "0".repeat(before.len());
    let token = fx.approve("alice", rel, &before, &zero, 60);
    let opt = format!("f2c-approval={token}");
    let out = fx.git(
        &fx.work,
        &["push", "-o", &opt, "origin", &del],
        Some("alice"),
    );
    assert!(out.status.success(), "{}", text(&out));
}

#[test]
fn missing_policy_fails_closed() {
    let fx = Fx::new(MAIN);
    std::fs::remove_file(fx.state.join("server.toml")).unwrap();
    fx.commit("a.txt", "two");
    let out = fx.git(&fx.work, &["push", "origin", "main"], Some("alice"));
    assert!(!out.status.success(), "{}", text(&out));
}

#[test]
fn configured_secret_policy_denies_and_never_echoes_the_value() {
    let fx = Fx::new(MAIN);
    let cfg = std::fs::read_to_string(fx.state.join("server.toml")).unwrap();
    std::fs::write(
        fx.state.join("server.toml"),
        cfg.replace("secret_policy = false", "secret_policy = true"),
    )
    .unwrap();
    let secret = ["AKIA", "IOSFODNN7EXAMPLE"].concat(); // built at runtime
    fx.commit("cfg.txt", &format!("aws_key = {secret}"));
    let out = fx.git(&fx.work, &["push", "origin", "main"], Some("alice"));
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains(&secret), "secret leaked");
}
