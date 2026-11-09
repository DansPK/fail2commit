//! Setup, uninstall and hook chaining (FR-001, SPEC-001).

mod git_support;
use git_support::*;
use std::path::Path;

fn global(env: &Env) -> Option<String> {
    let o = env
        .git_cmd(&env.root)
        .args(["config", "--global", "--get", "core.hooksPath"])
        .output()
        .unwrap();
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn write_hook(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn setup_installs_owned_changes_and_uninstall_restores_them() {
    let env = Env::new();
    let prior = env.root.join("my hooks");
    env.git(
        &env.root,
        &[
            "config",
            "--global",
            "core.hooksPath",
            prior.to_str().unwrap(),
        ],
    );
    std::fs::write(&env.path_target, "export KEEP=1\n").unwrap();
    let cfg_before = std::fs::read_to_string(&env.gitcfg).unwrap();

    env.setup();
    env.setup(); // idempotent: must not record our own value as "previous"
    let hooks = global(&env).unwrap();
    assert!(hooks.ends_with("/hooks"), "{hooks}");
    assert!(Path::new(&hooks).join("pre-push").is_file());
    let profile = std::fs::read_to_string(&env.path_target).unwrap();
    assert!(profile.starts_with("export KEEP=1\n") && profile.contains("fail2commit"));
    let shim = env
        .f2c_home
        .join("bin")
        .join(if cfg!(windows) { "git.exe" } else { "git" });
    assert!(shim.is_file());

    let o = env.f2c_cmd(&env.root).arg("status").output().unwrap();
    assert!(o.status.success());

    let o = env
        .f2c_cmd(&env.root)
        .arg("uninstall-integrations")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(global(&env).as_deref(), prior.to_str());
    assert_eq!(
        std::fs::read_to_string(&env.path_target).unwrap(),
        "export KEEP=1\n"
    );
    assert!(!shim.exists());
    assert!(!Path::new(&hooks).join("pre-push").exists());
    // the user's own config content is otherwise untouched
    let after = std::fs::read_to_string(&env.gitcfg).unwrap();
    assert!(after.starts_with(&cfg_before));
}

#[test]
fn uninstall_without_prior_hookspath_unsets_it_and_leaves_changed_values() {
    let env = Env::new();
    env.setup();
    env.f2c_cmd(&env.root)
        .arg("uninstall-integrations")
        .output()
        .unwrap();
    assert_eq!(global(&env), None);
    assert!(
        !env.path_target.exists(),
        "profile created by setup is removed"
    );

    // a hooksPath the user changed after setup is theirs; leave it alone
    env.setup();
    env.git(
        &env.root,
        &["config", "--global", "core.hooksPath", "/elsewhere"],
    );
    env.f2c_cmd(&env.root)
        .arg("uninstall-integrations")
        .output()
        .unwrap();
    assert_eq!(global(&env).as_deref(), Some("/elsewhere"));
}

#[test]
fn existing_repo_hook_runs_with_stdin_and_failure_aborts() {
    let env = Env::new();
    let (work, remote) = env.repo_with_remote("chain");
    env.setup();
    let log = env.root.join("hook-stdin.txt");
    let hook = work.join(".git").join("hooks").join("pre-push");
    write_hook(
        &hook,
        &format!(
            "cat > '{}'\nexit 0",
            log.to_string_lossy().replace('\\', "/")
        ),
    );
    let c = env.commit(&work, "a.txt", "1\n", "go");
    let o = env.push(&work, &["origin", "main"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let seen = std::fs::read_to_string(&log).unwrap();
    assert!(
        seen.contains(&c) && seen.contains("refs/heads/main"),
        "{seen}"
    );
    assert_eq!(env.head_of(&remote, "main"), c);

    write_hook(&hook, "exit 7");
    let c2 = env.commit(&work, "b.txt", "2\n", "blocked by repo hook");
    let o = env.push(&work, &["origin", "main"]);
    assert!(!o.status.success());
    assert_ne!(env.head_of(&remote, "main"), c2);
}

#[test]
fn previous_global_hookspath_and_local_hookspath_are_chained() {
    let env = Env::new();
    let prior = env.root.join("prior hooks");
    let log = env.root.join("prior.log");
    write_hook(
        &prior.join("pre-push"),
        &format!(
            "cat >> '{}'\nexit 0",
            log.to_string_lossy().replace('\\', "/")
        ),
    );
    env.git(
        &env.root,
        &[
            "config",
            "--global",
            "core.hooksPath",
            prior.to_str().unwrap(),
        ],
    );
    let (work, _remote) = env.repo_with_remote("prior");
    env.setup();
    env.commit(&work, "a.txt", "1\n", "x");
    let o = env.push(&work, &["origin", "main"]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(std::fs::read_to_string(&log)
        .unwrap()
        .contains("refs/heads/main"));

    // a repo-local hooksPath bypasses the global one for plain git, but the
    // shim re-injects ours, which chains to the repo's hooks
    let local = work.join("team hooks");
    write_hook(&local.join("pre-push"), "exit 9");
    env.git(
        &work,
        &["config", "core.hooksPath", local.to_str().unwrap()],
    );
    env.commit(&work, "b.txt", "2\n", "y");
    let o = env.shim_push(&work, &["origin", "main"]);
    assert!(
        !o.status.success(),
        "local hook must still run via the shim"
    );
}

#[test]
fn worktrees_run_the_hook() {
    let env = Env::new();
    let (work, remote) = env.repo_with_remote("wt");
    env.setup();
    let wt = env.root.join("second tree");
    env.git(
        &work,
        &["worktree", "add", "-q", "-b", "wtb", wt.to_str().unwrap()],
    );
    env.commit(&wt, "w.txt", "1\n", "in worktree");
    let o = env.push(&wt, &["origin", "wtb"]);
    assert!(o.status.success(), "{}", stderr(&o));
    env.commit(&wt, ".env", "A=1\n", "env in worktree");
    let o = env.push(&wt, &["origin", "wtb"]);
    assert_blocked(&o, "Secret");
    assert!(env.ref_exists(&remote, "refs/heads/wtb"));
}

#[test]
fn installed_shim_routes_push_by_argv0() {
    let env = Env::new();
    let (work, _remote) = env.repo_with_remote("shim");
    env.setup();
    let shim = env
        .f2c_home
        .join("bin")
        .join(if cfg!(windows) { "git.exe" } else { "git" });
    env.commit(&work, "a.txt", "1\n", "next");
    let mut c = std::process::Command::new(&shim);
    c.current_dir(&work)
        .args(["push", "--force", "origin", "main"])
        .env("HOME", &env.home)
        .env("USERPROFILE", &env.home)
        .env("GIT_CONFIG_GLOBAL", &env.gitcfg)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("FAIL2COMMIT_HOME", &env.f2c_home)
        .env("FAIL2COMMIT_PATH_TARGET", &env.path_target)
        // unattended: the hook must fail closed, never open a console prompt
        .env("FAIL2COMMIT_HOOK_FAIL_CLOSED", "1")
        .stdin(std::process::Stdio::null());
    let o = c.output().unwrap();
    assert_blocked(&o, "ForceIntent");
}
