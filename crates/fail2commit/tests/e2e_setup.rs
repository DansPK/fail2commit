//! FR-001, FR-009 end to end: `fail2commit setup` with a temp HOME and a
//! pre-existing third-party global hook, a push through the installed hook,
//! then `uninstall-integrations` restoring everything exactly. Nothing touches
//! the real user config, registry PATH or HKCU Run (the PATH edit goes to a
//! profile file via the test seam and no tray binary sits beside the CLI).

mod e2e_support;

use e2e_support::git::aws_key;
use e2e_support::World;
use std::path::Path;

fn write_hook(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn hooks_path(w: &World) -> Option<String> {
    let o = w
        .env
        .git_cmd(&w.env.root)
        .args(["config", "--global", "--get", "core.hooksPath"])
        .output()
        .unwrap();
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

#[test]
fn setup_push_through_installed_hook_and_exact_uninstall() {
    let mut w = World::new();
    w.private_exe();
    let g = &w.env;

    // A third-party global hook that must survive and keep running.
    let prior = g.root.join("team hooks");
    let prior_log = g.root.join("prior-hook.log");
    let prior_body = format!(
        "cat >> '{}'\nexit 0",
        prior_log.to_string_lossy().replace('\\', "/")
    );
    write_hook(&prior.join("pre-push"), &prior_body);
    g.git(&g.root, &["config", "--global", "core.hooksPath", prior.to_str().unwrap()]);
    std::fs::write(&g.path_target, "export KEEP=1\n").unwrap();

    let (work, remote) = g.repo_with_remote("round");
    let cfg_before = std::fs::read(&g.gitcfg).unwrap();
    let hook_before = std::fs::read(prior.join("pre-push")).unwrap();
    let profile_before = std::fs::read(&g.path_target).unwrap();

    w.setup();
    w.setup(); // idempotent: must not record fail2commit's own hooks as "previous"
    let installed = hooks_path(&w).unwrap();
    assert!(installed.ends_with("/hooks"), "{installed}");
    assert!(Path::new(&installed).join("pre-push").is_file());
    assert!(std::fs::read_to_string(&g.path_target).unwrap().contains("fail2commit"));

    // A clean push runs through the installed hook and the chained prior hook.
    let c = g.commit(&work, "a.txt", "1\n", "clean change");
    let o = g.push(&work, &["origin", "main"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(g.head_of(&remote, "main"), c);
    assert!(
        std::fs::read_to_string(&prior_log).unwrap().contains("refs/heads/main"),
        "the third-party hook was chained"
    );

    // A secret is stopped by the installed hook; the remote keeps its commit.
    g.commit(&work, "leak.env", &format!("KEY={}\n", aws_key()), "oops");
    let o = g.push(&work, &["origin", "main"]);
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("Secret"), "{err}");
    assert!(!err.contains(&aws_key()), "the secret value must never be printed");
    assert_eq!(g.head_of(&remote, "main"), c);

    let r = w.run(&g.root, &["uninstall-integrations"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(hooks_path(&w).as_deref(), prior.to_str());
    assert_eq!(std::fs::read(&g.gitcfg).unwrap(), cfg_before, "global git config restored byte for byte");
    assert_eq!(std::fs::read(prior.join("pre-push")).unwrap(), hook_before);
    assert_eq!(std::fs::read(&g.path_target).unwrap(), profile_before);
    assert!(!Path::new(&installed).join("pre-push").exists());
    assert!(!w.paths.bin_dir.join(if cfg!(windows) { "git.exe" } else { "git" }).exists());
    // With integrations gone the prior hook still guards pushes on its own.
    let c2 = g.commit(&work, "b.txt", "2\n", "after uninstall");
    let o = g.push(&work, &["origin", "main"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(g.head_of(&remote, "main"), c2);
}
