//! TC-004 / TC-008 interplay: lifecycle scripts go through the sandbox
//! decision (FR-008) with npm's lifecycle context preserved. The sandbox is
//! a double here; the real native build is Pending on T-007 (see
//! docs/verify/VERIFY-2026-11-08-npm.md).

mod npm_support;

use fail2commit_core::npm;
use fail2commit_core::protocol::Decision;
use fail2commit_core::ResultCode;
use npm_support::*;

const SETUP_JS: &str = "const fs=require('fs');\
fs.writeFileSync('built.txt',[process.env.npm_lifecycle_event,process.env.npm_package_name,\
process.env.npm_package_version,process.cwd()].join('|'));";

/// A project whose lockfile pins one package with a postinstall script.
fn scripted(command: &str) -> (Registry, Env) {
    require_node();
    let reg = Registry::start();
    let pkg = Pkg::new("scripty", "1.0.0")
        .script("postinstall", command)
        .file("setup.js", SETUP_JS);
    reg.publish(&pkg);
    let pj = r#"{"name":"clean-app","version":"1.0.0","private":true,"dependencies":{"scripty":"^1.0.0"}}"#;
    let env = Env::new(&reg, pj);
    std::fs::write(
        env.project.join("package-lock.json"),
        reg.lockfile(&["scripty"], &[&pkg]),
    )
    .unwrap();
    (reg, env)
}

fn built(env: &Env) -> Option<String> {
    std::fs::read_to_string(env.project.join("node_modules/scripty/built.txt")).ok()
}

#[test]
fn sandboxed_script_keeps_the_npm_lifecycle_context() {
    let (_reg, env) = scripted("node setup.js");
    let backend = FakeBackend::new(true, true);
    let run = Run::new(&env, &backend);
    let out = npm::execute(&run.deps(Behavior::default()), &env.request(&["ci"])).unwrap();
    assert_eq!(out.data["scripts"], "Sandboxed");

    let jobs = backend.jobs();
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    let env_of = |k: &str| {
        job.env
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.to_string_lossy().into_owned())
    };
    assert_eq!(
        env_of("npm_lifecycle_event").as_deref(),
        Some("postinstall")
    );
    assert_eq!(
        env_of("npm_lifecycle_script").as_deref(),
        Some("node setup.js")
    );
    assert_eq!(env_of("npm_package_name").as_deref(), Some("scripty"));
    assert_eq!(env_of("npm_package_version").as_deref(), Some("1.0.0"));
    assert!(env_of("npm_node_execpath").is_some() && env_of("npm_execpath").is_some());
    assert!(
        env_of("PATH").unwrap().contains(".bin"),
        "package .bin dirs are on PATH"
    );
    assert!(!job
        .env
        .iter()
        .any(|(k, _)| k.to_string_lossy().to_ascii_lowercase().contains("token")));

    // cwd is the package dir inside a scratch tree, not the user's checkout.
    assert!(job
        .cwd
        .ends_with(std::path::Path::new("node_modules").join("scripty")));
    assert!(job.cwd.starts_with(&job.work_dir));
    // The reviewed staging tree lives in the private cache (CR-008), not in the project.
    assert!(job.work_dir.starts_with(&env.paths.cache_dir));
    assert!(!job.work_dir.starts_with(&env.project));
    assert!(job.read_only.iter().all(|p| !p.starts_with(&env.project)));
    assert!(job.exports.is_empty() && job.export_to.is_none());

    let text = built(&env).expect("the script's output was committed");
    let lines: Vec<&str> = text.split('|').collect();
    assert_eq!(&lines[..3], ["postinstall", "scripty", "1.0.0"]);
    assert_no_scratch(&env.project);
}

#[test]
fn unavailable_sandbox_launches_nothing_and_changes_nothing() {
    let (_reg, env) = scripted("node setup.js");
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(false, true);
    let run = Run::new(&env, &backend);
    let e = npm::execute(&run.deps(Behavior::default()), &env.request(&["ci"])).unwrap_err();
    assert_eq!(e.code, ResultCode::IsolationUnavailable, "{e}");
    assert!(backend.jobs().is_empty());
    assert_eq!(snapshot(&env.project), before);
    assert_no_scratch(&env.project);
}

#[test]
fn sandbox_off_skips_scripts_that_are_not_required() {
    let (_reg, mut env) = scripted("node setup.js");
    env.settings.sandbox.enabled = false;
    let backend = FakeBackend::new(true, true);
    let run = Run::new(&env, &backend);
    let out = npm::execute(&run.deps(Behavior::default()), &env.request(&["ci"])).unwrap();
    assert!(
        out.message.contains("scripts were skipped"),
        "{}",
        out.message
    );
    assert!(env
        .project
        .join("node_modules/scripty/package.json")
        .is_file());
    assert!(built(&env).is_none());
    assert!(backend.jobs().is_empty() && run.host_asked.lock().unwrap().is_empty());
}

#[test]
fn user_ignore_scripts_runs_nothing_even_with_a_sandbox() {
    let (_reg, env) = scripted("node setup.js");
    let backend = FakeBackend::new(true, true);
    let run = Run::new(&env, &backend);
    npm::execute(
        &run.deps(Behavior::default()),
        &env.request(&["ci", "--ignore-scripts"]),
    )
    .unwrap();
    assert!(built(&env).is_none());
    assert!(backend.jobs().is_empty());
}

#[test]
fn required_script_with_sandbox_off_needs_separate_host_consent() {
    let (_reg, mut env) = scripted("node setup.js node-gyp");
    env.settings.sandbox.enabled = false;
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(true, true);
    let run = Run::new(&env, &backend);

    let e = npm::execute(&run.deps(Behavior::default()), &env.request(&["ci"])).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    assert_eq!(run.host_asked.lock().unwrap().len(), 1);
    assert!(run.host_asked.lock().unwrap()[0].contains("scripty"));
    assert_eq!(snapshot(&env.project), before);
    assert!(backend.jobs().is_empty());

    let b = Behavior {
        host_decision: Decision::RunOnHostOnce,
        ..Default::default()
    };
    let out = npm::execute(&run.deps(b), &env.request(&["ci"])).unwrap();
    assert_eq!(out.data["scripts"], "Host");
    assert!(
        backend.jobs().is_empty(),
        "host mode does not use the sandbox"
    );
    assert!(built(&env)
        .unwrap()
        .starts_with("postinstall|scripty|1.0.0|"));
}

#[test]
fn failing_script_rolls_everything_back() {
    let (_reg, env) = scripted("node -e process.exit(3)");
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(true, true);
    let run = Run::new(&env, &backend);
    let e = npm::execute(&run.deps(Behavior::default()), &env.request(&["ci"])).unwrap_err();
    assert!(
        e.message.contains("lifecycle script") && e.message.contains("nothing was installed"),
        "{e}"
    );
    assert_eq!(snapshot(&env.project), before);
    assert_no_scratch(&env.project);
}

#[test]
fn script_findings_reach_the_scanner_with_referenced_files() {
    let (_reg, env) = scripted("node setup.js");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let backend = FakeBackend::new(true, false);
    let run = Run::new(&env, &backend);
    let s2 = seen.clone();
    let b = Behavior {
        inspect: Box::new(move |p, scripts, files| {
            s2.lock().unwrap().push((
                p.display(),
                scripts.to_vec(),
                files.iter().map(|f| f.path.clone()).collect::<Vec<_>>(),
            ));
            vec![]
        }),
        ..Default::default()
    };
    npm::execute(&run.deps(b), &env.request(&["ci"])).unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "npm:scripty@1.0.0");
    assert_eq!(
        seen[0].1,
        vec![("postinstall".to_string(), "node setup.js".to_string())]
    );
    assert_eq!(seen[0].2, vec!["setup.js".to_string()]);
}
