//! TC-004 (FR-004, SPEC-004): guarded npm installs against an offline
//! loopback registry, with collaborating areas replaced by doubles.

mod npm_support;

use fail2commit_core::npm::{self, CrashPoint};
use fail2commit_core::protocol::{Decision, Finding, FindingAction, FindingKind};
use fail2commit_core::scan::AdvisoryReport;
use fail2commit_core::ResultCode;
use npm_support::*;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{FIXTURES}/{name}/package.json")).unwrap()
}

fn setup(project: &str) -> (Registry, Env) {
    require_node();
    let reg = Registry::start();
    reg.publish(&Pkg::new("left-pad", "1.0.0").file("index.js", "module.exports=1"));
    let env = Env::new(&reg, &fixture(project));
    (reg, env)
}

fn finding(kind: FindingKind, action: FindingAction, target: &str) -> Finding {
    Finding::new(kind, action, "test", "synthetic").target(target)
}

#[test]
fn clean_install_works_and_updates_manifest_and_lock() {
    let (reg, env) = setup("clean");
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let out = npm::execute(
        &run.deps(Behavior::default()),
        &env.request(&["install", "left-pad"]),
    )
    .unwrap();
    assert!(
        out.message.contains("installed 1 package"),
        "{}",
        out.message
    );
    assert!(
        run.requests.lock().unwrap().is_empty(),
        "no findings, no prompt"
    );
    assert!(env.project.join("node_modules/left-pad/index.js").is_file());
    let pj: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.project.join("package.json")).unwrap()).unwrap();
    assert_eq!(pj["dependencies"]["left-pad"], "^1.0.0", "{pj}");
    let lock = std::fs::read_to_string(env.project.join("package-lock.json")).unwrap();
    assert!(lock.contains(&format!("{}left-pad/-/left-pad-1.0.0.tgz", reg.url)));
    assert_no_scratch(&env.project);
    assert!(backend.jobs().is_empty(), "no scripts, no sandbox");
    // Exactly one download of the artifact: ours. npm installed from the cache.
    assert_eq!(reg.tarball_hits().len(), 1, "{:?}", reg.hits());
}

#[test]
fn ci_installs_the_lockfile_and_keeps_project_files() {
    let (reg, env) = setup("clean");
    let lib = Pkg::new("app-lib", "1.0.0").dep("left-pad", "^1.0.0");
    let pad = Pkg::new("left-pad", "1.0.0").file("index.js", "module.exports=1");
    reg.publish(&lib);
    let lock = reg.lockfile(&["app-lib"], &[&lib, &pad]);
    let pj = r#"{"name":"clean-app","version":"1.0.0","private":true,"dependencies":{"app-lib":"^1.0.0"}}"#;
    std::fs::write(env.project.join("package.json"), pj).unwrap();
    std::fs::write(env.project.join("package-lock.json"), &lock).unwrap();
    reg.clear_hits();
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let out = npm::execute(&run.deps(Behavior::default()), &env.request(&["ci"])).unwrap();
    assert!(
        out.message.contains("installed 2 package"),
        "{}",
        out.message
    );
    assert!(env
        .project
        .join("node_modules/left-pad/package.json")
        .is_file());
    assert!(env
        .project
        .join("node_modules/app-lib/package.json")
        .is_file());
    assert_eq!(
        std::fs::read_to_string(env.project.join("package-lock.json")).unwrap(),
        lock
    );
    assert_eq!(
        std::fs::read_to_string(env.project.join("package.json")).unwrap(),
        pj
    );
    assert!(
        reg.hits().iter().all(|h| h.ends_with(".tgz")),
        "ci resolves nothing: {:?}",
        reg.hits()
    );
}

#[test]
fn malicious_transitive_package_pauses_and_cancel_preserves_the_project() {
    let (reg, env) = setup("existing");
    reg.publish(&Pkg::new("mid", "1.0.0").dep("deep-evil", "^1.0.0"));
    reg.publish(
        &Pkg::new("deep-evil", "1.0.0")
            .script("postinstall", "node x.js")
            .file("x.js", ""),
    );
    // Existing project state that Cancel must leave byte-for-byte alone.
    std::fs::create_dir_all(env.project.join("node_modules/keep")).unwrap();
    std::fs::write(env.project.join("node_modules/keep/index.js"), "user data").unwrap();
    std::fs::write(
        env.project.join("package-lock.json"),
        "{\"lockfileVersion\":3}\n",
    )
    .unwrap();
    let before = snapshot(&env.project);

    let backend = FakeBackend::new(true, true);
    let run = Run::new(&env, &backend);
    let b = Behavior {
        decision: Decision::Cancel,
        advisories: Box::new(|pkgs| AdvisoryReport {
            findings: pkgs
                .iter()
                .filter(|p| p.name == "deep-evil")
                .map(|p| {
                    finding(FindingKind::Malware, FindingAction::Approve, &p.display())
                        .advisory("MAL-0000-TEST")
                })
                .collect(),
            complete: true,
        }),
        ..Default::default()
    };
    let e = npm::execute(&run.deps(b), &env.request(&["install", "mid"])).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    let reqs = run.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1, "exactly one approval prompt");
    let f = &reqs[0].findings;
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].kind, FindingKind::Malware);
    assert_eq!(f[0].target.as_deref(), Some("npm:deep-evil@1.0.0"));
    assert!(
        reqs[0]
            .details
            .iter()
            .any(|d| d.contains("deep-evil@1.0.0")),
        "{:?}",
        reqs[0].details
    );
    assert_eq!(
        snapshot(&env.project),
        before,
        "cancel leaves the project byte-for-byte unchanged"
    );
    assert!(backend.jobs().is_empty(), "no package code ran");
}

#[test]
fn approved_findings_install_once() {
    let (reg, env) = setup("clean");
    reg.publish(&Pkg::new("mid", "1.0.0").dep("left-pad", "^1.0.0"));
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let b = Behavior {
        advisories: Box::new(|pkgs| AdvisoryReport {
            findings: vec![finding(
                FindingKind::Advisory,
                FindingAction::Approve,
                &pkgs[0].display(),
            )
            .advisory("GHSA-test")],
            complete: true,
        }),
        ..Default::default()
    };
    let out = npm::execute(&run.deps(b), &env.request(&["install", "mid"])).unwrap();
    assert_eq!(run.requests.lock().unwrap().len(), 1);
    assert_eq!(kinds(&out.findings), ["Advisory".to_string()].into());
    assert!(env.project.join("node_modules/mid").is_dir());
}

#[test]
fn force_push_script_is_denied_without_a_prompt() {
    let (reg, env) = setup("clean");
    reg.publish(
        &Pkg::new("pusher", "1.0.0")
            .script("postinstall", "node push.js")
            .file("push.js", "// synthetic: runs git push --force"),
    );
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(true, true);
    let run = Run::new(&env, &backend);
    let b = Behavior {
        inspect: Box::new(|p, scripts, files| {
            assert_eq!(scripts[0].0, "postinstall");
            assert_eq!(
                files[0].path, "push.js",
                "referenced file is handed to the scanner"
            );
            vec![finding(
                FindingKind::SuspiciousScript,
                FindingAction::Deny,
                &p.display(),
            )]
        }),
        ..Default::default()
    };
    let e = npm::execute(&run.deps(b), &env.request(&["install", "pusher"])).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected);
    assert_eq!(kinds(&e.findings), ["SuspiciousScript".to_string()].into());
    assert!(
        run.requests.lock().unwrap().is_empty(),
        "a Deny is not approvable"
    );
    assert!(backend.jobs().is_empty());
    assert_eq!(snapshot(&env.project), before);
}

#[test]
fn stale_or_offline_advisory_data_is_reported_and_pauses() {
    let (_reg, env) = setup("clean");
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let b = Behavior {
        decision: Decision::Cancel,
        advisories: Box::new(|_| AdvisoryReport {
            findings: vec![Finding::new(
                FindingKind::StaleData,
                FindingAction::Approve,
                "osv",
                "cache older than ttl",
            )],
            complete: false,
        }),
        ..Default::default()
    };
    let e = npm::execute(&run.deps(b), &env.request(&["install", "left-pad"])).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected);
    assert_eq!(kinds(&e.findings), ["StaleData".to_string()].into());
    assert_eq!(
        kinds(&run.requests.lock().unwrap()[0].findings),
        ["StaleData".to_string()].into()
    );

    // An incomplete report without its own finding still cannot pass silently.
    let b = Behavior {
        decision: Decision::Cancel,
        advisories: Box::new(|_| AdvisoryReport {
            findings: vec![],
            complete: false,
        }),
        ..Default::default()
    };
    let e = npm::execute(&run.deps(b), &env.request(&["install", "left-pad"])).unwrap_err();
    assert_eq!(kinds(&e.findings), ["IncompleteScan".to_string()].into());
}

#[test]
fn the_real_stub_scanner_pauses_in_production_wiring() {
    // With T-006 still a stub, the production advisory path reports
    // IncompleteScan, which must pause for approval (fail closed).
    let (_reg, env) = setup("clean");
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let mut deps = run.deps(Behavior {
        decision: Decision::Cancel,
        ..Default::default()
    });
    // Offline with an empty cache: deterministic, never touches the network.
    let mut adv = env.settings.advisories.clone();
    adv.offline = true;
    let paths = env.paths.clone();
    deps.advisories = Box::new(move |p| fail2commit_core::scan::check_advisories(&paths, &adv, p));
    let e = npm::execute(&deps, &env.request(&["install", "left-pad"])).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected);
    assert_eq!(run.requests.lock().unwrap().len(), 1);
}

#[test]
fn mismatched_bytes_are_a_hard_integrity_failure() {
    let (reg, env) = setup("clean");
    let good = Pkg::new("swap", "1.0.0").file("index.js", "good");
    let bad = Pkg::new("swap", "1.0.0").file("index.js", "BAD");
    reg.publish_bytes(&good, &reg.url.clone(), &good.tarball(), &bad.tarball());
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let e = npm::execute(
        &run.deps(Behavior::default()),
        &env.request(&["install", "swap"]),
    )
    .unwrap_err();
    assert_eq!(e.code, ResultCode::IntegrityFailure, "{e}");
    assert_eq!(kinds(&e.findings), ["IntegrityMismatch".to_string()].into());
    assert!(
        run.requests.lock().unwrap().is_empty(),
        "integrity failures are not approvable"
    );
    assert_eq!(snapshot(&env.project), before);
    assert_no_scratch(&env.project);
}

#[test]
fn manifest_confusion_is_denied() {
    let (reg, env) = setup("clean");
    let mut p = Pkg::new("confuse", "1.0.0");
    p.archive_version = Some("9.9.9".into());
    reg.publish(&p);
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let e = npm::execute(
        &run.deps(Behavior::default()),
        &env.request(&["install", "confuse"]),
    )
    .unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    assert_eq!(kinds(&e.findings), ["IntegrityMismatch".to_string()].into());
}

#[test]
fn hostile_archive_paths_stop_the_install() {
    let (reg, env) = setup("clean");
    let mut p = Pkg::new("slip", "1.0.0");
    p.raw_entries = vec![("package/../../escape.txt".into(), b"x".to_vec())];
    reg.publish(&p);
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let e = npm::execute(
        &run.deps(Behavior::default()),
        &env.request(&["install", "slip"]),
    )
    .unwrap_err();
    assert_eq!(e.code, ResultCode::InvalidInput, "{e}");
    assert!(e.message.contains("unsafe archive entry"), "{e}");
    assert_eq!(snapshot(&env.project), before);
    assert!(!env.project.parent().unwrap().join("escape.txt").exists());
}

#[test]
fn unsupported_inputs_never_reach_resolution_or_npm() {
    require_node();
    let reg = Registry::start();
    reg.publish(&Pkg::new("left-pad", "1.0.0"));
    for fx in [
        "git-dep",
        "file-dep",
        "url-dep",
        "link-dep",
        "tarball-dep",
        "alias-dep",
        "workspaces",
        "override-url",
    ] {
        let env = Env::new(&reg, &fixture(fx));
        let before = snapshot(&env.project);
        let backend = FakeBackend::new(true, true);
        let run = Run::new(&env, &backend);
        for args in [&["install"][..], &["ci"], &["i", "left-pad"]] {
            let e = npm::execute(&run.deps(Behavior::default()), &env.request(args)).unwrap_err();
            assert_eq!(e.code, ResultCode::InvalidInput, "{fx} {args:?}: {e}");
        }
        assert_eq!(snapshot(&env.project), before, "{fx}");
        assert!(run.requests.lock().unwrap().is_empty());
    }
    assert!(
        reg.hits().is_empty(),
        "nothing was resolved or fetched: {:?}",
        reg.hits()
    );
}

#[test]
fn project_npmrc_cannot_redirect_the_registry_or_shell() {
    let (reg, env) = setup("clean");
    let rc = std::fs::read_to_string(format!("{FIXTURES}/hostile-npmrc/npmrc")).unwrap();
    std::fs::write(env.project.join(".npmrc"), rc).unwrap();
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let e = npm::execute(
        &run.deps(Behavior::default()),
        &env.request(&["install", "left-pad"]),
    )
    .unwrap_err();
    assert_eq!(e.code, ResultCode::InvalidInput);
    assert!(e.findings.len() >= 3, "{:?}", e.findings);
    assert!(reg.hits().is_empty());
    assert_eq!(snapshot(&env.project), before);
}

#[test]
fn artifacts_off_the_pinned_registry_are_refused() {
    let (reg, env) = setup("clean");
    let other = Registry::start(); // a second origin: the substitution target
    reg.publish_at(&Pkg::new("sneaky", "1.0.0"), &other.url);
    other.publish(&Pkg::new("sneaky", "1.0.0"));
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let e = npm::execute(
        &run.deps(Behavior::default()),
        &env.request(&["install", "sneaky"]),
    )
    .unwrap_err();
    assert_eq!(e.code, ResultCode::InvalidInput, "{e}");
    assert!(e.findings[0].evidence.contains("pinned registry"));
    assert!(other.hits().is_empty(), "never fetched: {:?}", other.hits());
}

#[test]
fn a_changed_plan_changes_the_approved_digest() {
    let (reg, env) = setup("clean");
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let ask = || Behavior {
        decision: Decision::Cancel,
        advisories: Box::new(|_| AdvisoryReport {
            findings: vec![Finding::new(
                FindingKind::StaleData,
                FindingAction::Approve,
                "osv",
                "stale",
            )],
            complete: false,
        }),
        ..Default::default()
    };
    let digest = |args: &[&str]| {
        let _ = npm::execute(&run.deps(ask()), &env.request(args));
        run.requests.lock().unwrap().last().unwrap().digest.clone()
    };
    let d1 = digest(&["install", "left-pad"]);
    assert_eq!(
        d1,
        digest(&["install", "left-pad"]),
        "same plan, same digest"
    );
    reg.publish(&Pkg::new("left-pad", "1.1.0").file("index.js", "changed"));
    let d2 = digest(&["install", "left-pad"]);
    assert_ne!(d1, d2, "new resolution -> new digest");
    assert_ne!(
        d2,
        digest(&["install", "-E", "left-pad"]),
        "different save options"
    );
    assert_ne!(d2, digest(&["install", "--ignore-scripts", "left-pad"]));
}

#[test]
fn project_edited_during_review_invalidates_the_approval() {
    let (reg, env) = setup("clean");
    reg.publish(&Pkg::new("mid", "1.0.0"));
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let pj = env.project.join("package.json");
    let edited = r#"{"name":"clean-app","version":"1.0.1","private":true}"#;
    let b = Behavior {
        advisories: Box::new(|_| AdvisoryReport {
            findings: vec![Finding::new(
                FindingKind::StaleData,
                FindingAction::Approve,
                "osv",
                "stale",
            )],
            complete: false,
        }),
        on_approval: Box::new({
            let pj = pj.clone();
            move |_| std::fs::write(&pj, edited).unwrap()
        }),
        ..Default::default()
    };
    let e = npm::execute(&run.deps(b), &env.request(&["install", "mid"])).unwrap_err();
    assert_eq!(e.code, ResultCode::IntegrityFailure, "{e}");
    assert_eq!(
        std::fs::read_to_string(&pj).unwrap(),
        edited,
        "the user's edit is kept"
    );
    assert!(!env.project.join("node_modules").exists());
    assert_no_scratch(&env.project);
}

fn crash_case(crash: CrashPoint) {
    let (reg, env) = setup("clean");
    let pad = Pkg::new("left-pad", "1.0.0").file("index.js", "module.exports=1");
    let pj = r#"{"name":"clean-app","version":"1.0.0","private":true,"dependencies":{"left-pad":"^1.0.0"}}"#;
    std::fs::write(env.project.join("package.json"), pj).unwrap();
    std::fs::write(
        env.project.join("package-lock.json"),
        reg.lockfile(&["left-pad"], &[&pad]),
    )
    .unwrap();
    std::fs::create_dir_all(env.project.join("node_modules/keep")).unwrap();
    std::fs::write(env.project.join("node_modules/keep/index.js"), "user data").unwrap();
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);

    let mut deps = run.deps(Behavior::default());
    deps.crash = Some(crash);
    let e = npm::execute(&deps, &env.request(&["ci"])).unwrap_err();
    assert!(e.message.contains("simulated crash"), "{crash:?}: {e}");

    // The next invocation recovers first. Cancel it, so only recovery acts.
    let b = Behavior {
        decision: Decision::Cancel,
        advisories: Box::new(|_| AdvisoryReport {
            findings: vec![Finding::new(
                FindingKind::StaleData,
                FindingAction::Approve,
                "osv",
                "stale",
            )],
            complete: false,
        }),
        ..Default::default()
    };
    let e = npm::execute(&run.deps(b), &env.request(&["ci"])).unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{crash:?}");
    assert_eq!(
        snapshot(&env.project),
        before,
        "{crash:?}: original restored byte-for-byte"
    );
    assert_no_scratch(&env.project);
}

#[test]
fn interrupted_apply_recovers_after_journal() {
    crash_case(CrashPoint::AfterJournal);
}

#[test]
fn interrupted_apply_recovers_after_backup() {
    crash_case(CrashPoint::AfterBackup);
}

#[test]
fn interrupted_apply_recovers_after_swap() {
    crash_case(CrashPoint::AfterSwap);
}

#[test]
fn interrupted_apply_recovers_after_files() {
    crash_case(CrashPoint::AfterFiles);
}

#[test]
fn recovery_note_is_reported_by_the_run_that_recovers() {
    let (reg, env) = setup("clean");
    let pad = Pkg::new("left-pad", "1.0.0").file("index.js", "module.exports=1");
    let pj = r#"{"name":"clean-app","version":"1.0.0","private":true,"dependencies":{"left-pad":"^1.0.0"}}"#;
    std::fs::write(env.project.join("package.json"), pj).unwrap();
    std::fs::write(
        env.project.join("package-lock.json"),
        reg.lockfile(&["left-pad"], &[&pad]),
    )
    .unwrap();
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let mut deps = run.deps(Behavior::default());
    deps.crash = Some(CrashPoint::AfterSwap);
    npm::execute(&deps, &env.request(&["ci"])).unwrap_err();
    let out = npm::execute(&run.deps(Behavior::default()), &env.request(&["ci"])).unwrap();
    assert!(
        out.message.contains("rolled back an interrupted npm apply"),
        "{}",
        out.message
    );
    assert!(env.project.join("node_modules/left-pad").is_dir());
    assert_no_scratch(&env.project);
}

#[test]
fn optional_platform_packages_are_reviewed_but_not_fetched() {
    let (reg, env) = setup("clean");
    let other_os = if cfg!(windows) { "linux" } else { "win32" };
    let mut native = Pkg::new("native-other", "1.0.0");
    native.os = Some(other_os.into());
    reg.publish(&native);
    let mut host = Pkg::new("host-pkg", "1.0.0");
    host.optional_deps = vec![("native-other".into(), "^1.0.0".into())];
    reg.publish(&host);
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let out = npm::execute(
        &run.deps(Behavior::default()),
        &env.request(&["install", "host-pkg"]),
    )
    .unwrap();
    assert_eq!(out.data["packages"].as_u64(), Some(2));
    assert!(env.project.join("node_modules/host-pkg").is_dir());
    assert!(!env.project.join("node_modules/native-other").exists());
    assert!(
        reg.tarball_hits()
            .iter()
            .all(|h| !h.contains("native-other")),
        "{:?}",
        reg.tarball_hits()
    );
}
