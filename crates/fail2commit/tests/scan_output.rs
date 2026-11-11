//! FR-028 (SPEC-015, TC-028-*): files that sandboxed scripts produced are
//! scanned before anything is committed into the project. The sandbox is the
//! npm test double that runs the script on the host inside the stage; the
//! "download" is a file the script writes (no network in tests).

mod npm_support;

use fail2commit_core::npm;
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::protocol::{Decision, FindingAction, FindingKind};
use fail2commit_core::scan::malware_list::{self, State};
use fail2commit_core::scan::output::scan_tree;
use fail2commit_core::scan::yara::Matcher;
use fail2commit_core::scan::{Ecosystem, PackageId};
use fail2commit_core::settings::AdvisorySettings;
use fail2commit_core::ResultCode;
use npm_support::*;
use std::io::{Read, Write};
use std::net::TcpListener;

/// Builds the payload at run time so the script itself does not match.
const BUILD_JS: &str = "const fs=require('fs');fs.mkdirSync('out',{recursive:true});\
fs.writeFileSync('out/miner.conf','pool = stratum'+'+tcp://pool.example.test:3333\\n');";

fn produced_project() -> (Registry, Env) {
    require_node();
    let reg = Registry::start();
    let pkg = Pkg::new("fetchy", "1.0.0")
        .script("postinstall", "node build.js")
        .file("build.js", BUILD_JS);
    reg.publish(&pkg);
    let env = Env::new(
        &reg,
        r#"{"name":"app","version":"1.0.0","private":true,"dependencies":{"fetchy":"^1.0.0"}}"#,
    );
    std::fs::write(
        env.project.join("package-lock.json"),
        reg.lockfile(&["fetchy"], &[&pkg]),
    )
    .unwrap();
    (reg, env)
}

fn pid(name: &str) -> PackageId {
    PackageId {
        ecosystem: Ecosystem::Npm,
        name: name.into(),
        version: "1.0.0".into(),
    }
}

/// A one-record offline index naming `evil-dep` (loopback download).
fn index_with_evil(paths: &TrustedPaths) {
    let rec = serde_json::to_vec(&serde_json::json!({
        "id": "MAL-2026-77",
        "affected": [{ "package": { "ecosystem": "npm", "name": "evil-dep" }, "versions": ["6.6.6"] }]
    }))
    .unwrap();
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    let mut h = tar::Header::new_gnu();
    h.set_size(rec.len() as u64);
    h.set_mode(0o644);
    h.set_entry_type(tar::EntryType::Regular);
    b.append_data(
        &mut h,
        "mp-main/osv/malicious/npm/evil-dep/MAL-2026-77.json",
        rec.as_slice(),
    )
    .unwrap();
    let body = b.into_inner().unwrap().finish().unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/a.tgz", l.local_addr().unwrap());
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf);
        let _ = s.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
        let _ = s.write_all(&body);
    });
    malware_list::update_latest_from_url(paths, &AdvisorySettings::default(), &url, 30).unwrap();
}

/// TC-028-1
#[test]
fn scan_tree_flags_yara_code_and_malware() {
    let d = tempfile::tempdir().unwrap();
    let paths = TrustedPaths::under(&d.path().join("home"));
    paths.ensure().unwrap();
    index_with_evil(&paths);
    let State::Valid(index) = malware_list::load(&paths) else {
        panic!("index")
    };
    let root = d.path().join("stage");
    let files = [
        (
            "node_modules/x/out/hook.js",
            "fetch('https://discord.com/api/webhooks/123456789/abc');\n",
        ),
        (
            "node_modules/x/vendor/node_modules/evil-dep/package.json",
            r#"{"name":"evil-dep","version":"6.6.6"}"#,
        ),
        ("node_modules/x/out/fine.txt", "nothing to see\n"),
    ];
    for (p, b) in files {
        let f = root.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, b).unwrap();
    }
    let list: Vec<(PackageId, String)> = files
        .iter()
        .map(|(p, _)| (pid("x"), p.to_string()))
        .collect();
    let m = Matcher::bundled();
    let f = scan_tree(Some(&m), Some(&index), &root, &list);
    let has = |k: FindingKind, a: FindingAction, loc: &str| {
        f.iter().any(|x| {
            x.kind == k
                && x.action == a
                && x.location.as_deref().is_some_and(|l| l.starts_with(loc))
        })
    };
    assert!(
        has(
            FindingKind::YaraMatch,
            FindingAction::Approve,
            "node_modules/x/out/hook.js:1"
        ),
        "{f:?}"
    );
    assert!(
        has(
            FindingKind::SuspiciousCode,
            FindingAction::Approve,
            "node_modules/x/out/hook.js:1"
        ),
        "{f:?}"
    );
    assert!(
        has(
            FindingKind::Malware,
            FindingAction::Deny,
            "node_modules/x/vendor/node_modules/evil-dep/package.json"
        ),
        "{f:?}"
    );
    assert!(f.iter().all(|x| x.source == "scan.output"));
    assert!(f.iter().all(|x| x.target.as_deref() == Some("npm:x@1.0.0")));
    assert!(!f.iter().any(|x| x
        .location
        .as_deref()
        .is_some_and(|l| l.contains("fine.txt"))));
}

/// TC-028-2
#[test]
fn script_output_match_pauses_before_commit() {
    let (_reg, env) = produced_project();
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(true, true);
    let run = Run::new(&env, &backend);
    let e = npm::execute(
        &run.deps(Behavior {
            decision: Decision::Cancel,
            ..Behavior::default()
        }),
        &env.request(&["ci"]),
    )
    .unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    assert_eq!(backend.jobs().len(), 1, "the script ran in the sandbox");
    let reqs = run.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    let hit = reqs[0]
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::YaraMatch)
        .unwrap_or_else(|| panic!("{:?}", reqs[0].findings));
    assert!(
        hit.evidence.contains("bundled:crypto_miner"),
        "{}",
        hit.evidence
    );
    assert_eq!(hit.source, "scan.output");
    assert_eq!(
        hit.location.as_deref(),
        Some("node_modules/fetchy/out/miner.conf:1")
    );
    assert!(
        reqs[0].summary.contains("produced by install scripts"),
        "{}",
        reqs[0].summary
    );
    assert_eq!(
        snapshot(&env.project),
        before,
        "cancelling leaves the project unchanged"
    );
    assert_no_scratch(&env.project);
}

/// TC-028-3
#[test]
fn approved_script_output_is_committed() {
    let (_reg, env) = produced_project();
    let backend = FakeBackend::new(true, true);
    let run = Run::new(&env, &backend);
    let out = npm::execute(&run.deps(Behavior::default()), &env.request(&["ci"])).unwrap();
    assert!(out
        .findings
        .iter()
        .any(|f| f.kind == FindingKind::YaraMatch && f.source == "scan.output"));
    assert!(env
        .project
        .join("node_modules/fetchy/out/miner.conf")
        .is_file());
    assert_eq!(run.requests.lock().unwrap().len(), 1);
    assert_no_scratch(&env.project);
}
