//! CR-018 (P-108): registry signatures and the provenance-downgrade warning,
//! against the loopback registry, which signs with a key made per test.

mod npm_support;

use fail2commit_core::npm;
use fail2commit_core::protocol::{FindingAction, FindingKind};
use fail2commit_core::ResultCode;
use npm_support::*;

/// Lock the project to exactly `pkgs`, all direct dependencies.
fn pin(reg: &Registry, env: &Env, pkgs: &[&Pkg]) {
    let roots: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
    let deps: serde_json::Map<_, _> = roots
        .iter()
        .map(|n| (n.to_string(), serde_json::json!("^1.0.0")))
        .collect();
    let pj = serde_json::json!({"name": "clean-app", "version": "1.0.0", "private": true, "dependencies": deps});
    std::fs::write(env.project.join("package.json"), pj.to_string()).unwrap();
    std::fs::write(
        env.project.join("package-lock.json"),
        reg.lockfile(&roots, pkgs),
    )
    .unwrap();
}

fn pad() -> Pkg {
    Pkg::new("left-pad", "1.0.0").file("index.js", "module.exports=1")
}

/// A registry serving `pkgs` and a project whose lockfile pins all of them.
fn world(pkgs: &[&Pkg]) -> (Registry, Env) {
    require_node();
    let reg = Registry::start();
    for p in pkgs {
        reg.publish(p);
    }
    let env = Env::new(&reg, "{}");
    pin(&reg, &env, pkgs);
    (reg, env)
}

static BACKEND: std::sync::LazyLock<FakeBackend> =
    std::sync::LazyLock::new(|| FakeBackend::new(false, false));

/// Guarded `npm ci` with default doubles; the run keeps the approval requests.
fn ci(env: &Env) -> (fail2commit_core::Result<npm::NpmOutcome>, Run<'_>) {
    let run = Run::new(env, &BACKEND);
    let out = npm::execute(&run.deps(Behavior::default()), &env.request(&["ci"]));
    (out, run)
}

fn assert_denied(reg: &Registry, env: &Env, case: &str, why: &str) {
    let before = snapshot(&env.project);
    let (out, run) = ci(env);
    let e = out.expect_err(case);
    assert_eq!(e.code, ResultCode::Rejected, "{case}: {e}");
    let f = e
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::SignatureInvalid)
        .unwrap_or_else(|| panic!("{case}: {:?}", e.findings));
    assert_eq!(f.action, FindingAction::Deny, "{case}");
    assert!(f.evidence.contains(why), "{case}: {}", f.evidence);
    assert_eq!(snapshot(&env.project), before, "{case}: project changed");
    assert!(
        reg.tarball_hits().is_empty(),
        "{case}: artifact was fetched"
    );
    assert!(run.requests.lock().unwrap().is_empty(), "{case}: prompted");
}

#[test]
fn a_valid_signature_installs_without_a_prompt() {
    let (reg, env) = world(&[&pad()]);
    // A key that expires after the publish time still counts.
    reg.set_key_expires(Some("2030-01-01T00:00:00Z"));
    let t0 = std::time::Instant::now();
    let (out, run) = ci(&env);
    out.unwrap();
    eprintln!("signed ci took {:?}", t0.elapsed());
    assert!(env.project.join("node_modules/left-pad/index.js").is_file());
    assert!(run.requests.lock().unwrap().is_empty());
    let sig = reg.sig_hits();
    assert!(sig.contains(&"/-/npm/v1/keys".to_string()), "{sig:?}");
    assert!(sig.contains(&"/left-pad".to_string()), "{sig:?}");
}

#[test]
fn bad_signatures_deny_before_anything_is_written() {
    type Tamper = fn(&Registry);
    let cases: [(&str, Tamper, &str); 6] = [
        (
            "tampered signature",
            |r| {
                // A valid signature, but over another package.
                r.publish(&Pkg::new("other", "1.0.0"));
                let mut sig = serde_json::Value::Null;
                r.edit_dist("other", "1.0.0", |d| sig = d["signatures"].clone());
                r.edit_dist("left-pad", "1.0.0", |d| d["signatures"] = sig);
            },
            "is invalid",
        ),
        (
            "garbage signature",
            |r| {
                r.edit_dist("left-pad", "1.0.0", |d| {
                    d["signatures"][0]["sig"] = "AAAA".into()
                })
            },
            "is invalid",
        ),
        (
            "changed integrity",
            |r| {
                r.edit_dist("left-pad", "1.0.0", |d| {
                    d["integrity"] = sri(b"something else").into()
                })
            },
            "differs from the lockfile integrity",
        ),
        (
            "missing signature",
            |r| {
                r.edit_dist("left-pad", "1.0.0", |d| {
                    d.as_object_mut().unwrap().remove("signatures");
                })
            },
            "no registry signature",
        ),
        (
            "unknown keyid",
            |r| {
                r.edit_dist("left-pad", "1.0.0", |d| {
                    d["signatures"][0]["keyid"] = "SHA256:someone-else".into()
                })
            },
            "unknown keyid",
        ),
        (
            "expired key",
            |r| r.set_key_expires(Some("2025-01-01T00:00:00Z")),
            "after the key expired",
        ),
    ];
    for (case, tamper, why) in cases {
        let (reg, env) = world(&[&pad()]);
        tamper(&reg);
        reg.clear_hits();
        assert_denied(&reg, &env, case, why);
        assert!(!env.project.join("node_modules").exists(), "{case}");
    }
}

#[test]
fn a_registry_without_keys_needs_one_approval() {
    let (reg, env) = world(&[&pad(), &Pkg::new("b", "1.0.0")]);
    reg.set_keys_response("404 Not Found", br#"{"error":"not found"}"#);
    let (out, run) = ci(&env);
    let out = out.unwrap();
    let reqs = run.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    let sig: Vec<_> = reqs[0]
        .findings
        .iter()
        .filter(|f| f.source == "npm.signatures")
        .collect();
    assert_eq!(sig.len(), 1, "one finding per install: {sig:?}");
    assert_eq!(sig[0].kind, FindingKind::IncompleteScan);
    assert_eq!(sig[0].action, FindingAction::Approve);
    assert!(
        sig[0]
            .evidence
            .contains("publishes no signing keys; signatures not verified"),
        "{}",
        sig[0].evidence
    );
    assert!(out.findings.iter().any(|f| f.source == "npm.signatures"));
    assert_eq!(reg.sig_hits(), vec!["/-/npm/v1/keys".to_string()]);
}

#[test]
fn a_broken_keys_endpoint_denies() {
    for (status, body) in [
        ("500 Internal Server Error", &b"oops"[..]),
        ("200 OK", b"{\"keys\": not json"),
        ("200 OK", br#"{"keys":[]}"#),
    ] {
        let (reg, env) = world(&[&pad()]);
        reg.set_keys_response(status, body);
        reg.clear_hits();
        assert_denied(&reg, &env, status, "signatures are unverifiable");
    }
}

#[test]
fn dropped_provenance_warns_but_never_having_it_does_not() {
    let old = Pkg::new("prov", "1.0.0").provenance();
    let new = Pkg::new("prov", "1.1.0");
    require_node();
    let reg = Registry::start();
    reg.publish(&old);
    reg.publish(&new);
    reg.publish(&pad());
    let env = Env::new(&reg, "{}");
    pin(&reg, &env, &[&new, &pad()]);
    let (out, run) = ci(&env);
    out.unwrap();
    let reqs = run.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1, "the warning needs approval");
    let prov: Vec<_> = reqs[0]
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::ProvenanceMissing)
        .collect();
    assert_eq!(prov.len(), 1, "{:?}", reqs[0].findings);
    assert_eq!(prov[0].action, FindingAction::Approve);
    assert_eq!(prov[0].target.as_deref(), Some("npm:prov@1.1.0"));
    assert!(prov[0].evidence.contains("possible hijacked account"));

    // Same shape, but no version ever had provenance: no prompt at all.
    let (_reg, env) = world(&[&Pkg::new("plain", "1.1.0"), &pad()]);
    let (out, run) = ci(&env);
    out.unwrap();
    assert!(run.requests.lock().unwrap().is_empty());
}

#[test]
fn verify_false_skips_the_check_and_status_says_so() {
    let (reg, mut env) = world(&[&pad()]);
    // A check that ran would deny this registry.
    reg.set_keys_response("500 Internal Server Error", b"oops");
    env.settings.signatures.verify = false;
    let (out, run) = ci(&env);
    out.unwrap();
    assert!(run.requests.lock().unwrap().is_empty());
    assert!(reg.sig_hits().is_empty(), "{:?}", reg.sig_hits());

    let status = |settings: &str| {
        std::fs::write(env.paths.settings_file(), settings).unwrap();
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_fail2commit"))
            .args(["--json", "status"])
            .current_dir(&env.project)
            .env("FAIL2COMMIT_HOME", env.paths.config_dir.parent().unwrap())
            .output()
            .unwrap();
        let line = String::from_utf8_lossy(&out.stdout).into_owned();
        serde_json::from_str::<serde_json::Value>(line.lines().last().unwrap()).unwrap()
    };
    let off = status("[signatures]\nverify = false\n");
    assert!(
        off.to_string()
            .contains("npm registry signature checks are off"),
        "{off}"
    );
    assert_eq!(off["data"]["signatures"]["verify"], false, "{off}");
    let on = status("");
    assert!(!on.to_string().contains("signature checks are off"), "{on}");
    assert_eq!(on["data"]["signatures"]["verify"], true, "{on}");
}
