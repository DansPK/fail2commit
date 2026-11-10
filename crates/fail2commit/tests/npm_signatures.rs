//! CR-018 (P-108): registry signatures and the provenance-downgrade warning,
//! against the loopback registry, which signs with a key made per test.
//!
//! The loopback registry is not registry.npmjs.org, so by default it is a
//! trust-on-first-use registry. Tests that need npm's built-in-key behaviour
//! pin the registry's key in `env.pinned_keys`, as the binary does for npm.

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
    reg.clear_hits();
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

/// The one approval request of a successful install, as its findings.
fn approved_findings(env: &Env) -> Vec<fail2commit_core::protocol::Finding> {
    let (out, run) = ci(env);
    out.unwrap();
    let reqs = run.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1, "one approval");
    reqs[0].findings.clone()
}

fn signature_findings(
    f: &[fail2commit_core::protocol::Finding],
) -> Vec<&fail2commit_core::protocol::Finding> {
    f.iter().filter(|f| f.source == "npm.signatures").collect()
}

fn installs_cleanly(env: &Env) {
    let (out, run) = ci(env);
    out.unwrap();
    assert!(run.requests.lock().unwrap().is_empty(), "no prompt");
    assert!(env.project.join("node_modules/left-pad/index.js").is_file());
}

/// `fail2commit <args>` against the test's trusted home.
fn cli(env: &Env, args: &[&str]) -> serde_json::Value {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_fail2commit"))
        .arg("--json")
        .args(args)
        .current_dir(&env.project)
        .env("FAIL2COMMIT_HOME", env.paths.config_dir.parent().unwrap())
        .output()
        .unwrap();
    let line = String::from_utf8_lossy(&out.stdout).into_owned();
    serde_json::from_str(line.lines().last().unwrap()).unwrap()
}

// ------------------------------------------------- trust on first use

#[test]
fn a_valid_signature_installs_without_a_prompt() {
    let (reg, env) = world(&[&pad()]);
    // A key that expires after the publish time still counts.
    reg.set_key_expires(Some("2030-01-01T00:00:00Z"));
    installs_cleanly(&env);
    let sig = reg.sig_hits();
    assert!(sig.contains(&"/-/npm/v1/keys".to_string()), "{sig:?}");
    assert!(sig.contains(&"/left-pad".to_string()), "{sig:?}");
    assert!(
        !env.paths.cache_dir.join("npm-signatures").exists(),
        "no key cache"
    );
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
            "does not list",
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
        assert_denied(&reg, &env, case, why);
        assert!(!env.project.join("node_modules").exists(), "{case}");
    }
}

#[test]
fn a_changed_key_set_denies_until_forget() {
    let (reg, mut env) = world(&[&pad()]);
    installs_cleanly(&env);
    // Within the TTL the recorded keys are used as they are: a new key fails.
    reg.rotate_key(KEYID);
    assert_denied(&reg, &env, "fresh record", "is invalid");
    // Past the TTL the endpoint is asked again and the change is named.
    env.settings.signatures.keys_ttl_secs = 0;
    assert_denied(&reg, &env, "changed set", "changed since first use");
    let cmd = format!("fail2commit signatures forget {}", reg.url);
    assert_denied(&reg, &env, "changed set", &cmd);

    let out = cli(&env, &["signatures", "forget", &reg.url]);
    let msg = out.to_string();
    assert!(
        msg.contains("removed 1 recorded signing key(s): SHA256:loopback-test-key"),
        "{msg}"
    );
    installs_cleanly(&env);
    let again = cli(&env, &["signatures", "forget", "http://127.0.0.1:1/"]);
    assert!(
        again.to_string().contains("no signing keys were recorded"),
        "{again}"
    );
}

#[test]
fn a_tampered_key_record_denies() {
    let (reg, env) = world(&[&pad()]);
    installs_cleanly(&env);
    let dir = env.paths.state_dir.join("npm-signatures");
    let rec = std::fs::read_dir(&dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let text = std::fs::read_to_string(&rec).unwrap();
    // Swap in another key, keep the old tag.
    let edited = text.replace(
        "ecdsa-sha2-nistp256\",\"key\":\"",
        "ecdsa-sha2-nistp256\",\"key\":\"X",
    );
    assert_ne!(edited, text);
    std::fs::write(&rec, edited).unwrap();
    assert_denied(
        &reg,
        &env,
        "tampered record",
        "failed their integrity check",
    );
}

#[test]
fn a_missing_keys_endpoint_approves_only_for_a_registry_never_seen() {
    let (reg, mut env) = world(&[&pad(), &Pkg::new("b", "1.0.0")]);
    env.settings.signatures.keys_ttl_secs = 0;
    reg.set_keys_response("404 Not Found", br#"{"error":"not found"}"#);
    let first = approved_findings(&env);
    let sig = signature_findings(&first);
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
    assert_eq!(reg.sig_hits(), vec!["/-/npm/v1/keys".to_string()]);

    // Recorded as unsigned: still unverified, still needs approval.
    let again = approved_findings(&env);
    assert!(signature_findings(&again)[0]
        .evidence
        .contains("recorded as unsigned"));

    // It starts signing: the keys are recorded, and dropping them is a deny.
    reg.clear_keys_response();
    let (out, run) = ci(&env);
    out.unwrap();
    assert!(run.requests.lock().unwrap().is_empty());
    reg.set_keys_response("404 Not Found", b"{}");
    assert_denied(&reg, &env, "recorded then 404", "now publishes none");
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
        assert_denied(&reg, &env, status, "signatures are unverifiable");
    }
}

// ------------------------------------------ built-in keys (npm's case)

#[test]
fn the_built_in_key_passes() {
    let (reg, mut env) = world(&[&pad()]);
    env.pinned_keys = vec![reg.pinned()];
    installs_cleanly(&env);
}

#[test]
fn a_mirror_signing_with_its_own_key_denies_for_a_pinned_registry() {
    // Its own keyid: fail2commit does not know it, whatever the keys endpoint says.
    let (reg, mut env) = world(&[&pad()]);
    env.pinned_keys = vec![reg.pinned()];
    reg.rotate_key("SHA256:mirror-key");
    assert_denied(
        &reg,
        &env,
        "unknown keyid",
        "signed with a key this fail2commit version does not know; update fail2commit",
    );
    // npm's keyid, but the mirror's key material: the built-in key decides.
    let (reg, mut env) = world(&[&pad()]);
    env.pinned_keys = vec![reg.pinned()];
    reg.rotate_key(KEYID);
    assert_denied(&reg, &env, "self-signed under npm's keyid", "is invalid");
}

#[test]
fn a_pinned_registry_without_keys_denies() {
    for (status, why) in [
        ("404 Not Found", "ships keys for it"),
        ("500 Internal Server Error", "signatures are unverifiable"),
    ] {
        let (reg, mut env) = world(&[&pad()]);
        env.pinned_keys = vec![reg.pinned()];
        reg.set_keys_response(status, b"{}");
        assert_denied(&reg, &env, status, why);
    }
}

// --------------------------------------------------------- metadata

#[test]
fn an_oversized_packument_is_incomplete_not_denied() {
    let (reg, mut env) = world(&[&pad(), &Pkg::new("b", "1.0.0")]);
    env.settings.limits.artifact_max_bytes = 16 * 1024;
    reg.edit_dist("left-pad", "1.0.0", |d| {
        d["padding"] = "x".repeat(32 * 1024).into()
    });
    let f = approved_findings(&env);
    let sig = signature_findings(&f);
    assert_eq!(sig.len(), 1, "{sig:?}");
    assert_eq!(sig[0].kind, FindingKind::IncompleteScan);
    assert_eq!(sig[0].action, FindingAction::Approve);
    assert_eq!(sig[0].target.as_deref(), Some("npm:left-pad@1.0.0"));
    assert!(
        sig[0].evidence.contains("larger than"),
        "{}",
        sig[0].evidence
    );
}

// -------------------------------------------------------- provenance

#[test]
fn dropped_provenance_warns_but_never_having_it_does_not() {
    let old = Pkg::new("prov", "1.0.0").provenance();
    let new = Pkg::new("prov", "1.1.0");
    let (reg, env) = world(&[&old, &new, &pad()]);
    pin(&reg, &env, &[&new, &pad()]);
    let f = approved_findings(&env);
    let prov: Vec<_> = f
        .iter()
        .filter(|f| f.kind == FindingKind::ProvenanceMissing)
        .collect();
    assert_eq!(prov.len(), 1, "{f:?}");
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
fn a_backport_published_after_provenance_began_warns() {
    // 2.0.0 shipped with provenance; 1.5.0 is numbered lower but published
    // later without it. Semver alone would call 2.0.0 "later" and stay silent.
    let first = Pkg::new("lib", "2.0.0").provenance();
    let backport = Pkg::new("lib", "1.5.0");
    let (reg, env) = world(&[&first, &backport, &pad()]);
    pin(&reg, &env, &[&backport, &pad()]);
    let f = approved_findings(&env);
    let prov: Vec<_> = f
        .iter()
        .filter(|f| f.kind == FindingKind::ProvenanceMissing)
        .collect();
    assert_eq!(prov.len(), 1, "{f:?}");
    assert_eq!(prov[0].target.as_deref(), Some("npm:lib@1.5.0"));
}

// ------------------------------------------------------------ opt out

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

    std::fs::write(env.paths.settings_file(), "[signatures]\nverify = false\n").unwrap();
    let off = cli(&env, &["status"]);
    assert!(
        off.to_string()
            .contains("npm registry signature checks are off"),
        "{off}"
    );
    assert_eq!(off["data"]["signatures"]["verify"], false, "{off}");
    std::fs::write(env.paths.settings_file(), "").unwrap();
    let on = cli(&env, &["status"]);
    assert!(!on.to_string().contains("signature checks are off"), "{on}");
    assert_eq!(on["data"]["signatures"]["verify"], true, "{on}");
}
