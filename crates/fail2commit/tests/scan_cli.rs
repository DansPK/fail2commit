//! TC-006 end to end: the `fail2commit scan` command run as a real process
//! against a loopback OSV server, with `FAIL2COMMIT_HOME` pointing at a
//! disposable directory. No test uses the network or the user's real home.

#[allow(dead_code)]
mod scan_support;

use scan_support::{fixture, Response, TestServer};
use std::path::Path;
use tempfile::tempdir;

/// Write the trusted settings the CLI reads, so it never reaches a real OSV
/// endpoint.
fn write_settings(home: &Path, osv_url: &str) {
    let config = home.join("config");
    std::fs::create_dir_all(&config).expect("config dir");
    std::fs::write(
        config.join("settings.toml"),
        format!("[advisories]\nosv_url = \"{osv_url}\"\n"),
    )
    .expect("settings.toml");
}

fn run(home: &Path, args: &[&str]) -> (i32, String, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_fail2commit"))
        .args(args)
        .env("FAIL2COMMIT_HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("spawn fail2commit");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn response(stdout: &str) -> serde_json::Value {
    let trimmed = stdout.trim();
    serde_json::from_str(trimmed)
        .unwrap_or_else(|e| panic!("stdout is not one JSON Response ({e}): {trimmed}"))
}

fn advisory_server() -> TestServer {
    TestServer::start(
        |request| match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v1/querybatch") => Response::json(fixture("osv/batch-advisory.json")),
            ("GET", "/v1/vulns/GHSA-aaaa-bbbb-cccc") => {
                Response::json(fixture("osv/vuln-ghsa.json"))
            }
            ("GET", "/v1/vulns/CVE-2024-0001") => Response::json(fixture("osv/vuln-cve.json")),
            _ => Response::with_status(404, "{}"),
        },
    )
}

#[test]
fn known_advisory_is_reported_once_as_json() {
    let server = advisory_server();
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), server.url());
    let (code, stdout, stderr) = run(home.path(), &["--json", "scan", "npm:demo@1.0.0"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let json = response(&stdout);
    assert_eq!(json["code"], "ok");
    assert_eq!(json["data"]["complete"], true);
    assert_eq!(json["data"]["packages"][0], "npm:demo@1.0.0");
    let findings = json["findings"].as_array().expect("findings array");
    let advisories: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|finding| finding["kind"] == "advisory")
        .collect();
    assert_eq!(advisories.len(), 2, "duplicate ids appear once");
    assert_eq!(advisories[0]["action"], "approve");
    assert_eq!(advisories[0]["target"], "npm:demo@1.0.0");
    assert!(advisories[0]["advisory_id"].as_str().is_some());
}

#[test]
fn malware_is_reported_separately_as_json() {
    let server =
        TestServer::start(
            |request| match (request.method.as_str(), request.path.as_str()) {
                ("POST", "/v1/querybatch") => Response::json(fixture("osv/batch-malware.json")),
                ("GET", "/v1/vulns/MAL-2024-9999") => {
                    Response::json(fixture("osv/vuln-malware.json"))
                }
                _ => Response::with_status(404, "{}"),
            },
        );
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), server.url());
    let (code, stdout, stderr) = run(home.path(), &["--json", "scan", "npm:demo-malware@1.0.0"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let json = response(&stdout);
    let findings = json["findings"].as_array().expect("findings array");
    assert!(findings.iter().any(|f| f["kind"] == "malware"));
    assert!(!findings.iter().any(|f| f["kind"] == "advisory"));
}

#[test]
fn offline_scan_without_cache_is_incomplete() {
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), "http://127.0.0.1:1");
    let (code, stdout, stderr) = run(
        home.path(),
        &["--json", "scan", "--offline", "npm:demo@1.0.0"],
    );
    assert_eq!(code, 12, "incomplete_scan exit status; stderr: {stderr}");
    let json = response(&stdout);
    assert_eq!(json["code"], "incomplete_scan");
    let findings = json["findings"].as_array().expect("findings array");
    assert!(findings.iter().any(|f| f["kind"] == "incomplete_scan"));
    assert!(
        !findings.iter().any(|f| f["kind"] == "advisory"),
        "an unfinished scan is never clean"
    );
}

#[test]
fn offline_scan_never_contacts_the_network() {
    let server = advisory_server();
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), server.url());
    let (code, _, _) = run(
        home.path(),
        &["--json", "scan", "--offline", "npm:demo@1.0.0"],
    );
    assert_eq!(code, 12);
    assert_eq!(server.hits(), 0, "--offline must not query OSV");
}

#[test]
fn suspicious_package_directory_is_denied() {
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), "http://127.0.0.1:1");
    let dir = scan_support::fixture_dir().join("pkg-suspicious");
    let (code, stdout, stderr) = run(
        home.path(),
        &["--json", "scan", "--dir", dir.to_str().expect("utf8 path")],
    );
    assert_eq!(code, 10, "rejected exit status; stderr: {stderr}");
    let json = response(&stdout);
    assert_eq!(json["code"], "rejected");
    let findings = json["findings"].as_array().expect("findings array");
    assert!(findings
        .iter()
        .any(|f| f["kind"] == "suspicious_script" && f["action"] == "deny"));
    assert!(findings.iter().any(|f| f["location"]
        .as_str()
        .is_some_and(|location| location.starts_with("prepare:"))));
    assert!(findings.iter().any(|f| f["location"]
        .as_str()
        .is_some_and(|location| location.starts_with("scripts/postinstall.js:"))));
}

#[test]
fn benign_package_directory_is_clean() {
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), "http://127.0.0.1:1");
    let dir = scan_support::fixture_dir().join("pkg-benign");
    let (code, stdout, stderr) = run(
        home.path(),
        &["--json", "scan", "--dir", dir.to_str().expect("utf8 path")],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let json = response(&stdout);
    assert_eq!(json["code"], "ok");
    assert_eq!(json["findings"].as_array().map(Vec::len), Some(0));
    assert!(json["data"]["scriptsInspected"].as_u64().unwrap_or(0) > 0);
}

#[test]
fn text_mode_names_the_denial() {
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), "http://127.0.0.1:1");
    let dir = scan_support::fixture_dir().join("pkg-suspicious");
    let (code, _, stderr) = run(
        home.path(),
        &["scan", "--dir", dir.to_str().expect("utf8 path")],
    );
    assert_eq!(code, 10);
    assert!(stderr.contains("SuspiciousScript"), "{stderr}");
    assert!(stderr.contains("npm:demo-suspicious@1.0.0"), "{stderr}");
}

#[test]
fn scan_needs_a_target() {
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), "http://127.0.0.1:1");
    let (code, stdout, _) = run(home.path(), &["--json", "scan"]);
    assert_eq!(code, 2, "invalid_input exit status");
    let json = response(&stdout);
    assert_eq!(json["code"], "invalid_input");
}

#[test]
fn unknown_ecosystem_is_invalid_input() {
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), "http://127.0.0.1:1");
    let (code, stdout, _) = run(
        home.path(),
        &["--json", "scan", "maven:com.example:demo@1.0"],
    );
    assert_eq!(code, 2);
    let json = response(&stdout);
    assert_eq!(json["code"], "invalid_input");
}

#[test]
fn package_spec_needs_a_version() {
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), "http://127.0.0.1:1");
    let (code, stdout, _) = run(home.path(), &["--json", "scan", "npm:demo"]);
    assert_eq!(code, 2);
    assert_eq!(response(&stdout)["code"], "invalid_input");
}

#[test]
fn dns_free_missing_directory_is_invalid_input() {
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), "http://127.0.0.1:1");
    let missing = home.path().join("no-such-package");
    let (code, stdout, _) = run(
        home.path(),
        &[
            "--json",
            "scan",
            "--dir",
            missing.to_str().expect("utf8 path"),
        ],
    );
    assert_eq!(code, 2);
    assert_eq!(response(&stdout)["code"], "invalid_input");
}

#[test]
fn scoped_package_spec_is_accepted() {
    let server = TestServer::start(|request| match request.path.as_str() {
        "/v1/querybatch" => Response::json(fixture("osv/batch-clean.json")),
        _ => Response::with_status(404, "{}"),
    });
    let home = tempdir().expect("tempdir");
    write_settings(home.path(), server.url());
    let (code, stdout, stderr) = run(home.path(), &["--json", "scan", "npm:@scope/name@1.2.3"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let json = response(&stdout);
    assert_eq!(json["data"]["packages"][0], "npm:@scope/name@1.2.3");
}
