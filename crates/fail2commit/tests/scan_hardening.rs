//! CR-019 advisory hardening: the OSV endpoint is HTTPS or loopback HTTP only,
//! redirects are not followed, and cache entries carry an HMAC tag keyed by a
//! private per-user secret. Every request goes to a loopback listener.

#[allow(dead_code)]
mod scan_support;

use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::protocol::FindingKind;
use fail2commit_core::scan::{self, Ecosystem, PackageId};
use scan_support::{advisory_settings, fixture, Response, TestServer};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use tempfile::tempdir;

fn pkg() -> PackageId {
    PackageId {
        ecosystem: Ecosystem::Npm,
        name: "demo".to_string(),
        version: "1.0.0".to_string(),
    }
}

fn home() -> (tempfile::TempDir, TrustedPaths) {
    let dir = tempdir().expect("tempdir");
    let paths = TrustedPaths::under(dir.path());
    paths.ensure().expect("private dirs");
    (dir, paths)
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

fn kinds(report: &scan::AdvisoryReport, kind: FindingKind) -> usize {
    report.findings.iter().filter(|f| f.kind == kind).count()
}

fn cache_files(paths: &TrustedPaths) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(paths.cache_dir.join("osv"))
        .expect("cache dir")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A fresh envelope claiming "no advisories", as an attacker would write it.
fn clean_claim() -> String {
    format!(r#"{{"stored_at":{},"data":[]}}"#, now())
}

fn assert_full_answer(report: &scan::AdvisoryReport) {
    assert!(report.complete, "{:?}", report.findings);
    assert_eq!(kinds(report, FindingKind::Advisory), 2);
}

fn assert_incomplete_not_clean(report: &scan::AdvisoryReport) {
    assert!(!report.complete);
    assert_eq!(kinds(report, FindingKind::IncompleteScan), 1);
    assert_eq!(kinds(report, FindingKind::Advisory), 0);
}

#[test]
fn plain_http_off_loopback_is_incomplete_without_any_request() {
    for url in [
        "http://api.osv.dev",
        "http://127.0.0.1.evil.example",
        "http://localhost.evil.example",
        "http://localhost@evil.example",
        "http://localhost.",
        "http://[::ffff:127.0.0.1]",
        "http://2130706433",
    ] {
        let (_dir, paths) = home();
        let report = scan::check_advisories(&paths, &advisory_settings(url), &[pkg()]);
        assert_incomplete_not_clean(&report);
    }
}

#[test]
fn loopback_http_with_uppercase_scheme_still_works() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let url = server.url().replacen("http://", "HTTP://", 1);
    let report = scan::check_advisories(&paths, &advisory_settings(&url), &[pkg()]);
    assert_full_answer(&report);
}

#[test]
fn redirects_are_not_followed() {
    let target = advisory_server();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let redirect_url = format!("http://{}", listener.local_addr().unwrap());
    let location = format!("{}/v1/querybatch", target.url());
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let reply = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    let (_dir, paths) = home();
    let report = scan::check_advisories(&paths, &advisory_settings(&redirect_url), &[pkg()]);
    assert_incomplete_not_clean(&report);
    assert_eq!(target.hits(), 0, "the redirect target was contacted");
}

#[test]
fn key_file_is_created_privately_in_the_state_dir() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let key = paths.state_dir.join("osv-cache.key");
    assert!(!key.exists());
    scan::check_advisories(&paths, &advisory_settings(server.url()), &[pkg()]);
    assert_eq!(std::fs::metadata(&key).expect("key file").len(), 32);
    assert_eq!(key.parent(), Some(paths.state_dir.as_path()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "key mode {mode:o}");
    }
    // The key is not stored next to the entries it protects.
    assert!(!cache_files(&paths)
        .iter()
        .any(|p| p.ends_with("osv-cache.key")));
}

#[test]
fn tampered_entries_are_refetched_online_and_incomplete_offline() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    assert_full_answer(&scan::check_advisories(&paths, &settings, &[pkg()]));
    let tamper = || {
        for file in cache_files(&paths) {
            let bytes = std::fs::read(&file).unwrap();
            let header_end = bytes.iter().position(|&b| b == b'\n').expect("tag line");
            let mut edited = bytes[..=header_end].to_vec();
            edited.extend_from_slice(clean_claim().as_bytes());
            std::fs::write(&file, edited).unwrap();
        }
    };

    tamper();
    let before = server.hits();
    assert_full_answer(&scan::check_advisories(&paths, &settings, &[pkg()]));
    assert!(
        server.hits() > before,
        "tampered entry was used, not refetched"
    );

    tamper();
    let mut offline = settings.clone();
    offline.offline = true;
    assert_incomplete_not_clean(&scan::check_advisories(&paths, &offline, &[pkg()]));
}

#[test]
fn legacy_untagged_entries_are_refetched() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    scan::check_advisories(&paths, &settings, &[pkg()]);
    // What a 0.1.2 build stored: the bare envelope.
    for file in cache_files(&paths) {
        std::fs::write(&file, clean_claim()).unwrap();
    }
    let mut offline = settings.clone();
    offline.offline = true;
    assert_incomplete_not_clean(&scan::check_advisories(&paths, &offline, &[pkg()]));

    let before = server.hits();
    assert_full_answer(&scan::check_advisories(&paths, &settings, &[pkg()]));
    assert!(
        server.hits() > before,
        "legacy entry was used, not refetched"
    );
    for file in cache_files(&paths) {
        assert!(std::fs::read(&file).unwrap().starts_with(b"f2c-hmac1:"));
    }
}

#[test]
fn a_replaced_key_invalidates_existing_entries() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    scan::check_advisories(&paths, &settings, &[pkg()]);
    std::fs::remove_file(paths.state_dir.join("osv-cache.key")).unwrap();
    let mut offline = settings.clone();
    offline.offline = true;
    assert_incomplete_not_clean(&scan::check_advisories(&paths, &offline, &[pkg()]));
}
