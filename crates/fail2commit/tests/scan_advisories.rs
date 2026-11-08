//! TC-006 advisory checks: dedupe, malware classification, cache bounds,
//! staleness, offline behaviour and timeouts. Every request is served by a
//! loopback listener from `scan_support`; nothing here reaches the internet.

mod scan_support;

use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::protocol::{FindingAction, FindingKind};
use fail2commit_core::scan::{self, Ecosystem, PackageId};
use scan_support::{advisory_settings, fixture, Response, TestServer};
use tempfile::tempdir;

fn pkg(name: &str) -> PackageId {
    PackageId {
        ecosystem: Ecosystem::Npm,
        name: name.to_string(),
        version: "1.0.0".to_string(),
    }
}

/// Disposable trusted home so a test never touches the real user directories.
fn home() -> (tempfile::TempDir, TrustedPaths) {
    let dir = tempdir().expect("tempdir");
    let paths = TrustedPaths::under(dir.path());
    paths.ensure().expect("private dirs");
    (dir, paths)
}

/// Loopback OSV: duplicate GHSA in the batch, one CVE, details for both.
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

fn advisory_ids(report: &scan::AdvisoryReport) -> Vec<&str> {
    report
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::Advisory)
        .filter_map(|f| f.advisory_id.as_deref())
        .collect()
}

/// A port that was just released, so connecting to it is refused immediately.
fn refused_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

#[test]
fn known_advisory_appears_once() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo")]);

    assert_eq!(
        advisory_ids(&report),
        vec!["GHSA-aaaa-bbbb-cccc", "CVE-2024-0001"]
    );
    assert_eq!(
        kinds(&report, FindingKind::Advisory),
        2,
        "duplicates merged"
    );
    assert_eq!(kinds(&report, FindingKind::Malware), 0);
    assert!(report.complete, "a served answer is a complete answer");
    for finding in &report.findings {
        assert_eq!(finding.action, FindingAction::Approve);
        assert_eq!(finding.target.as_deref(), Some("npm:demo@1.0.0"));
        assert_eq!(finding.source, "osv");
    }
    assert!(report
        .findings
        .iter()
        .any(|f| f.evidence.contains("Synthetic advisory")));
}

#[test]
fn malware_is_classified_separately() {
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
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo-malware")]);

    assert_eq!(kinds(&report, FindingKind::Malware), 1);
    assert_eq!(kinds(&report, FindingKind::Advisory), 0);
    let malware = report
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::Malware)
        .expect("malware finding");
    assert_eq!(malware.action, FindingAction::Approve);
    assert_eq!(malware.advisory_id.as_deref(), Some("MAL-2024-9999"));
    assert_eq!(malware.target.as_deref(), Some("npm:demo-malware@1.0.0"));
    assert!(report.complete);
}

#[test]
fn openssf_malicious_source_is_malware() {
    let server =
        TestServer::start(
            |request| match (request.method.as_str(), request.path.as_str()) {
                ("POST", "/v1/querybatch") => Response::json(fixture("osv/batch-openssf.json")),
                ("GET", "/v1/vulns/GHSA-1111-2222-3333") => {
                    Response::json(fixture("osv/vuln-openssf.json"))
                }
                _ => Response::with_status(404, "{}"),
            },
        );
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    assert_eq!(
        kinds(&report, FindingKind::Malware),
        1,
        "{:?}",
        report.findings
    );
    assert_eq!(kinds(&report, FindingKind::Advisory), 0);
}

#[test]
fn malware_without_detail_is_still_blocking_and_incomplete() {
    let server = TestServer::start(|request| match request.path.as_str() {
        "/v1/querybatch" => Response::json(fixture("osv/batch-malware.json")),
        _ => Response::with_status(500, "{}"),
    });
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo-malware")]);
    assert_eq!(kinds(&report, FindingKind::Malware), 1, "MAL- id is enough");
    assert!(!report.complete);
    assert_eq!(kinds(&report, FindingKind::IncompleteScan), 1);
}

#[test]
fn page_tokens_are_followed_and_deduped() {
    let server = TestServer::start(|request| {
        if request.path != "/v1/querybatch" {
            return match request.path.as_str() {
                "/v1/vulns/GHSA-aaaa-bbbb-cccc" => Response::json(fixture("osv/vuln-ghsa.json")),
                "/v1/vulns/GHSA-dddd-eeee-ffff" => Response::json(fixture("osv/vuln-ghsa-2.json")),
                _ => Response::with_status(404, "{}"),
            };
        }
        if request.body.contains("page-2") {
            Response::json(fixture("osv/batch-paged-second.json"))
        } else {
            Response::json(fixture("osv/batch-paged-first.json"))
        }
    });
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    assert_eq!(
        advisory_ids(&report),
        vec!["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]
    );
    assert!(report.complete);
}

#[test]
fn cache_hit_avoids_network() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    let first = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    let after_first = server.hits();
    let second = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    assert_eq!(server.hits(), after_first, "fresh cache must not re-query");
    assert!(first.complete && second.complete);
    assert_eq!(advisory_ids(&first), advisory_ids(&second));
}

#[test]
fn offline_uses_fresh_cache() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    let _ = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    server.stop();

    let mut offline = settings.clone();
    offline.offline = true;
    let report = scan::check_advisories(&paths, &offline, &[pkg("demo")]);
    assert_eq!(kinds(&report, FindingKind::Advisory), 2);
    assert_eq!(kinds(&report, FindingKind::StaleData), 0);
    assert_eq!(kinds(&report, FindingKind::IncompleteScan), 0);
    assert!(report.complete);
}

#[test]
fn stale_data_is_reported() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let mut settings = advisory_settings(server.url());
    let _ = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    server.stop();

    // Past the TTL: the cached answer is still used, but never called fresh.
    settings.ttl_secs = 0;
    settings.offline = true;
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    assert_eq!(kinds(&report, FindingKind::Advisory), 2);
    let stale = report
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::StaleData)
        .expect("stale data finding");
    assert_eq!(stale.action, FindingAction::Approve);
    assert_eq!(stale.target.as_deref(), Some("npm:demo@1.0.0"));
    assert!(!report.complete, "stale data is not a verified answer");
}

#[test]
fn network_failure_falls_back_to_stale_cache() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let mut settings = advisory_settings(server.url());
    let _ = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    server.stop();

    settings.osv_url = refused_url();
    settings.ttl_secs = 0;
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    assert_eq!(kinds(&report, FindingKind::Advisory), 2, "cache answered");
    assert_eq!(kinds(&report, FindingKind::StaleData), 1);
    assert!(!report.complete);
}

#[test]
fn offline_without_cache_is_incomplete() {
    let (_dir, paths) = home();
    let mut settings = advisory_settings(&refused_url());
    settings.offline = true;
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    assert!(!report.complete);
    assert_eq!(kinds(&report, FindingKind::IncompleteScan), 1);
    assert_eq!(
        kinds(&report, FindingKind::Advisory),
        0,
        "never report clean"
    );
    assert_eq!(kinds(&report, FindingKind::StaleData), 0);
}

#[test]
fn unusable_endpoint_is_incomplete() {
    for url in [
        "file:///etc/passwd",
        "ftp://example.test",
        "https://user:tok@example.test",
        "not a url",
    ] {
        let (_dir, paths) = home();
        let settings = advisory_settings(url);
        let report = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
        assert!(!report.complete, "{url}");
        assert_eq!(kinds(&report, FindingKind::IncompleteScan), 1, "{url}");
        assert_eq!(kinds(&report, FindingKind::Advisory), 0, "{url}");
    }
}

#[test]
fn timeout_is_incomplete() {
    let server = TestServer::start(|request| {
        if request.path == "/v1/querybatch" {
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
        Response::json(fixture("osv/batch-clean.json"))
    });
    let (_dir, paths) = home();
    let mut settings = advisory_settings(server.url());
    settings.timeout_secs = 1;
    let started = std::time::Instant::now();
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    let elapsed = started.elapsed();
    assert!(!report.complete);
    assert_eq!(kinds(&report, FindingKind::IncompleteScan), 1);
    assert!(
        elapsed < std::time::Duration::from_millis(2900),
        "timeout was not applied: {elapsed:?}"
    );
}

#[test]
fn cache_stays_within_bounds() {
    let server = advisory_server();
    let (_dir, paths) = home();
    let mut settings = advisory_settings(server.url());
    settings.cache_max_bytes = 512;
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    let stored = scan_support::cache_bytes(&paths);
    assert!(stored <= settings.cache_max_bytes, "cache grew to {stored}");
    assert_eq!(
        kinds(&report, FindingKind::Advisory),
        2,
        "results survive eviction"
    );
    assert!(report.complete);
}

#[test]
fn clean_version_reports_nothing() {
    let server = TestServer::start(|request| match request.path.as_str() {
        "/v1/querybatch" => Response::json(fixture("osv/batch-clean.json")),
        _ => Response::with_status(404, "{}"),
    });
    let (_dir, paths) = home();
    let settings = advisory_settings(server.url());
    let report = scan::check_advisories(&paths, &settings, &[pkg("demo")]);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert!(report.complete);
}

#[test]
#[ignore = "live internet: cargo test -p fail2commit --test scan_advisories -- --ignored"]
fn live_osv_smoke() {
    let (_dir, paths) = home();
    let settings = fail2commit_core::settings::AdvisorySettings {
        timeout_secs: 30,
        ..Default::default()
    };
    let report = scan::check_advisories(&paths, &settings, &[pkg("left-pad")]);
    assert!(report.complete, "{:?}", report.findings);
}
