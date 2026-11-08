//! TC-012 / NFR-012 / SPEC-012: bounds are configurable, reported, and an
//! incomplete scan is never reported as clean. Cheap enough for CI.

mod resource_support;
use resource_support::*;

#[test]
fn clean_scan_is_ok_and_exit_zero() {
    let (h, r) = (home(""), repo(3));
    let (out, v) = f2c(h.path(), r.path(), &["secret-scan"]);
    assert_eq!(v["code"], "ok", "{v}");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn exhausted_budget_is_incomplete_not_clean_and_names_the_limit() {
    // Default is 256 MiB; a 4-byte budget cannot cover any blob.
    let (h, r) = (home("[limits]\nscan_max_bytes = 4\n"), repo(3));
    let (out, v) = f2c(h.path(), r.path(), &["secret-scan"]);
    assert_eq!(v["code"], "incomplete_scan", "{v}");
    assert_eq!(out.status.code(), Some(12), "distinct exit code");
    let text = v.to_string();
    assert!(
        text.contains("budget of 4 bytes"),
        "the configured bound must be reported: {text}"
    );
}

#[test]
fn malformed_limit_fails_closed_instead_of_using_a_default() {
    let (h, r) = (home("[limits]\nscan_max_bytes = \"big\"\n"), repo(1));
    let (out, v) = f2c(h.path(), r.path(), &["secret-scan"]);
    assert_eq!(v["code"], "invalid_input", "{v}");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn offline_advisory_scan_without_cache_is_incomplete_not_clean() {
    let (h, r) = (home(""), tempfile::tempdir().unwrap());
    let (out, v) = f2c(
        h.path(),
        r.path(),
        &["scan", "--offline", "npm:left-pad@1.3.0"],
    );
    assert_eq!(v["code"], "incomplete_scan", "{v}");
    assert_eq!(out.status.code(), Some(12));
}

/// FINDING (docs/resources.md): no CLI surface prints the configured limit
/// values; `status` omits them. Pinned so a future change is noticed: when
/// limits are reported, update this test and the doc.
#[test]
fn status_does_not_yet_report_limits() {
    let (h, r) = (home(""), tempfile::tempdir().unwrap());
    let (_, v) = f2c(h.path(), r.path(), &["status"]);
    assert!(
        v["data"].get("limits").is_none(),
        "limits now reported: update docs/resources.md"
    );
}
