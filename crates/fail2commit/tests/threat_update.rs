//! FR-018 (SPEC-015, TC-018-*): updating threat data from current upstream
//! data. Every archive is built here and served from loopback; nothing
//! reaches the internet.

use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::protocol::{FindingAction, FindingKind};
use fail2commit_core::scan::malware_list::{self, State};
use fail2commit_core::scan::{self, Ecosystem, PackageId};
use fail2commit_core::settings::{AdvisorySettings, Settings};
use fail2commit_core::ResultCode;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;

const COMMIT: &str = "a7f5b1b4846a04c00848fe19ba19f1059f85e55b";
const TOP: &str = "malicious-packages-main";

fn home() -> (tempfile::TempDir, TrustedPaths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = TrustedPaths::under(dir.path());
    paths.ensure().unwrap();
    (dir, paths)
}

fn offline() -> AdvisorySettings {
    AdvisorySettings {
        offline: true,
        offline_malware: true,
        ..Default::default()
    }
}

fn record(id: &str, eco: &str, name: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "affected": [{ "package": { "ecosystem": eco, "name": name },
                       "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0" }] }] }]
    }))
    .unwrap()
}

/// A `git archive`-style tar.gz: pax global header naming the commit, then
/// the records.
fn archive(records: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    let pax = format!("52 comment={COMMIT}\n");
    let mut h = tar::Header::new_ustar();
    h.set_path("pax_global_header").unwrap();
    h.set_entry_type(tar::EntryType::XGlobalHeader);
    h.set_size(pax.len() as u64);
    h.set_mode(0o666);
    h.set_cksum();
    b.append(&h, pax.as_bytes()).unwrap();
    for (id, eco, name) in records {
        let data = record(id, eco, name);
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        let dir = if *eco == "npm" { "npm" } else { "pypi" };
        b.append_data(
            &mut h,
            format!("{TOP}/osv/malicious/{dir}/{name}/{id}.json"),
            data.as_slice(),
        )
        .unwrap();
    }
    b.into_inner().unwrap().finish().unwrap()
}

/// Serve one response; `send` bytes of the body at most (a cut-off transfer
/// when smaller than the advertised length).
fn serve(status: &str, body: Vec<u8>, send: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/main.tar.gz", listener.local_addr().unwrap());
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let mut seen = Vec::new();
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body[..send.min(body.len())]);
        }
    });
    url
}

fn serve_all(body: Vec<u8>) -> String {
    let n = body.len();
    serve("200 OK", body, n)
}

fn pkg(name: &str) -> PackageId {
    PackageId {
        ecosystem: Ecosystem::Npm,
        name: name.into(),
        version: "1.0.0".into(),
    }
}

fn denied(paths: &TrustedPaths, name: &str) -> bool {
    scan::check_advisories(paths, &offline(), &[pkg(name)])
        .findings
        .iter()
        .any(|f| f.kind == FindingKind::Malware && f.action == FindingAction::Deny)
}

fn update(paths: &TrustedPaths, url: &str) -> fail2commit_core::Result<malware_list::Header> {
    malware_list::update_latest_from_url(paths, &offline(), url, 60)
}

fn index_bytes(paths: &TrustedPaths) -> Vec<u8> {
    std::fs::read(malware_list::index_path(paths)).unwrap()
}

/// Rewrite the index body with `edit` and a matching tag (simulates an old
/// or 0.1.3-written index).
fn rewrite_index(paths: &TrustedPaths, edit: impl FnOnce(&mut serde_json::Value)) {
    let bytes = index_bytes(paths);
    let split = bytes.iter().position(|&b| b == b'\n').unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&bytes[split + 1..]).unwrap();
    edit(&mut body);
    let json = serde_json::to_vec(&body).unwrap();
    let mut out = hex::encode(Sha256::digest(&json)).into_bytes();
    out.push(b'\n');
    out.extend_from_slice(&json);
    std::fs::write(malware_list::index_path(paths), out).unwrap();
}

fn age_index(paths: &TrustedPaths, days: u64) {
    rewrite_index(paths, |b| {
        let at = b["header"]["imported_at"].as_u64().unwrap();
        b["header"]["imported_at"] = (at - days * 86_400).into();
    });
}

/// TC-018-1
#[test]
fn latest_update_lists_new_package_as_malware_offline() {
    let (_d, paths) = home();
    let url = serve_all(archive(&[("MAL-2026-1", "npm", "old-bad")]));
    update(&paths, &url).expect("first update");
    assert!(!denied(&paths, "brand-new-bad"), "not listed yet");

    let url = serve_all(archive(&[
        ("MAL-2026-1", "npm", "old-bad"),
        ("MAL-2026-9", "npm", "brand-new-bad"),
        ("MAL-2026-10", "PyPI", "Evil_Py"),
    ]));
    let h = update(&paths, &url).expect("second update");
    assert_eq!(h.source, "latest");
    assert_eq!(h.commit, COMMIT);
    assert_eq!((h.npm, h.pypi), (2, 1));
    assert!(
        denied(&paths, "brand-new-bad"),
        "an offline install of P is a malware deny"
    );
}

/// TC-018-2
#[test]
fn cut_off_download_keeps_previous_index() {
    let (_d, paths) = home();
    update(&paths, &serve_all(archive(&[("MAL-1", "npm", "a-bad")]))).unwrap();
    let before = index_bytes(&paths);
    let full = archive(&[("MAL-1", "npm", "a-bad"), ("MAL-2", "npm", "b-bad")]);
    let half = full.len() / 2;
    let err = update(&paths, &serve("200 OK", full.clone(), half)).expect_err("cut off");
    assert!(
        err.message.contains("read failed") || err.message.contains("rejected"),
        "names the reason: {}",
        err.message
    );
    // A body that ends early but matches its own length is a broken gzip.
    let err = update(&paths, &serve_all(full[..half].to_vec())).expect_err("truncated gzip");
    assert_eq!(err.code, ResultCode::Rejected, "{}", err.message);
    assert_eq!(index_bytes(&paths), before, "the old index still works");
    assert!(denied(&paths, "a-bad"));
}

/// TC-018-3
#[test]
fn oversized_download_keeps_previous_index() {
    let (_d, paths) = home();
    update(&paths, &serve_all(archive(&[("MAL-1", "npm", "a-bad")]))).unwrap();
    let before = index_bytes(&paths);
    let big = archive(&[("MAL-1", "npm", "a-bad"), ("MAL-2", "npm", "b-bad")]);
    let small = AdvisorySettings {
        malware_list_max_bytes: big.len() as u64 - 1,
        ..offline()
    };
    let err = malware_list::update_latest_from_url(&paths, &small, &serve_all(big), 60)
        .expect_err("too large");
    assert!(
        err.message.contains("malware_list_max_bytes"),
        "{}",
        err.message
    );
    assert_eq!(index_bytes(&paths), before);
}

/// TC-018-4
#[test]
fn invalid_archive_keeps_previous_index() {
    let (_d, paths) = home();
    update(&paths, &serve_all(archive(&[("MAL-1", "npm", "a-bad")]))).unwrap();
    let before = index_bytes(&paths);
    let err =
        update(&paths, &serve_all(b"<html>not an archive</html>".to_vec())).expect_err("not gzip");
    assert_eq!(err.code, ResultCode::Rejected, "{}", err.message);
    let err = update(&paths, &serve_all(archive(&[]))).expect_err("no records");
    assert!(
        err.message.contains("no npm or PyPI records"),
        "{}",
        err.message
    );
    let err = update(&paths, &serve("404 Not Found", Vec::new(), 0)).expect_err("404");
    assert!(err.message.contains("404"), "{}", err.message);
    assert_eq!(index_bytes(&paths), before);
}

/// TC-018-5
#[test]
fn unreachable_source_changes_nothing() {
    let (_d, paths) = home();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let err = update(&paths, &format!("http://127.0.0.1:{port}/main.tar.gz"))
        .expect_err("nothing listens");
    assert_eq!(err.code, ResultCode::IncompleteScan, "{}", err.message);
    assert!(!malware_list::index_path(&paths).exists());
}

fn cli(home: &Path, args: &[&str]) -> (i32, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_fail2commit"))
        .args(args)
        .env("FAIL2COMMIT_HOME", home)
        .output()
        .expect("spawn fail2commit");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// TC-018-6
#[test]
fn status_warns_when_index_is_old() {
    let (d, paths) = home();
    update(&paths, &serve_all(archive(&[("MAL-1", "npm", "a-bad")]))).unwrap();
    for args in [
        &["status"][..],
        &["malware-list", "status"],
        &["threat-data", "status"],
    ] {
        let (code, out) = cli(d.path(), args);
        assert_eq!(code, 0, "{args:?}: {out}");
        assert!(!out.contains("warning: threat data is"), "{args:?}: {out}");
    }
    let (_, out) = cli(d.path(), &["status"]);
    assert!(
        out.contains("threat data: latest a7f5b1b4846a, 1 record(s), 0 day(s) old"),
        "{out}"
    );

    age_index(&paths, 30);
    for args in [&["status"][..], &["malware-list", "status"]] {
        let (code, out) = cli(d.path(), args);
        assert_eq!(code, 0, "{args:?}: {out}");
        assert!(
            out.contains("warning: threat data is 30 day(s) old (threat_data.max_age_days = 7)"),
            "{args:?}: {out}"
        );
    }
}

/// TC-018-7
#[test]
fn auto_refresh_replaces_stale_index_and_failure_only_warns() {
    let (_d, paths) = home();
    update(&paths, &serve_all(archive(&[("MAL-1", "npm", "a-bad")]))).unwrap();
    let mut settings = Settings {
        advisories: offline(),
        ..Default::default()
    };

    // Off by default: nothing is fetched.
    assert!(malware_list::auto_refresh_from(&paths, &settings, "http://127.0.0.1:9/x").is_empty());
    settings.threat_data.auto_update = true;
    // Fresh index: nothing is fetched (the URL would fail).
    assert!(malware_list::auto_refresh_from(&paths, &settings, "http://127.0.0.1:9/x").is_empty());

    age_index(&paths, 30);
    let before = index_bytes(&paths);
    let f = malware_list::auto_refresh_from(&paths, &settings, "http://127.0.0.1:9/x");
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].action, FindingAction::Info);
    assert!(
        f[0].evidence.contains("threat data refresh failed"),
        "{}",
        f[0].evidence
    );
    assert_eq!(index_bytes(&paths), before, "the old index stays");

    let url = serve_all(archive(&[
        ("MAL-1", "npm", "a-bad"),
        ("MAL-2", "npm", "b-bad"),
    ]));
    assert!(malware_list::auto_refresh_from(&paths, &settings, &url).is_empty());
    let State::Valid(index) = malware_list::load(&paths) else {
        panic!("valid index")
    };
    assert_eq!(index.header.npm, 2);
    assert!(!index.header.is_stale(index.header.imported_at, 7));
    assert!(denied(&paths, "b-bad"));
}

/// TC-018-8
#[test]
fn old_index_without_source_loads_as_pinned() {
    let (_d, paths) = home();
    update(&paths, &serve_all(archive(&[("MAL-1", "npm", "a-bad")]))).unwrap();
    rewrite_index(&paths, |b| {
        b["header"].as_object_mut().unwrap().remove("source");
    });
    let State::Valid(index) = malware_list::load(&paths) else {
        panic!("a 0.1.3 index stays valid")
    };
    assert_eq!(index.header.source, "pinned");
    assert!(denied(&paths, "a-bad"));
}
