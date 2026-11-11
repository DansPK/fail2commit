//! FR-025 (SPEC-015, TC-025-*): pre-install risk checks from registry
//! metadata and the reviewed files. Registries are loopback fixtures.

mod npm_support;

use base64::Engine as _;
use fail2commit_core::npm;
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::protocol::{Decision, Finding, FindingAction, FindingKind};
use fail2commit_core::scan::checks::{self, Candidate, Origin};
use fail2commit_core::scan::{Ecosystem, PackageId};
use fail2commit_core::settings::Settings;
use npm_support::{require_node, snapshot, Behavior, Env, FakeBackend, Pkg, Registry, Run};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Loopback server: GET path -> body, else 404.
struct Srv {
    url: String,
    routes: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Srv {
    fn start() -> Srv {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let routes: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
        let r = routes.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let r = r.clone();
                std::thread::spawn(move || serve(c, &r));
            }
        });
        Srv { url, routes }
    }
    fn put(&self, path: &str, body: Vec<u8>) {
        self.routes.lock().unwrap().insert(path.to_string(), body);
    }
}

fn serve(mut c: std::net::TcpStream, routes: &Mutex<HashMap<String, Vec<u8>>>) {
    let mut buf = [0u8; 8192];
    let mut req = Vec::new();
    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => req.extend_from_slice(&buf[..n]),
        }
    }
    let text = String::from_utf8_lossy(&req);
    let path = text
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .replace("%2f", "/");
    let body = routes.lock().unwrap().get(&path).cloned();
    let (status, body) = match body {
        Some(b) => ("200 OK", b),
        None => ("404 Not Found", b"{}".to_vec()),
    };
    let _ = c.write_all(
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    let _ = c.write_all(&body);
}

fn home() -> (tempfile::TempDir, TrustedPaths) {
    let d = tempfile::tempdir().unwrap();
    let p = TrustedPaths::under(&d.path().join("home"));
    p.ensure().unwrap();
    (d, p)
}

fn hours_ago(h: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let t = now - h * 3600;
    // Civil from days (H. Hinnant).
    let (days, rem) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn tgz(files: &[(&str, &str)]) -> Vec<u8> {
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    for (p, body) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, format!("package/{p}"), body.as_bytes())
            .unwrap();
    }
    b.into_inner().unwrap().finish().unwrap()
}

fn sri(b: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(b))
    )
}

/// One npm version: (version, hours ago, scripts, maintainers, publisher,
/// tarball files).
struct V<'a> {
    v: &'a str,
    age_h: i64,
    install: bool,
    maint: &'a [&'a str],
    by: &'a str,
    files: &'a [(&'a str, &'a str)],
}

fn npm_doc(srv: &Srv, name: &str, vs: &[V]) {
    let mut versions = serde_json::Map::new();
    let mut time = serde_json::Map::new();
    time.insert("created".into(), hours_ago(100_000).into());
    for v in vs {
        let tar = tgz(v.files);
        let path = format!("/{name}/-/{name}-{}.tgz", v.v);
        let mut m = serde_json::json!({
            "name": name, "version": v.v,
            "maintainers": v.maint.iter().map(|n| serde_json::json!({"name": n, "email": format!("{n}@example.test")})).collect::<Vec<_>>(),
            "_npmUser": {"name": v.by, "email": "x@example.test"},
            "dist": {"tarball": format!("{}{path}", srv.url), "integrity": sri(&tar)},
        });
        if v.install {
            m["scripts"] = serde_json::json!({"postinstall": "node setup.js"});
        }
        versions.insert(v.v.into(), m);
        time.insert(v.v.into(), hours_ago(v.age_h).into());
        srv.put(&path, tar);
    }
    srv.put(
        &format!("/{name}"),
        serde_json::to_vec(&serde_json::json!({"name": name, "versions": versions, "time": time}))
            .unwrap(),
    );
}

fn pkg_dir(root: &Path, files: &[(&str, &str)]) -> PathBuf {
    let d = root.join(format!("pkg-{}", files.len() + rand_suffix()));
    for (p, b) in files {
        let f = d.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, b).unwrap();
    }
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn rand_suffix() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::Relaxed) * 1000
}

fn npm_run(
    srv: &Srv,
    paths: &TrustedPaths,
    settings: &Settings,
    c: Vec<Candidate>,
) -> Vec<Finding> {
    let url = format!("{}/", srv.url);
    checks::run(
        paths,
        settings,
        &Origin {
            url: &url,
            file_hosts: &[],
            artifact_max_bytes: 64 << 20,
        },
        &c,
    )
}

fn cand(name: &str, version: &str, dir: PathBuf, install: bool) -> Candidate {
    Candidate {
        pkg: PackageId {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
        },
        artifact: dir,
        install_script: install,
    }
}

fn signals(f: &[Finding]) -> Vec<String> {
    f.iter()
        .filter(|f| f.kind == FindingKind::RiskSignal)
        .inspect(|f| assert_eq!(f.action, FindingAction::Approve))
        .map(|f| f.evidence.clone())
        .collect()
}

const CLEAN: &[(&str, &str)] = &[("index.js", "module.exports = 1;\n")];

fn obfuscated() -> String {
    (0..40)
        .map(|i| format!("var _0x{i:04x}=_0x{:04x};\n", i + 1))
        .collect()
}

/// TC-025-1
#[test]
fn npm_new_install_script() {
    let srv = Srv::start();
    let (d, paths) = home();
    let m = &["alice"];
    npm_doc(
        &srv,
        "grows-script",
        &[
            V {
                v: "1.0.0",
                age_h: 5000,
                install: false,
                maint: m,
                by: "alice",
                files: CLEAN,
            },
            V {
                v: "1.1.0",
                age_h: 4000,
                install: true,
                maint: m,
                by: "alice",
                files: CLEAN,
            },
        ],
    );
    let dir = pkg_dir(d.path(), CLEAN);
    let f = npm_run(
        &srv,
        &paths,
        &Settings::default(),
        vec![cand("grows-script", "1.1.0", dir, true)],
    );
    let s = signals(&f);
    assert_eq!(s.len(), 1, "{f:?}");
    assert!(s[0].starts_with("(a) new install script"), "{}", s[0]);
    assert!(s[0].contains("1.0.0 had none"), "{}", s[0]);
}

/// TC-025-2
#[test]
fn npm_maintainer_change() {
    let srv = Srv::start();
    let (d, paths) = home();
    npm_doc(
        &srv,
        "hijacked",
        &[
            V {
                v: "1.0.0",
                age_h: 5000,
                install: false,
                maint: &["alice"],
                by: "alice",
                files: CLEAN,
            },
            V {
                v: "1.0.1",
                age_h: 4000,
                install: false,
                maint: &["alice", "mallory"],
                by: "mallory",
                files: CLEAN,
            },
        ],
    );
    npm_doc(
        &srv,
        "new-publisher",
        &[
            V {
                v: "1.0.0",
                age_h: 5000,
                install: false,
                maint: &["alice"],
                by: "alice",
                files: CLEAN,
            },
            V {
                v: "1.0.1",
                age_h: 4000,
                install: false,
                maint: &["alice"],
                by: "eve",
                files: CLEAN,
            },
        ],
    );
    let f = npm_run(
        &srv,
        &paths,
        &Settings::default(),
        vec![
            cand("hijacked", "1.0.1", pkg_dir(d.path(), CLEAN), false),
            cand("new-publisher", "1.0.1", pkg_dir(d.path(), CLEAN), false),
        ],
    );
    let s = signals(&f);
    assert_eq!(s.len(), 2, "{f:?}");
    assert!(
        s.iter()
            .any(|e| e.contains("(b) maintainers changed") && e.contains("added `mallory`")),
        "{s:?}"
    );
    assert!(
        s.iter()
            .any(|e| e.contains("(b) new publisher") && e.contains("`eve`")),
        "{s:?}"
    );
}

/// TC-025-3
#[test]
fn very_new_version() {
    let srv = Srv::start();
    let (d, paths) = home();
    npm_doc(
        &srv,
        "fresh-pkg",
        &[
            V {
                v: "1.0.0",
                age_h: 5000,
                install: false,
                maint: &["a"],
                by: "a",
                files: CLEAN,
            },
            V {
                v: "1.0.1",
                age_h: 1,
                install: false,
                maint: &["a"],
                by: "a",
                files: CLEAN,
            },
        ],
    );
    let f = npm_run(
        &srv,
        &paths,
        &Settings::default(),
        vec![cand("fresh-pkg", "1.0.1", pkg_dir(d.path(), CLEAN), false)],
    );
    let s = signals(&f);
    assert_eq!(s.len(), 1, "{f:?}");
    assert!(
        s[0].contains("(c) very new version") && s[0].contains("checks.min_age_hours = 48"),
        "{}",
        s[0]
    );
    // The setting decides.
    let mut lax = Settings::default();
    lax.checks.min_age_hours = 0;
    let (_d2, paths2) = home();
    let f = npm_run(
        &srv,
        &paths2,
        &lax,
        vec![cand("fresh-pkg", "1.0.1", pkg_dir(d.path(), CLEAN), false)],
    );
    assert!(signals(&f).is_empty(), "{f:?}");
}

/// TC-025-4
#[test]
fn look_alike_names() {
    for n in ["lodahs", "l0dash", "lodash_", "expresss"] {
        let (p, _) = checks::look_alike(Ecosystem::Npm, n).unwrap_or_else(|| panic!("{n}"));
        assert!(p == "lodash" || p == "express", "{n} -> {p}");
    }
    assert!(checks::look_alike(Ecosystem::Npm, "lodash").is_none());
    assert_eq!(
        checks::look_alike(Ecosystem::PyPI, "reqeusts").unwrap().0,
        "requests"
    );
    assert!(checks::look_alike(Ecosystem::PyPI, "requests").is_none());
    // Through the checks, without any registry data.
    let (d, paths) = home();
    let f = npm_run(
        &Srv::start(),
        &paths,
        &Settings::default(),
        vec![cand("lodahs", "1.0.0", pkg_dir(d.path(), CLEAN), false)],
    );
    let s = signals(&f);
    assert!(
        s.iter()
            .any(|e| e.starts_with("(d) look-alike name") && e.contains("`lodash`")),
        "{f:?}"
    );
}

/// TC-025-5
#[test]
fn npm_newly_obfuscated() {
    let srv = Srv::start();
    let (d, paths) = home();
    let obf = obfuscated();
    let now_files = [("index.js", obf.as_str())];
    npm_doc(
        &srv,
        "turned-obf",
        &[
            V {
                v: "1.0.0",
                age_h: 5000,
                install: false,
                maint: &["a"],
                by: "a",
                files: CLEAN,
            },
            V {
                v: "1.0.1",
                age_h: 4000,
                install: false,
                maint: &["a"],
                by: "a",
                files: &now_files,
            },
        ],
    );
    npm_doc(
        &srv,
        "always-obf",
        &[
            V {
                v: "1.0.0",
                age_h: 5000,
                install: false,
                maint: &["a"],
                by: "a",
                files: &now_files,
            },
            V {
                v: "1.0.1",
                age_h: 4000,
                install: false,
                maint: &["a"],
                by: "a",
                files: &now_files,
            },
        ],
    );
    let f = npm_run(
        &srv,
        &paths,
        &Settings::default(),
        vec![
            cand("turned-obf", "1.0.1", pkg_dir(d.path(), &now_files), false),
            cand("always-obf", "1.0.1", pkg_dir(d.path(), &now_files), false),
        ],
    );
    let s = signals(&f);
    assert_eq!(s.len(), 1, "{f:?}");
    assert!(
        s[0].contains("(e) newly obfuscated code") && s[0].contains("index.js"),
        "{}",
        s[0]
    );
    assert!(f
        .iter()
        .all(|x| x.target.as_deref() != Some("npm:always-obf@1.0.1")
            || x.kind != FindingKind::RiskSignal));

    // A previous tarball that does not match its integrity is "not checked".
    let (_d2, paths2) = home();
    srv.put(
        "/turned-obf/-/turned-obf-1.0.0.tgz",
        tgz(&[("index.js", "tampered")]),
    );
    let f = npm_run(
        &srv,
        &paths2,
        &Settings::default(),
        vec![cand(
            "turned-obf",
            "1.0.1",
            pkg_dir(d.path(), &now_files),
            false,
        )],
    );
    assert!(signals(&f).is_empty(), "{f:?}");
    assert!(
        f.iter().any(|x| x.kind == FindingKind::IncompleteScan
            && x.action == FindingAction::Info
            && x.evidence.contains("integrity")),
        "{f:?}"
    );
}

fn wheel(files: &[(&str, &str)]) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (p, b) in files {
        z.start_file(*p, zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(b.as_bytes()).unwrap();
    }
    z.finish().unwrap().into_inner()
}

/// (version, hours ago, author email, wheel files)
/// (version, hours ago, author email, wheel files)
type PyRelease<'a> = (&'a str, i64, &'a str, &'a [(&'a str, &'a str)]);

fn pypi_project(srv: &Srv, name: &str, rel: &[PyRelease]) {
    let mut releases = serde_json::Map::new();
    for (v, age, who, files) in rel {
        let w = wheel(files);
        let file = format!("{name}-{v}-py3-none-any.whl");
        let path = format!("/files/{file}");
        releases.insert(
            (*v).into(),
            serde_json::json!([{
                "filename": file, "packagetype": "bdist_wheel", "yanked": false,
                "url": format!("{}{path}", srv.url),
                "digests": {"sha256": hex::encode(Sha256::digest(&w))},
                "upload_time_iso_8601": hours_ago(*age),
            }]),
        );
        srv.put(&path, w);
        srv.put(
            &format!("/pypi/{name}/{v}/json"),
            serde_json::to_vec(&serde_json::json!({"info": {"version": v, "author_email": who}}))
                .unwrap(),
        );
    }
    let latest = rel.last().unwrap();
    srv.put(
        &format!("/pypi/{name}/json"),
        serde_json::to_vec(&serde_json::json!({
            "info": {"version": latest.0, "author_email": latest.2},
            "releases": releases,
        }))
        .unwrap(),
    );
}

fn pypi_run(srv: &Srv, paths: &TrustedPaths, c: Vec<(&str, &str, PathBuf)>) -> Vec<Finding> {
    let url = format!("{}/simple", srv.url);
    let cands = c
        .into_iter()
        .map(|(n, v, p)| Candidate {
            pkg: PackageId {
                ecosystem: Ecosystem::PyPI,
                name: n.into(),
                version: v.into(),
            },
            artifact: p,
            install_script: false,
        })
        .collect::<Vec<_>>();
    checks::run(
        paths,
        &Settings::default(),
        &Origin {
            url: &url,
            file_hosts: &[],
            artifact_max_bytes: 64 << 20,
        },
        &cands,
    )
}

/// TC-025-6
#[test]
fn pypi_checks_against_previous_release() {
    let srv = Srv::start();
    let (d, paths) = home();
    let clean: &[(&str, &str)] = &[("demo/__init__.py", "X = 1\n")];
    let evil_src = "import zlib\nexec(zlib.decompress(b'...'))\n";
    let evil: &[(&str, &str)] = &[
        ("demo/__init__.py", evil_src),
        ("demo-init.pth", "import demo\n"),
    ];
    pypi_project(
        &srv,
        "demo-lib",
        &[
            ("1.0.0", 5000, "alice@example.test", clean),
            ("1.1.0", 4000, "mallory@example.test", evil),
        ],
    );
    let current = d.path().join("demo_lib-1.1.0-py3-none-any.whl");
    std::fs::write(&current, wheel(evil)).unwrap();
    let f = pypi_run(&srv, &paths, vec![("demo-lib", "1.1.0", current)]);
    let s = signals(&f);
    assert!(s.iter().any(|e| e.starts_with("(b) maintainers changed") && e.contains("mallory@example.test")), "{f:?}");
    assert!(
        s.iter()
            .any(|e| e.starts_with("(a) new startup file") && e.contains("demo-init.pth")),
        "{f:?}"
    );
    assert!(
        s.iter().any(|e| e.starts_with("(e) newly obfuscated code")),
        "{f:?}"
    );
    assert_eq!(s.len(), 3, "{f:?}");
}

/// TC-025-7
#[test]
fn clean_established_package_has_no_signal() {
    let srv = Srv::start();
    let (d, paths) = home();
    let m = &["alice", "bob"];
    npm_doc(
        &srv,
        "steady-pkg",
        &[
            V {
                v: "1.0.0",
                age_h: 9000,
                install: true,
                maint: m,
                by: "alice",
                files: CLEAN,
            },
            V {
                v: "1.1.0",
                age_h: 5000,
                install: true,
                maint: m,
                by: "bob",
                files: CLEAN,
            },
        ],
    );
    let f = npm_run(
        &srv,
        &paths,
        &Settings::default(),
        vec![cand("steady-pkg", "1.1.0", pkg_dir(d.path(), CLEAN), true)],
    );
    assert!(f.is_empty(), "{f:?}");
    let clean: &[(&str, &str)] = &[("steady/__init__.py", "X = 1\n")];
    pypi_project(
        &srv,
        "steady",
        &[
            ("1.0.0", 9000, "alice@example.test", clean),
            ("1.1.0", 5000, "alice@example.test", clean),
        ],
    );
    let w = d.path().join("steady-1.1.0-py3-none-any.whl");
    std::fs::write(&w, wheel(clean)).unwrap();
    let f = pypi_run(&srv, &paths, vec![("steady", "1.1.0", w)]);
    assert!(f.is_empty(), "{f:?}");
}

/// TC-025-8
#[test]
fn missing_metadata_is_not_checked() {
    let srv = Srv::start();
    let (d, paths) = home();
    // No `time` map and no maintainers.
    srv.put(
        "/bare-pkg",
        serde_json::to_vec(&serde_json::json!({"versions": {"1.0.0": {"name": "bare-pkg"}}}))
            .unwrap(),
    );
    let f = npm_run(
        &srv,
        &paths,
        &Settings::default(),
        vec![
            cand("bare-pkg", "1.0.0", pkg_dir(d.path(), CLEAN), false),
            cand("unknown-pkg", "1.0.0", pkg_dir(d.path(), CLEAN), false),
        ],
    );
    assert!(signals(&f).is_empty(), "{f:?}");
    let info: Vec<&Finding> = f
        .iter()
        .filter(|x| x.kind == FindingKind::IncompleteScan && x.action == FindingAction::Info)
        .collect();
    assert_eq!(info.len(), 2, "{f:?}");
    let bare = info
        .iter()
        .find(|x| x.target.as_deref() == Some("npm:bare-pkg@1.0.0"))
        .unwrap();
    assert!(
        bare.evidence
            .contains("(c): the registry returned no publish time"),
        "{}",
        bare.evidence
    );
    let unknown = info
        .iter()
        .find(|x| x.target.as_deref() == Some("npm:unknown-pkg@1.0.0"))
        .unwrap();
    assert!(
        unknown.evidence.contains("(a), (b), (c), (e)"),
        "{}",
        unknown.evidence
    );
    // Off means nothing at all.
    let mut off = Settings::default();
    off.checks.enabled = false;
    assert!(npm_run(
        &srv,
        &paths,
        &off,
        vec![cand("lodahs", "1.0.0", pkg_dir(d.path(), CLEAN), false)]
    )
    .is_empty());
}

/// TC-025-9
#[test]
fn npm_flow_pauses_on_risk_signal() {
    require_node();
    let reg = Registry::start();
    reg.publish(&Pkg::new("left-pad", "1.0.0"));
    let mut env = Env::new(
        &reg,
        r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.0.0"}}"#,
    );
    // The fixture registry publishes at 2026-01-01; a huge minimum age makes
    // that "very new".
    env.settings.checks.min_age_hours = 10_000_000;
    let before = snapshot(&env.project);
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    let e = npm::execute(
        &run.deps(Behavior {
            decision: Decision::Cancel,
            ..Behavior::default()
        }),
        &env.request(&["install"]),
    )
    .unwrap_err();
    assert_eq!(e.code, fail2commit_core::ResultCode::Rejected, "{e}");
    let reqs = run.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert!(
        reqs[0]
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::RiskSignal && f.evidence.starts_with("(c)")),
        "{:?}",
        reqs[0].findings
    );
    assert_eq!(snapshot(&env.project), before);
}

/// TC-025-10: with checks on, `npm ci` adds exactly one packument GET per
/// package to the tarball downloads, and nothing else.
#[test]
fn npm_ci_checks_add_only_one_packument_request_per_package() {
    require_node();
    let reg = Registry::start();
    let lib = Pkg::new("app-lib", "1.0.0").dep("left-pad", "^1.0.0");
    let pad = Pkg::new("left-pad", "1.0.0").file("index.js", "module.exports=1");
    reg.publish(&lib);
    reg.publish(&pad);
    let env = Env::new(
        &reg,
        r#"{"name":"clean-app","version":"1.0.0","private":true,"dependencies":{"app-lib":"^1.0.0"}}"#,
    );
    std::fs::write(
        env.project.join("package-lock.json"),
        reg.lockfile(&["app-lib"], &[&lib, &pad]),
    )
    .unwrap();
    reg.clear_hits();
    let backend = FakeBackend::new(false, false);
    let run = Run::new(&env, &backend);
    npm::execute(&run.deps(Behavior::default()), &env.request(&["ci"])).unwrap();
    let mut other: Vec<String> = reg
        .hits()
        .into_iter()
        .filter(|h| !h.ends_with(".tgz"))
        .collect();
    other.sort();
    assert_eq!(other, vec!["/app-lib".to_string(), "/left-pad".to_string()]);
}
