#![cfg(windows)]

//! FR-020 hostile catalogue, FR-023 network, FR-024 bait and FR-026 report on
//! the Windows AppContainer backend in default mode (SPEC-014 section 10).
//!
//! Each job runs `tests/fixtures/hostile/windows/probe.rs`, compiled into the
//! job's read-only stage. The helper prints `<label>=<outcome>` for what the
//! OS answered, so every assertion reads a real result. Secrets are planted
//! fakes in temporary folders; the real user's files are never opened. Every
//! HKCU key a test creates is deleted by a guard, and AppContainer profiles
//! are checked for leaks against the backend's owner records.

use fail2commit_core::isolation::{
    ActivityKind, JobLimits, JobOutcome, JobSpec, JobStatus, NetworkMode, SandboxBackend,
};
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::sandbox;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

const STAGE_DIR: &str = "sandbox-stage";
const MAPPINGS: &str = r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings";

fn stage_root() -> PathBuf {
    let root = TrustedPaths::resolve()
        .expect("trusted paths")
        .cache_dir
        .join(STAGE_DIR);
    fs::create_dir_all(&root).expect("stage root");
    root
}

fn system32() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot")).join("System32")
}

/// The helper compiled once per test binary; each stage gets a copy.
fn compiled_helper() -> &'static Path {
    static HELPER: OnceLock<PathBuf> = OnceLock::new();
    HELPER.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("f2c-hostile-build-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hostile/windows/probe.rs");
        let out = dir.join("probe.exe");
        let status = Command::new("rustc")
            .args(["--edition=2021", "-C", "opt-level=1"])
            .arg(&source)
            .arg("-o")
            .arg(&out)
            .status()
            .expect("run rustc");
        assert!(status.success(), "helper compilation failed");
        out
    })
}

struct Stage {
    root: tempfile::TempDir,
    read_only: PathBuf,
    work: PathBuf,
    helper: PathBuf,
    /// Unique image name, so a surviving process can be looked up.
    image: String,
}

fn stage() -> Stage {
    let root = tempfile::Builder::new()
        .prefix("hostile-")
        .tempdir_in(stage_root())
        .expect("job stage");
    let read_only = root.path().join("read-only");
    let work = root.path().join("work");
    fs::create_dir_all(&read_only).unwrap();
    fs::create_dir_all(&work).unwrap();
    let image = format!(
        "f2c-hostile-{}.exe",
        root.path().file_name().unwrap().to_string_lossy()
    );
    let helper = read_only.join(&image);
    fs::copy(compiled_helper(), &helper).unwrap();
    fs::write(read_only.join("reviewed.js"), b"module.exports = 1;\n").unwrap();
    Stage {
        root,
        read_only,
        work,
        helper,
        image,
    }
}

fn limits() -> JobLimits {
    JobLimits {
        timeout: Duration::from_secs(20),
        memory_bytes: Some(256 * 1024 * 1024),
        max_processes: Some(8),
        max_output_bytes: 64 * 1024,
        disk_bytes: Some(256 * 1024 * 1024),
    }
}

fn spec(stage: &Stage, actions: &[&str], network: NetworkMode, bait: bool) -> JobSpec {
    JobSpec {
        program: stage.helper.clone(),
        args: actions.iter().map(OsString::from).collect(),
        cwd: stage.work.clone(),
        env: vec![],
        read_only: vec![stage.read_only.clone()],
        work_dir: stage.work.clone(),
        exports: vec![],
        export_to: None,
        limits: limits(),
        network,
        bait,
    }
}

fn backend() -> Box<dyn SandboxBackend> {
    let backend = sandbox::platform_backend();
    let report = backend.probe();
    assert!(report.available, "{}: {:?}", report.detail, report.controls);
    backend
}

fn run(job: &JobSpec) -> JobOutcome {
    let before = live_leak_baseline();
    let out = backend().run(job).expect("sandbox run");
    assert_no_profile_leak(&before);
    out
}

/// `label=outcome` lines the helper printed.
fn answers(out: &JobOutcome) -> BTreeMap<String, String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn answer(out: &JobOutcome, label: &str) -> String {
    answers(out).get(label).cloned().unwrap_or_else(|| {
        panic!(
            "no answer for {label}: stdout={} stderr={} status={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            out.status
        )
    })
}

fn entries(out: &JobOutcome, kind: ActivityKind) -> Vec<String> {
    out.report
        .events
        .iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.detail.clone())
        .collect()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

// ---- host-side checks ---------------------------------------------------

/// `fail2commit.sbx.*` profiles registered for this user.
fn sandbox_profiles() -> BTreeSet<String> {
    let out = Command::new("reg.exe")
        .args(["query", MAPPINGS, "/s", "/v", "Moniker"])
        .output()
        .expect("reg query");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .filter(|m| m.starts_with("fail2commit.sbx."))
        .map(str::to_string)
        .collect()
}

/// Profiles that may legitimately exist while this test runs: those of
/// other live jobs (they have an owner record) and leftovers from before
/// this test binary started.
fn live_leak_baseline() -> BTreeSet<String> {
    static AT_START: OnceLock<BTreeSet<String>> = OnceLock::new();
    AT_START.get_or_init(sandbox_profiles).clone()
}

fn recorded_profiles() -> BTreeSet<String> {
    fs::read_dir(stage_root().join("profile-records"))
        .map(|d| {
            d.flatten()
                .filter_map(|e| {
                    let p = e.path();
                    if p.extension()? != "json" {
                        return None;
                    }
                    Some(p.file_stem()?.to_string_lossy().into_owned())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Race-free against jobs of tests running in parallel: the backend writes a
/// profile's record before creating it and deletes it after removing it, so a
/// profile seen both before and after the record read is covered by a record
/// at that read unless it really leaked.
fn assert_no_profile_leak(baseline: &BTreeSet<String>) {
    let before = sandbox_profiles();
    let records = recorded_profiles();
    let after = sandbox_profiles();
    let leaked: Vec<_> = before
        .intersection(&after)
        .filter(|p| !baseline.contains(*p) && !records.contains(*p))
        .collect();
    assert!(
        leaked.is_empty(),
        "AppContainer profiles leaked: {leaked:?}"
    );
}

fn acl(path: &Path) -> String {
    let out = Command::new("icacls.exe").arg(path).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn startup_folder() -> PathBuf {
    PathBuf::from(std::env::var_os("APPDATA").unwrap())
        .join(r"Microsoft\Windows\Start Menu\Programs\Startup")
}

/// Persistence points and the profile's top level, compared after a test.
#[derive(Debug, PartialEq)]
struct HostSnapshot {
    run_key: String,
    startup: BTreeSet<String>,
}

impl HostSnapshot {
    fn take() -> HostSnapshot {
        let run = Command::new("reg.exe")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            ])
            .output()
            .unwrap();
        let startup = fs::read_dir(startup_folder())
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        HostSnapshot {
            run_key: String::from_utf8_lossy(&run.stdout).into_owned(),
            startup,
        }
    }
}

/// Planted fakes of HB-001..HB-005 in a temporary fake home and checkout.
struct FakeHost {
    _dir: tempfile::TempDir,
    home: PathBuf,
    checkout: PathBuf,
    files: Vec<(PathBuf, Vec<u8>)>,
}

fn fake_host() -> FakeHost {
    let dir = tempfile::Builder::new()
        .prefix("f2c-fake-host-")
        .tempdir()
        .unwrap();
    let home = dir.path().join("home");
    let checkout = dir.path().join("checkout");
    let plant = [
        ".ssh/id_ed25519",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
        ".config/gh/hosts.yml",
        "AppData/Local/fail2commit/state/settings.toml",
        "AppData/Local/fail2commit/state/approvals.json",
        "AppData/Local/fail2commit/state/password-verifier",
        "AppData/Local/Google/Chrome/User Data/Default/Login Data",
        "AppData/Roaming/Mozilla/Firefox/Profiles/x.default/cookies.sqlite",
        "AppData/Roaming/Exodus/exodus.wallet/seed.seco",
    ];
    let mut files = Vec::new();
    for rel in plant {
        let p = home.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let body = format!("synthetic-fake-{rel}").into_bytes();
        fs::write(&p, &body).unwrap();
        files.push((p, body));
    }
    for rel in [".env", ".git/config"] {
        let p = checkout.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let body = format!("synthetic-fake-{rel}").into_bytes();
        fs::write(&p, &body).unwrap();
        files.push((p, body));
    }
    FakeHost {
        _dir: dir,
        home,
        checkout,
        files,
    }
}

impl FakeHost {
    fn assert_unchanged(&self) {
        for (p, body) in &self.files {
            assert_eq!(&fs::read(p).unwrap(), body, "{} changed", p.display());
        }
    }
}

fn denied(v: &str) -> bool {
    v != "ok"
}

// ---- FR-020: secrets, files, links --------------------------------------

#[test]
fn hb001_005_secrets_and_checkout_outside_the_stage_are_denied() {
    let host = fake_host();
    let acl_before = acl(&host.home);
    let st = stage();
    let mut actions = Vec::new();
    for (p, _) in &host.files {
        actions.push("read".to_string());
        actions.push(p.to_string_lossy().into_owned());
    }
    let refs: Vec<&str> = actions.iter().map(String::as_str).collect();
    let out = run(&spec(&st, &refs, NetworkMode::Internet, false));
    assert_eq!(out.status, JobStatus::Exited(0));
    for (p, _) in &host.files {
        let a = answer(&out, &format!("read:{}", p.display()));
        assert_eq!(a, "denied", "{} was readable", p.display());
    }
    host.assert_unchanged();
    assert_eq!(
        acl(&host.home),
        acl_before,
        "an ACE was written on the fake home"
    );
}

#[test]
fn hb006_hb041_writes_outside_the_stage_are_denied() {
    let host = fake_host();
    let snap = HostSnapshot::take();
    let nonce = format!("f2c-catalogue-{}.txt", std::process::id());
    let targets = [
        host.home.join(&nonce),
        host.checkout.join(&nonce),
        std::env::temp_dir().join(&nonce),
        startup_folder().join(&nonce),
    ];
    let st = stage();
    let mut actions = Vec::new();
    for t in &targets {
        actions.push("write".to_string());
        actions.push(t.to_string_lossy().into_owned());
    }
    let refs: Vec<&str> = actions.iter().map(String::as_str).collect();
    let out = run(&spec(&st, &refs, NetworkMode::Internet, false));
    for t in &targets {
        let created = t.exists();
        // Never leave a file behind, even when the row fails.
        let _ = fs::remove_file(t);
        assert!(!created, "{} was created", t.display());
        assert!(denied(&answer(&out, &format!("write:{}", t.display()))));
    }
    host.assert_unchanged();
    assert_eq!(HostSnapshot::take(), snap, "a persistence point changed");
}

#[test]
fn hb007_links_created_in_the_stage_do_not_escape() {
    let host = fake_host();
    let target_dir = host.home.join(".ssh");
    fs::write(target_dir.join("planted.txt"), b"synthetic-planted").unwrap();
    let st = stage();
    let junction = st.work.join("escape");
    let link = st.work.join("linked-key");
    let cmd = system32().join("cmd.exe");
    let key = target_dir.join("id_ed25519");
    let out = run(&spec(
        &st,
        &[
            "junction-read",
            s(&cmd),
            s(&junction),
            s(&target_dir),
            "hardlink",
            s(&key),
            s(&link),
        ],
        NetworkMode::None,
        false,
    ));
    assert!(
        denied(&answer(&out, "junction-read")),
        "read through a junction"
    );
    assert!(denied(&answer(
        &out,
        &format!("hardlink:{}", key.display())
    )));
    assert!(!link.exists(), "a hard link to an outside file was created");
    host.assert_unchanged();
}

#[test]
fn hb008_hb065_read_only_inputs_cannot_be_replaced() {
    let st = stage();
    let reviewed = st.read_only.join("reviewed.js");
    let planted = st.read_only.join("version.dll");
    let out = run(&spec(
        &st,
        &["write", s(&reviewed), "write", s(&planted)],
        NetworkMode::None,
        false,
    ));
    assert_eq!(
        answer(&out, &format!("write:{}", reviewed.display())),
        "denied"
    );
    assert_eq!(
        answer(&out, &format!("write:{}", planted.display())),
        "denied"
    );
    assert_eq!(fs::read(&reviewed).unwrap(), b"module.exports = 1;\n");
    assert!(
        !planted.exists(),
        "a DLL was planted beside the staged program"
    );
}

#[test]
fn hb009_parent_environment_secrets_are_not_inherited() {
    let parent = [
        ("GITHUB_TOKEN", "ghp_parentsyntheticvalue000000000000000"),
        ("AWS_SECRET_ACCESS_KEY", "parent-synthetic-aws-secret"),
        ("NPM_TOKEN", "npm_parentsyntheticvalue0000000000000000"),
    ];
    for (k, v) in parent {
        std::env::set_var(k, v);
    }
    let st = stage();
    for bait in [false, true] {
        let out = run(&spec(
            &st,
            &[
                "env",
                "GITHUB_TOKEN",
                "env",
                "AWS_SECRET_ACCESS_KEY",
                "env",
                "NPM_TOKEN",
            ],
            NetworkMode::None,
            bait,
        ));
        assert_eq!(out.status, JobStatus::Exited(0));
        for (k, v) in parent {
            let seen = answer(&out, &format!("env:{k}"));
            assert_ne!(seen, v, "{k} leaked from the parent (bait={bait})");
            // With bait the variable holds this job's own fake value.
            assert_eq!(seen.is_empty(), !bait, "{k}={seen} (bait={bait})");
        }
    }
}

/// Deletes the HKCU test key on every exit path.
struct TestKey(String);

impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = Command::new("reg.exe")
            .args(["delete", &self.0, "/f"])
            .output();
    }
}

#[test]
fn hb010_hb041_registry_is_denied() {
    let key = TestKey(format!(
        r"HKCU\Software\fail2commit-catalogue-{}",
        std::process::id()
    ));
    let made = Command::new("reg.exe")
        .args([
            "add",
            &key.0,
            "/v",
            "token",
            "/d",
            "synthetic-registry-secret",
            "/f",
        ])
        .status()
        .unwrap();
    assert!(made.success(), "could not plant the test value");
    // Positive control: the parent can read it.
    assert!(Command::new("reg.exe")
        .args(["query", &key.0])
        .status()
        .unwrap()
        .success());
    let snap = HostSnapshot::take();
    let reg = system32().join("reg.exe");
    let sub = format!(r"{}\written-by-job", key.0);
    let st = stage();
    let out = run(&spec(
        &st,
        &["reg", s(&reg), "query", &key.0, "reg-add", s(&reg), &sub],
        NetworkMode::None,
        false,
    ));
    assert_eq!(answer(&out, "reg:query"), "denied");
    assert_eq!(answer(&out, "reg:add"), "denied");
    let sub_exists = Command::new("reg.exe")
        .args(["query", &sub])
        .output()
        .unwrap()
        .status
        .success();
    assert!(!sub_exists, "the job wrote to HKCU");
    assert_eq!(HostSnapshot::take(), snap);
}

// ---- FR-020: processes --------------------------------------------------

fn image_alive(image: &str) -> bool {
    let out = Command::new("tasklist.exe")
        .args(["/fi", &format!("imagename eq {image}"), "/fo", "csv", "/nh"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).contains(image)
}

#[test]
fn hb040_hb042_detached_children_end_with_the_job() {
    let st = stage();
    let mut job = spec(&st, &["breakaway", "detach"], NetworkMode::None, false);
    job.limits.timeout = Duration::from_secs(4);
    let out = run(&job);
    assert!(
        denied(&answer(&out, "breakaway")),
        "breakaway from the job worked"
    );
    assert_eq!(answer(&out, "detach"), "ok");
    // The detached child keeps the job alive until the timeout kills it.
    assert_eq!(out.status, JobStatus::TimedOut);
    assert!(entries(&out, ActivityKind::Limit).contains(&"time".to_string()));
    assert!(
        entries(&out, ActivityKind::Process).len() >= 2,
        "{:?}",
        out.report
    );
    assert!(!image_alive(&st.image), "a job process outlived the job");
}

#[test]
fn hb043_hb044_processes_outside_the_job_cannot_be_opened() {
    let st = stage();
    let me = std::process::id().to_string();
    // PROCESS_TERMINATE, and PROCESS_VM_WRITE | PROCESS_VM_OPERATION:
    // access checks only, the helper closes any handle unused.
    let out = run(&spec(
        &st,
        &["open-process", &me, "0x1", "open-process", &me, "0x28"],
        NetworkMode::None,
        false,
    ));
    assert_eq!(answer(&out, "open-process:0x1"), "denied");
    assert_eq!(answer(&out, "open-process:0x28"), "denied");
}

#[test]
fn controls_read_back_for_desktop_com_and_dll_rows() {
    let report = sandbox::platform_backend().probe();
    assert!(report.available, "{}", report.detail);
    for control in [
        "appcontainer-zero-capabilities",
        "job-tree-and-resource-limits",
        "mitigation-policies",
        "internet-capability-only",
        "bait-oplock-detection",
        "disk-accounting",
        "stale-profile-cleanup",
    ] {
        assert!(
            report
                .controls
                .iter()
                .any(|(name, ok)| name == control && *ok),
            "{control} not verified: {:?}",
            report.controls
        );
    }
}

// ---- FR-020: resources --------------------------------------------------

#[test]
fn hb050_052_054_limits_are_reported() {
    let st = stage();
    let mut job = spec(&st, &["spawn-many"], NetworkMode::None, false);
    job.limits.max_processes = Some(2);
    let out = run(&job);
    assert_eq!(out.status, JobStatus::Killed);
    assert!(entries(&out, ActivityKind::Limit).contains(&"processes".into()));

    let mut job = spec(&st, &["allocate"], NetworkMode::None, false);
    job.limits.memory_bytes = Some(48 * 1024 * 1024);
    let out = run(&job);
    assert_ne!(out.status, JobStatus::Exited(0));
    assert!(entries(&out, ActivityKind::Limit).contains(&"memory".into()));

    let mut job = spec(&st, &["spin"], NetworkMode::None, false);
    job.limits.timeout = Duration::from_millis(400);
    let out = run(&job);
    assert_eq!(out.status, JobStatus::TimedOut);
    assert!(entries(&out, ActivityKind::Limit).contains(&"time".into()));

    let mut job = spec(&st, &["noisy"], NetworkMode::None, false);
    job.limits.max_output_bytes = 31;
    let out = run(&job);
    assert!(out.truncated && out.stdout.len() + out.stderr.len() <= 31);
    assert!(entries(&out, ActivityKind::Limit).contains(&"output".into()));
}

#[test]
fn hb053_disk_limit_kills_the_job() {
    let st = stage();
    let big = st.work.join("fill.bin");
    let mut job = spec(&st, &["fill", s(&big), "64"], NetworkMode::None, false);
    job.limits.disk_bytes = Some(8 * 1024 * 1024);
    let out = run(&job);
    assert_eq!(out.status, JobStatus::Killed, "{:?}", out.report);
    assert!(entries(&out, ActivityKind::Limit).contains(&"disk".into()));
}

// ---- FR-023: network ----------------------------------------------------

#[test]
fn hb030_internet_mode_reaches_the_public_registry() {
    let st = stage();
    let out = run(&spec(
        &st,
        &["https-get", "registry.npmjs.org"],
        NetworkMode::Internet,
        false,
    ));
    assert_eq!(answer(&out, "https-get:registry.npmjs.org"), "ok");
    let allowed = entries(&out, ActivityKind::NetAllowed);
    assert!(
        allowed.iter().any(|d| d.ends_with(":443")),
        "no net_allowed entry: {:?}",
        out.report
    );
}

#[test]
fn hb031_none_mode_refuses_the_internet() {
    let st = stage();
    let out = run(&spec(
        &st,
        &["https-get", "registry.npmjs.org"],
        NetworkMode::None,
        false,
    ));
    assert!(denied(&answer(&out, "https-get:registry.npmjs.org")));
}

#[test]
fn hb032_hb035_loopback_and_local_names_are_refused() {
    let v4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let v6 = TcpListener::bind("[::1]:0").unwrap();
    let p4 = v4.local_addr().unwrap().port();
    let p6 = v6.local_addr().unwrap().port();
    let targets = [
        format!("127.0.0.1:{p4}"),
        format!("[::1]:{p6}"),
        format!("localhost:{p4}"),
    ];
    let st = stage();
    for mode in [NetworkMode::Internet, NetworkMode::None] {
        let mut actions = Vec::new();
        for t in &targets {
            actions.push("connect");
            actions.push(t.as_str());
        }
        let out = run(&spec(&st, &actions, mode, false));
        for t in &targets {
            assert!(
                denied(&answer(&out, &format!("connect:{t}"))),
                "{t} reachable in {mode:?}"
            );
        }
    }
}

/// The host's own LAN address (the source address for a public route).
fn lan_address() -> std::net::IpAddr {
    let probe = UdpSocket::bind("0.0.0.0:0").unwrap();
    probe.connect("8.8.8.8:53").unwrap();
    probe.local_addr().unwrap().ip()
}

fn gateway() -> Option<String> {
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        ])
        .output()
        .ok()?;
    let g = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!g.is_empty() && g != "0.0.0.0").then_some(g)
}

#[test]
fn hb033_lan_and_gateway_are_refused() {
    let lan = lan_address();
    let listener = TcpListener::bind((lan, 0)).unwrap();
    let target = listener.local_addr().unwrap().to_string();
    // Positive control: the host itself reaches it.
    assert!(std::net::TcpStream::connect(&target).is_ok());
    let mut targets = vec![target];
    if let Some(g) = gateway() {
        targets.push(format!("{g}:80"));
    }
    let st = stage();
    let mut actions = Vec::new();
    for t in &targets {
        actions.push("connect");
        actions.push(t.as_str());
    }
    let out = run(&spec(&st, &actions, NetworkMode::Internet, false));
    for t in &targets {
        assert!(
            denied(&answer(&out, &format!("connect:{t}"))),
            "{t} reachable"
        );
    }
}

#[test]
fn hb033_hb034_non_local_private_ranges_are_stopped() {
    let st = stage();
    for target in [
        "10.255.255.1:80",
        "172.31.255.254:80",
        "100.64.0.1:80",
        "169.254.169.254:80",
        "[fd00:ec2::254]:80",
        "[fc00::1]:80",
        "[fe80::1]:80",
    ] {
        let out = run(&spec(
            &st,
            &["connect", target],
            NetworkMode::Internet,
            false,
        ));
        let refused = entries(&out, ActivityKind::NetRefused);
        let stopped = out.status == JobStatus::Killed && !refused.is_empty();
        let failed = answers(&out)
            .get(&format!("connect:{target}"))
            .is_some_and(|a| denied(a));
        println!(
            "{target}: status={:?} answer={:?} net_refused={refused:?}",
            out.status,
            answers(&out).get(&format!("connect:{target}"))
        );
        assert!(stopped || failed, "{target} was reached: {:?}", out.report);
    }
}

#[test]
fn hb036_hb037_listen_multicast_and_broadcast_are_refused() {
    let st = stage();
    for mode in [NetworkMode::Internet, NetworkMode::None] {
        let out = run(&spec(&st, &["listen"], mode, false));
        let listen = answers(&out).get("listen").cloned().unwrap_or_default();
        let survived = answers(&out).contains_key("listen-survived");
        let refused = entries(&out, ActivityKind::NetRefused);
        println!(
            "listen {mode:?}: {listen} status={:?} {refused:?}",
            out.status
        );
        assert!(!survived, "a listener stayed up in {mode:?}");
        assert!(
            denied(&listen)
                || (out.status == JobStatus::Killed
                    && refused.iter().any(|d| d.starts_with("listen "))),
            "listen not refused in {mode:?}"
        );

        let out = run(&spec(
            &st,
            &["udp", "224.0.0.251:5353", "udp", "255.255.255.255:9"],
            mode,
            false,
        ));
        for t in ["224.0.0.251:5353", "255.255.255.255:9"] {
            assert!(
                denied(&answer(&out, &format!("udp:{t}"))),
                "udp {t} sent in {mode:?}"
            );
        }
    }
}

// ---- FR-024: bait -------------------------------------------------------

#[test]
fn hb020_reading_the_bait_npmrc_stops_the_job() {
    let st = stage();
    let out = run(&spec(
        &st,
        &["read-bait", ".npmrc"],
        NetworkMode::None,
        true,
    ));
    assert_eq!(out.status, JobStatus::Killed, "{:?}", out.report);
    assert_eq!(
        entries(&out, ActivityKind::Bait),
        vec![".npmrc".to_string()]
    );
    assert!(
        !answers(&out).contains_key("read-bait:.npmrc"),
        "the read returned before the job was stopped"
    );
}

#[test]
fn hb021_every_bait_file_trips() {
    let st = stage();
    for rel in [
        ".ssh/id_ed25519",
        ".git-credentials",
        ".aws/credentials",
        ".env",
        ".pypirc",
        ".config/gh/hosts.yml",
    ] {
        let out = run(&spec(&st, &["read-bait", rel], NetworkMode::None, true));
        assert_eq!(out.status, JobStatus::Killed, "{rel}: {:?}", out.report);
        let bait = entries(&out, ActivityKind::Bait);
        assert_eq!(bait.len(), 1, "{rel}: {bait:?}");
        assert_eq!(bait[0].replace('\\', "/"), rel);
    }
}

#[test]
fn hb024_clean_work_touches_no_bait() {
    let st = stage();
    let out = run(&spec(
        &st,
        &["clean-home-work", "env", "NPM_TOKEN"],
        NetworkMode::None,
        true,
    ));
    assert_eq!(out.status, JobStatus::Exited(0), "{:?}", out.report);
    assert!(entries(&out, ActivityKind::Bait).is_empty());
    assert_eq!(answer(&out, "home-stat"), "yes");
    assert_eq!(answer(&out, "build"), "ok");
    assert!(answer(&out, "env:NPM_TOKEN").starts_with("npm_"));
}

// ---- HB-070: owner killed mid-job ----------------------------------------

/// Run in a child test process by `hb070_a_killed_owner_leaves_nothing_behind`.
#[test]
#[ignore = "child half of hb070; started by that test"]
fn hb070_child_runs_a_long_job() {
    let Some(stage_dir) = std::env::var_os("F2C_HB070_STAGE") else {
        return;
    };
    let stage_dir = PathBuf::from(stage_dir);
    let work = stage_dir.join("work");
    let read_only = stage_dir.join("read-only");
    let helper = fs::read_dir(&read_only)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "exe"))
        .unwrap();
    let started = work.join("started.txt");
    let job = JobSpec {
        program: helper,
        args: ["write", s(&started), "sleep", "120000"]
            .iter()
            .map(OsString::from)
            .collect(),
        cwd: work.clone(),
        env: vec![],
        read_only: vec![read_only],
        work_dir: work,
        exports: vec![],
        export_to: None,
        limits: JobLimits {
            timeout: Duration::from_secs(120),
            ..limits()
        },
        network: NetworkMode::None,
        bait: true,
    };
    let _ = backend().run(&job);
}

#[test]
fn hb070_a_killed_owner_leaves_nothing_behind() {
    let st = stage();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hb070_child_runs_a_long_job",
            "--ignored",
            "--nocapture",
        ])
        .env("F2C_HB070_STAGE", st.root.path())
        .spawn()
        .unwrap();
    let started = st.work.join("started.txt");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while !started.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(started.exists(), "the child job never started");
    assert!(image_alive(&st.image), "the job is not running");
    let owner = child.id();
    let records_dir = stage_root().join("profile-records");
    let owned: Vec<String> = fs::read_dir(&records_dir)
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let text = fs::read_to_string(e.path()).ok()?;
            if !text.contains(&format!("\"pid\":{owner},")) {
                return None;
            }
            Some(e.path().file_stem()?.to_string_lossy().into_owned())
        })
        .collect();
    assert_eq!(owned.len(), 1, "expected one profile record of the owner");
    child.kill().unwrap();
    let _ = child.wait();
    // Kill-on-close: the job's processes die with their owner.
    let gone = std::time::Instant::now() + Duration::from_secs(10);
    while image_alive(&st.image) && std::time::Instant::now() < gone {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!image_alive(&st.image), "a job process outlived its owner");
    assert!(
        sandbox_profiles().contains(&owned[0]),
        "crash left no profile"
    );
    // The next run removes the dead owner's profile and record (a cached
    // probe verdict would not reach the sweep, a run always does).
    let next = stage();
    let out = run(&spec(&next, &["sleep", "10"], NetworkMode::None, false));
    assert_eq!(out.status, JobStatus::Exited(0));
    assert!(
        !sandbox_profiles().contains(&owned[0]),
        "stale profile kept"
    );
    assert!(!records_dir.join(format!("{}.json", owned[0])).exists());
}
