//! Shared helpers for the sandbox and `fail2commit run` tests (T-007a,
//! FR-007, TC-007). Each test crate uses a subset.
#![allow(dead_code)]

use std::path::PathBuf;

/// The CLI under test. `F2C_BIN` overrides the compile-time path when test
/// binaries built in the Linux container run elsewhere (scripts/linux).
pub fn f2c_bin() -> PathBuf {
    std::env::var_os("F2C_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_fail2commit")))
}

/// Set to 1 by scripts/linux on hosts with real bwrap: a missing sandbox is
/// then a test failure instead of a skip. A skip is pending evidence.
pub fn required(var: &str) -> bool {
    std::env::var_os(var).is_some_and(|v| v == "1")
}

pub fn skip(what: &str, why: &str) {
    eprintln!("SKIP (pending evidence) {what}: {why}");
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use fail2commit_core::isolation::{JobLimits, JobOutcome, JobSpec, SandboxBackend};
    use fail2commit_core::sandbox::Bubblewrap;
    use std::ffi::OsString;
    use std::fs;
    use std::net::{TcpListener, TcpStream};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use tempfile::TempDir;

    /// A verified backend, or `None` (skip) unless `F2C_REQUIRE_SANDBOX=1`.
    pub fn backend(b: Bubblewrap, test: &str) -> Option<Bubblewrap> {
        let p = b.probe();
        if p.available {
            return Some(b);
        }
        if super::required("F2C_REQUIRE_SANDBOX") {
            panic!(
                "sandbox required but unavailable: {} {:?}",
                p.detail, p.controls
            );
        }
        super::skip(test, &p.detail);
        None
    }

    pub fn limits() -> JobLimits {
        JobLimits {
            timeout: Duration::from_secs(60),
            memory_bytes: Some(1024 * 1024 * 1024),
            max_processes: Some(64),
            max_output_bytes: 1024 * 1024,
        }
    }

    /// A job in a fresh work dir; the TempDir must outlive the run.
    pub fn job(program: &str, args: &[&str]) -> (TempDir, JobSpec) {
        let work = tempfile::tempdir().unwrap();
        let w = work.path().canonicalize().unwrap();
        let spec = JobSpec {
            program: PathBuf::from(program),
            args: args.iter().map(OsString::from).collect(),
            cwd: w.clone(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            read_only: vec![],
            work_dir: w,
            exports: vec![],
            export_to: None,
            limits: limits(),
        };
        (work, spec)
    }

    pub fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    /// Unique marker for finding leftover processes by command line.
    pub fn marker() -> String {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        format!("{}{:09}", std::process::id() % 1000, n)
    }

    /// Host processes whose command line contains `needle`.
    pub fn processes_with(needle: &str) -> Vec<String> {
        let mut found = Vec::new();
        for e in fs::read_dir("/proc").unwrap().flatten() {
            if let Ok(cmd) = fs::read(e.path().join("cmdline")) {
                let cmd = String::from_utf8_lossy(&cmd).replace('\0', " ");
                if cmd.contains(needle) {
                    found.push(cmd);
                }
            }
        }
        found
    }

    pub const CHECKS: [&str; 8] = [
        "tcp_localhost",
        "planted_file",
        "host_home",
        "checkout_write",
        "credential_socket",
        "approval_socket",
        "abstract_socket",
        "git_host_repo",
    ];

    /// libtest arguments that run only the payload test of this binary.
    pub const PAYLOAD_ARGS: [&str; 5] = [
        "--exact",
        "hostile_payload",
        "--nocapture",
        "--test-threads=1",
        "-q",
    ];

    /// Host-side targets the hostile payload attacks: a loopback listener,
    /// a planted synthetic token, a stand-in checkout, fake credential and
    /// approval sockets (path and abstract) and a disposable bare repo.
    pub struct Fixture {
        pub dir: TempDir,
        pub env: Vec<(OsString, OsString)>,
        _listeners: (TcpListener, UnixListener, UnixListener, UnixListener),
    }

    impl Fixture {
        pub fn new(external: bool) -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path();
            let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = tcp.local_addr().unwrap().port();
            fs::create_dir(d.join("planted")).unwrap();
            // Synthetic, built at runtime; never a realistic credential.
            let token = ["f2c", "synthetic", "token", &marker()].join("-");
            fs::write(d.join("planted/token.txt"), token).unwrap();
            fs::create_dir(d.join("checkout")).unwrap();
            let cred = UnixListener::bind(d.join("agent.sock")).unwrap();
            let ipc = UnixListener::bind(d.join("approval.sock")).unwrap();
            let abstract_name = format!("f2c-test-approval-{}", marker());
            let abs = UnixListener::bind_addr(
                &SocketAddr::from_abstract_name(abstract_name.as_bytes()).unwrap(),
            )
            .unwrap();
            let gitcfg = d.join("gitconfig");
            fs::write(&gitcfg, b"").unwrap();
            let ok = Command::new("git")
                .args(["init", "-q", "--bare"])
                .arg(d.join("remote.git"))
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", &gitcfg)
                .status()
                .expect("git is required for the hostile fixture");
            assert!(ok.success());
            let home = std::env::var_os("HOME").expect("HOME");
            let p = |s: &str| d.join(s).into_os_string();
            let mut env: Vec<(OsString, OsString)> = vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("F2C_T_PORT".into(), port.to_string().into()),
                ("F2C_T_PLANTED".into(), p("planted/token.txt")),
                ("F2C_T_HOME".into(), home),
                ("F2C_T_CHECKOUT".into(), p("checkout")),
                ("F2C_T_CRED_SOCK".into(), p("agent.sock")),
                ("F2C_T_IPC_SOCK".into(), p("approval.sock")),
                ("F2C_T_ABSTRACT".into(), abstract_name.into()),
                ("F2C_T_BARE".into(), p("remote.git")),
                ("F2C_T_GITCFG".into(), gitcfg.into_os_string()),
            ];
            if external {
                env.push(("F2C_T_EXTERNAL".into(), "1".into()));
            }
            Fixture {
                dir,
                env,
                _listeners: (tcp, cred, ipc, abs),
            }
        }

        pub fn checkout_entries(&self) -> usize {
            fs::read_dir(self.dir.path().join("checkout"))
                .unwrap()
                .count()
        }
    }

    /// Copy this test binary into a read-only stage so it can run as the
    /// hostile program inside the sandbox.
    pub fn stage_self() -> (TempDir, PathBuf) {
        let stage = tempfile::tempdir().unwrap();
        let dest = stage.path().canonicalize().unwrap().join("payload");
        fs::copy(std::env::current_exe().unwrap(), &dest).unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o555)).unwrap();
        (stage, dest)
    }

    /// Run the payload in `mode` inside the sandbox.
    pub fn run_payload(
        b: &Bubblewrap,
        mode: &str,
        env: &[(OsString, OsString)],
        limits: JobLimits,
    ) -> fail2commit_core::Result<JobOutcome> {
        let (stage, exe) = stage_self();
        let (_work, mut spec) = job(exe.to_str().unwrap(), &PAYLOAD_ARGS);
        spec.read_only = vec![stage.path().canonicalize().unwrap()];
        spec.env = env.to_vec();
        spec.env.retain(|(k, _)| k != "F2C_HOSTILE_MODE");
        spec.env.push(("F2C_HOSTILE_MODE".into(), mode.into()));
        if !spec.env.iter().any(|(k, _)| k == "PATH") {
            spec.env.push(("PATH".into(), "/usr/bin:/bin".into()));
        }
        spec.limits = limits;
        fail2commit_core::sandbox::run_job(b, &spec)
    }

    /// `(who, check, verdict)` lines printed by the payload.
    pub fn results(stdout: &[u8]) -> Vec<(String, String, String)> {
        text(stdout)
            .lines()
            .filter_map(|l| {
                let mut it = l.strip_prefix("RESULT ")?.split(' ');
                Some((
                    it.next()?.to_string(),
                    it.next()?.to_string(),
                    it.next()?.to_string(),
                ))
            })
            .collect()
    }

    /// The hostile program. Does nothing unless `F2C_HOSTILE_MODE` is set,
    /// so the `hostile_payload` test passes trivially in normal runs.
    pub fn payload_main() {
        let Ok(mode) = std::env::var("F2C_HOSTILE_MODE") else {
            return;
        };
        let v = |k: &str| std::env::var(k).unwrap_or_default();
        match mode.as_str() {
            "parent" | "child" => {}
            "spawn" => {
                let mut kids = Vec::new();
                while kids.len() < 200 {
                    match Command::new("/bin/sleep").arg("30").spawn() {
                        Ok(c) => kids.push(c),
                        Err(_) => break,
                    }
                }
                println!("SPAWNED {}", kids.len());
                return;
            }
            "hog" => {
                let mut held: Vec<Vec<u8>> = Vec::new();
                for i in 1..=32 {
                    held.push(vec![1u8; 64 * 1024 * 1024]);
                    println!("ALLOC {}MiB", i * 64);
                }
                println!("HOG_DONE {}", held.len());
                return;
            }
            _ => return,
        }
        let report = |check: &str, leaked: bool| {
            println!(
                "RESULT {mode} {check} {}",
                if leaked { "LEAK" } else { "BLOCKED" }
            )
        };
        let t = Duration::from_secs(2);
        let local = format!("127.0.0.1:{}", v("F2C_T_PORT")).parse().unwrap();
        report(
            "tcp_localhost",
            TcpStream::connect_timeout(&local, t).is_ok(),
        );
        if v("F2C_T_EXTERNAL") == "1" {
            let ext = "1.1.1.1:443".parse().unwrap();
            report("tcp_external", TcpStream::connect_timeout(&ext, t).is_ok());
        }
        report("planted_file", fs::read(v("F2C_T_PLANTED")).is_ok());
        report("host_home", fs::read_dir(v("F2C_T_HOME")).is_ok());
        let probe = Path::new(&v("F2C_T_CHECKOUT")).join(format!("pwned-{mode}"));
        report("checkout_write", fs::write(probe, b"x").is_ok());
        report(
            "credential_socket",
            UnixStream::connect(v("F2C_T_CRED_SOCK")).is_ok(),
        );
        report(
            "approval_socket",
            UnixStream::connect(v("F2C_T_IPC_SOCK")).is_ok(),
        );
        let abs = SocketAddr::from_abstract_name(v("F2C_T_ABSTRACT").as_bytes()).unwrap();
        report("abstract_socket", UnixStream::connect_addr(&abs).is_ok());
        let git = Command::new("git")
            .args(["ls-remote", &v("F2C_T_BARE")])
            // Not inside any repository (the container's /src is a worktree).
            .current_dir("/")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", v("F2C_T_GITCFG"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        report("git_host_repo", git.is_ok_and(|s| s.success()));
        if mode == "parent" {
            let child = Command::new(std::env::current_exe().unwrap())
                .args(PAYLOAD_ARGS)
                .env("F2C_HOSTILE_MODE", "child")
                .status();
            println!("CHILD_RAN {}", child.is_ok_and(|s| s.success()));
        }
    }
}
