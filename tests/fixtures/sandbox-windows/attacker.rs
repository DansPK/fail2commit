//! Standalone Windows helper compiled by `sandbox_windows_matrix.rs` and the
//! review regression tests. It has no third-party dependencies and never prints
//! secret contents.
//!
//! Every outcome a test needs to assert is written to a report file the test
//! passes in, so a discarded result can never look like a pass.

#![cfg(windows)]

use std::env;
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::process::{self, Command};
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    let ok = match args.get(1).map(String::as_str) {
        Some("hostile-parent") => hostile(&args, true),
        Some("hostile-child") => hostile(&args, false),
        Some("native-work") => native_work(&args),
        Some("environment") => environment(&args),
        Some("read-handle") => read_handle(&args),
        Some("create-marker") => create_marker(&args),
        Some("allocate") => allocate(),
        Some("spawn-many") => spawn_many(),
        Some("noisy") => noisy(),
        Some("spin") => spin(),
        Some("external") => external(),
        _ => false,
    };
    process::exit(if ok { 0 } else { 71 });
}

fn report(path: &str, label: &str, check: &str, value: &str) {
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{label}:{check}={value}");
    }
}

fn hostile(args: &[String], spawn_child: bool) -> bool {
    if args.len() != 9 {
        eprintln!("hostile: expected 9 arguments, got {}", args.len());
        return false;
    }
    let label = if spawn_child { "parent" } else { "child" };
    let secret = &args[2];
    let checkout = &args[3];
    let local: SocketAddr = match args[4].parse() {
        Ok(addr) => addr,
        Err(error) => {
            eprintln!("hostile: bad address {:?}: {error}", args[4]);
            return false;
        }
    };
    let git = &args[5];
    let git_remote = &args[6];
    let launch_marker = &args[7];
    let report_path = &args[8];

    let mut denied = true;
    for (name, result) in [
        (
            "tcp",
            TcpStream::connect_timeout(&local, Duration::from_millis(300)).is_err(),
        ),
        ("secret", fs::read(secret).is_err()),
        ("checkout", fs::write(checkout, b"sandbox escape").is_err()),
        ("marker", !std::path::Path::new(launch_marker).exists()),
    ] {
        report(
            report_path,
            label,
            name,
            if result { "denied" } else { "OPEN" },
        );
        if !result {
            eprintln!("unexpected access: {name}");
            denied = false;
        }
    }

    // Git is installed under Program Files, which AppContainers may execute, so
    // reaching the executable proves nothing. What matters is that Git cannot
    // read a repository outside the stage: `ls-remote` against a disposable bare
    // remote must fail. Both outcomes are recorded, never discarded.
    let version = Command::new(git).arg("--version").output();
    match &version {
        Ok(output) => report(
            report_path,
            label,
            "git_version",
            &format!("SPAWNED:success={}", output.status.success()),
        ),
        Err(error) => report(
            report_path,
            label,
            "git_version",
            &format!("SPAWN_DENIED:{}", error.raw_os_error().unwrap_or(0)),
        ),
    }
    match Command::new(git).args(["ls-remote", git_remote]).output() {
        Ok(output) if output.status.success() => {
            report(report_path, label, "git_ls_remote", "OPEN");
            eprintln!("git read a repository outside the stage");
            denied = false;
        }
        Ok(_) => report(report_path, label, "git_ls_remote", "denied"),
        Err(error) => report(
            report_path,
            label,
            "git_ls_remote",
            &format!("denied:spawn:{}", error.raw_os_error().unwrap_or(0)),
        ),
    }
    if !denied {
        return false;
    }
    if !spawn_child {
        return true;
    }
    let me = match env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("hostile: current_exe failed: {error}");
            return false;
        }
    };
    let child = Command::new(me)
        .arg("hostile-child")
        .args(&args[2..])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !child {
        eprintln!("grandchild did not confirm denials");
    }
    child
}

fn native_work(args: &[String]) -> bool {
    if args.len() != 4 {
        return false;
    }
    let input = match fs::read(&args[2]) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let mut output = b"native-work: ".to_vec();
    output.extend(input.into_iter().map(|byte| byte.to_ascii_uppercase()));
    fs::write(&args[3], output).is_ok()
}

/// `LOCALAPPDATA` must be the caller-declared path inside the work directory,
/// `PATH` must be absent, the allowlisted value must be present and
/// `SystemRoot` must be set by the backend.
fn environment(args: &[String]) -> bool {
    if args.len() != 3 {
        return false;
    }
    let expected = &args[2];
    let path_absent = env::var_os("PATH").is_none();
    let allowed = env::var("F2C_TEST_ALLOWED").as_deref() == Ok("yes");
    let system_root = env::var_os("SystemRoot").is_some();
    // Windows derives the container's own profile folder from LOCALAPPDATA, so
    // the child's value is our work-scoped base plus the package path. What
    // matters is that the base is inside the work directory and never the real
    // user profile.
    let local_app_data_matches = env::var("LOCALAPPDATA")
        .map(|value| value.starts_with(expected.as_str()))
        .unwrap_or(false);
    if !path_absent || !allowed || !system_root || !local_app_data_matches {
        eprintln!(
            "environment mismatch: path_absent={path_absent} allowed={allowed} \
             system_root={system_root} local_app_data_matches={local_app_data_matches} \
             local_app_data={:?} expected={expected:?}",
            env::var("LOCALAPPDATA")
        );
        return false;
    }
    true
}

/// Read a numeric handle the parent passed. The read must fail with exactly the
/// error code the test declares, so a numeric value that happens to name a
/// different object in the child's handle table cannot look like containment.
fn read_handle(args: &[String]) -> bool {
    let raw = match args.get(2).and_then(|value| value.parse::<usize>().ok()) {
        Some(raw) => raw,
        None => return false,
    };
    let expected = match args.get(3).and_then(|value| value.parse::<i32>().ok()) {
        Some(code) => code,
        None => return false,
    };
    let handle = raw as *mut core::ffi::c_void;
    let mut buf = [0u8; 64];
    let mut read = 0u32;
    // SAFETY: ReadFile validates the untrusted numeric handle in the child
    // handle table. The output buffer and count pointer are valid.
    let ok = unsafe {
        ReadFile(
            handle,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut read,
            std::ptr::null_mut(),
        )
    };
    if ok != 0 {
        // The same number can name one of the child's own handles (its stdio
        // pipes or the NUL device); only the canary's bytes prove a leak.
        if buf[..read as usize].starts_with(b"synthetic-secret-value") {
            eprintln!("the inherited handle was readable");
            return false;
        }
        eprintln!("handle number names another of the child's own handles; no canary bytes");
        return true;
    }
    // SAFETY: read immediately after the failing call.
    let error = unsafe { GetLastError() } as i32;
    if error != expected {
        eprintln!("unexpected error code {error}, expected {expected}");
        return false;
    }
    true
}

/// Create the marker file. Used as the launch canary: if anything runs this
/// helper, the marker appears.
fn create_marker(args: &[String]) -> bool {
    if args.len() != 3 {
        return false;
    }
    fs::write(&args[2], b"package code ran").is_ok()
}

fn allocate() -> bool {
    let mut chunks = Vec::new();
    loop {
        let chunk = vec![0xA5u8; 4 * 1024 * 1024];
        chunks.push(chunk);
        std::hint::black_box(&chunks);
    }
}

fn spawn_many() -> bool {
    let me = match env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };
    let mut children = Vec::new();
    for _ in 0..16 {
        match Command::new(&me).arg("spin").spawn() {
            Ok(child) => children.push(child),
            Err(_) => return true,
        }
    }
    false
}

fn noisy() -> bool {
    for _ in 0..4096 {
        println!("0123456789abcdef0123456789abcdef");
        eprintln!("fedcba9876543210fedcba9876543210");
    }
    true
}

fn spin() -> bool {
    loop {
        std::hint::spin_loop();
    }
}

fn external() -> bool {
    let addr: SocketAddr = "1.1.1.1:443".parse().expect("constant endpoint");
    TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_err()
}

#[link(name = "kernel32")]
extern "system" {
    fn ReadFile(
        handle: *mut core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        bytes_to_read: u32,
        bytes_read: *mut u32,
        overlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn GetLastError() -> u32;
}

