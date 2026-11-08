//! Standalone Windows helper compiled by `sandbox_windows_matrix.rs`.
//! It has no third-party dependencies and never prints secret contents.

#![cfg(windows)]

use std::env;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::process::{self, Command};
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    let ok = match args.get(1).map(String::as_str) {
        Some("hostile-parent") => hostile(&args, true),
        Some("hostile-child") => hostile(&args, false),
        Some("native-work") => native_work(&args),
        Some("environment") => environment(),
        Some("read-handle") => read_handle(&args),
        Some("allocate") => allocate(),
        Some("spawn-many") => spawn_many(),
        Some("noisy") => noisy(),
        Some("spin") => spin(),
        Some("external") => external(),
        _ => false,
    };
    process::exit(if ok { 0 } else { 71 });
}

fn hostile(args: &[String], spawn_child: bool) -> bool {
    if args.len() != 7 {
        return false;
    }
    let secret = &args[2];
    let checkout = &args[3];
    let local: SocketAddr = match args[4].parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };
    let git = &args[5];
    let marker = &args[6];

    let mut denied = true;
    for (label, result) in [
        (
            "tcp",
            TcpStream::connect_timeout(&local, Duration::from_millis(300)).is_err(),
        ),
        ("secret", fs::read(secret).is_err()),
        ("checkout", fs::write(checkout, b"sandbox escape").is_err()),
        ("marker", !std::path::Path::new(marker).exists()),
    ] {
        if !result {
            eprintln!("unexpected access: {label}");
            denied = false;
        }
    }
    // Either execution itself is denied or Git runs in the same verified
    // zero-network AppContainer token whose direct TCP attempt just failed.
    let _ = Command::new(git).arg("--version").status();
    if !denied {
        return false;
    }
    if !spawn_child {
        return true;
    }
    let me = match env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
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

fn environment() -> bool {
    env::var_os("PATH").is_none()
        && env::var("F2C_TEST_ALLOWED").as_deref() == Ok("yes")
        && env::var_os("SystemRoot").is_some()
        && env::var_os("LOCALAPPDATA").is_some()
}

fn read_handle(args: &[String]) -> bool {
    let raw = match args.get(2).and_then(|value| value.parse::<usize>().ok()) {
        Some(raw) => raw,
        None => return false,
    };
    let handle = raw as *mut core::ffi::c_void;
    let mut byte = [0u8; 1];
    let mut read = 0u32;
    // SAFETY: ReadFile validates the untrusted numeric handle in the child
    // handle table. The one-byte output buffer and count pointer are valid.
    unsafe { ReadFile(handle, byte.as_mut_ptr().cast(), 1, &mut read, std::ptr::null_mut()) == 0 }
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
}

