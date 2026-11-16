//! FR-020 catalogue helper for the Windows sandbox tests (SPEC-014).
//!
//! Compiled with `rustc` into a job stage by
//! `crates/fail2commit/tests/sandbox_hostile_windows.rs`. Every action is an
//! ordinary operation (open, write, connect, listen, spawn) whose answer from
//! the operating system is printed as `<label>=<outcome>` on stdout, so the
//! test asserts what really happened. It carries out no attack technique: no
//! injection, hooking, input synthesis or screen capture.

use std::io::{Read, Write};
use std::net::{
    Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut core::ffi::c_void;
    fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
}

fn say(label: &str, outcome: &str) {
    println!("{label}={outcome}");
    let _ = std::io::stdout().flush();
}

fn outcome<T>(r: std::io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => "denied".into(),
        Err(e) => format!("error:{}", e.raw_os_error().unwrap_or(-1)),
    }
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("USERPROFILE").unwrap_or_default())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    // Several actions per run: `<action> <args...> ; <action> ...`
    while i < args.len() {
        let action = args[i].as_str();
        let take = |n: usize| -> Vec<String> { args[i + 1..i + 1 + n].to_vec() };
        let used = match action {
            "read" => {
                let a = take(1);
                say(&format!("read:{}", a[0]), &outcome(std::fs::read(&a[0])));
                1
            }
            "write" => {
                let a = take(1);
                say(
                    &format!("write:{}", a[0]),
                    &outcome(std::fs::write(&a[0], b"catalogue write")),
                );
                1
            }
            "hardlink" => {
                let a = take(2);
                say(
                    &format!("hardlink:{}", a[0]),
                    &outcome(std::fs::hard_link(&a[0], &a[1])),
                );
                2
            }
            "junction-read" => {
                // `mklink /J` through the system cmd, then read through it.
                let a = take(3);
                let made = Command::new(&a[0])
                    .args(["/d", "/c", "mklink", "/J", &a[1], &a[2]])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                say("junction-created", if made { "yes" } else { "no" });
                let through = PathBuf::from(&a[1]).join("planted.txt");
                say("junction-read", &outcome(std::fs::read(through)));
                3
            }
            "env" => {
                let a = take(1);
                let v = std::env::var(&a[0]).unwrap_or_default();
                say(&format!("env:{}", a[0]), &v);
                1
            }
            "connect" => {
                let a = take(1);
                let r = a[0]
                    .to_socket_addrs()
                    .and_then(|mut it| {
                        it.next().ok_or_else(|| {
                            std::io::Error::new(std::io::ErrorKind::NotFound, "no address")
                        })
                    })
                    .and_then(|addr: SocketAddr| {
                        TcpStream::connect_timeout(&addr, Duration::from_secs(4))
                    });
                say(&format!("connect:{}", a[0]), &outcome(r));
                1
            }
            "https-get" => {
                // Connect to port 443 and send a request line; a TLS server
                // answers with an alert or closes, either proves the reach.
                let a = take(1);
                let r = format!("{}:443", a[0])
                    .to_socket_addrs()
                    .and_then(|mut it| {
                        it.next().ok_or_else(|| {
                            std::io::Error::new(std::io::ErrorKind::NotFound, "no address")
                        })
                    })
                    .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(8)))
                    .and_then(|mut s| {
                        s.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
                        std::thread::sleep(Duration::from_millis(300));
                        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                        let mut b = [0u8; 16];
                        let _ = s.read(&mut b);
                        Ok(())
                    });
                say(&format!("https-get:{}", a[0]), &outcome(r));
                1
            }
            "listen" => {
                match TcpListener::bind("0.0.0.0:0") {
                    Ok(listener) => {
                        say("listen", "ok");
                        // Stay listening long enough for the parent to see it.
                        std::thread::sleep(Duration::from_secs(5));
                        say("listen-survived", "yes");
                        drop(listener);
                    }
                    Err(e) => say("listen", &outcome::<()>(Err(e))),
                }
                0
            }
            "udp" => {
                let a = take(1);
                let address = if let Some(scope_id) = a[0].strip_prefix("ff02::1%") {
                    scope_id
                        .strip_suffix(":9")
                        .unwrap_or(scope_id)
                        .parse::<u32>()
                        .ok()
                        .map(|scope_id| {
                        SocketAddr::V6(SocketAddrV6::new(
                            "ff02::1".parse::<Ipv6Addr>().expect("constant IPv6 group"),
                            9,
                            0,
                            scope_id,
                        ))
                    })
                } else {
                    a[0].parse::<SocketAddr>().ok()
                };
                let r = address.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid UDP target")
                }).and_then(|address| {
                    let bind = if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                    UdpSocket::bind(bind).and_then(|s| {
                    let _ = s.set_broadcast(true);
                        s.send_to(b"catalogue", address)
                    })
                });
                say(&format!("udp:{}", a[0]), &outcome(r));
                1
            }
            "detach" => {
                let me = std::env::current_exe().unwrap();
                let r = Command::new(me)
                    .args(["sleep", "600000"])
                    .creation_flags(DETACHED_PROCESS)
                    .spawn();
                say("detach", &outcome(r));
                0
            }
            "breakaway" => {
                let me = std::env::current_exe().unwrap();
                let r = Command::new(me)
                    .args(["sleep", "1"])
                    .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
                    .spawn()
                    .and_then(|mut c| c.wait());
                say("breakaway", &outcome(r));
                0
            }
            "open-process" => {
                // Access check only: the handle, if any, is closed unused.
                let a = take(2);
                let pid: u32 = a[0].parse().unwrap_or(0);
                let access = u32::from_str_radix(a[1].trim_start_matches("0x"), 16).unwrap_or(0);
                // SAFETY: plain OpenProcess; a returned handle is closed at once.
                let h = unsafe { OpenProcess(access, 0, pid) };
                let res = if h.is_null() {
                    Err(std::io::Error::last_os_error())
                } else {
                    unsafe { CloseHandle(h) };
                    Ok(())
                };
                say(&format!("open-process:{}", a[1]), &outcome(res));
                2
            }
            "reg" => {
                // `reg.exe <verb> ...` through the given system path.
                let a = take(3);
                let r = Command::new(&a[0])
                    .args([a[1].as_str(), a[2].as_str()])
                    .output()
                    .map(|o| o.status.success());
                let text = match r {
                    Ok(true) => "ok".to_string(),
                    Ok(false) => "denied".to_string(),
                    Err(e) => format!("error:{e}"),
                };
                say(&format!("reg:{}", a[1]), &text);
                3
            }
            "reg-add" => {
                let a = take(2);
                let r = Command::new(&a[0])
                    .args(["add", a[1].as_str(), "/v", "x", "/d", "y", "/f"])
                    .output()
                    .map(|o| o.status.success());
                say(
                    "reg:add",
                    match r {
                        Ok(true) => "ok",
                        _ => "denied",
                    },
                );
                2
            }
            "fill" => {
                let a = take(2);
                let mib: usize = a[1].parse().unwrap_or(1);
                let chunk = vec![0x5au8; 1024 * 1024];
                let r = std::fs::File::create(&a[0]).and_then(|mut f| {
                    for _ in 0..mib {
                        f.write_all(&chunk)?;
                    }
                    f.sync_all()
                });
                say("fill", &outcome(r));
                // Give the parent time to notice before exiting cleanly.
                std::thread::sleep(Duration::from_secs(6));
                2
            }
            "read-bait" => {
                let a = take(1);
                let r = std::fs::read(home().join(&a[0]));
                say(&format!("read-bait:{}", a[0]), &outcome(r));
                1
            }
            "clean-home-work" => {
                // What a normal build does near home: stat and list it, write
                // its own output. No bait file is opened for data.
                let h = home();
                let listed = std::fs::read_dir(&h).map(|d| d.count()).unwrap_or(0);
                let stat = std::fs::metadata(h.join(".npmrc")).is_ok();
                say("home-listed", &listed.to_string());
                say("home-stat", if stat { "yes" } else { "no" });
                let out = std::env::current_dir().unwrap().join("built.node");
                say("build", &outcome(std::fs::write(out, b"native output")));
                0
            }
            "spin" => loop {
                std::hint::spin_loop();
            },
            "sleep" => {
                let a = take(1);
                std::thread::sleep(Duration::from_millis(a[0].parse().unwrap_or(1000)));
                1
            }
            "spawn-many" => {
                let me = std::env::current_exe().unwrap();
                let mut kids = Vec::new();
                for _ in 0..16 {
                    match Command::new(&me).args(["sleep", "5000"]).spawn() {
                        Ok(c) => kids.push(c),
                        Err(_) => break,
                    }
                }
                say("spawned", &kids.len().to_string());
                std::thread::sleep(Duration::from_secs(3));
                0
            }
            "allocate" => {
                let mut keep = Vec::new();
                for _ in 0..64 {
                    keep.push(vec![1u8; 16 * 1024 * 1024]);
                }
                say("allocated", &keep.len().to_string());
                0
            }
            "noisy" => {
                for _ in 0..10_000 {
                    println!("0123456789abcdef0123456789abcdef");
                }
                0
            }
            other => {
                say("unknown-action", other);
                std::process::exit(2);
            }
        };
        i += 1 + used;
    }
}
