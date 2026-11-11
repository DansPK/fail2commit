//! In-sandbox TCP to Unix relay (SPEC-013 §4; FR-023).
//!
//! A TCP listener reachable from inside the sandbox's own network namespace has to live in that
//! namespace, and a process there has no internet. This process is therefore a dumb byte pump: it
//! accepts on `127.0.0.1:<port>`, connects the job's egress socket and copies both directions. All
//! policy lives in the parent-side proxy (`sandbox::linux::proxy`), so killing or confusing the
//! relay only removes the job's own network access.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Concurrent connections the relay will carry; a package cannot exhaust the parent.
const MAX_CONNECTIONS: usize = 64;
/// Longest idle wait on either side.
const IDLE: Duration = Duration::from_secs(60);

/// Bind `127.0.0.1:0`, publish the chosen port in `ready` and serve until the process is killed.
pub fn run(socket: &Path, ready: &Path) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0u16))?;
    let port = listener.local_addr()?.port();
    publish(ready, port)?;
    serve(listener, socket.to_path_buf())
}

/// Serve on an already-bound listener (tests use this to avoid a readiness file).
pub fn serve(listener: TcpListener, socket: PathBuf) -> std::io::Result<()> {
    let live = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else { continue };
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            live.fetch_sub(1, Ordering::SeqCst);
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }
        let live = Arc::clone(&live);
        let socket = socket.clone();
        thread::spawn(move || {
            let _ = pump(stream, &socket);
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

fn pump(tcp: TcpStream, socket: &Path) -> std::io::Result<()> {
    let _ = tcp.set_read_timeout(Some(IDLE));
    let _ = tcp.set_write_timeout(Some(IDLE));
    let mut unix = UnixStream::connect(socket)?;
    let _ = unix.set_read_timeout(Some(IDLE));
    let _ = unix.set_write_timeout(Some(IDLE));
    let (mut tcp_r, mut tcp_w) = (tcp.try_clone()?, tcp.try_clone()?);
    let mut unix_w = unix.try_clone()?;
    let up = thread::spawn(move || {
        let _ = copy(&mut tcp_r, &mut unix_w);
        let _ = unix_w.shutdown(Shutdown::Write);
    });
    let _ = copy(&mut unix, &mut tcp_w);
    let _ = tcp_w.shutdown(Shutdown::Write);
    let _ = up.join();
    Ok(())
}

fn copy(from: &mut impl Read, to: &mut impl Write) -> std::io::Result<u64> {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        match from.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                to.write_all(&buf[..n])?;
                total += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Write the port atomically so the wrapper never reads a half-written file.
fn publish(ready: &Path, port: u16) -> std::io::Result<()> {
    let tmp = ready.with_extension("tmp");
    std::fs::write(&tmp, port.to_string())?;
    std::fs::rename(&tmp, ready)
}

/// Entry point for `f2c-sandbox-relay --socket <path> --ready <path>`.
pub fn main_from_args() -> std::io::Result<()> {
    let (mut socket, mut ready) = (None, None);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = args.next().map(PathBuf::from),
            "--ready" => ready = args.next().map(PathBuf::from),
            // Older call sites passed an explicit port; the relay always binds port 0 now.
            "--port" => {
                let _ = args.next();
            }
            _ => {}
        }
    }
    let (Some(socket), Some(ready)) = (socket, ready) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: f2c-sandbox-relay --socket <path> --ready <path>",
        ));
    };
    run(&socket, &ready)
}

/// Path of the relay program for this job, from `F2C_SANDBOX_RELAY`, the compile-time cargo binary
/// path (tests) or a sibling of the running executable. `None` means `Internet` must fail closed.
pub fn locate() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("F2C_SANDBOX_RELAY") {
        candidates.push(PathBuf::from(p));
    }
    if let Some(p) = option_env!("CARGO_BIN_EXE_f2c-sandbox-relay") {
        candidates.push(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("f2c-sandbox-relay"));
            candidates.push(dir.join("fail2commit-sandbox-relay"));
            // Test binaries live in `<target>/debug/deps`, the binaries in `<target>/debug`.
            if let Some(up) = dir.parent() {
                candidates.push(up.join("f2c-sandbox-relay"));
                candidates.push(up.join("fail2commit-sandbox-relay"));
            }
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_pumps_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("egress.sock");
        let server = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let echo = thread::spawn(move || {
            let (mut s, _) = server.accept().unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&buf).unwrap();
        });
        let listener = TcpListener::bind(("127.0.0.1", 0u16)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let serving = thread::spawn(move || {
            let _ = serve(listener, socket);
        });
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        c.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        drop(c);
        echo.join().unwrap();
        drop(serving);
    }

    #[test]
    fn readiness_file_carries_the_port() {
        let dir = tempfile::tempdir().unwrap();
        let ready = dir.path().join("ready");
        publish(&ready, 4321).unwrap();
        assert_eq!(std::fs::read_to_string(&ready).unwrap(), "4321");
    }
}
