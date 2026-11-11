//! Bait file watcher (SPEC-013 §5; FR-024).
//!
//! The bait files are planted in the job's fake home and watched with inotify. inotify watches the
//! inode, so an open by a process inside the sandbox's mount namespace is seen here, on the host.
//! A touch becomes an `ActivityKind::Bait` entry and stops the job. Only the watched file's path is
//! recorded — never its contents.

#![allow(unsafe_code)]

use crate::isolation::ActivityKind;
use crate::sandbox::linux::proxy::Watch;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

/// Events that mean the file was opened or read.
const MASK: u32 = libc::IN_OPEN | libc::IN_ACCESS | libc::IN_MODIFY | libc::IN_ATTRIB;
/// `struct inotify_event` header, before the (padding +) name.
const EVENT_HDR: usize = std::mem::size_of::<libc::inotify_event>();

/// Watches every bait file until dropped.
pub struct BaitWatcher {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    /// Held so the inotify fd outlives the thread.
    _fd: Arc<OwnedFd>,
}

impl Drop for BaitWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl BaitWatcher {
    /// Start watching `files`, which are reported relative to `home`.
    pub fn start(home: &Path, files: &[PathBuf], watch: Arc<Watch>) -> crate::Result<BaitWatcher> {
        // SAFETY: inotify_init1 takes flags only and returns a new fd (or -1).
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if raw < 0 {
            return Err(crate::Error::isolation_unavailable(format!(
                "bait watch: inotify is unavailable: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `raw` is a fresh fd owned by this process.
        let fd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let mut names = Vec::with_capacity(files.len());
        for f in files {
            let c = std::ffi::CString::new(f.as_os_str().as_bytes())
                .map_err(|_| crate::Error::invalid("bait path contains a NUL byte"))?;
            // SAFETY: the fd is valid and `c` is a NUL-terminated path.
            let wd = unsafe { libc::inotify_add_watch(fd.as_raw_fd(), c.as_ptr(), MASK) };
            if wd < 0 {
                return Err(crate::Error::isolation_unavailable(format!(
                    "bait watch: cannot watch {}: {}",
                    f.display(),
                    std::io::Error::last_os_error()
                )));
            }
            let rel = f
                .strip_prefix(home)
                .unwrap_or(f)
                .to_string_lossy()
                .into_owned();
            names.push((wd, rel));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            let fd = Arc::clone(&fd);
            thread::spawn(move || poll_loop(fd, stop, names, watch))
        };
        Ok(BaitWatcher {
            stop,
            thread: Some(thread),
            _fd: fd,
        })
    }
}

fn poll_loop(
    fd: Arc<OwnedFd>,
    stop: Arc<AtomicBool>,
    names: Vec<(i32, String)>,
    watch: Arc<Watch>,
) {
    let mut buf = [0u8; 4096];
    while !stop.load(Ordering::SeqCst) {
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is one initialised pollfd for the duration of the call.
        let ready = unsafe { libc::poll(&mut pfd, 1, 100) };
        if ready <= 0 {
            continue;
        }
        // SAFETY: reading into a stack buffer of exactly the given length.
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            continue;
        }
        let mut offset = 0usize;
        let n = n as usize;
        while offset + EVENT_HDR <= n {
            // SAFETY: the kernel wrote a `struct inotify_event` at `offset`; copying the header
            // into a zeroed local keeps this free of alignment assumptions.
            let mut ev: libc::inotify_event = unsafe { std::mem::zeroed() };
            // SAFETY: `offset + EVENT_HDR <= n`, so the header bytes are inside `buf`.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    buf.as_ptr().add(offset),
                    (&mut ev as *mut libc::inotify_event).cast::<u8>(),
                    EVENT_HDR,
                );
            }
            offset += EVENT_HDR + ev.len as usize;
            let Some((_, rel)) = names.iter().find(|(wd, _)| *wd == ev.wd) else {
                continue;
            };
            watch.trip(ActivityKind::Bait, format!("home/{rel}"));
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn an_open_is_reported_and_trips_the_job() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let file = home.join(".ssh/id_ed25519");
        std::fs::write(&file, "synthetic").unwrap();
        let watch = Arc::new(Watch::default());
        let watcher =
            BaitWatcher::start(&home, std::slice::from_ref(&file), Arc::clone(&watch)).unwrap();
        // The watch is on the inode; reading the file is what a package script does.
        assert_eq!(std::fs::read(&file).unwrap(), b"synthetic");
        let mut tripped = false;
        for _ in 0..50 {
            if watch.tripped() {
                tripped = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(tripped, "an open of a bait file must trip the job");
        let report = watch.take_report();
        assert!(report.bait_touched());
        assert_eq!(report.events[0].detail, "home/.ssh/id_ed25519");
        assert!(!report.events[0].detail.contains("synthetic"));
        drop(watcher);
    }

    #[test]
    fn unrelated_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let bait = home.join(".env");
        std::fs::write(&bait, "synthetic").unwrap();
        let other = home.join("cache.bin");
        std::fs::write(&other, "x").unwrap();
        let watch = Arc::new(Watch::default());
        let _watcher = BaitWatcher::start(&home, &[bait], Arc::clone(&watch)).unwrap();
        for _ in 0..5 {
            std::fs::read(&other).unwrap();
        }
        thread::sleep(Duration::from_millis(200));
        assert!(!watch.tripped());
        assert!(watch.take_report().events.is_empty());
    }
}
