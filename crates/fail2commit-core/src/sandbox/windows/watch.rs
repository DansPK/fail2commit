//! Run-time observation for the AppContainer backend (SPEC-014): bait
//! oplocks, TCP table rows of job processes, process names and owner
//! liveness, and the stage size scan. Nothing here needs administrator
//! rights. Like `ffi.rs`, each unsafe call opts in locally.

use super::ffi::{self, Job};
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_IO_PENDING, FILETIME, GENERIC_READ, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING, SYNCHRONIZE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
    WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, OVERLAPPED};

/// winioctl.h; the Ioctl feature is not enabled for this crate.
const FSCTL_REQUEST_OPLOCK: u32 = 0x0009_0240;
const OPLOCK_LEVEL_CACHE_READ: u32 = 1;
const OPLOCK_LEVEL_CACHE_HANDLE: u32 = 2;
const OPLOCK_LEVEL_CACHE_WRITE: u32 = 4;
const REQUEST_OPLOCK_INPUT_FLAG_REQUEST: u32 = 1;

#[repr(C)]
struct OplockInput {
    version: u16,
    length: u16,
    level: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct OplockOutput {
    version: u16,
    length: u16,
    original: u32,
    new: u32,
    flags: u32,
    access: u32,
    share: u16,
}

/// The OVERLAPPED and output buffer the kernel writes into; boxed so their
/// addresses stay fixed while the request is pending.
#[repr(C)]
struct OplockState {
    ov: OVERLAPPED,
    out: OplockOutput,
}

/// An exclusive read/write/handle oplock on one bait file (SPEC-014 section
/// 2). Any other data or delete open breaks it; the break arrives on the job
/// port under [`ffi::BAIT_KEY`] and is never acknowledged, so the opener stays
/// blocked until the job is terminated.
pub(super) struct Oplock {
    /// `None` once released.
    handle: Option<OwnedHandle>,
    state: Box<OplockState>,
    /// The bait file relative to the bait home, for the report.
    pub(super) rel: String,
    /// Set once this request's completion was dequeued (its break arrived).
    /// The request no longer pends, so closing the holder needs no wait.
    completed: bool,
}

impl Oplock {
    #[allow(unsafe_code)]
    pub(super) fn request(path: &Path, rel: String, job: &Job) -> crate::Result<Oplock> {
        let w = ffi::wide(path.as_os_str());
        // SAFETY: NUL-terminated path; the returned handle is owned below.
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(ffi::unavailable("open bait file for an oplock"));
        }
        // SAFETY: fresh handle owned by nobody else.
        let handle = unsafe { OwnedHandle::from_raw_handle(h as _) };
        // Bind before issuing so the break is delivered to the job port.
        job.associate(h, ffi::BAIT_KEY)?;
        let mut state = Box::new(OplockState {
            // SAFETY: all-zero is a valid OVERLAPPED.
            ov: unsafe { std::mem::zeroed() },
            out: OplockOutput::default(),
        });
        state.out.version = 1;
        state.out.length = std::mem::size_of::<OplockOutput>() as u16;
        let input = OplockInput {
            version: 1,
            length: std::mem::size_of::<OplockInput>() as u16,
            level: OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE,
            flags: REQUEST_OPLOCK_INPUT_FLAG_REQUEST,
        };
        // SAFETY: `input` lives across the call; `state` is boxed and outlives
        // the pending request (Drop cancels and waits before freeing it).
        let ok = unsafe {
            DeviceIoControl(
                h,
                FSCTL_REQUEST_OPLOCK,
                (&input as *const OplockInput).cast(),
                std::mem::size_of::<OplockInput>() as u32,
                (&mut state.out as *mut OplockOutput).cast(),
                std::mem::size_of::<OplockOutput>() as u32,
                std::ptr::null_mut(),
                &mut state.ov,
            )
        };
        // SAFETY: read immediately after the call.
        let err = unsafe { GetLastError() };
        let oplock = Oplock {
            handle: Some(handle),
            state,
            rel,
            completed: false,
        };
        if ok != 0 || err != ERROR_IO_PENDING {
            // Completing at once means no oplock is held (refused or already
            // broken); Drop still waits for nothing.
            return Err(crate::Error::isolation_unavailable(format!(
                "the bait oplock for {} was not granted (error {err})",
                oplock.rel
            )));
        }
        Ok(oplock)
    }

    /// The OVERLAPPED address a break completion carries.
    pub(super) fn overlapped_addr(&self) -> usize {
        &self.state.ov as *const OVERLAPPED as usize
    }
}

/// How long a released oplock request may take to complete.
const RELEASE_WAIT: Duration = Duration::from_secs(5);
/// Longest single port wait while a released request completes.
const RELEASE_POLL_MS: u32 = 25;

/// A request state that no kernel request ever referenced.
#[allow(unsafe_code)]
fn idle_state() -> Box<OplockState> {
    Box::new(OplockState {
        // SAFETY: all-zero is a valid OVERLAPPED.
        ov: unsafe { std::mem::zeroed() },
        out: OplockOutput::default(),
    })
}

impl Oplock {
    /// Record that this request's completion was dequeued (its break arrived).
    pub(super) fn mark_completed(&mut self) {
        self.completed = true;
    }

    /// Closes the holder, which releases the oplock (and any opener waiting on
    /// its break). `true` means the request needs no further wait: it already
    /// completed, so its packet was dequeued earlier.
    fn close(&mut self) -> bool {
        self.handle.take().is_none() || self.completed
    }

    /// The request did not complete: its buffers are kept for the kernel,
    /// which may still write into them.
    fn abandon(&mut self) {
        let state = std::mem::replace(&mut self.state, idle_state());
        Box::leak(state);
    }

    /// Closes one holder and waits for its completion packet on the job port.
    ///
    /// Completion is read from the port, never from `OVERLAPPED::Internal`: for
    /// a handle bound to a completion port the I/O manager queues the
    /// completion packet and leaves `Internal` at `STATUS_PENDING` until that
    /// packet is dequeued (measured on the Windows 11 26200 host). Polling
    /// `Internal` alone therefore never finishes, which made the probe
    /// self-test fail its idle-oplock check and report the backend as
    /// unavailable. A cancel-then-wait-forever drop is not used either: bait
    /// jobs hung in it on the Win11 VM.
    ///
    /// A packet that belongs to another request is dropped here; callers with
    /// several holders release them with [`release_all`], which matches every
    /// packet to its own request. `false` means the request did not finish
    /// within [`RELEASE_WAIT`].
    pub(super) fn release(&mut self, job: &Job) -> bool {
        if self.close() {
            return true;
        }
        let deadline = std::time::Instant::now() + RELEASE_WAIT;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            let slice = left.min(Duration::from_millis(u64::from(RELEASE_POLL_MS)));
            let Some(event) = job.next_event(slice.as_millis() as u32) else {
                continue;
            };
            if event.key == ffi::BAIT_KEY && event.value == self.overlapped_addr() {
                self.completed = true;
                return true;
            }
        }
        self.abandon();
        false
    }
}

/// Close every holder, then wait at most [`RELEASE_WAIT`] in total for the
/// completion packet of each request that was still pending.
///
/// Every holder is closed before the first wait starts, so a packet cannot be
/// queued for a sibling that has not been closed yet, and each packet is matched
/// to its own request by `OVERLAPPED` address. Callers use this only once the
/// job has exited or been terminated: a packet that is not a bait completion is
/// then dropped, because the later waits poll the job's own accounting rather
/// than its notifications.
pub(super) fn release_all(oplocks: &mut [Oplock], job: &Job) {
    let mut pending: Vec<usize> = Vec::new();
    for (i, oplock) in oplocks.iter_mut().enumerate() {
        if !oplock.close() {
            pending.push(i);
        }
    }
    let deadline = std::time::Instant::now() + RELEASE_WAIT;
    while !pending.is_empty() {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let slice = left.min(Duration::from_millis(u64::from(RELEASE_POLL_MS)));
        let Some(event) = job.next_event(slice.as_millis() as u32) else {
            continue;
        };
        if event.key != ffi::BAIT_KEY {
            continue;
        }
        let matched = pending
            .iter()
            .position(|&i| oplocks[i].overlapped_addr() == event.value);
        if let Some(pos) = matched {
            let index = pending.remove(pos);
            oplocks[index].mark_completed();
        }
    }
    for index in pending {
        oplocks[index].abandon();
    }
}

impl Drop for Oplock {
    fn drop(&mut self) {
        // Without the job port a close cannot be confirmed, so a request that
        // may still be pending keeps its buffers: the kernel could write into
        // them. Every normal path releases first (`release`/`release_all`),
        // which leaves no handle behind and nothing the kernel still
        // references.
        if self.handle.take().is_some() && !self.completed {
            let state = std::mem::replace(&mut self.state, idle_state());
            Box::leak(state);
        }
    }
}

/// In-process check that an oplock break is delivered (probe control
/// `bait-oplock-detection`): a second thread opens the file for read and the
/// break must reach the port within 2 s; closing the holder lets it finish.
pub(super) fn self_test_oplock(dir: &Path) -> crate::Result<()> {
    let path = dir.join("oplock-self-test.txt");
    std::fs::write(&path, b"oplock self test")?;
    let job = Job::new(1, 16 * 1024 * 1024)?;
    let mut lock = Oplock::request(&path, "oplock-self-test.txt".into(), &job)?;
    let reader_path = path.clone();
    let reader = thread::spawn(move || std::fs::read(reader_path).is_ok());
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut broke = false;
    while std::time::Instant::now() < deadline {
        if let Some(e) = job.next_event(25) {
            if e.key == ffi::BAIT_KEY && e.value == lock.overlapped_addr() {
                lock.mark_completed();
                broke = true;
                break;
            }
        }
    }
    // The broken holder releases its blocked reader as it closes; the request
    // already completed above, so this only has to confirm the close.
    let broken_released = lock.release(&job);
    let read_ok = reader.join().unwrap_or(false);
    let _ = std::fs::remove_file(&path);
    // An oplock nobody broke must also release promptly (every bait file of a
    // clean job ends this way). Its completion is the only evidence the close
    // worked, so this is the case that catches a release that waits on the
    // wrong signal.
    let idle_path = dir.join("oplock-self-test-idle.txt");
    std::fs::write(&idle_path, b"oplock self test")?;
    let mut idle = Oplock::request(&idle_path, "oplock-self-test-idle.txt".into(), &job)?;
    let idle_released = idle.release(&job);
    drop(idle);
    let _ = std::fs::remove_file(&idle_path);
    if broke && read_ok && broken_released && idle_released {
        Ok(())
    } else {
        Err(crate::Error::isolation_unavailable(format!(
            "bait oplock self test failed (break delivered: {broke}, reader finished: {read_ok}, \
             broken oplock released: {broken_released}, idle oplock released: {idle_released})"
        )))
    }
}

// ---- TCP tables ---------------------------------------------------------

#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        table: *mut core::ffi::c_void,
        size: *mut u32,
        order: i32,
        family: u32,
        class: i32,
        reserved: u32,
    ) -> u32;
}

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const TCP_TABLE_OWNER_PID_ALL: i32 = 5;
const NO_ERROR: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub(super) const TCP_LISTEN: u32 = 2;
pub(super) const TCP_SYN_SENT: u32 = 3;
pub(super) const TCP_ESTABLISHED: u32 = 5;

#[repr(C)]
struct Row4 {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    pid: u32,
}

#[repr(C)]
struct Row6 {
    local_addr: [u8; 16],
    local_scope: u32,
    local_port: u32,
    remote_addr: [u8; 16],
    remote_scope: u32,
    remote_port: u32,
    state: u32,
    pid: u32,
}

pub(super) struct TcpRow {
    pub(super) pid: u32,
    pub(super) state: u32,
    pub(super) local: SocketAddr,
    pub(super) remote: SocketAddr,
}

fn port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

/// Every TCP row (IPv4 and IPv6) with its owning process id.
#[allow(unsafe_code)]
pub(super) fn tcp_rows() -> crate::Result<Vec<TcpRow>> {
    let mut rows = Vec::new();
    for family in [AF_INET, AF_INET6] {
        let mut size = 0u32;
        let mut buf: Vec<u64> = Vec::new();
        let mut result = ERROR_INSUFFICIENT_BUFFER;
        for _ in 0..4 {
            buf = vec![0u64; (size as usize).div_ceil(8).max(1)];
            size = (buf.len() * 8) as u32;
            // SAFETY: `buf` is 8-aligned and `size` bytes long.
            result = unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            if result != ERROR_INSUFFICIENT_BUFFER {
                break;
            }
        }
        if result != NO_ERROR {
            return Err(crate::Error::internal(format!(
                "GetExtendedTcpTable failed: {result}"
            )));
        }
        let base = buf.as_ptr() as *const u8;
        // SAFETY: the table starts with a u32 entry count followed by that
        // many rows of the family's layout (4-byte aligned), all within the
        // `size` bytes the call reported.
        unsafe {
            let count = *(base as *const u32) as usize;
            let first = base.add(4);
            for i in 0..count {
                if family == AF_INET {
                    let r = &*(first as *const Row4).add(i);
                    let ip = |a: u32| IpAddr::V4(Ipv4Addr::from(u32::from_be(a)));
                    rows.push(TcpRow {
                        pid: r.pid,
                        state: r.state,
                        local: SocketAddr::new(ip(r.local_addr), port(r.local_port)),
                        remote: SocketAddr::new(ip(r.remote_addr), port(r.remote_port)),
                    });
                } else {
                    let r = &*(first as *const Row6).add(i);
                    rows.push(TcpRow {
                        pid: r.pid,
                        state: r.state,
                        local: SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::from(r.local_addr)),
                            port(r.local_port),
                        ),
                        remote: SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::from(r.remote_addr)),
                            port(r.remote_port),
                        ),
                    });
                }
            }
        }
    }
    Ok(rows)
}

// ---- processes ----------------------------------------------------------

#[allow(unsafe_code)]
fn open_query(pid: u32) -> Option<OwnedHandle> {
    // SAFETY: plain query-only open; the handle is owned when non-null.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    // SAFETY: fresh handle owned by nobody else.
    (!h.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(h as _) })
}

#[allow(unsafe_code)]
fn open_query_and_synchronize(pid: u32) -> Result<OwnedHandle, u32> {
    // SAFETY: requesting query and wait access to the process identified by
    // its system-assigned PID; the returned handle is owned below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    if h.is_null() {
        // SAFETY: read immediately after the failed OpenProcess call.
        Err(unsafe { GetLastError() })
    } else {
        // SAFETY: fresh handle owned by nobody else.
        Ok(unsafe { OwnedHandle::from_raw_handle(h as _) })
    }
}

#[allow(unsafe_code)]
fn creation_time_of(h: HANDLE) -> Option<u64> {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut c, mut e, mut k, mut u) = (zero, zero, zero, zero);
    // SAFETY: live process handle with query access; valid out-parameters.
    let ok = unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) };
    (ok != 0).then(|| (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime))
}

/// Creation time of `pid`, or `None` when no such process exists.
#[allow(unsafe_code)]
pub(super) fn process_creation_time(pid: u32) -> Option<u64> {
    let h = match open_query_and_synchronize(pid) {
        Ok(h) => h,
        Err(ERROR_ACCESS_DENIED) => {
            return open_query(pid).and_then(|h| creation_time_of(h.as_raw_handle() as HANDLE))
        }
        Err(_) => return None,
    };
    // A terminated process object can still be opened while another handle
    // keeps it alive (for example, a parent that just waited on its child).
    // Its creation time still matches the recovery record, but it no longer
    // owns an AppContainer profile. Only a signaled handle proves termination;
    // an unexpected wait result stays conservatively live. Access denied when
    // requesting SYNCHRONIZE falls back to the old query-only behavior so a
    // live owner we cannot wait on is still considered present.
    // SAFETY: `h` is a valid process handle and a zero timeout does not block.
    if unsafe { WaitForSingleObject(h.as_raw_handle() as HANDLE, 0) } == WAIT_OBJECT_0 {
        return None;
    }
    creation_time_of(h.as_raw_handle() as HANDLE)
}

#[allow(unsafe_code)]
pub(super) fn own_creation_time() -> Option<u64> {
    // SAFETY: the pseudo handle needs no closing.
    creation_time_of(unsafe { GetCurrentProcess() })
}

/// The Win32 image path of `pid`, when it can still be read.
#[allow(unsafe_code)]
pub(super) fn image_name(pid: u32) -> Option<String> {
    let h = open_query(pid)?;
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` u16s; the call writes at most that many.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            h.as_raw_handle() as HANDLE,
            PROCESS_NAME_WIN32,
            buf.as_mut_ptr(),
            &mut len,
        )
    };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

// ---- disk ---------------------------------------------------------------

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// Entries one scan may visit; reaching it counts as over the limit.
pub(super) const SCAN_MAX_ENTRIES: usize = 1_000_000;
/// The slowest scan cadence (SPEC-014 section 3).
const SCAN_INTERVAL: Duration = Duration::from_secs(2);

/// Sum of file sizes below `root` without following links; `None` when more
/// than `max_entries` entries were seen.
pub(super) fn tree_bytes(root: &Path, max_entries: usize) -> Option<u64> {
    let mut total = 0u64;
    let mut seen = 0usize;
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > max_entries {
                return None;
            }
            let Ok(md) = entry.metadata() else { continue };
            if md.is_dir() && md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
                pending.push(entry.path());
            } else {
                total = total.saturating_add(md.len());
            }
        }
    }
    Some(total)
}

/// Background stage scan: sets `over` once growth above the baseline passes
/// `limit` (or the entry cap is reached). [`DiskWatch::kick`] asks for a
/// scan now; dropping the watch stops the thread.
pub(super) struct DiskWatch {
    pub(super) over: Arc<AtomicBool>,
    kick: Option<Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DiskWatch {
    pub(super) fn start(root: PathBuf, baseline: u64, limit: u64) -> DiskWatch {
        let over = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&over);
        let (tx, rx) = mpsc::channel::<()>();
        let thread = thread::spawn(move || {
            // A large tree (node_modules) makes each scan slow; wait at least
            // four scan durations so the watch stays a small share of the CPU.
            let mut wait = SCAN_INTERVAL;
            loop {
                match rx.recv_timeout(wait) {
                    Ok(()) | Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
                let started = std::time::Instant::now();
                let grown = tree_bytes(&root, SCAN_MAX_ENTRIES).map(|n| n.saturating_sub(baseline));
                if grown.is_none_or(|g| g > limit) {
                    flag.store(true, Ordering::SeqCst);
                    return;
                }
                wait = SCAN_INTERVAL.max(started.elapsed() * 4);
            }
        });
        DiskWatch {
            over,
            kick: Some(tx),
            thread: Some(thread),
        }
    }

    pub(super) fn kick(&self) {
        if let Some(tx) = &self.kick {
            let _ = tx.send(());
        }
    }

    pub(super) fn is_over(&self) -> bool {
        self.over.load(Ordering::SeqCst)
    }
}

impl Drop for DiskWatch {
    fn drop(&mut self) {
        self.kick.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Path text for the report, cut to `max` characters.
pub(super) fn bounded(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// `OsStr` helper kept here so `windows.rs` stays free of UTF-16 detail.
pub(super) fn lossy(s: &OsStr) -> String {
    s.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::process_creation_time;
    use std::process::Command;

    #[test]
    fn terminated_child_is_not_considered_live_while_parent_holds_its_handle() {
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let ping = std::path::PathBuf::from(system_root)
            .join("System32")
            .join("ping.exe");
        let mut child = Command::new(ping)
            .args(["-n", "30", "127.0.0.1"])
            .spawn()
            .expect("start child process");
        assert!(process_creation_time(child.id()).is_some());
        child.kill().expect("terminate child process");
        child.wait().expect("reap child process");

        // The Child object still owns a process handle, so OpenProcess can
        // query the exited process object's creation time. It must not make a
        // crashed sandbox profile look live to the stale-profile sweep.
        assert!(process_creation_time(child.id()).is_none());
    }
}
