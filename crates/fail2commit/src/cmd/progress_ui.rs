//! Best-effort user-facing progress sinks for guarded package reviews (FR-013).

use fail2commit_core::progress::{End, Progress, Step};
use fail2commit_core::protocol::Finding;
use std::io::{IsTerminal, Write};
use std::sync::{mpsc, Mutex};
use std::time::Instant;

const HANDOVER_ARG: &str = "--f2c-progress-result-window";
const MAX_HANDOVER_BYTES: usize = 1024;

pub struct ProgressUi {
    terminal: bool,
    started: Instant,
    state: Mutex<State>,
    #[cfg(windows)]
    window: Option<mpsc::SyncSender<WindowEvent>>,
}

#[derive(Default)]
struct State {
    step: Option<Step>,
    total: u64,
    done: u64,
    current: String,
    findings: usize,
    reported: Vec<Finding>,
    finding_details: Vec<String>,
}

impl ProgressUi {
    pub fn new(json: bool, window_enabled: bool) -> Self {
        let terminal = !json && std::io::stderr().is_terminal();
        #[cfg(windows)]
        let window = if !json && window_enabled && interactive_desktop() {
            Some(start_window())
        } else {
            None
        };
        #[cfg(not(windows))]
        let _ = window_enabled;
        ProgressUi {
            terminal,
            started: Instant::now(),
            state: Mutex::new(State::default()),
            #[cfg(windows)]
            window,
        }
    }

    fn render(&self, s: &State, show_findings: bool) -> String {
        let step = s.step.map(Step::label).unwrap_or("Starting review");
        let current = if s.current.is_empty() {
            String::new()
        } else {
            format!(" — {}", s.current)
        };
        let detail = if !show_findings || s.finding_details.is_empty() {
            String::new()
        } else {
            format!(" · {}", s.finding_details.join(" | "))
        };
        format!(
            "fail2commit: {step} ({}/{}){current} · {} finding(s){detail} · {}s",
            s.done,
            s.total,
            s.findings,
            self.started.elapsed().as_secs()
        )
    }

    fn update(&self, s: &State) {
        let text = self.render(s, cfg!(windows));
        if self.terminal {
            let safe = fail2commit_core::approval::console::sanitize(&text);
            let _ = write!(std::io::stderr().lock(), "\r\x1b[2K{safe}");
            let _ = std::io::stderr().flush();
        }
        #[cfg(windows)]
        if let Some(tx) = &self.window {
            let _ = tx.try_send(WindowEvent::Update(
                fail2commit_core::approval::console::sanitize(&text),
            ));
        }
    }
}

impl Progress for ProgressUi {
    fn step(&self, step: Step, total: u64) {
        if let Ok(mut s) = self.state.lock() {
            s.step = Some(step);
            s.total = total;
            s.done = 0;
            s.current.clear();
            self.update(&s);
        }
    }
    fn advance(&self, done: u64, current: &str) {
        if let Ok(mut s) = self.state.lock() {
            s.done = s.done.max(done);
            s.current = current.chars().take(80).collect();
            self.update(&s);
        }
    }
    fn finding(&self, finding: &Finding) {
        if let Ok(mut s) = self.state.lock() {
            if s.reported.contains(finding) {
                return;
            }
            if s.reported.len() < 256 {
                s.reported.push(finding.clone());
            }
            s.findings = s.findings.saturating_add(1);
            let evidence = fail2commit_core::approval::console::sanitize(&finding.evidence);
            let target = finding
                .target
                .as_deref()
                .map(fail2commit_core::approval::console::sanitize)
                .unwrap_or_default();
            let detail = format!("{:?}: {} {}", finding.kind, target, evidence);
            s.finding_details.push(detail.chars().take(120).collect());
            if s.finding_details.len() > 3 {
                s.finding_details.remove(0);
            }
            self.update(&s);
        }
    }
    fn pause(&self) {
        if self.terminal {
            let _ = write!(std::io::stderr().lock(), "\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
    }
    fn finish(&self, end: End, _summary: &str) {
        if self.terminal {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
        #[cfg(windows)]
        if let Some(tx) = &self.window {
            if end != End::Clean {
                let (count, details) = self
                    .state
                    .lock()
                    .map(|s| (s.findings, s.finding_details.clone()))
                    .unwrap_or_default();
                let text = result_window_text(end, count, &details);
                if let Err(e) = queue_result_handover(end, &text, spawn_result_window) {
                    if self.terminal {
                        eprintln!(
                            "fail2commit: could not retain the review result window: {}",
                            e.kind()
                        );
                    }
                }
            }
            let _ = tx.try_send(WindowEvent::Close);
        }
    }
}

#[cfg(windows)]
enum WindowEvent {
    Update(String),
    Close,
}

fn result_window_text(end: End, count: usize, details: &[String]) -> String {
    let result = match end {
        End::Findings => "Review completed with findings",
        End::Stopped => "Review stopped or failed",
        End::Clean => "Review completed",
    };
    let mut text = format!("{result}\r\n{count} finding(s)");
    for item in details.iter().take(3) {
        text.push_str("\r\n• ");
        text.push_str(
            &fail2commit_core::approval::console::sanitize(item)
                .chars()
                .take(120)
                .collect::<String>(),
        );
    }
    while text.len() > MAX_HANDOVER_BYTES {
        text.pop();
    }
    text
}

fn encode_handover(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_HANDOVER_BYTES {
        return None;
    }
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    Some(out)
}

fn queue_result_handover(
    end: End,
    text: &str,
    launch: impl FnOnce(&str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    if end == End::Clean {
        return Ok(());
    }
    match encode_handover(text) {
        Some(encoded) => launch(&encoded),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "result window payload exceeds its bound",
        )),
    }
}

fn decode_handover(hex: &str) -> Option<String> {
    if hex.is_empty() || hex.len() % 2 != 0 || hex.len() > MAX_HANDOVER_BYTES * 2 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        bytes.push((digit(pair[0])? << 4) | digit(pair[1])?);
    }
    String::from_utf8(bytes).ok()
}

#[cfg(windows)]
fn spawn_result_window(payload: &str) -> std::io::Result<()> {
    spawn_detached_process(&std::env::current_exe()?, &[HANDOVER_ARG, payload])
}

#[cfg(windows)]
fn spawn_detached_process(executable: &std::path::Path, args: &[&str]) -> std::io::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute, CREATE_NO_WINDOW,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };

    if args.iter().any(|arg| {
        arg.bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'"')
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "detached process argument is not a safe token",
        ));
    }
    let executable_text = executable.to_string_lossy();
    let command_line = format!("\"{executable_text}\" {}", args.join(" "));
    let mut application: Vec<u16> = executable.as_os_str().encode_wide().collect();
    application.push(0);
    let mut command_wide: Vec<u16> = OsStr::new(&command_line).encode_wide().collect();
    command_wide.push(0);

    let input = std::fs::OpenOptions::new().read(true).open("NUL")?;
    let output = std::fs::OpenOptions::new().write(true).open("NUL")?;
    let duplicate = |handle: HANDLE| -> std::io::Result<OwnedHandle> {
        let mut duplicate: HANDLE = std::ptr::null_mut();
        // SAFETY: source and destination are the current process; the source
        // handles are live NUL devices and the out pointer is valid.
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: DuplicateHandle returned a new owned kernel handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(duplicate as RawHandle) })
    };
    let std_handles = [
        duplicate(input.as_raw_handle() as HANDLE)?,
        duplicate(output.as_raw_handle() as HANDLE)?,
        duplicate(output.as_raw_handle() as HANDLE)?,
    ];
    let raw_handles: Vec<HANDLE> = std_handles
        .iter()
        .map(|handle| handle.as_raw_handle() as HANDLE)
        .collect();

    let mut size = 0usize;
    // SAFETY: sizing call with a null list is documented to fail and set size.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    if size == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let attribute_list = storage.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    // SAFETY: storage is sized and aligned for the opaque attribute list.
    if unsafe { InitializeProcThreadAttributeList(attribute_list, 1, 0, &mut size) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    struct AttributeListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for AttributeListGuard {
        fn drop(&mut self) {
            // SAFETY: this pointer was successfully initialized above.
            unsafe { DeleteProcThreadAttributeList(self.0) }
        }
    }
    let _attribute_guard = AttributeListGuard(attribute_list);
    // SAFETY: raw_handles remains alive through CreateProcessW.
    if unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            raw_handles.as_ptr().cast(),
            std::mem::size_of_val(&raw_handles),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: all-zero STARTUPINFOEXW / PROCESS_INFORMATION are valid.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = raw_handles[0];
    startup.StartupInfo.hStdOutput = raw_handles[1];
    startup.StartupInfo.hStdError = raw_handles[2];
    startup.lpAttributeList = attribute_list;
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: application and command_line are NUL-terminated, mutable command
    // line storage is valid, and the attribute list whitelists exactly the
    // three NUL stdio handles. No caller pipe or unrelated handle is inherited.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            std::ptr::null(),
            std::ptr::null(),
            &startup.StartupInfo,
            &mut process,
        )
    };
    if created == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: CreateProcessW returned valid process/thread handles; this
    // handover is fire-and-forget, so neither handle needs to stay open.
    unsafe {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    Ok(())
}

#[cfg(not(windows))]
fn spawn_result_window(_payload: &str) -> std::io::Result<()> {
    Ok(())
}

pub fn run_handover_argument(argument: &std::ffi::OsStr) -> i32 {
    let Some(encoded) = argument.to_str() else {
        return 2;
    };
    let Some(text) = decode_handover(encoded) else {
        return 2;
    };
    #[cfg(windows)]
    {
        show_result_window(&text)
    }
    #[cfg(not(windows))]
    {
        let _ = text;
        2
    }
}

#[cfg(windows)]
fn interactive_desktop() -> bool {
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, OpenInputDesktop, DESKTOP_READOBJECTS,
    };
    // SAFETY: only probes whether this process has an interactive input desktop.
    unsafe {
        let d = OpenInputDesktop(0, 0, DESKTOP_READOBJECTS);
        if d.is_null() {
            false
        } else {
            CloseDesktop(d);
            true
        }
    }
}

#[cfg(windows)]
fn start_window() -> mpsc::SyncSender<WindowEvent> {
    use std::os::windows::ffi::OsStrExt;
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        use windows_sys::Win32::Graphics::Gdi::UpdateWindow;
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows_sys::Win32::System::SystemServices::SS_LEFT;
        use windows_sys::Win32::UI::WindowsAndMessaging::*;
        let wide = |s: &str| {
            std::ffi::OsStr::new(s)
                .encode_wide()
                .chain([0])
                .collect::<Vec<u16>>()
        };
        // SAFETY: the window and message queue are owned by this thread; strings are NUL terminated.
        unsafe {
            let title = wide("fail2commit install review");
            let body = wide("Starting review…");
            let class_name = wide("F2CProgressWindow");
            let hinst = GetModuleHandleW(std::ptr::null());
            let mut class: WNDCLASSW = std::mem::zeroed();
            class.lpfnWndProc = Some(progress_proc);
            class.hInstance = hinst;
            class.lpszClassName = class_name.as_ptr();
            let _ = RegisterClassW(&class);
            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                560,
                150,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                hinst,
                std::ptr::null(),
            );
            if hwnd.is_null() {
                return;
            }
            let child = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                body.as_ptr(),
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                18,
                20,
                510,
                70,
                hwnd,
                std::ptr::null_mut(),
                hinst,
                std::ptr::null(),
            );
            let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
            let _ = UpdateWindow(hwnd);
            while IsWindow(hwnd) != 0 {
                let mut msg: MSG = std::mem::zeroed();
                while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                match rx.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(WindowEvent::Update(text)) => {
                        let _ = SetWindowTextW(child, wide(&text).as_ptr());
                    }
                    Ok(WindowEvent::Close) => {
                        let _ = DestroyWindow(hwnd);
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        }
    });
    tx
}

#[cfg(windows)]
fn show_result_window(text: &str) -> i32 {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Graphics::Gdi::UpdateWindow;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::SystemServices::SS_LEFT;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;
    let wide = |s: &str| {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain([0])
            .collect::<Vec<u16>>()
    };
    // SAFETY: this helper process owns the window and its message loop.
    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let class_name = wide("F2CProgressResultWindow");
        let mut class: WNDCLASSW = std::mem::zeroed();
        class.lpfnWndProc = Some(progress_proc);
        class.hInstance = hinst;
        class.lpszClassName = class_name.as_ptr();
        let _ = RegisterClassW(&class);
        let title = wide("fail2commit install review result");
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            560,
            220,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return 2;
        }
        let display = wide(text);
        let child = CreateWindowExW(
            0,
            wide("STATIC").as_ptr(),
            display.as_ptr(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            18,
            20,
            510,
            140,
            hwnd,
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        let _ = UpdateWindow(hwnd);
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let _ = child;
    }
    0
}

#[cfg(windows)]
unsafe extern "system" fn progress_proc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows_sys::Win32::Foundation::WPARAM,
    lparam: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::LRESULT {
    // SAFETY: forwards unhandled messages to the system window procedure.
    if msg == windows_sys::Win32::UI::WindowsAndMessaging::WM_DESTROY {
        unsafe { windows_sys::Win32::UI::WindowsAndMessaging::PostQuitMessage(0) };
        return 0;
    }
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::io::Read;

    #[test]
    fn result_handover_is_bounded_sanitized_and_round_trips() {
        let text = result_window_text(
            End::Findings,
            1,
            &[
                "YARA: pkg@1.0 \u{1b}[2J suspicious".to_owned(),
                "ignored second".into(),
            ],
        );
        assert!(text.len() <= MAX_HANDOVER_BYTES);
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("Review completed with findings"));
        assert!(text.contains("1 finding(s)"));
        let encoded = encode_handover(&text).unwrap();
        assert!(encoded.len() <= MAX_HANDOVER_BYTES * 2);
        assert_eq!(decode_handover(&encoded), Some(text));
    }

    #[test]
    fn result_handover_rejects_malformed_or_oversized_arguments() {
        assert_eq!(decode_handover("xyz"), None);
        assert_eq!(decode_handover(&"aa".repeat(MAX_HANDOVER_BYTES + 1)), None);
        assert_eq!(encode_handover(&"x".repeat(MAX_HANDOVER_BYTES + 1)), None);
    }

    #[test]
    fn result_handover_queues_without_waiting_and_clean_results_do_not_spawn() {
        let mut queued = None;
        queue_result_handover(End::Findings, "safe result", |encoded| {
            queued = Some(encoded.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            decode_handover(queued.as_deref().unwrap()).as_deref(),
            Some("safe result")
        );
        let mut called = false;
        queue_result_handover(End::Clean, "clean", |_| {
            called = true;
            Ok(())
        })
        .unwrap();
        assert!(!called);
    }

    #[cfg(windows)]
    #[test]
    fn result_helper_does_not_hold_captured_parent_pipes_open() {
        const PARENT: &str = "F2C_PROGRESS_PIPE_TEST_PARENT";
        const CHILD: &str = "F2C_PROGRESS_PIPE_TEST_CHILD";
        const STOP: &str = "F2C_PROGRESS_PIPE_TEST_STOP";

        if let Some(marker) = std::env::var_os(CHILD) {
            let marker = std::path::PathBuf::from(marker);
            let stop = std::path::PathBuf::from(std::env::var_os(STOP).unwrap());
            std::fs::write(&marker, b"alive").unwrap();
            while !stop.exists() {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let _ = std::fs::remove_file(marker);
            return;
        }

        if let Some(marker) = std::env::var_os(PARENT) {
            let marker = std::path::PathBuf::from(marker);
            let stop = marker.with_extension("stop");
            std::env::set_var(CHILD, &marker);
            std::env::set_var(STOP, &stop);
            spawn_detached_process(
                &std::env::current_exe().unwrap(),
                &[
                    "--exact",
                    "cmd::progress_ui::tests::result_helper_does_not_hold_captured_parent_pipes_open",
                    "--nocapture",
                ],
            )
            .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while !marker.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(marker.exists(), "detached helper did not start");
            return;
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let marker = std::env::temp_dir().join(format!(
            "f2c-progress-pipe-{}-{nonce}.alive",
            std::process::id()
        ));
        let stop = marker.with_extension("stop");
        let mut parent = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cmd::progress_ui::tests::result_helper_does_not_hold_captured_parent_pipes_open",
                "--nocapture",
            ])
            .env(PARENT, &marker)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut stdout = parent.stdout.take().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stdout.read_to_end(&mut bytes);
            let _ = sent.send(bytes);
        });
        assert!(parent.wait().unwrap().success());

        let eof_received = received
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_ok();
        let helper_alive_at_eof = marker.exists();
        let eof_while_helper_alive = eof_received && helper_alive_at_eof;
        let _ = std::fs::write(&stop, b"stop");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while marker.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = std::fs::remove_file(marker);
        let _ = std::fs::remove_file(stop);
        assert!(
            eof_while_helper_alive,
            "stdout EOF before helper close: {eof_received}; helper alive at EOF: {helper_alive_at_eof}"
        );
    }
}
