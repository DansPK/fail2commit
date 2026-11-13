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
    use std::os::windows::process::CommandExt;
    std::process::Command::new(std::env::current_exe()?)
        .arg(HANDOVER_ARG)
        .arg(payload)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()
        .map(|_| ())
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
}
