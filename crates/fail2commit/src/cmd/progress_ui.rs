//! Best-effort user-facing progress sinks for guarded package reviews (FR-013).

use fail2commit_core::progress::{End, Progress, Step};
use fail2commit_core::protocol::Finding;
use std::io::{IsTerminal, Write};
use std::sync::{mpsc, Mutex};
use std::time::Instant;

pub struct ProgressUi {
    terminal: bool,
    started: Instant,
    state: Mutex<State>,
    #[cfg(windows)]
    window: Option<(
        mpsc::SyncSender<WindowEvent>,
        Mutex<Option<std::thread::JoinHandle<()>>>,
    )>,
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
        if let Some((tx, _)) = &self.window {
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
    fn finish(&self, end: End, summary: &str) {
        if self.terminal {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
        #[cfg(windows)]
        if let Some((tx, _)) = &self.window {
            let (count, details) = self
                .state
                .lock()
                .map(|s| {
                    (
                        s.findings,
                        s.finding_details
                            .iter()
                            .map(|f| format!("\r\n• {f}"))
                            .collect::<String>(),
                    )
                })
                .unwrap_or((0, String::new()));
            let safe = format!(
                "Review result: {}\r\n{count} finding(s){details}",
                fail2commit_core::approval::console::sanitize(summary),
            );
            let _ = tx.send(WindowEvent::Finish(end, safe.chars().take(240).collect()));
        }
        #[cfg(windows)]
        if let Some((_, join)) = &self.window {
            // On findings/errors the native result remains visible until the user closes it.
            if end != End::Clean {
                if let Ok(mut slot) = join.lock() {
                    if let Some(handle) = slot.take() {
                        let _ = handle.join();
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
enum WindowEvent {
    Update(String),
    Finish(End, String),
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
fn start_window() -> (
    mpsc::SyncSender<WindowEvent>,
    Mutex<Option<std::thread::JoinHandle<()>>>,
) {
    use std::os::windows::ffi::OsStrExt;
    let (tx, rx) = mpsc::sync_channel(1);
    let join = std::thread::spawn(move || {
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
                    Ok(WindowEvent::Finish(end, summary)) => {
                        if end == End::Clean {
                            let _ = DestroyWindow(hwnd);
                            break;
                        }
                        let details = wide(&format!(
                            "{summary}\r\nThis window will close when you close it."
                        ));
                        let _ = SetWindowTextW(child, details.as_ptr());
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        }
    });
    (tx, Mutex::new(Some(join)))
}

#[cfg(windows)]
unsafe extern "system" fn progress_proc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows_sys::Win32::Foundation::WPARAM,
    lparam: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::LRESULT {
    // SAFETY: forwards unhandled messages to the system window procedure.
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}
