//! Win32 tray UI. Event driven: the pipe threads post `WM_NEW_REQUEST` to the
//! UI thread; nothing polls. Closing the tray closes the pipe, so the CLI
//! falls back to the terminal or rejects (guards stay active).
#![allow(unsafe_code)]

use crate::render;
use fail2commit_core::approver::now_secs;
use fail2commit_core::ipc::pipe::{PipeServer, Prompter, Reply};
use fail2commit_core::ipc::startup::StartupIntegration;
use fail2commit_core::paths::TrustedPaths;
use fail2commit_core::protocol::{ApprovalRequest, Decision};
use fail2commit_core::settings::Settings;
use std::cell::RefCell;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::process::ExitCode;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{GetStockObject, DEFAULT_GUI_FONT};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WM_NEW_REQUEST: u32 = WM_APP + 1;
const WM_TRAY: u32 = WM_APP + 2;
const NIN_BALLOONUSERCLICK: u32 = WM_USER + 5;

const ID_PENDING: usize = 100;
const ID_SANDBOX: usize = 101;
const ID_PW_SET: usize = 102;
const ID_PW_CHANGE: usize = 103;
const ID_PW_RESET: usize = 104;
const ID_STARTUP: usize = 105;
const ID_EXIT: usize = 106;

const COLOR_BTNFACE: u32 = 15;
const SS_LEFT: u32 = 0;
const EM_LIMITTEXT: u32 = 0xC5;
const ID_OK: i32 = 1; // Enter
const BTN_CANCEL: i32 = 2; // IDCANCEL: Esc
const BTN_APPROVE: i32 = 101;
const BTN_HOST: i32 = 102;
const EDIT_PASSWORD: i32 = 103;

static MAIN_WND: AtomicIsize = AtomicIsize::new(0);

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain([0]).collect()
}

/// One request waiting for the user. Dropping it without answering drops the
/// sender, which the pipe thread treats as Cancel.
struct Pending {
    req: ApprovalRequest,
    reply: Option<mpsc::Sender<Reply>>,
    password_edit: HWND,
}

#[derive(Default)]
struct State {
    dialogs: Vec<HWND>,
    taskbar_created: u32,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

struct TrayPrompter;

impl Prompter for TrayPrompter {
    fn prompt(&self, req: ApprovalRequest) -> Reply {
        let (tx, rx) = mpsc::channel();
        let wait = req.expires_at.saturating_sub(now_secs());
        let pending = Box::new(Pending {
            req,
            reply: Some(tx),
            password_edit: std::ptr::null_mut(),
        });
        let raw = Box::into_raw(pending);
        let hwnd = MAIN_WND.load(Ordering::SeqCst) as HWND;
        // SAFETY: posts to our own window; ownership of `raw` moves to the UI thread.
        if hwnd.is_null() || unsafe { PostMessageW(hwnd, WM_NEW_REQUEST, 0, raw as LPARAM) } == 0 {
            // SAFETY: the post failed, so we still own `raw`.
            drop(unsafe { Box::from_raw(raw) });
            return Reply::Cancel;
        }
        // The dialog also closes itself at expiry; this bounds the wait if
        // the UI thread is gone.
        rx.recv_timeout(Duration::from_secs(wait + 5))
            .unwrap_or(Reply::Cancel)
    }
}

pub fn run() -> ExitCode {
    // The first pipe instance doubles as the single-instance lock.
    let server = match PipeServer::start_default(Arc::new(TrayPrompter)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fail2commit-tray: not started (already running?): {e}");
            return ExitCode::FAILURE;
        }
    };
    // SAFETY: standard window-class registration and message loop.
    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let main_class = wide("F2CTrayMain");
        let dlg_class = wide("F2CApproval");
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(main_proc);
        wc.hInstance = hinst;
        wc.lpszClassName = main_class.as_ptr();
        RegisterClassW(&wc);
        let mut dc: WNDCLASSW = std::mem::zeroed();
        dc.lpfnWndProc = Some(dialog_proc);
        dc.hInstance = hinst;
        dc.lpszClassName = dlg_class.as_ptr();
        dc.hCursor = LoadCursorW(std::ptr::null_mut(), IDC_ARROW);
        dc.hbrBackground = (COLOR_BTNFACE + 1) as usize as _;
        RegisterClassW(&dc);

        let title = wide("fail2commit");
        let hwnd = CreateWindowExW(
            0,
            main_class.as_ptr(),
            title.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return ExitCode::FAILURE;
        }
        MAIN_WND.store(hwnd as isize, Ordering::SeqCst);
        STATE.with(|s| {
            s.borrow_mut().taskbar_created = RegisterWindowMessageW(wide("TaskbarCreated").as_ptr())
        });
        notify(hwnd, NIM_ADD, None);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            // Tab/Esc handling for the approval dialogs.
            let top = GetAncestor(msg.hwnd, GA_ROOT);
            if !top.is_null() && top != hwnd && IsDialogMessageW(top, &msg) != 0 {
                continue;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    server.shutdown();
    ExitCode::SUCCESS
}

// ------------------------------------------------------------ tray icon

fn pending_count() -> usize {
    STATE.with(|s| s.borrow().dialogs.len())
}

fn copy_wide<const N: usize>(dst: &mut [u16; N], text: &str) {
    for (i, c) in text.encode_utf16().take(N - 1).enumerate() {
        dst[i] = c;
    }
}

unsafe fn notify(hwnd: HWND, op: u32, balloon: Option<&str>) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = LoadIconW(std::ptr::null_mut(), IDI_SHIELD);
    let n = pending_count();
    copy_wide(
        &mut nid.szTip,
        &if n == 0 {
            "fail2commit".to_string()
        } else {
            format!("fail2commit - {n} pending approval(s)")
        },
    );
    if let Some(text) = balloon {
        nid.uFlags |= NIF_INFO;
        nid.dwInfoFlags = NIIF_INFO;
        copy_wide(&mut nid.szInfoTitle, "fail2commit approval needed");
        copy_wide(&mut nid.szInfo, text);
    }
    Shell_NotifyIconW(op, &nid);
}

unsafe fn remove_icon(hwnd: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = 1;
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

fn tray_exe() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_default()
}

fn show_error(hwnd: HWND, text: &str) {
    // SAFETY: modal box on the UI thread.
    unsafe {
        MessageBoxW(
            hwnd,
            wide(text).as_ptr(),
            wide("fail2commit").as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
}

/// Password management runs the CLI in its own console so secrets are typed
/// on hidden console input and never pass through this process.
fn launch_password(hwnd: HWND, sub: &str) {
    let cli = tray_exe().with_file_name("fail2commit.exe");
    let r = std::process::Command::new("cmd.exe")
        .arg("/c")
        .raw_arg(format!("\"\"{}\" password {sub} & pause\"", cli.display()))
        .creation_flags(0x0000_0010) // CREATE_NEW_CONSOLE
        .spawn();
    if let Err(e) = r {
        show_error(hwnd, &format!("Could not start fail2commit: {e}"));
    }
}

unsafe fn show_menu(hwnd: HWND) {
    let paths = TrustedPaths::resolve().ok();
    let sandbox_on = paths
        .as_ref()
        .and_then(|p| Settings::load(p).ok())
        .map(|s| s.sandbox.enabled);
    let startup_on = StartupIntegration::default().is_enabled();
    let menu = CreatePopupMenu();
    let n = pending_count();
    let add = |flags: u32, id: usize, text: &str| {
        AppendMenuW(menu, flags, id, wide(text).as_ptr());
    };
    add(
        MF_STRING | if n == 0 { MF_GRAYED } else { 0 },
        ID_PENDING,
        &format!("Pending approvals ({n})"),
    );
    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
    add(
        MF_STRING
            | if sandbox_on == Some(true) {
                MF_CHECKED
            } else {
                0
            }
            | if sandbox_on.is_none() { MF_GRAYED } else { 0 },
        ID_SANDBOX,
        "Run build scripts in sandbox",
    );
    add(MF_STRING, ID_PW_SET, "Set force-push password...");
    add(MF_STRING, ID_PW_CHANGE, "Change password...");
    add(MF_STRING, ID_PW_RESET, "Reset password (recovery code)...");
    add(
        MF_STRING | if startup_on { MF_CHECKED } else { 0 },
        ID_STARTUP,
        "Start at sign-in",
    );
    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
    add(MF_STRING, ID_EXIT, "Exit (guards stay active)");

    let mut pt = POINT { x: 0, y: 0 };
    GetCursorPos(&mut pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, std::ptr::null());
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

unsafe fn on_command(hwnd: HWND, id: usize) {
    match id {
        ID_PENDING => focus_dialogs(),
        ID_SANDBOX => {
            let r = TrustedPaths::resolve()
                .and_then(|p| Settings::update(&p, |s| s.sandbox.enabled = !s.sandbox.enabled));
            if let Err(e) = r {
                show_error(hwnd, &format!("Could not change the sandbox setting: {e}"));
            }
        }
        ID_PW_SET => launch_password(hwnd, "set"),
        ID_PW_CHANGE => launch_password(hwnd, "change"),
        ID_PW_RESET => launch_password(hwnd, "reset"),
        ID_STARTUP => {
            let s = StartupIntegration::default();
            if let Err(e) = s.set_enabled(&tray_exe(), !s.is_enabled()) {
                show_error(hwnd, &format!("Could not change start at sign-in: {e}"));
            }
        }
        ID_EXIT => {
            DestroyWindow(hwnd);
        }
        _ => {}
    }
}

fn focus_dialogs() {
    let list = STATE.with(|s| s.borrow().dialogs.clone());
    for d in list {
        // SAFETY: windows owned by this thread.
        unsafe {
            ShowWindow(d, SW_SHOW);
            SetForegroundWindow(d);
        }
    }
}

unsafe extern "system" fn main_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_NEW_REQUEST => {
            let pending = Box::from_raw(lp as *mut Pending);
            let summary = render::summary(&pending.req);
            open_dialog(pending);
            notify(hwnd, NIM_MODIFY, Some(&summary));
            0
        }
        WM_TRAY => {
            match (lp as u32) & 0xFFFF {
                WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(hwnd),
                WM_LBUTTONUP | NIN_BALLOONUSERCLICK => focus_dialogs(),
                _ => {}
            }
            0
        }
        WM_COMMAND => {
            on_command(hwnd, wp & 0xFFFF);
            0
        }
        WM_DESTROY => {
            // Close every dialog (each answers Cancel), then leave.
            let list = STATE.with(|s| s.borrow().dialogs.clone());
            for d in list {
                DestroyWindow(d);
            }
            remove_icon(hwnd);
            MAIN_WND.store(0, Ordering::SeqCst);
            PostQuitMessage(0);
            0
        }
        _ => {
            let created = STATE.with(|s| s.borrow().taskbar_created);
            if msg == created && created != 0 {
                notify(hwnd, NIM_ADD, None);
            }
            DefWindowProcW(hwnd, msg, wp, lp)
        }
    }
}

// --------------------------------------------------------------- dialog

unsafe fn child(
    parent: HWND,
    class: &str,
    text: &str,
    style: u32,
    (x, y, w, h): (i32, i32, i32, i32),
    id: i32,
) -> HWND {
    let hwnd = CreateWindowExW(
        if class == "EDIT" { WS_EX_CLIENTEDGE } else { 0 },
        wide(class).as_ptr(),
        wide(text).as_ptr(),
        WS_CHILD | WS_VISIBLE | style,
        x,
        y,
        w,
        h,
        parent,
        id as isize as _,
        GetModuleHandleW(std::ptr::null()),
        std::ptr::null(),
    );
    SendMessageW(
        hwnd,
        WM_SETFONT,
        GetStockObject(DEFAULT_GUI_FONT) as usize,
        1,
    );
    hwnd
}

unsafe fn open_dialog(mut pending: Box<Pending>) {
    let req = pending.req.clone();
    let hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        wide("F2CApproval").as_ptr(),
        wide(render::title(&req)).as_ptr(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        580,
        470,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        GetModuleHandleW(std::ptr::null()),
        std::ptr::null(),
    );
    if hwnd.is_null() {
        return; // dropping `pending` cancels
    }
    child(
        hwnd,
        "STATIC",
        &render::summary(&req),
        SS_LEFT,
        (12, 10, 540, 40),
        0,
    );
    let ro = (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32 | WS_VSCROLL | WS_TABSTOP;
    child(hwnd, "EDIT", &render::body(&req), ro, (12, 56, 540, 220), 0);
    let mut y = 290;
    if req.password_required {
        child(
            hwnd,
            "STATIC",
            "Force-push password:",
            SS_LEFT,
            (12, y + 4, 150, 20),
            0,
        );
        let e = child(
            hwnd,
            "EDIT",
            "",
            (ES_PASSWORD | ES_AUTOHSCROLL) as u32 | WS_TABSTOP,
            (170, y, 250, 24),
            EDIT_PASSWORD,
        );
        SendMessageW(e, EM_LIMITTEXT, 256, 0);
        pending.password_edit = e;
        y += 40;
    }
    let btn = |text: &str, id: i32, x: i32, w: i32, default: bool| {
        let style = if default {
            BS_DEFPUSHBUTTON
        } else {
            BS_PUSHBUTTON
        } as u32;
        child(hwnd, "BUTTON", text, style | WS_TABSTOP, (x, y, w, 30), id);
    };
    // Cancel first: it owns the default focus.
    btn("Cancel", BTN_CANCEL, 12, 100, true);
    if render::offers(&req, Decision::ApproveOnce) {
        btn("Approve once", BTN_APPROVE, 300, 110, false);
    }
    if render::offers(&req, Decision::RunOnHostOnce) {
        btn("Run on host once", BTN_HOST, 420, 132, false);
    }
    let remaining_ms = req
        .expires_at
        .saturating_sub(now_secs())
        .saturating_mul(1000);
    SetTimer(hwnd, 1, remaining_ms.min(u32::MAX as u64 - 1) as u32, None);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(pending) as isize);
    STATE.with(|s| s.borrow_mut().dialogs.push(hwnd));
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
}

unsafe fn read_password(edit: HWND) -> Option<String> {
    if edit.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 300];
    let n = GetWindowTextW(edit, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
    let s = String::from_utf16_lossy(&buf[..n]);
    buf.iter_mut().for_each(|c| *c = 0);
    SetWindowTextW(edit, wide("").as_ptr());
    Some(s)
}

unsafe fn answer(hwnd: HWND, decision: Option<Decision>) {
    let p = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Pending;
    if p.is_null() {
        return;
    }
    let pending = &mut *p;
    if let Some(tx) = pending.reply.take() {
        let reply = match decision {
            Some(d) => Reply::Decide {
                decision: d,
                password: if pending.req.password_required {
                    read_password(pending.password_edit)
                } else {
                    None
                },
            },
            None => Reply::Cancel,
        };
        let _ = tx.send(reply);
    }
    DestroyWindow(hwnd);
}

unsafe extern "system" fn dialog_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => {
            match (wp & 0xFFFF) as i32 {
                BTN_APPROVE => answer(hwnd, Some(Decision::ApproveOnce)),
                BTN_HOST => answer(hwnd, Some(Decision::RunOnHostOnce)),
                // Enter, Esc and the Cancel button all cancel.
                BTN_CANCEL | ID_OK => answer(hwnd, None),
                _ => {}
            }
            0
        }
        WM_TIMER | WM_CLOSE => {
            answer(hwnd, None);
            0
        }
        WM_DESTROY => {
            KillTimer(hwnd, 1);
            let p = SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) as *mut Pending;
            if !p.is_null() {
                drop(Box::from_raw(p)); // unanswered => sender drops => Cancel
            }
            STATE.with(|s| s.borrow_mut().dialogs.retain(|d| *d != hwnd));
            let main = MAIN_WND.load(Ordering::SeqCst) as HWND;
            if !main.is_null() {
                notify(main, NIM_MODIFY, None);
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}
