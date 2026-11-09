//! TC-009 runtime check: a real AppContainer (LowBox) process cannot open the
//! approval pipe, while an ordinary same-user process can. The probe is
//! `cmd.exe /c "echo x>PIPE"`, which succeeds only if CreateFile on the pipe
//! succeeds. cmd.exe lives under System32, which AppContainers may execute.
#![cfg(windows)]
#![allow(unsafe_code)]

use fail2commit_core::digest::random_hex32;
use fail2commit_core::ipc::pipe::{PipeServer, Prompter, Reply};
use fail2commit_core::protocol::ApprovalRequest;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{FreeSid, SECURITY_CAPABILITIES};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
    CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW,
};

struct Count(AtomicUsize);
impl Prompter for Count {
    fn prompt(&self, _req: ApprovalRequest) -> Reply {
        self.0.fetch_add(1, Ordering::SeqCst);
        Reply::Cancel
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// Run `cmdline` inside a fresh AppContainer and return its exit code.
fn run_in_app_container(cmdline: &str) -> u32 {
    let profile = format!("f2ctest{}", &random_hex32().unwrap()[..12]);
    let pw = wide(&profile);
    // SAFETY: documented Win32 calls with valid buffers; every handle and
    // allocation created here is released before returning.
    unsafe {
        let mut sid = std::ptr::null_mut();
        let hr = CreateAppContainerProfile(
            pw.as_ptr(),
            pw.as_ptr(),
            pw.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        );
        assert!(hr >= 0, "CreateAppContainerProfile failed: {hr:#x}");

        let caps = SECURITY_CAPABILITIES {
            AppContainerSid: sid,
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut size = 0usize;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
        let mut buf = vec![0u8; size];
        let list = buf.as_mut_ptr().cast();
        assert!(InitializeProcThreadAttributeList(list, 1, 0, &mut size) != 0);
        assert!(
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&caps as *const SECURITY_CAPABILITIES).cast(),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            ) != 0
        );
        let mut si: STARTUPINFOEXW = std::mem::zeroed();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = list;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let mut cmd = wide(cmdline);
        let cwd = wide(r"C:\Windows\System32");
        let ok = CreateProcessW(
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            std::ptr::null(),
            cwd.as_ptr(),
            &si.StartupInfo,
            &mut pi,
        );
        let err = std::io::Error::last_os_error();
        let mut code = u32::MAX;
        if ok != 0 {
            WaitForSingleObject(pi.hProcess, 20_000);
            GetExitCodeProcess(pi.hProcess, &mut code);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        DeleteProcThreadAttributeList(list);
        DeleteAppContainerProfile(pw.as_ptr());
        FreeSid(sid);
        assert!(ok != 0, "CreateProcessW in AppContainer failed: {err}");
        code
    }
}

#[test]
fn app_container_process_cannot_open_the_pipe_but_same_user_can() {
    let name = format!(r"\\.\pipe\fail2commit-test-{}", random_hex32().unwrap());
    let ui = Arc::new(Count(AtomicUsize::new(0)));
    let server = PipeServer::start(&name, ui.clone()).unwrap();
    let cmdline = format!(r#"C:\Windows\System32\cmd.exe /c "echo x>{name}""#);

    // Positive control: an ordinary process of this user opens the pipe.
    let ok = std::process::Command::new(r"C:\Windows\System32\cmd.exe")
        .arg("/c")
        .raw_arg_for_test(&format!("echo x>{name}"))
        .status()
        .unwrap();
    assert!(ok.success(), "same-user control failed: {ok:?}");

    // Control: cmd itself runs inside the AppContainer.
    assert_eq!(
        run_in_app_container(r"C:\Windows\System32\cmd.exe /c ver"),
        0
    );
    // The redirect to the pipe fails with ERROR_ACCESS_DENIED: cmd exits 1.
    let code = run_in_app_container(&cmdline);
    assert_eq!(
        code, 1,
        "AppContainer process reached the pipe or cmd broke"
    );
    assert_eq!(ui.0.load(Ordering::SeqCst), 0, "no prompt may be shown");
    server.shutdown();
}

trait RawArgForTest {
    fn raw_arg_for_test(&mut self, s: &str) -> &mut Self;
}
impl RawArgForTest for std::process::Command {
    fn raw_arg_for_test(&mut self, s: &str) -> &mut Self {
        use std::os::windows::process::CommandExt;
        self.raw_arg(format!("\"{s}\""))
    }
}
