//! Windows Sandbox transport and lifecycle for the VM backend.

use super::super::windows::{self as appcontainer, AppContainer, ValidatedPaths};
use super::PlatformFallback;
use crate::isolation::{
    ActivityReport, JobOutcome, JobSpec, JobStatus, ProbeReport, SandboxBackend,
};
use crate::sandbox::hardened::protocol::{self, MAX_OUTCOME_BYTES};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, USEROBJECTFLAGS,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{IsProcessorFeaturePresent, PF_VIRT_FIRMWARE_ENABLED};

const BOOT_GRACE: Duration = Duration::from_secs(45);
const CONTROL_GRACE: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_CONTROL_OUTPUT: usize = 16 * 1024;
const MAX_GUEST_ID: usize = 32;
const XML_HEADER: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";

enum ProbeFailure {
    Absent(String),
    Failed(String),
}

struct ReadyHost {
    system_dir: PathBuf,
    sandbox_exe: PathBuf,
}

enum Selection {
    Ready(ReadyHost),
    Failed(String),
}

pub(super) fn selected() -> Box<dyn SandboxBackend> {
    match preflight() {
        Ok(host) => Box::new(WindowsSandbox {
            selection: Selection::Ready(host),
        }),
        Err(ProbeFailure::Absent(reason)) => Box::new(PlatformFallback::new(
            crate::sandbox::platform_backend(),
            reason,
        )),
        Err(ProbeFailure::Failed(reason)) => Box::new(WindowsSandbox {
            selection: Selection::Failed(reason),
        }),
    }
}

struct WindowsSandbox {
    selection: Selection,
}

impl SandboxBackend for WindowsSandbox {
    fn probe(&self) -> ProbeReport {
        match &self.selection {
            Selection::Ready(_) => ProbeReport {
                backend: "windows-sandbox",
                available: true,
                detail: "Windows Sandbox prerequisites and inner AppContainer probe passed".into(),
                controls: vec![
                    ("windows-sandbox-feature-enabled".into(), true),
                    ("firmware-virtualization-enabled".into(), true),
                    ("windows-sandbox-executable-trusted".into(), true),
                    ("interactive-desktop-session".into(), true),
                    ("inner-appcontainer-controls".into(), true),
                ],
            },
            Selection::Failed(reason) => unavailable(reason.clone()),
        }
    }

    fn run(&self, job: &JobSpec) -> crate::Result<JobOutcome> {
        let host = match &self.selection {
            Selection::Ready(host) => host,
            Selection::Failed(reason) => {
                return Err(crate::Error::isolation_unavailable(format!(
                    "Windows Sandbox unavailable: {reason}"
                )))
            }
        };
        run_job(host, job)
    }
}

fn unavailable(detail: String) -> ProbeReport {
    ProbeReport {
        backend: "windows-sandbox",
        available: false,
        detail,
        controls: vec![("windows-sandbox-preflight".into(), false)],
    }
}

fn preflight() -> Result<ReadyHost, ProbeFailure> {
    let system_dir = trusted_system_dir().map_err(ProbeFailure::Failed)?;
    let feature_state = query_feature_state(&system_dir).map_err(ProbeFailure::Failed)?;
    match feature_disposition(&feature_state) {
        Some(true) => {}
        Some(false) => {
            return Err(ProbeFailure::Absent(
                "Windows Sandbox optional feature is disabled".into(),
            ));
        }
        None => {
            return Err(ProbeFailure::Failed(format!(
                "Windows Sandbox feature state is not definitive: {feature_state}"
            )));
        }
    }
    if !firmware_virtualization_enabled() {
        return Err(ProbeFailure::Absent(
            "firmware virtualization is not enabled".into(),
        ));
    }
    let sandbox_exe = system_dir.join("WindowsSandbox.exe");
    let meta = fs::metadata(&sandbox_exe).map_err(|error| {
        ProbeFailure::Failed(format!(
            "Windows Sandbox feature is enabled but its trusted executable is unavailable: {error}"
        ))
    })?;
    if !meta.is_file() {
        return Err(ProbeFailure::Failed(
            "WindowsSandbox.exe is not a regular system file".into(),
        ));
    }
    if !interactive_desktop_available() {
        return Err(ProbeFailure::Failed(
            "Windows Sandbox requires an interactive desktop session".into(),
        ));
    }
    let inner = AppContainer.probe();
    if !inner.available {
        return Err(ProbeFailure::Failed(format!(
            "inner AppContainer controls failed: {}",
            inner.detail
        )));
    }
    Ok(ReadyHost {
        system_dir,
        sandbox_exe,
    })
}

#[allow(unsafe_code)]
fn firmware_virtualization_enabled() -> bool {
    // SAFETY: IsProcessorFeaturePresent takes a documented processor feature ID.
    unsafe { IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) != 0 }
}

fn query_feature_state(system_dir: &Path) -> Result<String, String> {
    let powershell = system_dir.join("WindowsPowerShell\\v1.0\\powershell.exe");
    if !powershell.is_file() {
        return Err("trusted Windows PowerShell executable is missing".into());
    }
    let script = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; try { $f=Get-CimInstance -Namespace 'root/cimv2' -ClassName Win32_OptionalFeature -Filter 'Name=\"Containers-DisposableClientVM\"'; if ($null -eq $f) { [Console]::Out.Write('Absent') } else { [Console]::Out.Write($f.InstallState) } } catch { [Console]::Error.Write($_.Exception.Message); exit 3 }";
    let mut child = Command::new(powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("query Windows Sandbox feature state: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "feature query stdout pipe is missing".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "feature query stderr pipe is missing".to_owned())?;
    // Drain both pipes while the query runs. Waiting before reading can block
    // forever when CIM emits enough diagnostics to fill either pipe.
    let stdout_reader = thread::spawn(move || read_capped(stdout, MAX_CONTROL_OUTPUT));
    let stderr_reader = thread::spawn(move || read_capped(stderr, MAX_CONTROL_OUTPUT));
    let status = match wait_child(&mut child, CONTROL_GRACE) {
        Ok(status) => status,
        Err(WaitError::TimedOut) => {
            terminate_process_tree(&mut child, system_dir).map_err(|error| {
                format!("feature query timed out and process-tree cleanup is uncertain: {error}")
            })?;
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("Windows Sandbox feature query timed out".into());
        }
        Err(WaitError::Failed(error)) => {
            terminate_process_tree(&mut child, system_dir).map_err(|cleanup| {
                format!("feature query failed ({error}) and process-tree cleanup is uncertain: {cleanup}")
            })?;
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!("Windows Sandbox feature query failed: {error}"));
        }
    };
    let (stdout, stdout_overflow) = stdout_reader
        .join()
        .map_err(|_| "feature query stdout reader failed".to_owned())??;
    let (stderr, stderr_overflow) = stderr_reader
        .join()
        .map_err(|_| "feature query stderr reader failed".to_owned())??;
    if !status.success() {
        let diagnostic = String::from_utf8_lossy(&stderr);
        return Err(format!(
            "Windows Sandbox feature state could not be queried (permission/OS query failure): {}",
            bounded_text(&diagnostic, MAX_CONTROL_OUTPUT)
        ));
    }
    if stdout_overflow || stderr_overflow {
        return Err("Windows Sandbox feature query returned oversized output".into());
    }
    let state = String::from_utf8(stdout)
        .map_err(|_| "Windows Sandbox feature query returned non-UTF-8 output".to_owned())?;
    Ok(state.trim().to_owned())
}

#[allow(unsafe_code)]
fn trusted_system_dir() -> Result<PathBuf, String> {
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: writable buffer is valid and its length fits in u32.
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 || len >= buffer.len() {
        return Err("GetSystemDirectoryW failed".into());
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len])))
}

#[allow(unsafe_code)]
fn interactive_desktop_available() -> bool {
    // SAFETY: a valid process window station handle is returned by the OS.
    let station = unsafe { GetProcessWindowStation() };
    if station.is_null() {
        return false;
    }
    let mut flags = USEROBJECTFLAGS::default();
    let mut needed = 0u32;
    // SAFETY: flags is a correctly sized writable USEROBJECTFLAGS output buffer.
    let ok = unsafe {
        GetUserObjectInformationW(
            station,
            UOI_FLAGS,
            (&mut flags as *mut USEROBJECTFLAGS).cast(),
            std::mem::size_of::<USEROBJECTFLAGS>() as u32,
            &mut needed,
        )
    };
    ok != 0 && (flags.dwFlags & 1) != 0 // WSF_VISIBLE
}

struct HostMappings {
    job_id: String,
    guest_work: PathBuf,
    entries: Vec<(PathBuf, PathBuf, bool)>,
}

fn run_job(host: &ReadyHost, job: &JobSpec) -> crate::Result<JobOutcome> {
    // The launcher process can exit before its disposable guest has stopped.
    // Until an instance-specific lifecycle proof is available, refuse before
    // creating or exposing mapped job state to WSB.
    let _ = (host, job);
    return Err(crate::Error::isolation_unavailable(
        "Windows Sandbox instance lifecycle cannot be confirmed on this host",
    ));
    #[allow(unreachable_code)]
    {
    let host_stage = appcontainer::stage_root()?;
    let validated = ValidatedPaths::new(job, &host_stage)?;
    let mappings = HostMappings::new(&host_stage, &validated)?;
    let install_exe = std::env::current_exe().map_err(|error| {
        crate::Error::isolation_unavailable(format!("resolve fail2commit executable: {error}"))
    })?;
    let install_dir = install_exe
        .canonicalize()
        .map_err(|error| {
            crate::Error::isolation_unavailable(format!("canonicalize install: {error}"))
        })?
        .parent()
        .ok_or_else(|| crate::Error::isolation_unavailable("install path has no parent"))?
        .to_path_buf();
    let install_exe = install_dir.join("fail2commit.exe");
    if !install_exe.is_file() {
        return Err(crate::Error::isolation_unavailable(
            "fail2commit.exe is missing from the trusted install directory",
        ));
    }

    let control_dir = tempfile::Builder::new()
        .prefix("f2c-vm-control-")
        .tempdir_in(&host_stage)
        .map_err(|error| {
            crate::Error::isolation_unavailable(format!("create VM control stage: {error}"))
        })?;
    let result_dir = tempfile::Builder::new()
        .prefix("f2c-vm-result-")
        .tempdir_in(&host_stage)
        .map_err(|error| {
            crate::Error::isolation_unavailable(format!("create VM result stage: {error}"))
        })?;
    let guest_job = remap_job(job, &validated, &mappings)?;
    let encoded_job = protocol::encode_job(&guest_job)?;
    write_new_file(&control_dir.path().join("job.json"), &encoded_job)?;

    let mut entries = mappings.entries.clone();
    entries.push((install_dir, PathBuf::from(r"C:\f2c\bin"), true));
    entries.push((
        control_dir.path().to_path_buf(),
        guest_control_dir(&mappings.job_id),
        true,
    ));
    entries.push((
        result_dir.path().to_path_buf(),
        guest_result_dir(&mappings.job_id),
        false,
    ));
    let config = render_wsb(&entries, job, &mappings.job_id)?;
    let config_file = tempfile::Builder::new()
        .prefix("f2c-vm-")
        .suffix(".wsb")
        .tempfile_in(&host_stage)
        .map_err(|error| {
            crate::Error::isolation_unavailable(format!("create WSB config: {error}"))
        })?;
    config_file.as_file().write_all(config.as_bytes())?;
    config_file.as_file().sync_all()?;
    let config_path = config_file.path().to_path_buf();

    // Rewalk immediately before exposing paths to Windows Sandbox, then keep
    // handles to the stage anchor, writable root, and every read-only input
    // object open until Sandbox exits. This closes the validation-to-mapping
    // replacement window without changing the platform backend contract.
    let revalidated = ValidatedPaths::new(job, &host_stage)?;
    if revalidated.identities != validated.identities {
        return Err(crate::Error::integrity(
            "staged paths changed while preparing Windows Sandbox",
        ));
    }
    let _mount_pins = revalidated.pin_vm_mounts(&host_stage)?;

    let duration = timeout_deadline(job.limits.timeout).ok_or_else(|| {
        crate::Error::isolation_unavailable("job timeout plus VM boot grace cannot be represented")
    })?;
    let deadline = Instant::now().checked_add(duration).ok_or_else(|| {
        crate::Error::isolation_unavailable("job deadline cannot be represented")
    })?;
    let mut child = Command::new(&host.sandbox_exe)
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            crate::Error::isolation_unavailable(format!("start Windows Sandbox: {error}"))
        })?;
    let exit = match wait_child_until(&mut child, deadline) {
        Ok(status) => status,
        Err(WaitError::TimedOut) => {
            terminate_process_tree(&mut child, &host.system_dir)?;
            return match read_expected_outcome(&result_dir.path().join("outcome.json")) {
                Ok(_) => Err(crate::Error::isolation_unavailable(
                    "Windows Sandbox wrote an outcome but did not shut down before its deadline",
                )),
                Err(_) => Ok(timeout_outcome()),
            };
        }
        Err(WaitError::Failed(error)) => {
            terminate_process_tree(&mut child, &host.system_dir)?;
            return Err(crate::Error::isolation_unavailable(format!(
                "wait for Windows Sandbox: {error}"
            )));
        }
    };
    if !exit.success() {
        return Err(crate::Error::isolation_unavailable(format!(
            "Windows Sandbox exited unsuccessfully: {exit}"
        )));
    }
    let outcome_path = result_dir.path().join("outcome.json");
    let outcome = read_expected_outcome(&outcome_path)?;
    Ok(outcome)
    }
}

impl HostMappings {
    fn new(stage_root: &Path, paths: &ValidatedPaths) -> crate::Result<Self> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|error| {
            crate::Error::isolation_unavailable(format!("create VM job identity: {error}"))
        })?;
        let job_id = hex::encode(id);
        let guest_stage = PathBuf::from(r"C:\f2c\cache\sandbox-stage").join(&job_id);
        let guest_work = guest_stage.join("work");
        let mut entries = Vec::new();
        for (index, input) in paths.read_only.iter().enumerate() {
            if !input.is_dir() {
                return Err(crate::Error::isolation_unavailable(
                    "Windows Sandbox read-only inputs must be staged directories",
                ));
            }
            entries.push((
                input.clone(),
                guest_stage.join(format!("input-{index}")),
                true,
            ));
        }
        entries.push((paths.work_dir.clone(), guest_work.clone(), false));
        if !path_under(
            &guest_stage,
            PathBuf::from(r"C:\f2c\cache\sandbox-stage").as_path(),
        ) {
            return Err(crate::Error::integrity(
                "invalid generated guest stage root",
            ));
        }
        if !path_under(&paths.work_dir, stage_root) {
            return Err(crate::Error::isolation_unavailable(
                "VM writable directory escaped the validated host stage",
            ));
        }
        Ok(Self {
            job_id,
            guest_work,
            entries,
        })
    }
}

fn remap_job(
    job: &JobSpec,
    paths: &ValidatedPaths,
    mappings: &HostMappings,
) -> crate::Result<JobSpec> {
    let guest_path = |path: &Path| -> crate::Result<PathBuf> {
        let source = path.canonicalize().map_err(|error| {
            crate::Error::isolation_unavailable(format!("canonicalize job path: {error}"))
        })?;
        for (host, guest, _) in &mappings.entries {
            if path_under(&source, host) {
                let relative = source.strip_prefix(host).map_err(|_| {
                    crate::Error::integrity("canonical job path prefix changed during VM staging")
                })?;
                return Ok(guest.join(relative));
            }
        }
        Err(crate::Error::isolation_unavailable(format!(
            "job path is outside its assigned VM mounts: {}",
            path.display()
        )))
    };
    let translate_text = |value: &std::ffi::OsStr| -> crate::Result<OsString> {
        let mut text = value
            .to_str()
            .ok_or_else(|| {
                crate::Error::isolation_unavailable(
                    "VM job has a non-UTF-8 argument or environment value",
                )
            })?
            .to_owned();
        if let Some(system_root) = job
            .env
            .iter()
            .find(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case("SystemRoot"))
            .and_then(|(_, value)| value.to_str())
        {
            text = replace_path_text(&text, system_root, r"C:\Windows");
        }
        for (host, guest, _) in &mappings.entries {
            let old = wsb_host_path(host)?.to_string_lossy().into_owned();
            let new = guest.to_string_lossy();
            text = replace_path_text(&text, &old, new.as_ref());
            let canonical = host.to_string_lossy();
            text = replace_path_text(&text, canonical.as_ref(), new.as_ref());
        }
        Ok(text.into())
    };
    let env = job
        .env
        .iter()
        .map(|(key, value)| Ok((translate_text(key)?, translate_text(value)?)))
        .collect::<crate::Result<Vec<_>>>()?;
    Ok(JobSpec {
        program: guest_path(&paths.program)?,
        args: job
            .args
            .iter()
            .map(|arg| translate_text(arg))
            .collect::<crate::Result<_>>()?,
        cwd: guest_path(&paths.cwd)?,
        env,
        read_only: paths
            .read_only
            .iter()
            .map(|p| guest_path(p))
            .collect::<crate::Result<_>>()?,
        work_dir: mappings.guest_work.clone(),
        exports: job.exports.clone(),
        export_to: None,
        limits: job.limits.clone(),
        network: job.network,
        bait: job.bait,
    })
}

fn render_wsb(
    mappings: &[(PathBuf, PathBuf, bool)],
    job: &JobSpec,
    job_id: &str,
) -> crate::Result<String> {
    if !valid_job_id(job_id) {
        return Err(crate::Error::integrity("invalid VM job identity"));
    }
    let mut xml = String::from(XML_HEADER);
    xml.push_str("\n<Configuration>\n<Networking>");
    xml.push_str(if job.network == crate::isolation::NetworkMode::Internet {
        "Enable"
    } else {
        "Disable"
    });
    xml.push_str("</Networking>\n<vGPU>Disable</vGPU>\n");
    if let Some(memory) = job.limits.memory_bytes {
        let mib = memory
            .saturating_add(512 * 1024 * 1024)
            .div_ceil(1024 * 1024);
        let mib = u32::try_from(mib)
            .map_err(|_| crate::Error::isolation_unavailable("VM memory limit is out of range"))?;
        xml.push_str(&format!("<MemoryInMB>{mib}</MemoryInMB>\n"));
    }
    xml.push_str("<MappedFolders>\n");
    for (host, guest, read_only) in mappings {
        let canonical_host = host.canonicalize().map_err(|error| {
            crate::Error::isolation_unavailable(format!(
                "canonicalize VM mapped folder {}: {error}",
                host.display()
            ))
        })?;
        if !canonical_host.is_dir() || !guest.is_absolute() || !same_path(&canonical_host, host) {
            return Err(crate::Error::isolation_unavailable(
                "WSB mapped folder identity changed after validation",
            ));
        }
        xml.push_str("<MappedFolder><HostFolder>");
        let host_for_xml = wsb_host_path(&canonical_host)?;
        xml.push_str(&escape_xml(&host_for_xml.to_string_lossy()));
        xml.push_str("</HostFolder><SandboxFolder>");
        xml.push_str(&escape_xml(&guest.to_string_lossy()));
        xml.push_str("</SandboxFolder><ReadOnly>");
        xml.push_str(if *read_only { "true" } else { "false" });
        xml.push_str("</ReadOnly></MappedFolder>\n");
    }
    xml.push_str("</MappedFolders>\n<LogonCommand><Command>");
    let script = logon_powershell_script(job_id)?;
    let encoded = base64_utf16(&script);
    let ps = Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
    let command = format!(
        "\"{}\" -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}",
        ps.display()
    );
    xml.push_str(&escape_xml(&command));
    xml.push_str("</Command></LogonCommand>\n</Configuration>\n");
    Ok(xml)
}

fn logon_powershell_script(job_id: &str) -> crate::Result<String> {
    if !valid_job_id(job_id) {
        return Err(crate::Error::integrity("invalid VM job identity"));
    }
    let id = job_id;
    let guest_job = format!(r"C:\f2c\control\{id}\job.json");
    let guest_exe = r"C:\f2c\bin\fail2commit.exe";
    Ok(format!(
        "$rc=70; try {{ & '{guest_exe}' sandbox launch '{guest_job}' --vm-guest; $rc=$LASTEXITCODE }} catch {{ $rc=70 }}; try {{ & \"$env:SystemRoot\\System32\\shutdown.exe\" /s /t 0; if ($LASTEXITCODE -ne 0) {{ $rc=70 }} }} catch {{ $rc=70 }}; exit $rc"
    ))
}

fn wsb_host_path(canonical: &Path) -> crate::Result<PathBuf> {
    let text = canonical.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return Ok(PathBuf::from(format!(r"\\{rest}")));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return Ok(PathBuf::from(rest));
    }
    if text.starts_with(r"\Device\") {
        return Err(crate::Error::isolation_unavailable(
            "WSB cannot map a device namespace path",
        ));
    }
    Ok(canonical.to_path_buf())
}

fn replace_path_text(value: &str, source: &str, replacement: &str) -> String {
    if source.is_empty() {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len());
    let mut cursor = 0usize;
    while cursor < value.len() {
        let found = value[cursor..].char_indices().find_map(|(relative, _)| {
            let start = cursor + relative;
            let end = start.checked_add(source.len())?;
            if end > value.len()
                || !value.is_char_boundary(end)
                || !value[start..end].eq_ignore_ascii_case(source)
            {
                return None;
            }
            let after = value[end..].chars().next();
            let boundary = after.is_none_or(|ch| {
                ch.is_whitespace()
                    || matches!(ch, '\\' | '/' | ';' | '\'' | '"' | ',' | ')' | ']' | '=')
            });
            boundary.then_some((start, end))
        });
        let Some((start, end)) = found else {
            out.push_str(&value[cursor..]);
            break;
        };
        out.push_str(&value[cursor..start]);
        out.push_str(replacement);
        cursor = end;
    }
    out
}

fn guest_control_dir(job_id: &str) -> PathBuf {
    PathBuf::from(r"C:\f2c\control").join(job_id)
}

fn guest_result_dir(job_id: &str) -> PathBuf {
    PathBuf::from(r"C:\f2c\result").join(job_id)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> crate::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            crate::Error::isolation_unavailable(format!("create VM job file: {error}"))
        })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_expected_outcome(path: &Path) -> crate::Result<JobOutcome> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    let file = options.open(path).map_err(|error| {
        crate::Error::isolation_unavailable(format!("VM outcome is missing or unreadable: {error}"))
    })?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_OUTCOME_BYTES as u64 {
        return Err(crate::Error::integrity(
            "VM outcome is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_OUTCOME_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| crate::Error::integrity(format!("read VM outcome: {error}")))?;
    if bytes.len() as u64 != meta.len() {
        return Err(crate::Error::integrity(
            "VM outcome changed during bounded read",
        ));
    }
    protocol::decode_outcome(&bytes)
}

enum WaitError {
    TimedOut,
    Failed(String),
}

fn wait_child(child: &mut Child, timeout: Duration) -> Result<ExitStatus, WaitError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| WaitError::Failed("timeout cannot be represented".into()))?;
    wait_child_until(child, deadline)
}

fn wait_child_until(child: &mut Child, deadline: Instant) -> Result<ExitStatus, WaitError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => return Err(WaitError::TimedOut),
            Err(error) => return Err(WaitError::Failed(error.to_string())),
        }
    }
}

fn read_capped(mut reader: impl Read, cap: usize) -> Result<(Vec<u8>, bool), String> {
    let mut kept = Vec::with_capacity(cap.min(4096));
    let mut overflow = false;
    let mut buffer = [0u8; 4096];
    loop {
        let count = reader.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        let remaining = cap.saturating_sub(kept.len());
        let take = remaining.min(count);
        kept.extend_from_slice(&buffer[..take]);
        overflow |= take != count;
    }
    Ok((kept, overflow))
}

fn terminate_process_tree(child: &mut Child, system_dir: &Path) -> crate::Result<()> {
    let pid = child.id();
    let taskkill = system_dir.join("taskkill.exe");
    let mut killer = Command::new(taskkill)
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            crate::Error::isolation_unavailable(format!("start VM process-tree cleanup: {error}"))
        })?;
    let kill_status = wait_child(&mut killer, CONTROL_GRACE).map_err(|error| {
        let _ = killer.kill();
        let _ = killer.wait();
        crate::Error::isolation_unavailable(format!(
            "VM process-tree cleanup did not complete: {}",
            wait_error(error)
        ))
    })?;
    let wait = wait_child(child, CONTROL_GRACE);
    match wait {
        Ok(_) => {}
        Err(_) => {
            child.kill().map_err(|error| {
                crate::Error::isolation_unavailable(format!(
                    "kill VM launcher after tree cleanup: {error}"
                ))
            })?;
            child.wait().map_err(|error| {
                crate::Error::isolation_unavailable(format!(
                    "wait for VM launcher after kill: {error}"
                ))
            })?;
            return Err(crate::Error::isolation_unavailable(
                "Windows Sandbox process tree did not stop cleanly",
            ));
        }
    }
    if !kill_status.success() {
        return Err(crate::Error::isolation_unavailable(format!(
            "taskkill could not confirm Windows Sandbox process-tree termination: {kill_status}"
        )));
    }
    Ok(())
}

fn wait_error(error: WaitError) -> String {
    match error {
        WaitError::TimedOut => "timed out".into(),
        WaitError::Failed(error) => error,
    }
}

fn timeout_outcome() -> JobOutcome {
    JobOutcome {
        status: JobStatus::TimedOut,
        stdout: vec![],
        stderr: b"Windows Sandbox job exceeded its deadline and the VM was terminated".to_vec(),
        truncated: false,
        exported: vec![],
        report: ActivityReport::default(),
    }
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn base64_utf16(value: &str) -> String {
    let bytes = value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn valid_job_id(id: &str) -> bool {
    id.len() == MAX_GUEST_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn bounded_text(text: &str, cap: usize) -> String {
    text.chars().take(cap).collect()
}

fn path_under(child: &Path, parent: &Path) -> bool {
    let mut child = child.components();
    let mut parent = parent.components();
    loop {
        match (child.next(), parent.next()) {
            (_, None) => return true,
            (Some(a), Some(b))
                if a.as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy()) => {}
            _ => return false,
        }
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    let left = strip_windows_device_prefix(left);
    let right = strip_windows_device_prefix(right);
    path_under(&left, &right) && path_under(&right, &left)
}

fn strip_windows_device_prefix(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

fn timeout_deadline(timeout: Duration) -> Option<Duration> {
    timeout.checked_add(BOOT_GRACE)
}

#[cfg(test)]
mod lifecycle_gate_tests {
    use super::*;

    #[test]
    fn deadlines_are_rejected_before_a_vm_can_be_spawned() {
        assert!(timeout_deadline(Duration::MAX).is_none());
        assert!(Instant::now().checked_add(Duration::MAX).is_none());
    }

    #[test]
    fn feature_query_output_is_drained_and_capped() {
        let (bytes, overflow) = read_capped(&b"enabled"[..], 16).unwrap();
        assert_eq!(bytes, b"enabled");
        assert!(!overflow);
        let (bytes, overflow) = read_capped(&b"0123456789"[..], 4).unwrap();
        assert_eq!(bytes, b"0123");
        assert!(overflow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> JobSpec {
        JobSpec {
            program: PathBuf::from(r"C:\stage\job\input\tool.exe"),
            args: vec!["--ok".into()],
            cwd: PathBuf::from(r"C:\stage\job\work"),
            env: vec![],
            read_only: vec![PathBuf::from(r"C:\stage\job\input")],
            work_dir: PathBuf::from(r"C:\stage\job\work"),
            exports: vec![],
            export_to: None,
            limits: crate::isolation::JobLimits {
                timeout: Duration::from_secs(10),
                memory_bytes: Some(256 * 1024 * 1024),
                max_processes: Some(8),
                max_output_bytes: 4096,
                disk_bytes: Some(1024 * 1024),
            },
            network: crate::isolation::NetworkMode::None,
            bait: true,
        }
    }

    #[test]
    fn xml_escapes_paths_and_keeps_only_explicit_mapping_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("tools & stuff");
        let work = tmp.path().join("work");
        let install = tmp.path().join("install");
        let control = tmp.path().join("control");
        let result = tmp.path().join("result");
        for path in [&source, &work, &install, &control, &result] {
            fs::create_dir(path).unwrap();
        }
        let id = "0123456789abcdef0123456789abcdef";
        let maps = vec![
            (
                source.clone(),
                PathBuf::from(r"C:\f2c\cache\sandbox-stage")
                    .join(id)
                    .join("input-0"),
                true,
            ),
            (
                work,
                PathBuf::from(r"C:\f2c\cache\sandbox-stage")
                    .join(id)
                    .join("work"),
                false,
            ),
            (install, PathBuf::from(r"C:\f2c\bin"), true),
            (control, PathBuf::from(r"C:\f2c\control").join(id), true),
            (result, PathBuf::from(r"C:\f2c\result").join(id), false),
        ];
        let xml = render_wsb(&maps, &job(), id).unwrap();
        assert!(xml.contains("tools &amp; stuff"));
        assert!(xml.contains("<ReadOnly>true</ReadOnly>"));
        assert!(xml.contains("<ReadOnly>false</ReadOnly>"));
        assert!(xml.contains("<Networking>Disable</Networking>"));
        assert!(xml.contains("<MemoryInMB>768</MemoryInMB>"));
        assert!(xml.contains(r"C:\f2c\control\0123456789abcdef0123456789abcdef"));
        assert!(xml.contains(r"C:\f2c\result\0123456789abcdef0123456789abcdef"));
        assert!(xml.contains("-EncodedCommand"));
        let finalizer = logon_powershell_script(id).unwrap();
        assert!(finalizer.contains("shutdown.exe"));
        assert!(finalizer.contains("catch { $rc=70 }"));
        assert!(!xml.contains("<HostFolder>C:\\host\\stage"));
    }

    #[test]
    fn generated_wsb_rejects_untrusted_job_identity() {
        let error = render_wsb(&[], &job(), "bad/id");
        assert!(error.is_err());
        assert_eq!(
            timeout_deadline(Duration::from_secs(10)),
            Some(Duration::from_secs(55))
        );
    }

    #[test]
    fn outcome_reader_rejects_missing_and_oversized_or_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outcome.json");
        assert!(read_expected_outcome(&path).is_err());
        fs::write(&path, vec![b'x'; MAX_OUTCOME_BYTES + 1]).unwrap();
        assert!(read_expected_outcome(&path).is_err());
    }

    #[test]
    fn outcome_reader_accepts_only_bounded_successful_transport() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outcome.json");
        let value = JobOutcome {
            status: JobStatus::Exited(0),
            stdout: b"ok".to_vec(),
            stderr: vec![],
            truncated: false,
            exported: vec![],
            report: ActivityReport::default(),
        };
        fs::write(&path, protocol::encode_outcome(&value).unwrap()).unwrap();
        assert_eq!(read_expected_outcome(&path).unwrap(), value);
        let forged = fs::read_to_string(&path)
            .unwrap()
            .replace("\"exported\":[]", "\"exported\":[\"host.txt\"]");
        fs::write(&path, forged).unwrap();
        assert!(read_expected_outcome(&path).is_err());
    }

    #[test]
    fn remapped_job_contains_only_guest_stage_paths_and_preserves_job_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("input");
        let work = tmp.path().join("work");
        fs::create_dir(&input).unwrap();
        fs::create_dir(&work).unwrap();
        fs::write(input.join("tool.exe"), b"stub").unwrap();
        let input = input.canonicalize().unwrap();
        let work = work.canonicalize().unwrap();
        let paths = ValidatedPaths {
            program: input.join("tool.exe"),
            cwd: work.clone(),
            read_only: vec![input.clone()],
            work_dir: work.clone(),
            identities: vec![],
        };
        let id = "0123456789abcdef0123456789abcdef".to_owned();
        let guest_input = PathBuf::from(r"C:\f2c\cache\sandbox-stage")
            .join(&id)
            .join("input-0");
        let guest_work = PathBuf::from(r"C:\f2c\cache\sandbox-stage")
            .join(&id)
            .join("work");
        let mappings = HostMappings {
            job_id: id.clone(),
            guest_work: guest_work.clone(),
            entries: vec![
                (input.clone(), guest_input.clone(), true),
                (work.clone(), guest_work.clone(), false),
            ],
        };
        let mut host_job = job();
        host_job.program = paths.program.clone();
        host_job.cwd = paths.cwd.clone();
        host_job.work_dir = paths.work_dir.clone();
        host_job.read_only = paths.read_only.clone();
        host_job.args = vec![format!("--src={}", input.join("tool.exe").display()).into()];
        host_job.env = vec![(
            "PATH".into(),
            format!("{};C:\\Windows\\System32", input.display()).into(),
        )];
        let guest = remap_job(&host_job, &paths, &mappings).unwrap();
        assert_eq!(guest.program, guest_input.join("tool.exe"));
        assert_eq!(guest.work_dir, guest_work);
        assert_eq!(guest.export_to, None);
        assert!(!guest.args[0]
            .to_string_lossy()
            .contains(&input.to_string_lossy().to_string()));
        assert!(!guest.env[0]
            .1
            .to_string_lossy()
            .contains(&input.to_string_lossy().to_string()));
        assert!(guest.args[0].to_string_lossy().contains(&id));
    }

    #[test]
    fn known_absence_is_distinct_from_unknown_state() {
        assert_eq!(feature_disposition("Disabled"), Some(false));
        assert_eq!(feature_disposition("Enabled"), Some(true));
        assert_eq!(feature_disposition("EnablePending"), None);
    }
}

fn feature_disposition(state: &str) -> Option<bool> {
    match state {
        "Enabled" | "1" => Some(true),
        // WMI InstallState: disabled or absent. Neither provides the optional
        // Windows Sandbox feature required by this backend.
        "Disabled" | "DisabledWithPayloadRemoved" | "Absent" | "2" | "3" => Some(false),
        _ => None,
    }
}
