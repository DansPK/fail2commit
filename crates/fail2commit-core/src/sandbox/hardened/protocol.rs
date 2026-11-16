//! Bounded JSON wire formats for the hardened launcher (SPEC-018 §2, §6).
//!
//! The platform service never parses these records. Only the user CLI writes
//! `job.json`; the authenticated launcher reads it and writes `outcome.json`.

use crate::isolation::{ActivityReport, JobLimits, JobOutcome, JobSpec, JobStatus, NetworkMode};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MAX_JOB_BYTES: usize = 1024 * 1024;
pub const MAX_OUTCOME_BYTES: usize = 2 * 1024 * 1024;
/// The VM envelope base64-expands the frozen outcome payload and adds identity.
pub const MAX_VM_OUTCOME_BYTES: usize = MAX_OUTCOME_BYTES * 4 / 3 + 1024;
const MAX_STREAM_BYTES: usize = 768 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobFile {
    program: String,
    args: Vec<String>,
    cwd: String,
    env: Vec<(String, String)>,
    read_only: Vec<String>,
    work_dir: String,
    exports: Vec<String>,
    export_to: Option<String>,
    timeout_ms: u64,
    memory_bytes: Option<u64>,
    max_processes: Option<u32>,
    max_output_bytes: u64,
    disk_bytes: Option<u64>,
    network: NetworkMode,
    bait: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HardenedJobFile {
    version: u32,
    stage_root: String,
    job: JobFile,
    #[serde(default)]
    test_diagnostic: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeFile {
    status: JobStatus,
    stdout_b64: String,
    stderr_b64: String,
    truncated: bool,
    exported: Vec<String>,
    report: ActivityReport,
}

/// Additive VM transport: binds the frozen outcome payload to the fresh job
/// identity assigned by the host. The inner `JobOutcome` wire contract is
/// unchanged; the envelope only authenticates which run produced it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VmOutcomeFile {
    version: u32,
    job_id: String,
    payload_b64: String,
}

impl TryFrom<&JobSpec> for JobFile {
    type Error = crate::Error;

    fn try_from(job: &JobSpec) -> crate::Result<Self> {
        fn utf8(path: &Path) -> crate::Result<String> {
            path.to_str()
                .map(str::to_owned)
                .ok_or_else(|| crate::Error::isolation_unavailable("job contains a non-UTF-8 path"))
        }
        fn text(value: &std::ffi::OsStr) -> crate::Result<String> {
            value.to_str().map(str::to_owned).ok_or_else(|| {
                crate::Error::isolation_unavailable(
                    "job contains a non-UTF-8 argument or environment value",
                )
            })
        }
        let duration_ms = job.limits.timeout.as_millis();
        let timeout_ms = u64::try_from(duration_ms).map_err(|_| {
            crate::Error::isolation_unavailable("job timeout cannot be represented on the wire")
        })?;
        Ok(Self {
            program: utf8(&job.program)?,
            args: job
                .args
                .iter()
                .map(|s| text(s))
                .collect::<crate::Result<_>>()?,
            cwd: utf8(&job.cwd)?,
            env: job
                .env
                .iter()
                .map(|(k, v)| Ok((text(k)?, text(v)?)))
                .collect::<crate::Result<_>>()?,
            read_only: job
                .read_only
                .iter()
                .map(|p| utf8(p))
                .collect::<crate::Result<_>>()?,
            work_dir: utf8(&job.work_dir)?,
            exports: job
                .exports
                .iter()
                .map(|p| utf8(p))
                .collect::<crate::Result<_>>()?,
            export_to: job.export_to.as_deref().map(utf8).transpose()?,
            timeout_ms,
            memory_bytes: job.limits.memory_bytes,
            max_processes: job.limits.max_processes,
            max_output_bytes: job.limits.max_output_bytes,
            disk_bytes: job.limits.disk_bytes,
            network: job.network,
            bait: job.bait,
        })
    }
}

impl TryFrom<JobFile> for JobSpec {
    type Error = crate::Error;

    fn try_from(j: JobFile) -> crate::Result<Self> {
        let duration = Duration::from_millis(j.timeout_ms);
        if duration.as_millis() != u128::from(j.timeout_ms) {
            return Err(crate::Error::invalid("job timeout is out of range"));
        }
        Ok(Self {
            program: PathBuf::from(j.program),
            args: j.args.into_iter().map(OsString::from).collect(),
            cwd: PathBuf::from(j.cwd),
            env: j
                .env
                .into_iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v)))
                .collect(),
            read_only: j.read_only.into_iter().map(PathBuf::from).collect(),
            work_dir: PathBuf::from(j.work_dir),
            exports: j.exports.into_iter().map(PathBuf::from).collect(),
            export_to: j.export_to.map(PathBuf::from),
            limits: JobLimits {
                timeout: duration,
                memory_bytes: j.memory_bytes,
                max_processes: j.max_processes,
                max_output_bytes: j.max_output_bytes,
                disk_bytes: j.disk_bytes,
            },
            network: j.network,
            bait: j.bait,
        })
    }
}

pub fn encode_job(job: &JobSpec) -> crate::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&JobFile::try_from(job)?).map_err(|e| {
        crate::Error::isolation_unavailable(format!("job serialization failed: {e}"))
    })?;
    if bytes.len() > MAX_JOB_BYTES {
        return Err(crate::Error::isolation_unavailable(
            "job file exceeds size limit",
        ));
    }
    Ok(bytes)
}

pub fn decode_job(bytes: &[u8]) -> crate::Result<JobSpec> {
    if bytes.len() > MAX_JOB_BYTES {
        return Err(crate::Error::invalid("job file exceeds size limit"));
    }
    let wire: JobFile = serde_json::from_slice(bytes)
        .map_err(|e| crate::Error::invalid(format!("invalid job file: {e}")))?;
    JobSpec::try_from(wire)
}

/// Validate that every filesystem path in a decoded VM guest request refers
/// only to the guest's assigned mounts. The outer VM may share read-only input
/// mounts and one writable work mount; arbitrary host paths are forbidden.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn validate_vm_guest_job(
    job: &JobSpec,
    guest_work: &Path,
    guest_mounts: &[PathBuf],
) -> crate::Result<()> {
    if !guest_work.is_absolute() || job.export_to.is_some() || guest_mounts.is_empty() {
        return Err(crate::Error::integrity("invalid VM guest path envelope"));
    }
    let clean_absolute = |path: &Path| {
        path.is_absolute()
            && !path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
    };
    let inside = |path: &Path| {
        clean_absolute(path)
            && guest_mounts
                .iter()
                .any(|mount| clean_absolute(mount) && (path == mount || path.starts_with(mount)))
    };
    if !clean_absolute(guest_work)
        || job.work_dir != guest_work
        || !inside(&job.program)
        || !inside(&job.cwd)
        || !inside(&job.work_dir)
        || job.read_only.iter().any(|p| !inside(p))
    {
        return Err(crate::Error::integrity(
            "VM guest job contains a path outside its assigned mounts",
        ));
    }
    Ok(())
}

/// Bind the frozen outcome transport to a fresh VM job identity without
/// changing the `JobOutcome` wire contract used by the hardened launcher.
pub fn encode_vm_outcome(job_id: &str, outcome: &JobOutcome) -> crate::Result<Vec<u8>> {
    if !valid_vm_job_id(job_id) {
        return Err(crate::Error::integrity("invalid VM outcome identity"));
    }
    use base64::Engine;
    let payload = encode_outcome(outcome)?;
    let wire = VmOutcomeFile {
        version: 1,
        job_id: job_id.to_owned(),
        payload_b64: base64::engine::general_purpose::STANDARD.encode(payload),
    };
    let bytes = serde_json::to_vec(&wire).map_err(|error| {
        crate::Error::internal(format!("VM outcome serialization failed: {error}"))
    })?;
    if bytes.len() > MAX_VM_OUTCOME_BYTES {
        return Err(crate::Error::isolation_unavailable(
            "VM outcome envelope exceeds size limit",
        ));
    }
    Ok(bytes)
}

/// Decode only an outcome carrying the identity assigned to this VM run. A
/// stale, forged or missing identity is rejected before the payload is parsed.
pub fn decode_vm_outcome(job_id: &str, bytes: &[u8]) -> crate::Result<JobOutcome> {
    if !valid_vm_job_id(job_id) || bytes.len() > MAX_VM_OUTCOME_BYTES {
        return Err(crate::Error::integrity(
            "VM outcome envelope is invalid or oversized",
        ));
    }
    use base64::Engine;
    let wire: VmOutcomeFile = serde_json::from_slice(bytes).map_err(|error| {
        crate::Error::integrity(format!("invalid VM outcome envelope: {error}"))
    })?;
    if wire.version != 1 || wire.job_id != job_id {
        return Err(crate::Error::integrity(
            "VM outcome does not match the active job identity",
        ));
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(wire.payload_b64)
        .map_err(|_| crate::Error::integrity("invalid VM outcome payload encoding"))?;
    decode_outcome(&payload)
}

fn valid_vm_job_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Private launcher envelope; the public JobSpec and backend APIs are unchanged.
pub fn encode_hardened_job(job: &JobSpec, stage_root: &Path) -> crate::Result<Vec<u8>> {
    if !stage_root.is_absolute() {
        return Err(crate::Error::isolation_unavailable(
            "hardened stage root must be absolute",
        ));
    }
    let stage_root = stage_root.to_str().ok_or_else(|| {
        crate::Error::isolation_unavailable("hardened stage root is not valid UTF-8")
    })?;
    let envelope = HardenedJobFile {
        version: 1,
        stage_root: stage_root.to_owned(),
        job: JobFile::try_from(job)?,
        test_diagnostic: false,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|e| {
        crate::Error::isolation_unavailable(format!("hardened job serialization failed: {e}"))
    })?;
    if bytes.len() > MAX_JOB_BYTES {
        return Err(crate::Error::isolation_unavailable(
            "hardened job envelope exceeds size limit",
        ));
    }
    Ok(bytes)
}

pub fn decode_hardened_job(bytes: &[u8]) -> crate::Result<(JobSpec, PathBuf)> {
    let (job, stage_root, test_diagnostic) = decode_hardened_job_mode(bytes)?;
    if test_diagnostic {
        return Err(crate::Error::rejected(
            "test diagnostic job envelopes are unavailable in this build",
        ));
    }
    Ok((job, stage_root))
}

fn decode_hardened_job_mode(bytes: &[u8]) -> crate::Result<(JobSpec, PathBuf, bool)> {
    if bytes.len() > MAX_JOB_BYTES {
        return Err(crate::Error::invalid(
            "hardened job envelope exceeds size limit",
        ));
    }
    let envelope: HardenedJobFile = serde_json::from_slice(bytes)
        .map_err(|e| crate::Error::invalid(format!("invalid hardened job envelope: {e}")))?;
    if envelope.version != 1 || !Path::new(&envelope.stage_root).is_absolute() {
        return Err(crate::Error::integrity(
            "hardened job envelope has an invalid stage identity",
        ));
    }
    Ok((
        JobSpec::try_from(envelope.job)?,
        PathBuf::from(envelope.stage_root),
        envelope.test_diagnostic,
    ))
}

#[cfg(all(feature = "hardened-test-diagnostics", debug_assertions))]
pub fn encode_hardened_diagnostic_job(job: &JobSpec, stage_root: &Path) -> crate::Result<Vec<u8>> {
    if job.network != NetworkMode::None || !stage_root.is_absolute() {
        return Err(crate::Error::rejected(
            "test diagnostic jobs require absolute stage roots and network mode none",
        ));
    }
    let stage_root = stage_root.to_str().ok_or_else(|| {
        crate::Error::isolation_unavailable("hardened stage root is not valid UTF-8")
    })?;
    let envelope = HardenedJobFile {
        version: 1,
        stage_root: stage_root.to_owned(),
        job: JobFile::try_from(job)?,
        test_diagnostic: true,
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| crate::Error::internal(format!("encode test diagnostic job: {error}")))?;
    if bytes.len() > MAX_JOB_BYTES {
        return Err(crate::Error::rejected(
            "test diagnostic job envelope exceeds size limit",
        ));
    }
    Ok(bytes)
}

pub(crate) fn decode_hardened_job_for_service(
    bytes: &[u8],
) -> crate::Result<(JobSpec, PathBuf, bool)> {
    let (job, root, test_diagnostic) = decode_hardened_job_mode(bytes)?;
    if test_diagnostic && !cfg!(all(feature = "hardened-test-diagnostics", debug_assertions)) {
        return Err(crate::Error::rejected(
            "test diagnostic job envelopes are unavailable in this build",
        ));
    }
    Ok((job, root, test_diagnostic))
}

pub fn encode_outcome(outcome: &JobOutcome) -> crate::Result<Vec<u8>> {
    use base64::Engine;
    if outcome.stdout.len() > MAX_STREAM_BYTES || outcome.stderr.len() > MAX_STREAM_BYTES {
        return Err(crate::Error::isolation_unavailable(
            "job output exceeds wire limit",
        ));
    }
    let wire = OutcomeFile {
        status: outcome.status.clone(),
        stdout_b64: base64::engine::general_purpose::STANDARD.encode(&outcome.stdout),
        stderr_b64: base64::engine::general_purpose::STANDARD.encode(&outcome.stderr),
        truncated: outcome.truncated,
        exported: Vec::new(),
        report: outcome.report.clone(),
    };
    let bytes = serde_json::to_vec(&wire)
        .map_err(|e| crate::Error::internal(format!("outcome serialization failed: {e}")))?;
    if bytes.len() > MAX_OUTCOME_BYTES {
        return Err(crate::Error::isolation_unavailable(
            "outcome file exceeds size limit",
        ));
    }
    Ok(bytes)
}

pub fn decode_outcome(bytes: &[u8]) -> crate::Result<JobOutcome> {
    use base64::Engine;
    if bytes.len() > MAX_OUTCOME_BYTES {
        return Err(crate::Error::integrity("outcome file exceeds size limit"));
    }
    let wire: OutcomeFile = serde_json::from_slice(bytes)
        .map_err(|e| crate::Error::integrity(format!("invalid outcome file: {e}")))?;
    if !wire.exported.is_empty() {
        return Err(crate::Error::integrity(
            "backend outcome may not export files",
        ));
    }
    let stdout = base64::engine::general_purpose::STANDARD
        .decode(wire.stdout_b64)
        .map_err(|_| crate::Error::integrity("invalid stdout encoding"))?;
    let stderr = base64::engine::general_purpose::STANDARD
        .decode(wire.stderr_b64)
        .map_err(|_| crate::Error::integrity("invalid stderr encoding"))?;
    if stdout.len() > MAX_STREAM_BYTES || stderr.len() > MAX_STREAM_BYTES {
        return Err(crate::Error::integrity("outcome stream exceeds size limit"));
    }
    if wire.report.events.len() > crate::isolation::MAX_ACTIVITY {
        return Err(crate::Error::integrity(
            "outcome activity exceeds size limit",
        ));
    }
    Ok(JobOutcome {
        status: wire.status,
        stdout,
        stderr,
        truncated: wire.truncated,
        exported: Vec::new(),
        report: wire.report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::{ActivityReport, JobLimits, JobOutcome};

    #[cfg(windows)]
    fn job() -> JobSpec {
        JobSpec {
            program: PathBuf::from("C:\\work\\tool.exe"),
            args: vec!["--version".into()],
            cwd: PathBuf::from("C:\\work\\job"),
            env: vec![("PATH".into(), "C:\\work".into())],
            read_only: vec![PathBuf::from("C:\\work\\stage\\input")],
            work_dir: PathBuf::from("C:\\work\\stage\\job"),
            exports: Vec::new(),
            export_to: None,
            limits: JobLimits {
                timeout: Duration::from_secs(20),
                memory_bytes: Some(128 * 1024 * 1024),
                max_processes: Some(8),
                max_output_bytes: 64 * 1024,
                disk_bytes: Some(256 * 1024 * 1024),
            },
            network: NetworkMode::None,
            bait: true,
        }
    }

    fn outcome() -> JobOutcome {
        JobOutcome {
            status: JobStatus::Exited(0),
            stdout: vec![0, 255],
            stderr: b"err".to_vec(),
            truncated: false,
            exported: Vec::new(),
            report: ActivityReport::default(),
        }
    }

    #[test]
    fn outcome_round_trip_keeps_arbitrary_output_bytes() {
        let encoded = encode_outcome(&outcome()).unwrap();
        let decoded = decode_outcome(&encoded).unwrap();
        assert_eq!(decoded.stdout, vec![0, 255]);
        assert_eq!(decoded.stderr, b"err");
        assert!(decoded.exported.is_empty());
    }

    #[test]
    fn outcome_rejects_export_claims_and_oversize() {
        let mut encoded = encode_outcome(&outcome()).unwrap();
        let raw = String::from_utf8(encoded.clone())
            .unwrap()
            .replace("\"exported\":[]", "\"exported\":[\"x\"]");
        assert!(decode_outcome(raw.as_bytes()).is_err());
        encoded.resize(MAX_OUTCOME_BYTES + 1, b' ');
        assert!(decode_outcome(&encoded).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn vm_guest_paths_are_limited_to_clean_assigned_mounts() {
        let mut guest = job();
        guest.program = PathBuf::from(r"C:\f2c\bin\tool.exe");
        guest.cwd = PathBuf::from(r"C:\f2c\work\job");
        guest.work_dir = PathBuf::from(r"C:\f2c\work");
        guest.read_only = vec![PathBuf::from(r"C:\f2c\in\0")];
        let mounts = vec![
            PathBuf::from(r"C:\f2c\bin"),
            PathBuf::from(r"C:\f2c\in"),
            PathBuf::from(r"C:\f2c\work"),
        ];
        assert!(validate_vm_guest_job(&guest, &guest.work_dir, &mounts).is_ok());

        guest.program = PathBuf::from(r"C:\Users\host\tool.exe");
        assert!(validate_vm_guest_job(&guest, &guest.work_dir, &mounts).is_err());
        guest.program = PathBuf::from(r"C:\f2c\bin\..\host\tool.exe");
        assert!(validate_vm_guest_job(&guest, &guest.work_dir, &mounts).is_err());
        guest.program = PathBuf::from(r"C:\f2c\bin\tool.exe");
        guest.export_to = Some(PathBuf::from(r"C:\Users\host\out"));
        assert!(validate_vm_guest_job(&guest, &guest.work_dir, &mounts).is_err());
    }

    /// TC-029-11 (SPEC-019): a guest job.json carrying host paths is refused
    /// before anything runs. The Windows twin above covers drive-letter
    /// paths; this exercises the Linux guest mount envelope.
    #[cfg(target_os = "linux")]
    #[test]
    fn guest_paths_are_validated() {
        let id = "0123456789abcdef0123456789abcdef";
        let stage = PathBuf::from("/mnt/fail2commit-vm/jobs").join(id);
        let work = stage.join("work");
        let input = stage.join("input-0");
        let mounts = vec![PathBuf::from("/usr"), stage.clone()];
        let mut guest = JobSpec {
            program: input.join("tool"),
            args: vec![],
            cwd: work.clone(),
            env: vec![],
            read_only: vec![input.clone()],
            work_dir: work.clone(),
            exports: Vec::new(),
            export_to: None,
            limits: JobLimits {
                timeout: Duration::from_secs(10),
                memory_bytes: None,
                max_processes: None,
                max_output_bytes: 4096,
                disk_bytes: None,
            },
            network: NetworkMode::None,
            bait: false,
        };
        assert!(validate_vm_guest_job(&guest, &work, &mounts).is_ok());

        // Host paths in any field are refused.
        guest.program = PathBuf::from("/home/dev/tool");
        assert!(validate_vm_guest_job(&guest, &work, &mounts).is_err());
        guest.program = input.join("tool");
        guest.read_only = vec![PathBuf::from("/home/dev/.ssh")];
        assert!(validate_vm_guest_job(&guest, &work, &mounts).is_err());
        guest.read_only = vec![input.clone()];
        guest.cwd = PathBuf::from("/etc");
        assert!(validate_vm_guest_job(&guest, &work, &mounts).is_err());
        guest.cwd = work.clone();
        guest.work_dir = PathBuf::from("/tmp/host-work");
        assert!(validate_vm_guest_job(&guest, &work, &mounts).is_err());
        guest.work_dir = work.clone();
        // Traversal out of the assigned mounts is refused even when the
        // spelling starts inside them.
        guest.program = stage.join("../host/tool");
        assert!(validate_vm_guest_job(&guest, &work, &mounts).is_err());
        guest.program = input.join("tool");
        // A guest-side export destination is never allowed.
        guest.export_to = Some(PathBuf::from("/mnt/fail2commit-vm/out"));
        assert!(validate_vm_guest_job(&guest, &work, &mounts).is_err());
    }

    #[test]
    fn vm_outcome_transport_binds_fresh_identity_and_bounds_payload() {
        let outcome = JobOutcome {
            status: JobStatus::Exited(0),
            stdout: b"done".to_vec(),
            stderr: vec![],
            truncated: false,
            exported: vec![],
            report: ActivityReport::default(),
        };
        let id = "0123456789abcdef0123456789abcdef";
        let bytes = encode_vm_outcome(id, &outcome).unwrap();
        assert_eq!(decode_vm_outcome(id, &bytes).unwrap(), outcome);
        assert!(decode_vm_outcome("1123456789abcdef0123456789abcdef", &bytes).is_err());
        assert!(encode_vm_outcome("ABC", &outcome).is_err());
        assert!(decode_vm_outcome(id, &vec![0; MAX_VM_OUTCOME_BYTES + 1]).is_err());
        // A forged export claim inside the payload is still refused.
        let payload = encode_outcome(&outcome).unwrap();
        let raw = String::from_utf8(payload)
            .unwrap()
            .replace("\"exported\":[]", "\"exported\":[\"x\"]");
        use base64::Engine;
        let forged = serde_json::to_vec(&VmOutcomeFile {
            version: 1,
            job_id: id.to_owned(),
            payload_b64: base64::engine::general_purpose::STANDARD.encode(raw),
        })
        .unwrap();
        assert!(decode_vm_outcome(id, &forged).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn hardened_job_envelope_round_trips_and_rejects_relative_or_unknown_roots() {
        let root = PathBuf::from(r"C:\Users\fixture\AppData\Local\f2c\cache\sandbox-stage");
        let encoded = encode_hardened_job(&job(), &root).unwrap();
        let (decoded, decoded_root) = decode_hardened_job(&encoded).unwrap();
        assert_eq!(decoded.program, job().program);
        assert_eq!(decoded.work_dir, job().work_dir);
        assert_eq!(decoded_root, root);

        let relative = String::from_utf8(encoded.clone()).unwrap().replace(
            r"C:\\Users\\fixture\\AppData\\Local\\f2c\\cache\\sandbox-stage",
            "relative",
        );
        assert!(decode_hardened_job(relative.as_bytes()).is_err());
        let unknown = String::from_utf8(encoded)
            .unwrap()
            .replace("\"version\":1", "\"version\":2");
        assert!(decode_hardened_job(unknown.as_bytes()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn hardened_job_envelope_never_accepts_relative_stage_root() {
        assert!(encode_hardened_job(&job(), Path::new("relative-stage")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn job_encoding_refuses_non_utf8_paths_before_launch() {
        use std::os::unix::ffi::OsStringExt;
        let job = JobSpec {
            program: PathBuf::from(OsString::from_vec(vec![b'/', 0xff])),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env: vec![],
            read_only: vec![],
            work_dir: PathBuf::from("/tmp"),
            exports: vec![],
            export_to: None,
            limits: JobLimits {
                timeout: Duration::from_secs(1),
                memory_bytes: None,
                max_processes: None,
                max_output_bytes: 1024,
                disk_bytes: None,
            },
            network: NetworkMode::None,
            bait: false,
        };
        assert_eq!(
            encode_job(&job).unwrap_err().code,
            crate::ResultCode::IsolationUnavailable
        );
    }
}
