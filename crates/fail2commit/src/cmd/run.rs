//! `fail2commit run` (T-007a; FR-007, SPEC-007): run one program in the
//! sandbox on a disposable copy of `--input` and copy out only the declared
//! `--export` paths after a clean exit. Always requires isolation.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::isolation::{JobLimits, JobSpec, JobStatus};
use fail2commit_core::{fsutil, policy, sandbox, toolpath, Error};
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Characters of each output stream shown to the user.
const DISPLAY_MAX: usize = 64 * 1024;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Project directory to stage. It is copied (without `.git`); the
    /// original is never visible to the sandbox.
    #[arg(long, value_name = "DIR")]
    pub input: PathBuf,
    /// Path relative to the staged input to copy out after exit status 0.
    #[arg(long = "export", value_name = "RELPATH")]
    pub exports: Vec<PathBuf>,
    /// Destination directory for `--export` paths.
    #[arg(long, value_name = "DIR")]
    pub to: Option<PathBuf>,
    /// Program and arguments, after `--`. The program is an absolute path or
    /// a bare name found on PATH.
    #[arg(last = true, required = true, value_name = "PROGRAM")]
    pub command: Vec<OsString>,
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    if !args.exports.is_empty() && args.to.is_none() {
        return Err(Error::invalid("--export needs --to <dir>"));
    }
    for e in &args.exports {
        if e.as_os_str().is_empty() || !e.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(Error::rejected(format!(
                "--export {} must be a plain relative path inside the input",
                e.display()
            )));
        }
    }
    // Explicit runs need a verified sandbox whatever the sandbox toggle says.
    let backend = sandbox::platform_backend();
    let probe = backend.probe();
    policy::explicit_run_allowed(probe.available).map_err(|mut e| {
        e.message = format!("{} ({}: {})", e.message, probe.backend, probe.detail);
        e
    })?;

    let input = args
        .input
        .canonicalize()
        .map_err(|e| Error::invalid(format!("--input {}: {e}", args.input.display())))?;
    if !input.is_dir() {
        return Err(Error::invalid("--input must be a directory"));
    }
    let to = args.to.as_deref().map(std::path::absolute).transpose()?;
    let limits = &ctx.settings.limits;
    // CR-007: the Windows backend only accepts stages that are direct children
    // of this fail2commit-owned root.
    let staging = ctx.paths.cache_dir.join("sandbox-stage");
    fsutil::ensure_private_dir(&staging)?;
    fail2commit_core::npm::sweep_stale(&staging); // ER-005
    let stage = Stage::new(&staging)?;
    let work = stage.0.join("work");
    fs::create_dir(&work)?;
    let mut budget = Budget {
        bytes: limits.artifact_max_bytes,
        entries: limits.graph_max_nodes,
    };
    copy_tree(&input, &work, &mut budget)?;
    let (program, read_only) = stage_program(
        ctx,
        &args.command[0],
        &stage.0.join("toolchain"),
        limits.artifact_max_bytes,
    )?;
    let job = JobSpec {
        env: job_env(&work, read_only.first()),
        program: program.clone(),
        args: args.command[1..].to_vec(),
        cwd: work.clone(),
        read_only,
        work_dir: work,
        exports: args.exports.clone(),
        export_to: to.clone(),
        limits: JobLimits::from_settings(limits),
        network: fail2commit_core::isolation::NetworkMode::None,
        bait: false,
    };
    let outcome = sandbox::run_job(backend.as_ref(), &job)?;

    let stdout = sanitize(&outcome.stdout);
    let stderr = sanitize(&outcome.stderr);
    if !ctx.json {
        print!("{stdout}");
        eprint!("{stderr}");
    }
    let (status, label, code) = match outcome.status {
        JobStatus::Exited(c) => ("exited", format!("exited with status {c}"), c),
        JobStatus::TimedOut => ("timed_out", "timed out and was killed".into(), 124),
        JobStatus::Killed => ("killed", "was killed".into(), 137),
    };
    let name = program
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut message = format!("sandboxed {} {label}", sanitize(name.as_bytes()));
    if outcome.truncated {
        message.push_str("; output truncated");
    }
    if let Some(to) = &to {
        if !args.exports.is_empty() {
            message.push_str(&match outcome.exported.len() {
                0 => "; nothing exported".to_string(),
                n => format!("; exported {n} file(s) to {}", to.display()),
            });
        }
    }
    Ok(Outcome {
        message,
        findings: Vec::new(),
        tool_exit: Some(code),
        data: serde_json::json!({
            "backend": probe.backend,
            "status": status,
            "exit_code": code,
            "truncated": outcome.truncated,
            "stdout": stdout,
            "stderr": stderr,
            "exported": outcome
                .exported
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
        }),
    })
}

/// Disposable staging directory, removed on drop.
struct Stage(PathBuf);

impl Stage {
    fn new(parent: &Path) -> fail2commit_core::Result<Stage> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for n in 0..100u32 {
            let p = parent.join(format!("run-{}-{nanos}-{n}", std::process::id()));
            match fs::create_dir(&p) {
                Ok(()) => return Ok(Stage(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::internal("cannot create a staging directory"))
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if fs::remove_dir_all(&self.0).is_err() {
            // Sandbox code may have left read-only dirs; it ran as this user.
            make_writable(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn make_writable(p: &Path) {
    let Ok(md) = fs::symlink_metadata(p) else {
        return;
    };
    if md.is_dir() {
        let mut perm = md.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perm.set_mode(0o700);
        }
        #[cfg(not(unix))]
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        let _ = fs::set_permissions(p, perm);
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                make_writable(&e.path());
            }
        }
    }
}

struct Budget {
    bytes: u64,
    entries: u64,
}

fn is_link(md: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if md.file_attributes() & 0x400 != 0 {
            return true; // FILE_ATTRIBUTE_REPARSE_POINT: junctions too
        }
    }
    md.file_type().is_symlink()
}

/// Copy the untrusted input tree without following links. `.git` is left
/// out so remote URLs, credentials and hooks never enter the sandbox.
fn copy_tree(src: &Path, dst: &Path, budget: &mut Budget) -> fail2commit_core::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        budget.entries = budget
            .entries
            .checked_sub(1)
            .ok_or_else(|| Error::invalid("--input has too many entries"))?;
        let (from, to) = (entry.path(), dst.join(&name));
        let md = fs::symlink_metadata(&from)?;
        if is_link(&md) {
            copy_link(&from, &to)?;
        } else if md.is_dir() {
            fs::create_dir(&to)?;
            copy_tree(&from, &to, budget)?;
        } else if md.is_file() {
            budget.bytes = budget
                .bytes
                .checked_sub(md.len())
                .ok_or_else(|| Error::invalid("--input exceeds limits.artifact_max_bytes"))?;
            fs::copy(&from, &to)?;
        } else {
            return Err(Error::invalid(format!(
                "--input contains a special file: {}",
                from.display()
            )));
        }
    }
    Ok(())
}

/// Recreate a link as a link: inside the sandbox it resolves against the
/// sandbox's own filesystem, never the host's.
#[cfg(unix)]
fn copy_link(from: &Path, to: &Path) -> fail2commit_core::Result<()> {
    std::os::unix::fs::symlink(fs::read_link(from)?, to)?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_link(from: &Path, _to: &Path) -> fail2commit_core::Result<()> {
    Err(Error::invalid(format!(
        "--input contains a link or junction: {}",
        from.display()
    )))
}

#[cfg(target_os = "linux")]
fn system_roots() -> Vec<PathBuf> {
    ["/usr", "/bin", "/sbin", "/lib", "/lib64"]
        .iter()
        .filter_map(|d| Path::new(d).canonicalize().ok())
        .collect()
}

/// No in-place system roots on Windows: the AppContainer backend grants only
/// inside the job stage (CR-007), so even `cmd.exe` is copied into it.
#[cfg(windows)]
fn system_roots() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(not(any(target_os = "linux", windows)))]
fn system_roots() -> Vec<PathBuf> {
    Vec::new()
}

/// Resolve the program. System tools run in place; anything else is copied
/// alone into a staged read-only toolchain directory.
fn stage_program(
    ctx: &Ctx,
    prog: &OsString,
    tool_dir: &Path,
    max_bytes: u64,
) -> fail2commit_core::Result<(PathBuf, Vec<PathBuf>)> {
    let p = Path::new(prog);
    let resolved = if p.is_absolute() {
        p.to_path_buf()
    } else if p.components().count() == 1 {
        toolpath::find_real(&p.to_string_lossy(), Some(&ctx.paths.bin_dir))?
    } else {
        return Err(Error::invalid(
            "program must be absolute or a bare name on PATH; run input scripts \
             through an interpreter, e.g. -- /bin/sh build.sh",
        ));
    };
    let canon = resolved
        .canonicalize()
        .map_err(|e| Error::invalid(format!("program {}: {e}", resolved.display())))?;
    let md = fs::metadata(&canon)?;
    if !md.is_file() {
        return Err(Error::invalid("program is not a file"));
    }
    if system_roots().iter().any(|r| canon.starts_with(r)) {
        return Ok((resolved, Vec::new()));
    }
    if md.len() > max_bytes {
        return Err(Error::invalid("program exceeds limits.artifact_max_bytes"));
    }
    fs::create_dir(tool_dir)?;
    let dest = tool_dir.join(canon.file_name().unwrap_or_default());
    fs::copy(&canon, &dest)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o555))?;
        fs::set_permissions(tool_dir, fs::Permissions::from_mode(0o555))?;
    }
    Ok((dest, vec![tool_dir.to_path_buf()]))
}

/// The complete job environment: nothing from the caller is inherited.
#[cfg(not(windows))]
fn job_env(work: &Path, tools: Option<&PathBuf>) -> Vec<(OsString, OsString)> {
    let mut path = OsString::new();
    if let Some(t) = tools {
        path.push(t);
        path.push(":");
    }
    path.push("/usr/local/bin:/usr/bin:/bin");
    vec![
        ("PATH".into(), path),
        ("HOME".into(), work.into()),
        ("TMPDIR".into(), "/tmp".into()),
        ("LANG".into(), "C.UTF-8".into()),
    ]
}

#[cfg(windows)]
fn job_env(work: &Path, tools: Option<&PathBuf>) -> Vec<(OsString, OsString)> {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let mut path = OsString::new();
    if let Some(t) = tools {
        path.push(t);
        path.push(";");
    }
    path.push(Path::new(&root).join("System32"));
    path.push(";");
    path.push(&root);
    vec![
        ("SystemRoot".into(), root),
        ("PATH".into(), path),
        ("USERPROFILE".into(), work.into()),
        ("TEMP".into(), work.into()),
        ("TMP".into(), work.into()),
    ]
}

/// Untrusted output for display: lossy UTF-8, control and bidi-override
/// characters replaced (no terminal escapes), bounded length.
fn sanitize(b: &[u8]) -> String {
    let text = String::from_utf8_lossy(b);
    let mut out: String = text
        .chars()
        .take(DISPLAY_MAX)
        .map(|c| match c {
            '\n' | '\t' => c,
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => '?',
            c if c.is_control() => '?',
            c => c,
        })
        .collect();
    if text.chars().nth(DISPLAY_MAX).is_some() {
        out.push_str("\n[output truncated for display]\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_terminal_escapes() {
        let s = sanitize(b"ok\x1b[31mred\r\n\xff\xe2\x80\xae");
        assert!(!s.contains('\x1b') && !s.contains('\r') && !s.contains('\u{202E}'));
        assert!(s.starts_with("ok?[31mred?\n"));
    }

    #[test]
    fn copy_tree_skips_git_and_enforces_budget() {
        let d = tempfile::tempdir().unwrap();
        let (src, dst) = (d.path().join("src"), d.path().join("dst"));
        fs::create_dir_all(src.join(".git")).unwrap();
        fs::write(src.join(".git/config"), b"[remote]").unwrap();
        fs::create_dir_all(src.join("a")).unwrap();
        fs::write(src.join("a/f"), b"12345").unwrap();
        fs::create_dir(&dst).unwrap();
        let mut b = Budget {
            bytes: 5,
            entries: 10,
        };
        copy_tree(&src, &dst, &mut b).unwrap();
        assert_eq!(fs::read(dst.join("a/f")).unwrap(), b"12345");
        assert!(!dst.join(".git").exists());
        let dst2 = d.path().join("dst2");
        fs::create_dir(&dst2).unwrap();
        let mut small = Budget {
            bytes: 4,
            entries: 10,
        };
        assert!(copy_tree(&src, &dst2, &mut small).is_err());
    }
}
