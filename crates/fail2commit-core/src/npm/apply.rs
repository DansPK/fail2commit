//! Apply phase (SPEC-004): build the install from the reviewed tarballs only,
//! prove the result matches the plan, and run lifecycle scripts through the
//! SPEC-007/008 path. The project is not touched here; `commit` does that.

use super::lockfile::PlanPkg;
use super::review::Reviewed;
use super::runner::{self, Toolchain};
use super::Deps;
use crate::exec::ScriptRun;
use crate::isolation::{JobLimits, JobSpec, JobStatus};
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct Staging<'a> {
    pub dir: &'a Path,
    pub userconfig: &'a Path,
    pub globalconfig: &'a Path,
}

impl Staging<'_> {
    pub fn cache(&self) -> PathBuf {
        self.dir.join("cache")
    }
    pub fn home(&self) -> PathBuf {
        self.dir.join("home")
    }
}

/// Flags that pin npm to the staged configuration.
pub fn config_args(st: &Staging<'_>) -> Vec<OsString> {
    let mut a: Vec<OsString> = Vec::new();
    for (flag, path) in [
        ("--userconfig", st.userconfig.to_path_buf()),
        ("--globalconfig", st.globalconfig.to_path_buf()),
        ("--cache", st.cache()),
    ] {
        a.push(flag.into());
        a.push(path.into());
    }
    for f in [
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--no-update-notifier",
    ] {
        a.push(f.into());
    }
    a
}

pub fn npm_step(
    deps: &Deps<'_>,
    tc: &Toolchain,
    st: &Staging<'_>,
    cwd: &Path,
    head: &[&str],
    extra: &[OsString],
) -> Result<runner::Captured> {
    let mut args: Vec<OsString> = head.iter().map(OsString::from).collect();
    args.extend(config_args(st));
    args.extend(extra.iter().cloned());
    let l = &deps.settings.limits;
    let out = runner::run_npm(
        tc,
        &args,
        cwd,
        &runner::clean_env(&st.home(), tc),
        Duration::from_secs(l.job_timeout_secs),
        l.job_max_output_bytes,
    )?;
    if !out.status.success() {
        return Err(Error::internal(format!(
            "npm {} failed ({}): {}",
            head.join(" "),
            out.status,
            runner::tail(&[out.stderr.as_slice(), out.stdout.as_slice()].concat())
        )));
    }
    Ok(out)
}

/// Put every verified tarball into the private cache by content digest, so
/// `npm ci --offline` can only use bytes that were reviewed.
pub fn seed_cache(
    deps: &Deps<'_>,
    tc: &Toolchain,
    st: &Staging<'_>,
    reviewed: &Reviewed,
) -> Result<()> {
    let files: BTreeSet<&PathBuf> = reviewed
        .pkgs
        .iter()
        .filter_map(|p| p.file.as_ref())
        .collect();
    let mut chunk: Vec<OsString> = vec!["--offline".into()];
    let mut size = 0;
    let flush = |chunk: &mut Vec<OsString>| -> Result<()> {
        if chunk.len() > 1 {
            // `cache add` with a tarball path stores it by integrity.
            npm_step(deps, tc, st, st.dir, &["cache", "add"], chunk)
                .map(|_| ())
                .map_err(|e| {
                    Error::internal(format!("seeding the private cache: {}", e.message))
                })?;
        }
        chunk.truncate(1);
        Ok(())
    };
    for f in files {
        size += f.as_os_str().len() + 1;
        chunk.push(f.clone().into());
        if size > 16_000 {
            flush(&mut chunk)?;
            size = 0;
        }
    }
    flush(&mut chunk)
}

pub(super) fn mismatch(msg: impl Into<String>, target: Option<&str>) -> Error {
    let msg = msg.into();
    let mut f = Finding::new(
        FindingKind::IntegrityMismatch,
        FindingAction::Deny,
        "npm.apply",
        msg.clone(),
    );
    if let Some(t) = target {
        f = f.target(t.to_string());
    }
    Error::integrity(format!(
        "installed tree does not match the reviewed plan: {msg}"
    ))
    .with_findings(vec![f])
}

/// Reject links anywhere below `dir` (a symlink or junction would let a
/// package point outside the reviewed tree). npm's own `node_modules/.bin`
/// links are the one exception; they are not followed by the review.
fn deny_links(dir: &Path, budget: &mut usize) -> Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| mismatch("the installed tree has too many entries to review", None))?;
        let ft = e.file_type()?;
        if ft.is_symlink() {
            return Err(mismatch(
                format!("unexpected link `{}`", e.path().display()),
                None,
            ));
        }
        let in_nm = dir.file_name().is_some_and(|n| n == "node_modules");
        if ft.is_dir() && !(in_nm && e.file_name() == ".bin") {
            deny_links(&e.path(), budget)?;
        }
    }
    Ok(())
}

fn installed(nm: &Path, prefix: &str, out: &mut BTreeSet<String>) -> Result<()> {
    let Ok(rd) = std::fs::read_dir(nm) else {
        return Ok(());
    };
    for e in rd {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let ft = e.file_type()?;
        if name == ".bin" || name == ".package-lock.json" {
            continue;
        }
        if !ft.is_dir() {
            return Err(mismatch(format!("unexpected entry `{prefix}{name}`"), None));
        }
        let dirs: Vec<(String, PathBuf)> = if name.starts_with('@') {
            std::fs::read_dir(e.path())?
                .filter_map(|s| s.ok())
                .map(|s| {
                    (
                        format!("{name}/{}", s.file_name().to_string_lossy()),
                        s.path(),
                    )
                })
                .collect()
        } else {
            vec![(name, e.path())]
        };
        for (n, p) in dirs {
            if !p.join("package.json").is_file() {
                return Err(mismatch(
                    format!("`{prefix}{n}` is not a package directory"),
                    None,
                ));
            }
            let key = format!("{prefix}{n}");
            installed(
                &p.join("node_modules"),
                &format!("{key}/node_modules/"),
                out,
            )?;
            out.insert(key);
        }
    }
    Ok(())
}

/// Every installed package must be in the plan with the same name/version,
/// and every non-skipped plan package must be installed.
pub fn verify_tree(tree: &Path, plan: &[PlanPkg]) -> Result<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    if tree.join("node_modules").is_dir() {
        deny_links(&tree.join("node_modules"), &mut 2_000_000)?;
    }
    installed(&tree.join("node_modules"), "node_modules/", &mut found)?;
    let by_path: BTreeMap<&str, &PlanPkg> = plan.iter().map(|p| (p.path.as_str(), p)).collect();
    for key in &found {
        if !by_path.contains_key(key.as_str()) {
            return Err(mismatch(format!("`{key}` is not part of the plan"), None));
        }
    }
    for p in plan.iter().filter(|p| !p.skip_platform) {
        if !found.contains(&p.path) {
            return Err(mismatch(format!("`{}` was not installed", p.path), None));
        }
    }
    // npm's hidden lockfile records what it actually fetched.
    if let Ok(b) = std::fs::read(tree.join("node_modules/.package-lock.json")) {
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
        if let Some(pk) = v.get("packages").and_then(|p| p.as_object()) {
            for (key, e) in pk {
                let Some(p) = by_path.get(key.as_str()) else {
                    return Err(mismatch(format!("`{key}` is not part of the plan"), None));
                };
                let s = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("");
                if s("version") != p.version
                    || s("resolved") != p.resolved
                    || s("integrity") != p.integrity
                {
                    return Err(mismatch(
                        format!("`{key}` differs from its plan entry"),
                        Some(key),
                    ));
                }
            }
        }
    }
    Ok(found)
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        let ft = e.file_type()?;
        if ft.is_dir() {
            copy_tree(&e.path(), &to)?;
        } else if ft.is_symlink() {
            // Only npm's own `.bin` links survive the review.
            #[cfg(unix)]
            std::os::unix::fs::symlink(std::fs::read_link(e.path())?, &to)?;
            #[cfg(not(unix))]
            return Err(mismatch("unexpected link in the staged tree", None));
        } else {
            std::fs::copy(e.path(), &to)?;
        }
    }
    Ok(())
}

/// Move the reviewed `node_modules` out of the staging tree into the project
/// scratch directory: a rename, or a copy across filesystems.
pub fn move_tree(src: &Path, dst: &Path) -> Result<()> {
    if !src.is_dir() {
        return Ok(());
    }
    if std::fs::rename(src, dst).is_err() {
        copy_tree(src, dst)?;
        let _ = std::fs::remove_dir_all(src);
    }
    Ok(())
}

struct Lifecycle {
    path: String,
    name: String,
    version: String,
    event: String,
    command: String,
}

fn lifecycle(reviewed: &Reviewed, found: &BTreeSet<String>) -> Vec<Lifecycle> {
    let mut v: Vec<&super::review::ReviewedPkg> = reviewed
        .pkgs
        .iter()
        .filter(|p| !p.scripts.is_empty() && found.contains(&p.plan.path))
        .collect();
    // Dependencies (deeper paths) first, like npm's build order.
    v.sort_by(|a, b| {
        let depth = |p: &str| p.matches("node_modules/").count();
        depth(&b.plan.path)
            .cmp(&depth(&a.plan.path))
            .then(a.plan.path.cmp(&b.plan.path))
    });
    v.into_iter()
        .flat_map(|p| {
            p.scripts.iter().map(move |(event, command)| Lifecycle {
                path: p.plan.path.clone(),
                name: p.plan.name.clone(),
                version: p.plan.version.clone(),
                event: event.clone(),
                command: command.clone(),
            })
        })
        .collect()
}

pub fn script_situation(reviewed: &Reviewed, ignore: bool) -> crate::policy::ScriptSituation {
    let any = !ignore
        && reviewed
            .pkgs
            .iter()
            .any(|p| p.file.is_some() && !p.scripts.is_empty());
    crate::policy::ScriptSituation {
        has_scripts: any,
        required: any
            && reviewed
                .pkgs
                .iter()
                .flat_map(|p| p.scripts.iter())
                .any(|(_, c)| c.contains("node-gyp")),
        flagged: false,
    }
}

fn shell(script: &str) -> (PathBuf, Vec<OsString>) {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        (
            PathBuf::from(root).join("System32").join("cmd.exe"),
            vec!["/d".into(), "/s".into(), "/c".into(), script.into()],
        )
    }
    #[cfg(not(windows))]
    {
        ("/bin/sh".into(), vec!["-c".into(), script.into()])
    }
}

/// The `.bin` directories a lifecycle script of `pkg_dir` finds on PATH,
/// nearest first; the k-th is `pkg_dir.ancestors().nth(k)/node_modules/.bin`.
pub(super) fn bin_dirs(tree: &Path, pkg_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut d = Some(pkg_dir);
    while let Some(dir) = d {
        out.push(dir.join("node_modules").join(".bin"));
        if dir == tree {
            break;
        }
        d = dir.parent();
    }
    out
}

/// CR-014: preload written next to the staged node on Windows. Inside the
/// AppContainer, libuv cannot create the named pipes it uses for child stdio
/// and loops forever; the preload routes piped child stdio through files.
pub(crate) const NODE_PRELOAD_NAME: &str = "f2c-node-preload.js";
pub(crate) const NODE_PRELOAD: &str = include_str!("node_preload.js");

/// `NODE_OPTIONS` for lifecycle scripts on Windows. An AppContainer cannot
/// lstat the ancestors of its stage (`C:\`), which node's default realpath of
/// the main script and of every required module does; npm on Windows creates
/// no symlinks, so resolving without it is equivalent. The preload is added
/// when it sits beside the (staged) node.
#[cfg(windows)]
fn node_options(tc: &Toolchain) -> String {
    let mut o = String::from("--preserve-symlinks --preserve-symlinks-main");
    let preload = tc.node_dir().join(NODE_PRELOAD_NAME);
    if preload.is_file() {
        // Forward slashes: NODE_OPTIONS treats a backslash inside quotes as an
        // escape character.
        let p = crate::fsutil::plain_path(&preload)
            .to_string_lossy()
            .replace('\\', "/");
        o.push_str(&format!(" --require \"{p}\""));
    }
    o
}

/// npm's lifecycle environment: `npm_*` context, `.bin` dirs on PATH,
/// cwd = the package directory. Nothing is inherited.
fn lifecycle_env(tc: &Toolchain, tree: &Path, l: &Lifecycle) -> Vec<(OsString, OsString)> {
    let pkg_dir = tree.join(&l.path);
    let tmp = tree.join(".f2c-tmp");
    let mut path = bin_dirs(tree, &pkg_dir);
    if let Some(root) = tc.npm_root() {
        path.push(root.join("bin").join("node-gyp-bin"));
    }
    path.push(tc.node_dir().to_path_buf());
    #[cfg(windows)]
    if let Some(r) = std::env::var_os("SystemRoot") {
        path.push(Path::new(&r).join("System32"));
    }
    #[cfg(not(windows))]
    path.extend(["/usr/bin", "/bin"].map(PathBuf::from));
    let mut e: Vec<(OsString, OsString)> = vec![
        ("npm_lifecycle_event".into(), l.event.clone().into()),
        ("npm_lifecycle_script".into(), l.command.clone().into()),
        ("npm_package_name".into(), l.name.clone().into()),
        ("npm_package_version".into(), l.version.clone().into()),
        ("npm_node_execpath".into(), tc.node.clone().into()),
        ("npm_execpath".into(), tc.npm_cli.clone().into()),
        ("npm_config_global".into(), "false".into()),
        ("INIT_CWD".into(), tree.into()),
        (
            "PATH".into(),
            std::env::join_paths(&path).unwrap_or_default(),
        ),
        ("HOME".into(), tmp.clone().into()),
        ("TMPDIR".into(), tmp.clone().into()),
        ("TEMP".into(), tmp.clone().into()),
        ("TMP".into(), tmp.clone().into()),
        // CR-014 preload: Windows overrides TEMP inside the AppContainer.
        ("F2C_IO_DIR".into(), tmp.into()),
    ];
    if let Some(gyp) = tc
        .npm_root()
        .map(|r| r.join("node_modules/node-gyp/bin/node-gyp.js"))
        .filter(|p| p.is_file())
    {
        e.push(("npm_config_node_gyp".into(), gyp.into()));
    }
    // An AppContainer cannot lstat the ancestors of its stage (`C:\`), which is
    // what node's default realpath of the main script and of every required
    // module does. npm on Windows creates no symlinks, so resolving without it
    // is equivalent.
    #[cfg(windows)]
    e.push(("NODE_OPTIONS".into(), node_options(tc).into()));
    #[cfg(windows)]
    for k in ["SystemRoot", "windir", "ComSpec"] {
        if let Some(v) = std::env::var_os(k) {
            e.push((k.into(), v));
        }
    }
    e
}

/// Run the approved lifecycle scripts for installed packages. Failure aborts
/// the whole apply (the caller discards the scratch tree).
// Stage dir (CR-007) and the per-script recheck (RN3-004) are both required inputs.
#[allow(clippy::too_many_arguments)]
pub fn run_scripts(
    deps: &Deps<'_>,
    tc: &Toolchain,
    stage_dir: &Path,
    tree: &Path,
    reviewed: &Reviewed,
    found: &BTreeSet<String>,
    mode: ScriptRun,
    before_each: &dyn Fn() -> Result<()>,
) -> Result<Vec<String>> {
    if !matches!(mode, ScriptRun::Sandboxed | ScriptRun::Host) {
        return Ok(vec![]);
    }
    // CR-007: sandboxed scripts run in a stage below `sandbox-stage`; an
    // approved host run uses the tree and toolchain in place.
    let stage = (mode == ScriptRun::Sandboxed)
        .then(|| super::stage::Tools::create(stage_dir, tc))
        .transpose()?;
    let (tc, tree) = match &stage {
        Some(s) => (&s.toolchain, tree),
        None => (tc, tree),
    };
    std::fs::create_dir_all(tree.join(".f2c-tmp"))?;
    let mut ran = Vec::new();
    for l in lifecycle(reviewed, found) {
        // An earlier script must not have rewritten what this one runs.
        before_each()?;
        let (mut program, args) = shell(&l.command);
        if let Some(sh) = stage.as_ref().and_then(|s| s.shell.clone()) {
            program = sh;
        }
        let env = lifecycle_env(tc, tree, &l);
        let cwd = tree.join(&l.path);
        let label = format!("{}@{} {}", l.name, l.version, l.event);
        let (status, tail) = if let Some(stage) = &stage {
            let job = JobSpec {
                program,
                args,
                cwd,
                env,
                read_only: stage.read_only.clone(),
                work_dir: tree.to_path_buf(),
                exports: vec![],
                export_to: None,
                limits: JobLimits::from_settings(&deps.settings.limits),
            };
            let out = crate::sandbox::run_job(deps.backend, &job)?;
            let tail = runner::tail(&[out.stderr.as_slice(), out.stdout.as_slice()].concat());
            (out.status, tail)
        } else {
            let mut cmd = crate::winenv::command(&program);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.args(&args[..3]).raw_arg(format!("\"{}\"", l.command));
            }
            #[cfg(not(windows))]
            cmd.args(&args);
            cmd.current_dir(&cwd)
                .env_clear()
                .envs(env.iter().map(|(k, v)| (k, v)));
            let lim = &deps.settings.limits;
            let out = runner::run_bounded(
                &mut cmd,
                Duration::from_secs(lim.job_timeout_secs),
                lim.job_max_output_bytes,
            )?;
            let st = out
                .status
                .code()
                .map_or(JobStatus::Killed, JobStatus::Exited);
            (
                st,
                runner::tail(&[out.stderr.as_slice(), out.stdout.as_slice()].concat()),
            )
        };
        if status != JobStatus::Exited(0) {
            let why = match status {
                JobStatus::Exited(code) => format!("exited with {code}"),
                JobStatus::TimedOut => format!(
                    "did not finish within limits.job_timeout_secs ({} s)",
                    deps.settings.limits.job_timeout_secs
                ),
                JobStatus::Killed => "was stopped by a sandbox resource limit".to_string(),
            };
            let tail = if tail.is_empty() {
                "no output".to_string()
            } else {
                tail
            };
            return Err(Error::internal(format!(
                "lifecycle script {why} ({label}); nothing was installed: {tail}"
            )));
        }
        ran.push(label);
    }
    Ok(ran)
}
