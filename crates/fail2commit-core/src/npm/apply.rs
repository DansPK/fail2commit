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

fn mismatch(msg: impl Into<String>, target: Option<&str>) -> Error {
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

fn installed(nm: &Path, prefix: &str, out: &mut BTreeSet<String>) -> Result<()> {
    let Ok(rd) = std::fs::read_dir(nm) else {
        return Ok(());
    };
    for e in rd {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let ft = e.file_type()?;
        if ft.is_symlink() {
            return Err(mismatch(format!("unexpected link `{prefix}{name}`"), None));
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
            if p.join("package.json").is_file() {
                let key = format!("{prefix}{n}");
                installed(
                    &p.join("node_modules"),
                    &format!("{key}/node_modules/"),
                    out,
                )?;
                out.insert(key);
            }
        }
    }
    Ok(())
}

/// Every installed package must be in the plan with the same name/version,
/// and every non-skipped plan package must be installed.
pub fn verify_tree(tree: &Path, plan: &[PlanPkg]) -> Result<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    installed(&tree.join("node_modules"), "node_modules/", &mut found)?;
    let by_path: BTreeMap<&str, &PlanPkg> = plan.iter().map(|p| (p.path.as_str(), p)).collect();
    for key in &found {
        let Some(p) = by_path.get(key.as_str()) else {
            return Err(mismatch(format!("`{key}` is not part of the plan"), None));
        };
        let dir = tree.join(key);
        let manifest: serde_json::Value = std::fs::read(dir.join("package.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| mismatch(format!("`{key}` has no readable package.json"), None))?;
        let s = |k: &str| manifest.get(k).and_then(|v| v.as_str()).unwrap_or("");
        if s("name") != p.name || s("version") != p.version {
            return Err(mismatch(
                format!(
                    "`{key}` is {}@{}, plan says {}@{}",
                    s("name"),
                    s("version"),
                    p.name,
                    p.version
                ),
                Some(key),
            ));
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

/// npm's lifecycle environment: `npm_*` context, `.bin` dirs on PATH,
/// cwd = the package directory. Nothing is inherited.
fn lifecycle_env(tc: &Toolchain, tree: &Path, l: &Lifecycle) -> Vec<(OsString, OsString)> {
    let pkg_dir = tree.join(&l.path);
    let tmp = tree.join(".f2c-tmp");
    let mut path: Vec<PathBuf> = Vec::new();
    let mut d = Some(pkg_dir.as_path());
    while let Some(dir) = d {
        path.push(dir.join("node_modules").join(".bin"));
        if dir == tree {
            break;
        }
        d = dir.parent();
    }
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
        ("TMP".into(), tmp.into()),
    ];
    if let Some(gyp) = tc
        .npm_root()
        .map(|r| r.join("node_modules/node-gyp/bin/node-gyp.js"))
        .filter(|p| p.is_file())
    {
        e.push(("npm_config_node_gyp".into(), gyp.into()));
    }
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
pub fn run_scripts(
    deps: &Deps<'_>,
    tc: &Toolchain,
    tree: &Path,
    reviewed: &Reviewed,
    found: &BTreeSet<String>,
    mode: ScriptRun,
) -> Result<Vec<String>> {
    if !matches!(mode, ScriptRun::Sandboxed | ScriptRun::Host) {
        return Ok(vec![]);
    }
    std::fs::create_dir_all(tree.join(".f2c-tmp"))?;
    let mut ran = Vec::new();
    for l in lifecycle(reviewed, found) {
        let (program, args) = shell(&l.command);
        let env = lifecycle_env(tc, tree, &l);
        let cwd = tree.join(&l.path);
        let label = format!("{}@{} {}", l.name, l.version, l.event);
        let (status, tail) = if mode == ScriptRun::Sandboxed {
            let job = JobSpec {
                program,
                args,
                cwd,
                env,
                read_only: [
                    Some(tc.node_dir().to_path_buf()),
                    tc.npm_root().map(Path::to_path_buf),
                ]
                .into_iter()
                .flatten()
                .collect(),
                work_dir: tree.to_path_buf(),
                exports: vec![],
                export_to: None,
                limits: JobLimits::from_settings(&deps.settings.limits),
            };
            let out = crate::sandbox::run_job(deps.backend, &job)?;
            let tail = runner::tail(&[out.stderr.as_slice(), out.stdout.as_slice()].concat());
            (out.status, tail)
        } else {
            let mut cmd = std::process::Command::new(&program);
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
            return Err(Error::internal(format!(
                "lifecycle script failed ({label}): {tail}"
            )));
        }
        ran.push(label);
    }
    Ok(ran)
}
