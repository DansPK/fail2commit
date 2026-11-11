//! T-004 (FR-004, SPEC-004) owns this directory.
//!
//! Frozen API: [`integration`]. Everything else is the worker's choice.
//!
//! Flow of a guarded `npm ci | install | i [pkg...]` (see docs/npm.md, CR-008):
//! stage (project files + pinned config) -> resolve with scripts disabled ->
//! download and verify every tarball of the lockfile graph, seed the private
//! cache -> `npm ci --offline --ignore-scripts` into the staging tree -> review
//! that extracted tree on disk (manifests, scripts, referenced files,
//! advisories) -> one approval over a digest of the reviewed tree -> run
//! approved lifecycle scripts through the sandbox in the same tree -> journaled
//! commit of that tree into the project. Nothing is extracted twice.

mod apply;
mod archive;
mod cmdline;
mod commit;
mod config;
mod lockfile;
mod review;
mod runner;
mod scripts;
mod shim;
mod signatures;
mod stage;
pub use stage::sweep_stale;
mod tree;

use crate::approval::ApprovalCtx;
use crate::approver::new_request;
use crate::digest::Digest;
use crate::exec::ScriptRun;
use crate::integration::Integration;
use crate::isolation::SandboxBackend;
use crate::paths::TrustedPaths;
use crate::policy::ScriptSituation;
use crate::protocol::{
    ApprovalKind, ApprovalRequest, Decision, Finding, FindingAction, FindingKind,
};
use crate::scan::{AdvisoryReport, PackageId, ScriptFile};
use crate::settings::Settings;
use crate::{Error, Result};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub use cmdline::{parse, Action, Request, Verb};
pub use commit::CrashPoint;
pub use signatures::{builtin_keys, forget as forget_signing_keys, PinnedKey, PinnedKeys};

/// npm shim integration for `fail2commit setup`.
pub fn integration() -> Option<Box<dyn Integration>> {
    Some(Box::new(shim::NpmShim))
}

/// Everything the flow needs from other areas. Production wiring
/// ([`Deps::production`]) uses the frozen APIs; tests inject doubles.
type ApproveFn<'a> = Box<dyn Fn(&ApprovalRequest) -> Result<Decision> + 'a>;
type AuthorizeFn<'a> = Box<dyn Fn(ScriptSituation, &str, &Digest) -> Result<ScriptRun> + 'a>;
type AdvisoryFn<'a> = Box<dyn Fn(&[PackageId]) -> AdvisoryReport + 'a>;
type InspectFn<'a> =
    Box<dyn Fn(&PackageId, &[(String, String)], &[ScriptFile]) -> Vec<Finding> + 'a>;

pub struct Deps<'a> {
    pub paths: &'a TrustedPaths,
    pub settings: &'a Settings,
    pub backend: &'a dyn SandboxBackend,
    pub approve: ApproveFn<'a>,
    pub authorize: AuthorizeFn<'a>,
    pub advisories: AdvisoryFn<'a>,
    pub inspect: InspectFn<'a>,
    /// Test seam: simulate the process dying during commit.
    pub crash: Option<CrashPoint>,
    /// Registries whose signing keys are built in (CR-018); production uses
    /// [`builtin_keys`], tests pin their loopback registry.
    pub pinned_keys: Vec<PinnedKeys>,
}

impl<'a> Deps<'a> {
    pub fn production(ctx: &'a ApprovalCtx<'a>, backend: &'a dyn SandboxBackend) -> Deps<'a> {
        Deps {
            paths: ctx.paths,
            settings: ctx.settings,
            backend,
            approve: Box::new(move |req| crate::approval::approve(ctx, req)),
            authorize: Box::new(move |sit, summary, digest| {
                crate::exec::authorize_scripts(ctx, backend, sit, summary, digest)
            }),
            advisories: Box::new(move |pkgs| {
                crate::scan::check_advisories(ctx.paths, &ctx.settings.advisories, pkgs)
            }),
            inspect: Box::new(crate::scan::inspect_scripts),
            crash: None,
            pinned_keys: builtin_keys(),
        }
    }
}

#[derive(Debug, Default)]
pub struct NpmOutcome {
    pub message: String,
    pub findings: Vec<Finding>,
    pub data: serde_json::Value,
}

/// Run a command that cannot install packages with the real npm.
pub fn passthrough(paths: &TrustedPaths, args: &[OsString]) -> Result<i32> {
    runner::passthrough(paths, args)
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[derive(Serialize)]
struct ArtifactDigest<'a> {
    path: &'a str,
    name: &'a str,
    version: &'a str,
    resolved: &'a str,
    integrity: &'a str,
    skipped: bool,
    scripts: &'a [(String, String)],
    /// Digests of the reviewed on-disk manifest and referenced files.
    tree: &'a [(String, String)],
}

type FindingDigest<'a> = (String, String, Option<&'a str>, Option<&'a str>, &'a str);

#[derive(Serialize)]
struct PlanDigest<'a> {
    command: &'a str,
    specs: &'a [String],
    save_flag: Option<&'a str>,
    save_exact: bool,
    ignore_scripts: bool,
    project: String,
    registry: &'a str,
    project_settings: &'a std::collections::BTreeMap<String, String>,
    npm: String,
    sandbox_enabled: bool,
    package_json: String,
    lockfile: String,
    artifacts: Vec<ArtifactDigest<'a>>,
    /// `(path, size, sha256)` of every entry of the reviewed staging tree.
    tree_files: &'a tree::Snapshot,
    findings: Vec<FindingDigest<'a>>,
}

fn unsupported_manifest(pj: &serde_json::Value) -> Result<()> {
    let deny = |msg: &str| {
        Error::invalid(msg.to_string()).with_findings(vec![Finding::new(
            FindingKind::UnsupportedInput,
            FindingAction::Deny,
            "npm.manifest",
            msg,
        )
        .location("package.json")])
    };
    if pj.get("workspaces").is_some() {
        return Err(deny("npm workspaces are not supported by the guard"));
    }
    for sect in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(m) = pj.get(sect).and_then(|m| m.as_object()) {
            for (name, range) in m {
                cmdline::validate_dep_range(name, range.as_str().unwrap_or(""))?;
            }
        }
    }
    fn walk(name: &str, v: &serde_json::Value) -> Result<()> {
        match v {
            serde_json::Value::String(s) if !s.starts_with('$') => {
                cmdline::validate_dep_range(name, s)
            }
            serde_json::Value::Object(m) => m.iter().try_for_each(|(k, v)| walk(k, v)),
            _ => Ok(()),
        }
    }
    if let Some(o) = pj.get("overrides") {
        walk("overrides", o)?;
    }
    Ok(())
}

/// Execute one guarded install. Serialized per project; an interrupted
/// earlier apply is recovered first.
pub fn execute(deps: &Deps<'_>, req: &Request) -> Result<NpmOutcome> {
    let lock = commit::lock_path(deps.paths, &req.project);
    crate::fsutil::with_lock(&lock, || execute_locked(deps, req))
}

fn execute_locked(deps: &Deps<'_>, req: &Request) -> Result<NpmOutcome> {
    let paths = deps.paths;
    let recovered = commit::recover(paths, &req.project)?;
    let tc = runner::Toolchain::resolve(paths)?;
    let registry = config::trusted_registry(paths)?;
    let (proj_cfg, npmrc) = config::project_settings(&req.project)?;

    let pj_bytes = crate::fsutil::read_bounded(&req.project.join("package.json"), 8 * 1024 * 1024)?;
    let lock_file = req.project.join("package-lock.json");
    let lock_bytes = lock_file
        .is_file()
        .then(|| crate::fsutil::read_bounded(&lock_file, 256 * 1024 * 1024))
        .transpose()?;
    if req.project.join("npm-shrinkwrap.json").exists() {
        return Err(Error::invalid(
            "npm-shrinkwrap.json is not supported by the guard",
        ));
    }
    let manifest: serde_json::Value = serde_json::from_slice(&pj_bytes)
        .map_err(|e| Error::invalid(format!("package.json is not valid JSON: {e}")))?;
    unsupported_manifest(&manifest)?;
    let fingerprint = {
        let mut h = Sha256::new();
        for part in [Some(&pj_bytes), lock_bytes.as_ref(), npmrc.as_ref()] {
            h.update(part.map_or(b"-".to_vec(), |b| sha_hex(b).into_bytes()));
            h.update(b"\0");
        }
        hex::encode(h.finalize())
    };

    // 1. Stage: nothing from the project except the three inputs.
    let stage_root = paths.cache_dir.join("sandbox-stage"); // CR-007
    crate::fsutil::ensure_private_dir(&stage_root)?;
    stage::sweep_stale(&stage_root); // ER-005
    let stage = tempfile::Builder::new()
        .prefix("npm-")
        .tempdir_in(&stage_root)?;
    let sd = stage.path();
    for d in ["home/tmp", "cache", "proj", "tarballs"] {
        std::fs::create_dir_all(sd.join(d))?;
    }
    let userconfig = sd.join("userconfig");
    let globalconfig = sd.join("globalconfig");
    std::fs::write(&userconfig, config::staged_userconfig(&registry, &proj_cfg))?;
    std::fs::write(&globalconfig, "")?;
    let proj_stage = sd.join("proj");
    std::fs::write(proj_stage.join("package.json"), &pj_bytes)?;
    if let Some(l) = &lock_bytes {
        std::fs::write(proj_stage.join("package-lock.json"), l)?;
    }
    let st = apply::Staging {
        dir: sd,
        userconfig: &userconfig,
        globalconfig: &globalconfig,
    };

    // 2. Resolve with scripts disabled (install only; ci uses the lockfile).
    if req.verb == Verb::Install {
        let mut extra: Vec<OsString> = vec!["--package-lock-only".into()];
        extra.extend(req.save_flag.map(OsString::from));
        if req.save_exact {
            extra.push("--save-exact".into());
        }
        if !req.specs.is_empty() {
            extra.push("--".into());
            extra.extend(req.specs.iter().map(OsString::from));
        }
        apply::npm_step(deps, &tc, &st, &proj_stage, &["install"], &extra)
            .map_err(|e| Error::invalid(format!("dependency resolution failed: {}", e.message)))?;
    } else if lock_bytes.is_none() {
        return Err(Error::invalid("`npm ci` needs a package-lock.json"));
    }
    let final_lock = std::fs::read(proj_stage.join("package-lock.json"))
        .map_err(|_| Error::invalid("resolution produced no package-lock.json"))?;
    let final_pj = std::fs::read(proj_stage.join("package.json"))?;
    let final_manifest: serde_json::Value = serde_json::from_slice(&final_pj)
        .map_err(|e| Error::invalid(format!("resolved package.json is invalid: {e}")))?;
    unsupported_manifest(&final_manifest)?;

    // 3. Review the exact graph: verified tarballs, extracted by npm itself
    //    (scripts off) into the staging tree, reviewed from disk.
    let plan = lockfile::parse(&final_lock, &registry, deps.settings.limits.graph_max_nodes)?;
    let mut reviewed = review::review(deps, &registry, &plan, &sd.join("tarballs"))?;
    apply::seed_cache(deps, &tc, &st, &reviewed)?;
    apply::npm_step(deps, &tc, &st, &proj_stage, &["ci"], &["--offline".into()])?;
    // Hashed before the review reads anything: a later difference is a change.
    let snap = tree::snapshot(&proj_stage)?;
    let found = tree::review(deps, &proj_stage, &plan, &mut reviewed)?;
    let ids: Vec<PackageId> = {
        let mut v: Vec<_> = plan.pkgs.iter().map(review::package_id).collect();
        v.sort();
        v.dedup();
        v
    };
    let report = (deps.advisories)(&ids);
    let mut findings = reviewed.findings.clone();
    findings.extend(report.findings);
    if !report.complete
        && !findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::IncompleteScan | FindingKind::StaleData))
    {
        findings.push(Finding::new(
            FindingKind::IncompleteScan,
            FindingAction::Approve,
            "npm.advisories",
            "advisory data was incomplete for this graph",
        ));
    }
    let mut seen = Vec::new();
    findings.retain(|f| {
        let dup = seen.contains(f);
        if !dup {
            seen.push(f.clone());
        }
        !dup
    });
    if findings.iter().any(|f| f.action == FindingAction::Deny) {
        return Err(
            Error::rejected("install blocked by policy; nothing was changed")
                .with_findings(findings),
        );
    }

    let plan_digest = Digest::of(
        "npm.install",
        &PlanDigest {
            command: if req.verb == Verb::Ci {
                "ci"
            } else {
                "install"
            },
            specs: &req.specs,
            save_flag: req.save_flag,
            save_exact: req.save_exact,
            ignore_scripts: req.ignore_scripts,
            project: req.project.to_string_lossy().into_owned(),
            registry: &registry.url,
            project_settings: &proj_cfg,
            npm: tc.npm_version(),
            sandbox_enabled: deps.settings.sandbox.enabled,
            package_json: sha_hex(&final_pj),
            lockfile: sha_hex(&final_lock),
            artifacts: reviewed
                .pkgs
                .iter()
                .map(|p| ArtifactDigest {
                    path: &p.plan.path,
                    name: &p.plan.name,
                    version: &p.plan.version,
                    resolved: &p.plan.resolved,
                    integrity: &p.plan.integrity,
                    skipped: p.plan.skip_platform,
                    scripts: &p.scripts,
                    tree: &p.inputs,
                })
                .collect(),
            tree_files: &snap,
            findings: findings
                .iter()
                .map(|f| {
                    (
                        format!("{:?}", f.kind),
                        format!("{:?}", f.action),
                        f.target.as_deref(),
                        f.advisory_id.as_deref(),
                        f.source.as_str(),
                    )
                })
                .collect(),
        },
    )?;

    // 4. One approval for everything that needs one.
    let summary = format!(
        "npm {} in {}: {} package(s)",
        if req.verb == Verb::Ci {
            "ci"
        } else {
            "install"
        },
        req.project.display(),
        plan.pkgs.len()
    );
    if findings.iter().any(|f| f.action == FindingAction::Approve) {
        let mut details: Vec<String> = findings
            .iter()
            .map(|f| {
                format!(
                    "{:?}: {} {}",
                    f.kind,
                    f.target.as_deref().unwrap_or(""),
                    crate::redact::redact_url_credentials(&f.evidence)
                )
            })
            .collect();
        details.extend(
            reviewed
                .pkgs
                .iter()
                .take(50)
                .map(|p| format!("{}@{}", p.plan.name, p.plan.version)),
        );
        let request = new_request(
            ApprovalKind::Operation,
            &plan_digest,
            summary.clone(),
            details,
            findings.clone(),
            deps.settings.approval.request_ttl_secs,
            false,
            vec![Decision::ApproveOnce],
        )?;
        match (deps.approve)(&request)? {
            Decision::ApproveOnce => {}
            _ => {
                return Err(Error::rejected("install cancelled; nothing was changed")
                    .with_findings(findings))
            }
        }
    }

    // 5. Lifecycle scripts: FR-008 decides; nothing runs on the host unless
    //    the user approved exactly this plan for host execution.
    let situation = apply::script_situation(&reviewed, req.ignore_scripts);
    let mode = if situation.has_scripts {
        let scripts: Vec<(&str, &str, &str)> = reviewed
            .pkgs
            .iter()
            .filter(|p| p.file.is_some())
            .flat_map(|p| {
                p.scripts
                    .iter()
                    .map(move |(e, c)| (p.plan.path.as_str(), e.as_str(), c.as_str()))
            })
            .collect();
        let sd = Digest::of("npm.scripts", &(plan_digest.as_hex(), &scripts))?;
        let names: Vec<&str> = reviewed
            .pkgs
            .iter()
            .filter(|p| p.file.is_some() && !p.scripts.is_empty())
            .map(|p| p.plan.name.as_str())
            .collect();
        (deps.authorize)(
            situation,
            &format!("{summary}; lifecycle scripts: {}", names.join(", ")),
            &sd,
        )?
    } else if req.ignore_scripts {
        ScriptRun::Skipped
    } else {
        ScriptRun::NoScripts
    };

    // 6. Apply: build offline from the reviewed bytes, verify, commit.
    let current = {
        let pj = crate::fsutil::read_bounded(&req.project.join("package.json"), 8 * 1024 * 1024)?;
        let lk = lock_file
            .is_file()
            .then(|| crate::fsutil::read_bounded(&lock_file, 256 * 1024 * 1024))
            .transpose()?;
        let np = crate::fsutil::read_bounded(&req.project.join(".npmrc"), 64 * 1024).ok();
        let mut h = Sha256::new();
        for part in [Some(&pj), lk.as_ref(), np.as_ref()] {
            h.update(part.map_or(b"-".to_vec(), |b| sha_hex(b).into_bytes()));
            h.update(b"\0");
        }
        hex::encode(h.finalize())
    };
    if current != fingerprint {
        return Err(Error::integrity(
            "project files changed while the install was being reviewed; nothing was changed",
        ));
    }
    let apply_dir = req.project.join(format!(
        ".f2c-npm-{}",
        &crate::digest::random_hex32()?[..16]
    ));
    commit::begin(paths, &req.project, &apply_dir)?;
    std::fs::create_dir(&apply_dir)
        .inspect_err(|_| commit::abandon(paths, &req.project, &apply_dir))?;
    let built = (|| -> Result<(Vec<String>, Vec<String>, Vec<Finding>)> {
        std::fs::write(apply_dir.join("package.json"), &final_pj)?;
        std::fs::write(apply_dir.join("package-lock.json"), &final_lock)?;
        tree::recheck(&proj_stage, &reviewed)?;
        tree::verify_unchanged(&proj_stage, &snap)?;
        let (ran, activity) =
            apply::run_scripts(deps, &tc, sd, &proj_stage, &reviewed, &found, mode, &|| {
                tree::recheck(&proj_stage, &reviewed)
            })?;
        let output = if ran.is_empty() {
            Vec::new()
        } else {
            tree::verify_after_scripts(&proj_stage, &plan, &found, &snap, &reviewed)?
        };
        let _ = std::fs::remove_dir_all(proj_stage.join(".f2c-tmp"));
        apply::move_tree(
            &proj_stage.join("node_modules"),
            &apply_dir.join("node_modules"),
        )?;
        Ok((ran, output, activity))
    })();
    let (ran, build_output, activity) = match built {
        Ok(r) => r,
        Err(e) => {
            commit::abandon(paths, &req.project, &apply_dir);
            return Err(e);
        }
    };
    commit::commit(
        paths,
        &commit::Commit {
            project: &req.project,
            apply_dir: &apply_dir,
            package_json: &final_pj,
            lock: &final_lock,
        },
        deps.crash,
    )?;

    let mut message = format!(
        "installed {} package(s)",
        plan.pkgs.iter().filter(|p| !p.skip_platform).count()
    );
    if mode == ScriptRun::Skipped {
        message.push_str("; lifecycle scripts were skipped");
    }
    if let Some(note) = &recovered {
        message.push_str(&format!("; {note}"));
    }
    // FR-026: what the sandboxed scripts tried, shown with the result.
    findings.extend(activity);
    Ok(NpmOutcome {
        message,
        findings,
        data: serde_json::json!({
            "digest": plan_digest.as_hex(),
            "tree_digest": tree::digest(&reviewed),
            "packages": plan.pkgs.len(),
            "scripts": format!("{mode:?}"),
            "scripts_run": ran,
            "build_output": build_output,
            "recovered": recovered,
        }),
    })
}

/// Project directory used by the CLI: nearest ancestor with a package.json.
pub fn project_for(cwd: &Path) -> Result<PathBuf> {
    cmdline::find_project(cwd)
}
