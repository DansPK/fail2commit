//! Review phase (SPEC-004): download every artifact ourselves, verify its
//! integrity, inspect the archive, and collect script/advisory findings.

use super::lockfile::{verify_sri, Plan, PlanPkg};
use super::{archive, Deps};
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::scan::{Ecosystem, PackageId};
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ReviewedPkg {
    pub plan: PlanPkg,
    /// Verified tarball on disk; `None` for platform-skipped optionals.
    pub file: Option<PathBuf>,
    pub scripts: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct Reviewed {
    pub pkgs: Vec<ReviewedPkg>,
    pub findings: Vec<Finding>,
}

pub fn package_id(p: &PlanPkg) -> PackageId {
    PackageId {
        ecosystem: Ecosystem::Npm,
        name: p.name.clone(),
        version: p.version.clone(),
    }
}

/// GET `url` without following redirects, bounded by `max` bytes.
pub fn download(url: &str, max: u64, timeout: Duration) -> Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(timeout))
        .build()
        .into();
    let incomplete = |e: &dyn std::fmt::Display| {
        Error::incomplete(format!(
            "could not download {}: {e}",
            crate::redact::redact_url_credentials(url)
        ))
    };
    let mut resp = agent
        .get(url)
        .header("Accept-Encoding", "identity")
        .call()
        .map_err(|e| incomplete(&e))?;
    resp.body_mut()
        .with_config()
        .limit(max)
        .read_to_vec()
        .map_err(|e| incomplete(&e))
}

/// Unique artifacts by `(resolved, integrity)`; the value lists plan indexes.
fn unique(plan: &Plan) -> Vec<(usize, Vec<usize>)> {
    let mut out: Vec<(usize, Vec<usize>)> = Vec::new();
    for (i, p) in plan.pkgs.iter().enumerate() {
        if p.skip_platform {
            continue;
        }
        match out.iter_mut().find(|(f, _)| {
            plan.pkgs[*f].resolved == p.resolved && plan.pkgs[*f].integrity == p.integrity
        }) {
            Some((_, users)) => users.push(i),
            None => out.push((i, vec![i])),
        }
    }
    out
}

struct Fetched {
    file: PathBuf,
    scripts: Vec<(String, String)>,
    scan_files: Vec<crate::scan::ScriptFile>,
    findings: Vec<Finding>,
}

fn fetch_one(
    limits: &crate::settings::Limits,
    p: &PlanPkg,
    idx: usize,
    dir: &Path,
) -> Result<Fetched> {
    let id = package_id(p);
    let bytes = download(
        &p.resolved,
        limits.artifact_max_bytes,
        Duration::from_secs(120),
    )?;
    if !verify_sri(&p.integrity, &bytes) {
        return Err(Error::integrity(format!(
            "artifact bytes do not match the lockfile integrity for {}",
            id.display()
        ))
        .with_findings(vec![Finding::new(
            FindingKind::IntegrityMismatch,
            FindingAction::Deny,
            "npm.integrity",
            "downloaded bytes do not match the lockfile integrity",
        )
        .target(id.display())]));
    }
    let info = archive::inspect(&bytes, limits.artifact_max_bytes).map_err(|mut e| {
        e.message = format!("{}: {}", id.display(), e.message);
        e
    })?;
    let mut findings = Vec::new();
    if info.name != p.name || info.version != p.version {
        findings.push(
            Finding::new(
                FindingKind::IntegrityMismatch,
                FindingAction::Deny,
                "npm.manifest",
                "archive package.json name/version differs from the lockfile entry",
            )
            .target(id.display()),
        );
    }
    let file = dir.join(format!("{idx}.tgz"));
    std::fs::write(&file, &bytes)?;
    Ok(Fetched {
        file,
        scripts: info.scripts,
        scan_files: info.files,
        findings,
    })
}

/// Download and verify the whole graph, then run script inspection.
/// Advisory lookup happens in the caller so it sees the full package set.
pub fn review(deps: &Deps<'_>, plan: &Plan, dir: &Path) -> Result<Reviewed> {
    std::fs::create_dir_all(dir)?;
    let uniq = unique(plan);
    let limits = &deps.settings.limits;
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Result<Fetched>>>> =
        uniq.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..uniq.len().clamp(1, 8) {
            s.spawn(|| loop {
                let n = next.fetch_add(1, Ordering::Relaxed);
                let Some((first, _)) = uniq.get(n) else {
                    break;
                };
                let r = fetch_one(limits, &plan.pkgs[*first], n, dir);
                *slots[n].lock().expect("slot") = Some(r);
            });
        }
    });
    let mut fetched = Vec::new();
    let mut errors: Vec<Error> = Vec::new();
    for slot in slots {
        match slot.into_inner().expect("slot").expect("worker ran") {
            Ok(f) => fetched.push(f),
            Err(e) => errors.push(e),
        }
    }
    if !errors.is_empty() {
        let findings: Vec<Finding> = errors.iter().flat_map(|e| e.findings.clone()).collect();
        let pick = errors
            .iter()
            .find(|e| e.code == crate::ResultCode::IntegrityFailure)
            .unwrap_or(&errors[0])
            .clone();
        return Err(pick.with_findings(findings));
    }

    let mut findings = Vec::new();
    let mut slots: Vec<Option<ReviewedPkg>> = vec![None; plan.pkgs.len()];
    for ((_, users), f) in uniq.iter().zip(&fetched) {
        findings.extend(f.findings.clone());
        for &u in users {
            let p = &plan.pkgs[u];
            if !f.scripts.is_empty() {
                findings.extend((deps.inspect)(&package_id(p), &f.scripts, &f.scan_files));
            }
            slots[u] = Some(ReviewedPkg {
                plan: p.clone(),
                file: Some(f.file.clone()),
                scripts: f.scripts.clone(),
            });
        }
    }
    let pkgs = plan
        .pkgs
        .iter()
        .zip(slots)
        .map(|(p, r)| {
            r.unwrap_or_else(|| ReviewedPkg {
                plan: p.clone(),
                file: None,
                scripts: vec![],
            })
        })
        .collect();
    Ok(Reviewed { pkgs, findings })
}
