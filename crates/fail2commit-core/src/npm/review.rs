//! Review phase (SPEC-004): download every artifact ourselves, verify its
//! integrity, inspect the archive, and collect script/advisory findings.

use super::config::Registry;
use super::lockfile::{verify_sri, Plan, PlanPkg};
use super::{archive, signatures, Deps};
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
    /// Install-time lifecycle scripts, read from the extracted tree (`tree`).
    pub scripts: Vec<(String, String)>,
    /// `(package-relative path, sha256)` of every reviewed on-disk input.
    pub inputs: Vec<(String, String)>,
    /// Candidates of local command paths that did not exist at review time;
    /// none may appear before the scripts run.
    pub absent: Vec<String>,
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

pub fn unique_artifact_count(plan: &Plan) -> u64 {
    unique(plan).len() as u64
}

fn note_successful_fetch(
    progress: &dyn crate::progress::Progress,
    completed: &AtomicUsize,
    result: &Result<PathBuf>,
    current: &str,
) {
    if result.is_ok() {
        let done = completed.fetch_add(1, Ordering::SeqCst) + 1;
        progress.advance(done as u64, current);
    }
}

fn fetch_one(
    limits: &crate::settings::Limits,
    p: &PlanPkg,
    idx: usize,
    dir: &Path,
) -> Result<PathBuf> {
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
    // Defence in depth only: content is reviewed from what npm extracts.
    archive::precheck(&bytes, limits.artifact_max_bytes).map_err(|mut e| {
        e.message = format!("{}: {}", id.display(), e.message);
        for f in &mut e.findings {
            f.target = Some(id.display());
        }
        e
    })?;
    let file = dir.join(format!("{idx}.tgz"));
    std::fs::write(&file, &bytes)?;
    Ok(file)
}

/// Verify registry signatures (CR-018), then download and verify the whole
/// graph. Script inspection happens later on the extracted tree
/// (`tree::review`); advisory lookup in the caller.
pub fn review(deps: &Deps<'_>, registry: &Registry, plan: &Plan, dir: &Path) -> Result<Reviewed> {
    let findings = signatures::check(deps, registry, plan);
    if findings.iter().any(|f| f.action == FindingAction::Deny) {
        return Err(
            Error::rejected("install blocked by policy; nothing was changed")
                .with_findings(findings),
        );
    }
    std::fs::create_dir_all(dir)?;
    let uniq = unique(plan);
    let limits = &deps.settings.limits;
    let next = AtomicUsize::new(0);
    let completed = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Result<PathBuf>>>> =
        uniq.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..uniq.len().clamp(1, 8) {
            s.spawn(|| loop {
                let n = next.fetch_add(1, Ordering::Relaxed);
                let Some((first, _)) = uniq.get(n) else {
                    break;
                };
                let pkg = &plan.pkgs[*first];
                deps.progress.advance(
                    completed.load(Ordering::SeqCst) as u64,
                    &format!("Downloading {}@{}", pkg.name, pkg.version),
                );
                let r = fetch_one(limits, &plan.pkgs[*first], n, dir);
                note_successful_fetch(
                    deps.progress,
                    &completed,
                    &r,
                    &format!("Verified {}@{}", pkg.name, pkg.version),
                );
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

    let mut slots: Vec<Option<ReviewedPkg>> = vec![None; plan.pkgs.len()];
    for ((_, users), f) in uniq.iter().zip(&fetched) {
        for &u in users {
            slots[u] = Some(ReviewedPkg {
                plan: plan.pkgs[u].clone(),
                file: Some(f.clone()),
                scripts: vec![],
                inputs: vec![],
                absent: vec![],
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
                inputs: vec![],
                absent: vec![],
            })
        })
        .collect();
    Ok(Reviewed { pkgs, findings })
}

#[cfg(test)]
mod progress_tests {
    use super::*;
    use crate::progress::{End, Progress, Step};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(u64, String)>>);
    impl Progress for Recorder {
        fn advance(&self, done: u64, current: &str) {
            self.0.lock().unwrap().push((done, current.to_owned()));
        }
    }

    fn pkg(path: &str, resolved: &str, integrity: &str, skip_platform: bool) -> PlanPkg {
        PlanPkg {
            path: path.to_owned(),
            name: path.to_owned(),
            version: "1.0.0".into(),
            resolved: resolved.into(),
            integrity: integrity.into(),
            optional: false,
            skip_platform,
        }
    }

    #[test]
    fn download_total_counts_unique_artifacts_and_skips_unfetched_platform_packages() {
        let plan = Plan {
            pkgs: vec![
                pkg("a", "https://r/a.tgz", "sha512-x", false),
                pkg("b", "https://r/a.tgz", "sha512-x", false),
                pkg("c", "https://r/c.tgz", "sha512-c", false),
                pkg("d", "https://r/d.tgz", "sha512-d", true),
            ],
        };
        assert_eq!(unique_artifact_count(&plan), 2);
    }

    #[test]
    fn concurrent_download_progress_counts_only_successful_verifications() {
        let recorder = Arc::new(Recorder::default());
        let completed = Arc::new(AtomicUsize::new(0));
        let failed: Result<PathBuf> = Err(crate::Error::integrity("bad hash"));
        note_successful_fetch(recorder.as_ref(), &completed, &failed, "broken@1");
        std::thread::scope(|s| {
            for n in 0..8 {
                let recorder = recorder.clone();
                let completed = completed.clone();
                s.spawn(move || {
                    let success = Ok(PathBuf::from(format!("artifact-{n}")));
                    note_successful_fetch(recorder.as_ref(), &completed, &success, "verified");
                });
            }
        });
        assert_eq!(completed.load(Ordering::SeqCst), 8);
        let events = recorder.0.lock().unwrap();
        assert_eq!(events.len(), 8);
        assert_eq!(events.iter().map(|(n, _)| *n).max(), Some(8));
        assert!(!events.iter().any(|(_, name)| name == "broken@1"));
    }

    #[test]
    fn progress_recorder_remains_compatible_with_frozen_trait() {
        let p = Recorder::default();
        p.step(Step::DownloadVerify, 2);
        p.advance(1, "a@1");
        p.finding(&crate::protocol::Finding::new(
            crate::protocol::FindingKind::YaraMatch,
            crate::protocol::FindingAction::Approve,
            "test",
            "sample",
        ));
        p.pause();
        p.finish(End::Findings, "done");
        assert_eq!(p.0.lock().unwrap().len(), 1);
    }
}
