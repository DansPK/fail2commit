//! Review of what npm actually extracted (CR-008, SPEC-004). The archive
//! pre-checks in `archive` are defence in depth; every content decision
//! (manifest, lifecycle scripts, referenced files, findings) is made here from
//! the staged `node_modules` tree on disk, so the reviewed bytes are the bytes
//! npm wrote and the bytes that later run and get committed.

use super::lockfile::Plan;
use super::review::{package_id, Reviewed};
use super::{apply, scripts, sha_hex, Deps};
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::scan::ScriptFile;
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_REF_FILE: u64 = 256 * 1024;
const MAX_REF_TOTAL: u64 = 2 * 1024 * 1024;
const MAX_REF_FILES: usize = 32;
const MAX_MANIFEST: u64 = 1024 * 1024;
/// Nested `package.json` files read for their `main` field.
const MAX_NESTED_MANIFEST: u64 = 64 * 1024;
/// Files listed to expand a glob in a lifecycle command.
const MAX_LISTED: usize = 100_000;
const EXTS: [&str; 4] = [".js", ".cjs", ".mjs", ".json"];
/// Non-install lifecycle entries npm may run for a dependency; inspected,
/// never run by the guard.
const EXTRA_LIFECYCLE: [&str; 4] = ["prepublish", "preprepare", "prepare", "postprepare"];

#[derive(Debug, Default)]
pub struct PkgReview {
    pub name: String,
    pub version: String,
    pub scripts: Vec<(String, String)>,
    pub chained: Vec<(String, String)>,
    pub files: Vec<ScriptFile>,
    pub incomplete: Vec<String>,
    /// `(path relative to the package, sha256)` of the manifest and every
    /// referenced file that was read.
    pub inputs: Vec<(String, String)>,
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// Name as a case-insensitive or Windows filesystem sees it (glob matching only).
fn fold(rel: &str) -> String {
    rel.split('/')
        .map(|c| c.trim_end_matches(['.', ' ']).to_uppercase().to_lowercase())
        .collect::<Vec<_>>()
        .join("/")
}

struct Cx<'a> {
    dir: &'a Path,
    listing: Option<Vec<String>>,
    wanted: BTreeSet<String>,
    incomplete: Vec<String>,
}

impl Cx<'_> {
    /// Every file below the package directory, `/`-separated.
    fn listing(&mut self) -> &[String] {
        if self.listing.is_none() {
            let mut out = Vec::new();
            let mut stack = vec![(self.dir.to_path_buf(), String::new())];
            'walk: while let Some((d, rel)) = stack.pop() {
                let Ok(rd) = std::fs::read_dir(&d) else {
                    continue;
                };
                for e in rd.flatten() {
                    let r = join(&rel, &e.file_name().to_string_lossy());
                    match e.file_type() {
                        Ok(t) if t.is_dir() => stack.push((e.path(), r)),
                        Ok(_) => out.push(r),
                        Err(_) => {}
                    }
                    if out.len() > MAX_LISTED {
                        self.incomplete.push("*".into());
                        break 'walk;
                    }
                }
            }
            self.listing = Some(out);
        }
        self.listing.as_deref().unwrap_or_default()
    }

    fn add_tree(&mut self, t: &str) {
        if !t.is_empty() {
            self.wanted.insert(t.to_string());
            self.wanted.extend(EXTS.iter().map(|e| format!("{t}{e}")));
        }
        for e in EXTS {
            self.wanted.insert(join(t, &format!("index{e}")));
        }
        self.wanted.insert(join(t, "package.json"));
    }

    /// Add every file `node` or the shell could open for the path `p`
    /// (relative to the package root; `""` is the root): the path itself,
    /// node's extension and `index` resolution, and a directory's
    /// `package.json` `main`.
    fn expand(&mut self, p: &str) -> Result<()> {
        if p.contains(['*', '?']) {
            let pat = fold(p);
            let hits: Vec<String> = self
                .listing()
                .iter()
                .filter(|k| scripts::glob_match(pat.as_bytes(), fold(k).as_bytes()))
                .cloned()
                .collect();
            self.wanted.extend(hits);
            return Ok(());
        }
        self.add_tree(p);
        let manifest = self.dir.join(p).join("package.json");
        let Ok(meta) = std::fs::metadata(&manifest) else {
            return Ok(());
        };
        if !meta.is_file() {
            return Ok(());
        }
        let limit = if p.is_empty() {
            MAX_MANIFEST
        } else {
            MAX_NESTED_MANIFEST
        };
        if meta.len() > limit {
            self.incomplete.push(join(p, "package.json"));
            return Ok(());
        }
        let main = std::fs::read(&manifest)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("main").and_then(|m| m.as_str()).map(String::from));
        let Some(main) = main else {
            return Ok(());
        };
        let deny = |why: String| {
            Error::invalid(why.clone()).with_findings(vec![Finding::new(
                FindingKind::UnsupportedInput,
                FindingAction::Deny,
                "npm.archive",
                why,
            )])
        };
        let mut parts: Vec<&str> = p.split('/').filter(|c| !c.is_empty()).collect();
        for c in main.split('/') {
            match c {
                "" | "." => {}
                ".." if parts.pop().is_some() => {}
                ".." => {
                    return Err(deny(format!(
                        "package.json `main` of `{p}` escapes the package root"
                    )))
                }
                c if scripts::is_short_name(c) => {
                    return Err(deny(format!(
                        "package.json `main` of `{p}` names `{c}`, an 8.3 short-name alias"
                    )))
                }
                c if c.contains(':') => {
                    return Err(deny(format!(
                        "package.json `main` of `{p}` has a drive or stream marker"
                    )))
                }
                c => parts.push(c),
            }
        }
        self.add_tree(&parts.join("/"));
        Ok(())
    }
}

/// Review one installed package directory as npm wrote it.
pub fn review_pkg(dir: &Path) -> Result<PkgReview> {
    let manifest = crate::fsutil::read_bounded(&dir.join("package.json"), MAX_MANIFEST)?;
    let pj: serde_json::Value = serde_json::from_slice(&manifest)
        .map_err(|e| Error::invalid(format!("installed package.json is invalid: {e}")))?;
    let text = |k: &str| pj.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut out = PkgReview {
        name: text("name"),
        version: text("version"),
        ..Default::default()
    };
    let smap = pj.get("scripts").and_then(|s| s.as_object());
    if let Some(s) = smap {
        for k in ["preinstall", "install", "postinstall"] {
            if let Some(cmd) = s.get(k).and_then(|c| c.as_str()) {
                out.scripts.push((k.to_string(), cmd.to_string()));
            }
        }
    }
    let gyp = std::fs::metadata(dir.join("binding.gyp")).is_ok_and(|m| m.is_file());
    let gypfile_off = pj.get("gypfile").and_then(|g| g.as_bool()) == Some(false);
    let has_install = out
        .scripts
        .iter()
        .any(|(k, _)| k == "install" || k == "preinstall");
    if gyp && !gypfile_off && !has_install {
        out.scripts
            .push(("install".into(), "node-gyp rebuild".into()));
    }
    let scripts_map: BTreeMap<String, String> = smap
        .map(|s| {
            s.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let mut roots = out.scripts.clone();
    roots.extend(
        EXTRA_LIFECYCLE
            .iter()
            .filter_map(|k| Some((k.to_string(), scripts_map.get(*k)?.clone()))),
    );
    out.chained = scripts::follow(&roots, &scripts_map)?;
    out.chained
        .extend(roots[out.scripts.len()..].iter().cloned());

    // Every path word of a lifecycle (or chained) command is a candidate,
    // resolved on disk the way node and the shell would.
    let mut cx = Cx {
        dir,
        listing: None,
        wanted: BTreeSet::new(),
        incomplete: Vec::new(),
    };
    if gyp {
        cx.wanted.insert("binding.gyp".into());
    }
    for (_, cmd) in out.scripts.iter().chain(&out.chained) {
        for p in scripts::paths(cmd)? {
            cx.expand(&p)?;
        }
    }
    // The filesystem answers exact lookups, but a case-insensitive or Unicode
    // folding volume (NTFS, vfat, casefold ext4) may open `Ü.js` for `ü.js`:
    // also read every file whose folded name matches a candidate (fail closed).
    let want: BTreeSet<String> = cx.wanted.iter().map(|w| fold(w)).collect();
    if !want.is_empty() {
        let hits: Vec<String> = cx
            .listing()
            .iter()
            .filter(|k| want.contains(&fold(k)))
            .cloned()
            .collect();
        cx.wanted.extend(hits);
    }
    out.incomplete = std::mem::take(&mut cx.incomplete);

    out.inputs.push(("package.json".into(), sha_hex(&manifest)));
    let mut total = 0u64;
    let mut real: BTreeSet<std::path::PathBuf> = BTreeSet::new();
    for rel in std::mem::take(&mut cx.wanted) {
        let full = dir.join(&rel);
        let Ok(meta) = std::fs::metadata(&full) else {
            continue;
        };
        if !meta.is_file() || !real.insert(std::fs::canonicalize(&full).unwrap_or(full.clone())) {
            continue;
        }
        if meta.len() > MAX_REF_FILE
            || total + meta.len() > MAX_REF_TOTAL
            || out.files.len() >= MAX_REF_FILES
        {
            out.incomplete.push(rel);
            continue;
        }
        let bytes = crate::fsutil::read_bounded(&full, MAX_REF_FILE)?;
        total += bytes.len() as u64;
        out.inputs.push((rel.clone(), sha_hex(&bytes)));
        out.files.push(ScriptFile { path: rel, bytes });
    }
    Ok(out)
}

/// Verify the staged tree against the plan, then review every installed
/// package from disk. Fills `scripts` and `inputs` of each reviewed package
/// and appends script findings. Returns the installed package paths.
pub fn review(
    deps: &Deps<'_>,
    tree: &Path,
    plan: &Plan,
    reviewed: &mut Reviewed,
) -> Result<BTreeSet<String>> {
    let found = apply::verify_tree(tree, &plan.pkgs)?;
    for rp in reviewed.pkgs.iter_mut() {
        if rp.file.is_none() || !found.contains(&rp.plan.path) {
            continue;
        }
        let id = package_id(&rp.plan);
        let r = review_pkg(&tree.join(&rp.plan.path)).map_err(|mut e| {
            e.message = format!("{}: {}", id.display(), e.message);
            for f in &mut e.findings {
                f.target = Some(id.display());
            }
            e
        })?;
        if r.name != rp.plan.name || r.version != rp.plan.version {
            reviewed.findings.push(
                Finding::new(
                    FindingKind::IntegrityMismatch,
                    FindingAction::Deny,
                    "npm.manifest",
                    "installed package.json name/version differs from the lockfile entry",
                )
                .target(id.display()),
            );
        }
        for name in &r.incomplete {
            reviewed.findings.push(
                Finding::new(
                    FindingKind::IncompleteScan,
                    FindingAction::Deny,
                    "npm.archive",
                    format!(
                        "referenced script {name} was not inspected: over the size or count limit"
                    ),
                )
                .target(id.display())
                .location(name.clone()),
            );
        }
        if !r.scripts.is_empty() {
            let all = [r.scripts.clone(), r.chained.clone()].concat();
            reviewed
                .findings
                .extend((deps.inspect)(&id, &all, &r.files));
        }
        rp.scripts = r.scripts;
        rp.inputs = r.inputs;
    }
    Ok(found)
}

/// Hash `inputs` again just before anything runs: the tree must still be the
/// one that was reviewed.
pub fn recheck(tree: &Path, reviewed: &Reviewed) -> Result<()> {
    for p in reviewed.pkgs.iter().filter(|p| !p.inputs.is_empty()) {
        for (rel, sha) in &p.inputs {
            let now = std::fs::read(tree.join(&p.plan.path).join(rel)).map(|b| sha_hex(&b));
            if now.as_ref().ok() != Some(sha) {
                return Err(apply::mismatch(
                    format!("`{}/{rel}` changed after it was reviewed", p.plan.path),
                    Some(&p.plan.path),
                ));
            }
        }
    }
    Ok(())
}

/// Digest of everything that was reviewed from disk, for the approval.
pub fn digest(reviewed: &Reviewed) -> String {
    let all: Vec<(&str, &[(String, String)])> = reviewed
        .pkgs
        .iter()
        .map(|p| (p.plan.path.as_str(), p.inputs.as_slice()))
        .collect();
    sha_hex(&serde_json::to_vec(&all).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (p, b) in files {
            let f = d.path().join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, b).unwrap();
        }
        d
    }

    fn pj(cmd: &str) -> Vec<u8> {
        serde_json::json!({"name":"a","version":"1.0.0","scripts":{"postinstall":cmd}})
            .to_string()
            .into_bytes()
    }

    #[test]
    fn reads_scripts_and_referenced_files_from_disk() {
        let d = pkg(&[
            ("package.json", &pj("node ./setup.js && echo hi")),
            ("setup.js", b"console.log(1)"),
            ("unrelated.js", b"x"),
        ]);
        let r = review_pkg(d.path()).unwrap();
        assert_eq!(
            r.scripts,
            vec![("postinstall".into(), "node ./setup.js && echo hi".into())]
        );
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].path, "setup.js");
        let manifest = std::fs::read(d.path().join("package.json")).unwrap();
        assert_eq!(r.inputs[0], ("package.json".into(), sha_hex(&manifest)));
    }

    #[test]
    fn implicit_gyp_install() {
        let d = pkg(&[
            ("package.json", br#"{"name":"n","version":"1.0.0"}"#),
            ("binding.gyp", b"{}"),
        ]);
        let r = review_pkg(d.path()).unwrap();
        assert_eq!(
            r.scripts,
            vec![("install".into(), "node-gyp rebuild".into())]
        );
        assert_eq!(r.files[0].path, "binding.gyp");
    }

    #[test]
    fn node_resolution_candidates_are_read() {
        for (cmd, file) in [
            ("node ./setup", "setup.js"),
            ("node ./lib", "lib/index.js"),
            ("node .", "index.js"),
            ("sh \"./my script\"", "my script"),
            ("sh $PWD/x/../run", "run"),
            ("sh ./run", "run"),
            ("sh ./.npmignore", ".npmignore"),
        ] {
            let d = pkg(&[("package.json", &pj(cmd)), (file, b"x")]);
            let r = review_pkg(d.path()).unwrap();
            assert!(r.files.iter().any(|f| f.path == file), "{cmd}");
        }
        let d = pkg(&[
            ("package.json", &pj("node ./lib")),
            ("lib/package.json", br#"{"main":"./entry"}"#),
            ("lib/entry.js", b"x"),
        ]);
        let r = review_pkg(d.path()).unwrap();
        assert!(r.files.iter().any(|f| f.path == "lib/entry.js"));
        let d = pkg(&[("package.json", &pj("sh ./x/*.sh")), ("x/a.sh", b"1")]);
        assert!(review_pkg(d.path())
            .unwrap()
            .files
            .iter()
            .any(|f| f.path == "x/a.sh"));
    }

    #[test]
    fn short_name_main_and_trailing_dot_tokens_are_denied() {
        let d = pkg(&[
            (
                "package.json",
                br#"{"name":"a","version":"1","main":"BUILDH~1.JS","scripts":{"postinstall":"node ."}}"#,
            ),
            ("buildhelper.js", b"x"),
        ]);
        assert!(review_pkg(d.path()).is_err());
        let d = pkg(&[("package.json", &pj("sh ./BUILDH~1.JS."))]);
        assert!(review_pkg(d.path()).is_err());
    }

    #[test]
    fn referenced_files_dropped_by_caps_are_reported() {
        let cmd: Vec<String> = (0..33).map(|n| format!("./f{n}")).collect();
        let mut files: Vec<(String, Vec<u8>)> =
            vec![("package.json".into(), pj(&format!("sh {}", cmd.join(" "))))];
        files.extend((0..33).map(|n| (format!("f{n}"), b"x".to_vec())));
        let refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(p, b)| (p.as_str(), b.as_slice()))
            .collect();
        let r = review_pkg(pkg(&refs).path()).unwrap();
        assert_eq!(r.files.len(), MAX_REF_FILES);
        assert_eq!(r.incomplete.len(), 1);

        let big = vec![b'a'; MAX_REF_FILE as usize + 1];
        let d = pkg(&[("package.json", &pj("sh ./big")), ("big", &big)]);
        let r = review_pkg(d.path()).unwrap();
        assert!(r.files.is_empty());
        assert_eq!(r.incomplete, vec!["big".to_string()]);
    }

    fn plan_pkg(path: &str) -> super::super::lockfile::PlanPkg {
        super::super::lockfile::PlanPkg {
            path: path.into(),
            name: "a".into(),
            version: "1.0.0".into(),
            resolved: "http://x/a.tgz".into(),
            integrity: "sha512-x".into(),
            optional: false,
            skip_platform: false,
        }
    }

    #[test]
    fn unexpected_directories_and_links_are_denied() {
        let ok = pkg(&[("node_modules/a/package.json", &pj("true"))]);
        assert!(apply::verify_tree(ok.path(), &[plan_pkg("node_modules/a")]).is_ok());
        // A directory that is not in the plan, with or without a manifest.
        for extra in [
            "node_modules/b/package.json",
            "node_modules/c/x.js",
            "node_modules/.evil/package.json",
        ] {
            let d = pkg(&[("node_modules/a/package.json", &pj("true")), (extra, b"{}")]);
            let e = apply::verify_tree(d.path(), &[plan_pkg("node_modules/a")]).unwrap_err();
            assert_eq!(e.findings[0].action, FindingAction::Deny, "{extra}");
        }
        #[cfg(unix)]
        {
            let d = pkg(&[
                ("node_modules/a/package.json", &pj("true")),
                ("elsewhere/x", b"1"),
            ]);
            std::os::unix::fs::symlink(
                d.path().join("elsewhere"),
                d.path().join("node_modules/a/lnk"),
            )
            .unwrap();
            assert!(apply::verify_tree(d.path(), &[plan_pkg("node_modules/a")]).is_err());
            // npm's own `.bin` links are fine.
            let d = pkg(&[
                ("node_modules/a/package.json", &pj("true")),
                ("node_modules/a/cli.js", b"1"),
            ]);
            std::fs::create_dir_all(d.path().join("node_modules/.bin")).unwrap();
            std::os::unix::fs::symlink("../a/cli.js", d.path().join("node_modules/.bin/a"))
                .unwrap();
            assert!(apply::verify_tree(d.path(), &[plan_pkg("node_modules/a")]).is_ok());
        }
    }

    #[test]
    fn recheck_catches_a_changed_reviewed_file() {
        let d = pkg(&[
            ("node_modules/a/package.json", &pj("sh ./run")),
            ("node_modules/a/run", b"echo hi"),
        ]);
        let r = review_pkg(&d.path().join("node_modules/a")).unwrap();
        let reviewed = Reviewed {
            pkgs: vec![super::super::review::ReviewedPkg {
                plan: plan_pkg("node_modules/a"),
                file: None,
                scripts: r.scripts,
                inputs: r.inputs,
            }],
            findings: vec![],
        };
        assert!(recheck(d.path(), &reviewed).is_ok());
        std::fs::write(d.path().join("node_modules/a/run"), b"echo evil").unwrap();
        assert!(recheck(d.path(), &reviewed).is_err());
    }
}
