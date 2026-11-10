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
use sha2::{Digest as _, Sha256};
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
/// Extensions `cmd.exe` may run for a bare command (default PATHEXT and the
/// scripting hosts); reviewed on Windows in addition to node's own.
const WIN_EXTS: [&str; 12] = [
    ".com", ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc", ".ps1",
];
/// Interpreters and core tools a package must not shadow through `.bin`.
const SHADOWED: [&str; 28] = [
    "node",
    "nodejs",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "corepack",
    "sh",
    "bash",
    "dash",
    "zsh",
    "cmd",
    "powershell",
    "pwsh",
    "python",
    "python3",
    "py",
    "perl",
    "ruby",
    "git",
    "gcc",
    "cc",
    "c++",
    "g++",
    "clang",
    "make",
    "cmake",
    "node-gyp",
];
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
    /// Referenced files that are binary or otherwise cannot be read as text.
    pub uninspectable: Vec<String>,
    /// `(path relative to the package, sha256)` of the manifest and every
    /// referenced file that was read.
    pub inputs: Vec<(String, String)>,
    /// Local command paths with no candidate on disk (denied), by path.
    pub missing: Vec<String>,
    /// Candidates of local command paths that are absent now and must stay so.
    pub absent: Vec<String>,
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

/// Extensions tried for a path word: node's, plus PATHEXT's on Windows.
fn candidate_exts(windows: bool, pathext: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = EXTS.iter().map(|e| e.to_string()).collect();
    if windows {
        v.extend(WIN_EXTS.iter().map(|e| e.to_string()));
        v.extend(
            pathext
                .unwrap_or("")
                .split(';')
                .filter(|e| e.len() > 1 && e.starts_with('.'))
                .map(|e| e.to_ascii_lowercase()),
        );
        v.sort();
        v.dedup();
    }
    v
}

/// Command name without case, trailing dots/spaces or an executable extension
/// (`Node.CMD.` -> `node`).
fn bin_stem(name: &str) -> String {
    let l = name.trim_end_matches(['.', ' ']).to_ascii_lowercase();
    WIN_EXTS
        .iter()
        .find_map(|e| l.strip_suffix(e))
        .unwrap_or(&l)
        .to_string()
}

/// A candidate the review cannot read as a script: a PE/ELF/Mach-O image, or
/// anything with NUL bytes.
fn uninspectable(b: &[u8]) -> bool {
    const MAGIC: [&[u8]; 7] = [
        b"MZ",
        b"\x7fELF",
        &[0xfe, 0xed, 0xfa, 0xce],
        &[0xfe, 0xed, 0xfa, 0xcf],
        &[0xce, 0xfa, 0xed, 0xfe],
        &[0xcf, 0xfa, 0xed, 0xfe],
        &[0xca, 0xfe, 0xba, 0xbe],
    ];
    MAGIC.iter().any(|m| b.starts_with(m)) || b.contains(&0)
}

struct Cx<'a> {
    dir: &'a Path,
    exts: Vec<String>,
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
            self.wanted
                .extend(self.exts.iter().map(|e| format!("{t}{e}")));
        }
        for e in self.exts.clone() {
            self.wanted.insert(join(t, &format!("index{e}")));
        }
        self.wanted.insert(join(t, "package.json"));
    }

    /// Files the command word `w` runs through a `.bin` directory on the
    /// lifecycle PATH: the entry itself and the file the owning package
    /// declares in `bin` (a Windows `.cmd` shim only points at it).
    fn bin_command(&mut self, tree: &Path, w: &str) {
        let key = bin_stem(w);
        for (k, bd) in apply::bin_dirs(tree, self.dir).iter().enumerate() {
            let Ok(rd) = std::fs::read_dir(bd) else {
                continue;
            };
            let up = "../".repeat(k);
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if bin_stem(&n) == key {
                    self.wanted.insert(format!("{up}node_modules/.bin/{n}"));
                    if let Some(nm) = bd.parent() {
                        self.declared_bin(nm, &format!("{up}node_modules"), &key);
                    }
                }
            }
        }
    }

    /// Files named by `bin` in the manifests of the packages directly in `nm`.
    fn declared_bin(&mut self, nm: &Path, nm_rel: &str, key: &str) {
        let Ok(rd) = std::fs::read_dir(nm) else {
            return;
        };
        let mut kids: Vec<String> = Vec::new();
        for e in rd.flatten().take(5000) {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with('@') {
                if let Ok(sub) = std::fs::read_dir(e.path()) {
                    kids.extend(
                        sub.flatten()
                            .map(|s| format!("{n}/{}", s.file_name().to_string_lossy())),
                    );
                }
            } else {
                kids.push(n);
            }
        }
        for kid in kids {
            let manifest = nm.join(&kid).join("package.json");
            if std::fs::metadata(&manifest).map_or(true, |m| m.len() > MAX_NESTED_MANIFEST) {
                continue;
            }
            let Some(pj) = std::fs::read(&manifest)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            else {
                continue;
            };
            let declared: Vec<(String, String)> = match pj.get("bin") {
                Some(serde_json::Value::String(f)) => {
                    let n = pj.get("name").and_then(|n| n.as_str()).unwrap_or(&kid);
                    vec![(n.rsplit('/').next().unwrap_or(n).to_string(), f.clone())]
                }
                Some(serde_json::Value::Object(m)) => m
                    .iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                    .collect(),
                _ => vec![],
            };
            for (name, file) in declared {
                if bin_stem(&name) == key && !file.starts_with('/') && !file.contains(':') {
                    self.wanted.insert(format!("{nm_rel}/{kid}/{file}"));
                }
            }
        }
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
#[cfg(test)]
pub fn review_pkg(dir: &Path) -> Result<PkgReview> {
    review_pkg_in(dir, None, candidate_exts(false, None))
}

/// `tree` is the staging project root; with it, commands that resolve to a
/// `.bin` entry on the lifecycle PATH are reviewed too.
pub fn review_pkg_in(dir: &Path, tree: Option<&Path>, exts: Vec<String>) -> Result<PkgReview> {
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
        exts,
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
        for p in scripts::local_paths(cmd)? {
            let before = std::mem::take(&mut cx.wanted);
            cx.expand(&p)?;
            let mine = cx.wanted.clone();
            if !mine.iter().any(|r| dir.join(r).is_file()) {
                // Nothing to shadow: named for approval as built at runtime (CR-012).
                out.missing.push(p);
            } else {
                // A reviewed candidate exists; any other candidate appearing
                // later could shadow it, so those must stay absent.
                out.absent
                    .extend(mine.iter().filter(|r| !dir.join(r).exists()).cloned());
            }
            cx.wanted.extend(before);
        }
        if let Some(tree) = tree {
            for w in scripts::first_words(cmd) {
                cx.bin_command(tree, &w);
            }
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
        if uninspectable(&bytes) {
            out.uninspectable.push(rel);
            continue;
        }
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
    reviewed.findings.extend(bin_findings(tree)?);
    for rp in reviewed.pkgs.iter_mut() {
        if rp.file.is_none() || !found.contains(&rp.plan.path) {
            continue;
        }
        let id = package_id(&rp.plan);
        let exts = candidate_exts(cfg!(windows), std::env::var("PATHEXT").ok().as_deref());
        let r = review_pkg_in(&tree.join(&rp.plan.path), Some(tree), exts).map_err(|mut e| {
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
        // CR-012: a build that compiles and then runs its own output is
        // legitimate (FR-007), so a path absent at review is named for a
        // one-time approval rather than denied; the sandbox stays the boundary.
        for name in &r.missing {
            reviewed.findings.push(
                Finding::new(
                    FindingKind::IncompleteScan,
                    FindingAction::Approve,
                    "npm.scripts",
                    format!("lifecycle command runs `{name}`, which does not exist at review time (built or created by the package's scripts); it was not inspected"),
                )
                .target(id.display())
                .location(name.clone()),
            );
        }
        for name in &r.uninspectable {
            reviewed.findings.push(
                Finding::new(
                    FindingKind::IncompleteScan,
                    FindingAction::Deny,
                    "npm.archive",
                    format!(
                        "referenced file {name} is a binary or not text and cannot be inspected"
                    ),
                )
                .target(id.display())
                .location(name.clone()),
            );
        }
        let all = [r.scripts.clone(), r.chained.clone()].concat();
        if !r.scripts.is_empty() {
            reviewed
                .findings
                .extend((deps.inspect)(&id, &all, &r.files));
        }
        // CR-017: every package's own code, not only packages with scripts;
        // code that runs on `require()` is outside install-time isolation.
        let install: BTreeSet<String> = r.files.iter().map(|f| f.path.clone()).collect();
        reviewed.findings.extend(crate::scan::code::scan_package(
            &id,
            &tree.join(&rp.plan.path),
            if r.scripts.is_empty() { &[] } else { &all },
            &install,
        ));
        rp.scripts = r.scripts;
        rp.inputs = r.inputs;
        rp.absent = r.absent;
    }
    Ok(found)
}

/// Deny every `.bin` entry (any nested `node_modules/.bin`) that shadows an
/// interpreter or core tool: lifecycle PATH puts `.bin` first (RN3-001).
fn bin_findings(tree: &Path) -> Result<Vec<Finding>> {
    fn walk(dir: &Path, rel: &str, budget: &mut usize, out: &mut Vec<Finding>) -> Result<()> {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            *budget = budget
                .checked_sub(1)
                .ok_or_else(|| apply::mismatch("the installed tree has too many entries", None))?;
            let name = e.file_name().to_string_lossy().into_owned();
            let r = join(rel, &name);
            if !e.file_type()?.is_dir() {
                continue;
            }
            if name == ".bin" && dir.file_name().is_some_and(|n| n == "node_modules") {
                for b in std::fs::read_dir(e.path())? {
                    let n = b?.file_name().to_string_lossy().into_owned();
                    let stem = bin_stem(&n);
                    if SHADOWED.contains(&stem.as_str()) || scripts::is_short_name(&n) {
                        out.push(
                            Finding::new(
                                FindingKind::SuspiciousScript,
                                FindingAction::Deny,
                                "npm.bin",
                                format!(
                                    "`{r}/{n}` shadows the `{stem}` command on the lifecycle PATH"
                                ),
                            )
                            .location(format!("{r}/{n}")),
                        );
                    }
                }
            } else {
                walk(&e.path(), &r, budget, out)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    let nm = tree.join("node_modules");
    if nm.is_dir() {
        walk(&nm, "node_modules", &mut 2_000_000, &mut out)?;
    }
    Ok(out)
}

/// `(path relative to the tree, size, sha256)` of everything below
/// `node_modules`: files, directories (`path/`), links and special entries.
pub type Snapshot = Vec<(String, u64, String)>;

fn is_link(e: &std::fs::DirEntry, ft: &std::fs::FileType) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Symlinks, junctions and any other reparse point.
        ft.is_symlink() || e.metadata().is_ok_and(|m| m.file_attributes() & 0x400 != 0)
    }
    #[cfg(not(windows))]
    {
        let _ = e;
        ft.is_symlink()
    }
}

pub fn snapshot(tree: &Path) -> Result<Snapshot> {
    fn walk(dir: &Path, rel: &str, budget: &mut usize, out: &mut Snapshot) -> Result<()> {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            *budget = budget
                .checked_sub(1)
                .ok_or_else(|| apply::mismatch("the installed tree has too many entries", None))?;
            let r = join(rel, &e.file_name().to_string_lossy());
            let ft = e.file_type()?;
            if is_link(&e, &ft) {
                let to = std::fs::read_link(e.path())
                    .map(|t| t.to_string_lossy().into_owned())
                    .unwrap_or_default();
                out.push((r, 0, format!("link:{to}")));
            } else if ft.is_dir() {
                out.push((format!("{r}/"), 0, "dir".into()));
                walk(&e.path(), &r, budget, out)?;
            } else if ft.is_file() {
                use std::io::Read;
                let mut f = std::fs::File::open(e.path())?;
                let (mut h, mut n, mut buf) = (Sha256::new(), 0u64, vec![0u8; 64 * 1024]);
                loop {
                    let k = f.read(&mut buf)?;
                    if k == 0 {
                        break;
                    }
                    h.update(&buf[..k]);
                    n += k as u64;
                }
                out.push((r, n, hex::encode(h.finalize())));
            } else {
                out.push((r, 0, "special".into()));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    let nm = tree.join("node_modules");
    if nm.is_dir() {
        walk(&nm, "node_modules", &mut 2_000_000, &mut out)?;
    }
    out.sort();
    Ok(out)
}

/// Entries that differ from `before`: `(path, existed before, now)`; `now`
/// is `None` when the entry is gone.
fn changes(tree: &Path, before: &Snapshot) -> Result<Vec<(String, bool, Option<String>)>> {
    let key = |s: &Snapshot| -> BTreeMap<String, (u64, String)> {
        s.iter()
            .map(|(p, n, h)| (p.clone(), (*n, h.clone())))
            .collect()
    };
    let (old, new) = (key(before), key(&snapshot(tree)?));
    let mut out = Vec::new();
    for (p, v) in &new {
        if old.get(p) != Some(v) {
            out.push((p.clone(), old.contains_key(p), Some(v.1.clone())));
        }
    }
    out.extend(
        old.keys()
            .filter(|p| !new.contains_key(*p))
            .map(|p| (p.clone(), true, None)),
    );
    Ok(out)
}

/// Re-hash the whole tree: nothing may differ from what was reviewed.
pub fn verify_unchanged(tree: &Path, before: &Snapshot) -> Result<()> {
    let c = changes(tree, before)?;
    match c.first() {
        None => Ok(()),
        Some((p, _, _)) => Err(apply::mismatch(
            format!(
                "`{p}` changed after it was reviewed ({} path(s) differ)",
                c.len()
            ),
            None,
        )),
    }
}

/// After lifecycle scripts ran (RN3-004): the tree must still be the planned
/// packages, with no links or package/reviewed-file changes; only new or
/// changed files inside a package's own directory (build output) are allowed.
/// Returns those files.
pub fn verify_after_scripts(
    tree: &Path,
    plan: &Plan,
    found: &BTreeSet<String>,
    before: &Snapshot,
    reviewed: &Reviewed,
) -> Result<Vec<String>> {
    apply::verify_tree(tree, &plan.pkgs)?;
    recheck(tree, reviewed)?;
    let roots: Vec<String> = found.iter().map(|p| format!("{p}/")).collect();
    let mut output = Vec::new();
    for (p, existed, now) in changes(tree, before)? {
        let bad = |why: &str| apply::mismatch(format!("`{p}` {why}"), None);
        if now
            .as_deref()
            .is_some_and(|h| h.starts_with("link:") || h == "special")
        {
            return Err(bad("is a link or special file created by a script"));
        }
        if !roots.iter().any(|r| p.starts_with(r.as_str())) {
            return Err(bad("was changed outside the package directories"));
        }
        if existed && p.ends_with("/package.json") {
            return Err(bad("is a package.json that a script changed"));
        }
        if !p.ends_with('/') && now.is_some() {
            output.push(p);
        }
    }
    Ok(output)
}

/// Hash `inputs` again just before anything runs: the tree must still be the
/// one that was reviewed.
pub fn recheck(tree: &Path, reviewed: &Reviewed) -> Result<()> {
    for p in &reviewed.pkgs {
        for rel in &p.absent {
            if std::fs::symlink_metadata(tree.join(&p.plan.path).join(rel)).is_ok() {
                return Err(apply::mismatch(
                    format!(
                        "`{}/{rel}` appeared after it was reviewed as absent",
                        p.plan.path
                    ),
                    Some(&p.plan.path),
                ));
            }
        }
    }
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
    fn pathext_candidates_and_bin_names() {
        let e = candidate_exts(true, Some(".COM;.EXE;.XYZ;bad"));
        for x in [
            ".bat", ".cmd", ".exe", ".com", ".ps1", ".vbs", ".wsf", ".xyz", ".js",
        ] {
            assert!(e.contains(&x.to_string()), "{x}");
        }
        assert!(!candidate_exts(false, Some(".XYZ")).contains(&".bat".to_string()));
        for n in ["node", "NODE.EXE", "node.cmd.", "Node.PS1"] {
            assert_eq!(bin_stem(n), "node", "{n}");
        }
        let d = pkg(&[
            ("package.json", &pj(r".\setup")),
            ("setup.bat", b"@echo off"),
        ]);
        let r = review_pkg_in(d.path(), None, candidate_exts(true, None)).unwrap();
        assert!(r.files.iter().any(|f| f.path == "setup.bat"));
        let d = pkg(&[("package.json", &pj("setup")), ("setup.exe", b"MZ\x90\0")]);
        let r = review_pkg_in(d.path(), None, candidate_exts(true, None)).unwrap();
        assert_eq!(r.uninspectable, vec!["setup.exe".to_string()]);
    }

    #[test]
    fn bin_shadows_denied_and_other_bin_targets_read() {
        let d = pkg(&[
            ("node_modules/a/package.json", &pj("tool go")),
            ("node_modules/a/node_modules/.bin/tool.cmd", b"@echo hi"),
            ("node_modules/.bin/Make.CMD", b"@echo hi"),
            ("node_modules/.bin/fine", b"x"),
        ]);
        let f = bin_findings(d.path()).unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].action, FindingAction::Deny);
        let r = review_pkg_in(
            &d.path().join("node_modules/a"),
            Some(d.path()),
            candidate_exts(false, None),
        )
        .unwrap();
        assert!(r
            .files
            .iter()
            .any(|f| f.path == "node_modules/.bin/tool.cmd"));
    }

    #[test]
    fn declared_bin_file_is_read_through_a_shim() {
        let d = pkg(&[
            ("node_modules/a/package.json", &pj("tool go")),
            ("node_modules/.bin/tool.cmd", br"@node ..\tool\cli.js"),
            (
                "node_modules/tool/package.json",
                br#"{"name":"tool","version":"1.0.0","bin":{"tool":"cli.js"}}"#,
            ),
            ("node_modules/tool/cli.js", b"console.log(1)"),
        ]);
        let r = review_pkg_in(
            &d.path().join("node_modules/a"),
            Some(d.path()),
            candidate_exts(false, None),
        )
        .unwrap();
        assert!(
            r.files
                .iter()
                .any(|f| f.path == "../../node_modules/tool/cli.js"),
            "{:?}",
            r.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn snapshot_detects_changes_and_script_output_rules() {
        let d = pkg(&[
            ("node_modules/a/package.json", &pj("true")),
            ("node_modules/a/x.js", b"1"),
        ]);
        let plan = Plan {
            pkgs: vec![plan_pkg("node_modules/a")],
        };
        let found: BTreeSet<String> = ["node_modules/a".to_string()].into();
        let reviewed = Reviewed {
            pkgs: vec![],
            findings: vec![],
        };
        let snap = snapshot(d.path()).unwrap();
        assert!(verify_unchanged(d.path(), &snap).is_ok());
        // Build output in the package dir is returned.
        std::fs::write(d.path().join("node_modules/a/x.js"), b"2").unwrap();
        std::fs::write(d.path().join("node_modules/a/out.bin"), b"2").unwrap();
        assert!(verify_unchanged(d.path(), &snap).is_err());
        let out = verify_after_scripts(d.path(), &plan, &found, &snap, &reviewed).unwrap();
        assert_eq!(out, vec!["node_modules/a/out.bin", "node_modules/a/x.js"]);
        // A changed package.json, or a file outside the package dir, fails.
        std::fs::write(d.path().join("node_modules/a/package.json"), b"{}").unwrap();
        assert!(verify_after_scripts(d.path(), &plan, &found, &snap, &reviewed).is_err());
        let snap2 = snapshot(d.path()).unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.bin")).unwrap();
        std::fs::write(d.path().join("node_modules/.bin/x"), b"1").unwrap();
        assert!(verify_after_scripts(d.path(), &plan, &found, &snap2, &reviewed).is_err());
        std::fs::remove_dir_all(d.path().join("node_modules/.bin")).unwrap();
        // A link made by a script fails even inside the package dir.
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc", d.path().join("node_modules/a/lnk")).unwrap();
        #[cfg(windows)]
        assert!(std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(d.path().join("node_modules").join("a").join("lnk"))
            .arg(d.path())
            .output()
            .unwrap()
            .status
            .success());
        assert!(verify_after_scripts(d.path(), &plan, &found, &snap2, &reviewed).is_err());
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
                absent: vec![],
            }],
            findings: vec![],
        };
        assert!(recheck(d.path(), &reviewed).is_ok());
        std::fs::write(d.path().join("node_modules/a/run"), b"echo evil").unwrap();
        assert!(recheck(d.path(), &reviewed).is_err());
    }
}
