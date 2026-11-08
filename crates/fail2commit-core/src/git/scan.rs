//! Bounded secret scan of the commits a push would publish.

use super::detect::{is_env_file, scan_text};
use super::gitcmd::{self, check_oid};
use super::RefUpdate;
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::settings::Limits;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::Stdio;

const SRC: &str = "git.secret-scan";
/// Largest single blob read into memory. Bigger blobs are never partially
/// scanned: they are reported as unexamined (IncompleteScan).
const MAX_BLOB_BYTES: u64 = 32 * 1024 * 1024;
const ENTRIES_PER_NODE: u64 = 10;

/// Entries of one changed path in outgoing history.
struct Changes {
    /// new blob oid -> first path that carried it
    added: HashMap<String, Vec<u8>>,
    env_added: Vec<Vec<u8>>,
    env_deleted: Vec<Vec<u8>>,
    commits: u64,
    entries: u64,
    node_limit_hit: bool,
    entry_limit_hit: bool,
}

pub fn scan(
    git: &Path,
    repo: &Path,
    updates: &[RefUpdate],
    // Ignored on purpose: remote-tracking refs are repository-controlled and
    // prove nothing about what the remote has (W1-001). Only the old OIDs of
    // `updates`, which the remote itself reported, bound the walk.
    _remote: Option<&str>,
    limits: &Limits,
) -> crate::Result<Vec<Finding>> {
    let target = updates
        .iter()
        .find(|u| !RefUpdate::is_zero(&u.new))
        .map(|u| u.refname.clone())
        .unwrap_or_default();
    let mk = |kind, ev: String| {
        let f = Finding::new(kind, FindingAction::Approve, SRC, ev);
        if target.is_empty() {
            f
        } else {
            f.target(target.clone())
        }
    };

    let mut tips: Vec<String> = Vec::new(); // peeled commits
    let mut direct: Vec<(String, String)> = Vec::new(); // peeled (blob|tree oid, ref)
    let mut excludes: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for u in updates {
        check_oid(&u.old)?;
        check_oid(&u.new)?;
        if !RefUpdate::is_zero(&u.new) {
            // Peel annotated tags (recursively) to the object a push really
            // carries; a tip whose type cannot be established fails closed.
            match peel(git, repo, &u.new)? {
                Some((oid, t)) if t == "commit" => {
                    if !tips.contains(&oid) {
                        tips.push(oid);
                    }
                }
                Some((oid, t)) if t == "blob" || t == "tree" => {
                    if !direct.iter().any(|(o, _)| *o == oid) {
                        direct.push((oid, u.refname.clone()));
                    }
                }
                _ => out.push(mk(
                    FindingKind::IncompleteScan,
                    format!(
                        "the type of {} could not be established; its contents were not scanned",
                        u.refname
                    ),
                )),
            }
        }
        // The remote itself reported `old`, so everything it reaches is
        // already published, provided we have a commit to walk from.
        if !RefUpdate::is_zero(&u.old) {
            if let Some((oid, t)) = peel(git, repo, &u.old)? {
                if t == "commit" && !excludes.contains(&oid) {
                    excludes.push(oid);
                }
            }
        }
    }

    let mut changes = if tips.is_empty() {
        Changes::new()
    } else {
        let mut rev_args = tips;
        if !excludes.is_empty() {
            rev_args.push("--not".into());
            rev_args.extend(excludes);
        }
        collect_changes(git, repo, &rev_args, limits)?
    };
    for (oid, refname) in &direct {
        walk_direct(git, repo, oid, refname, limits, &mut changes)?;
    }
    if changes.node_limit_hit || changes.entry_limit_hit {
        out.push(mk(
            FindingKind::IncompleteScan,
            format!(
                "history walk stopped at its bound ({} commits, {} changed paths); remaining outgoing history was not scanned",
                changes.commits, changes.entries
            ),
        ));
    }
    let mut seen = HashSet::new();
    for (list, verb) in [
        (&changes.env_added, "added"),
        (&changes.env_deleted, "deleted"),
    ] {
        for p in list {
            if seen.insert((verb, p.clone())) {
                let path = String::from_utf8_lossy(p).into_owned();
                out.push(
                    mk(
                        FindingKind::Secret,
                        format!(
                            "environment file {path} {verb} in outgoing history (contents not shown)"
                        ),
                    )
                    .location(path),
                );
            }
        }
    }
    let (content, unexamined) = scan_blobs(git, repo, &changes.added, limits)?;
    for (path, hit) in content {
        out.push(
            mk(
                FindingKind::Secret,
                format!(
                    "{} in {} at line {}: {}",
                    hit.detector, path, hit.line, hit.evidence
                ),
            )
            .location(path),
        );
    }
    for why in unexamined {
        out.push(mk(FindingKind::IncompleteScan, why));
    }
    Ok(out)
}

impl Changes {
    fn new() -> Self {
        Changes {
            added: HashMap::new(),
            env_added: vec![],
            env_deleted: vec![],
            commits: 0,
            entries: 0,
            node_limit_hit: false,
            entry_limit_hit: false,
        }
    }
}

/// Peel `oid` through annotated tags to `(final oid, type)`. `None` when Git
/// cannot resolve it (missing object, broken tag chain).
fn peel(git: &Path, repo: &Path, oid: &str) -> crate::Result<Option<(String, String)>> {
    let r = gitcmd::run(
        git,
        repo,
        &["rev-parse", "--verify", "-q", &format!("{oid}^{{}}")],
    )?;
    let peeled = r.text();
    if !r.ok() || !gitcmd::valid_oid(&peeled) {
        return Ok(None);
    }
    Ok(gitcmd::object_type(git, repo, &peeled)?.map(|t| (peeled, t)))
}

/// A tip that is a blob or a tree (for example a tag to one): queue its blobs
/// within the same entry bound as the commit walk.
fn walk_direct(
    git: &Path,
    repo: &Path,
    oid: &str,
    refname: &str,
    limits: &Limits,
    c: &mut Changes,
) -> crate::Result<()> {
    let max_entries = limits.graph_max_nodes.saturating_mul(ENTRIES_PER_NODE);
    if gitcmd::object_type(git, repo, oid)?.as_deref() == Some("blob") {
        c.added
            .entry(oid.to_string())
            .or_insert_with(|| refname.as_bytes().to_vec());
        return Ok(());
    }
    let mut cmd = gitcmd::command(git, repo);
    cmd.args(["ls-tree", "-r", "-z", "--full-tree", oid])
        .stdout(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| crate::Error::internal(format!("cannot run git: {e}")))?;
    let mut rd = BufReader::new(child.stdout.take().expect("piped"));
    let mut tok = Vec::new();
    loop {
        tok.clear();
        if rd.read_until(0, &mut tok)? == 0 {
            break;
        }
        if tok.last() == Some(&0) {
            tok.pop();
        }
        c.entries += 1;
        if c.entries > max_entries {
            c.entry_limit_hit = true;
            break;
        }
        // "<mode> SP <type> SP <oid> TAB <path>"; submodules ("commit") are skipped.
        let Some(tab) = tok.iter().position(|b| *b == b'\t') else {
            return Err(crate::Error::internal("unexpected git ls-tree output"));
        };
        let head = String::from_utf8_lossy(&tok[..tab]).into_owned();
        let f: Vec<&str> = head.split(' ').collect();
        if f.len() != 3 || !gitcmd::valid_oid(f[2]) {
            return Err(crate::Error::internal("unexpected git ls-tree output"));
        }
        if f[1] == "blob" {
            c.added
                .entry(f[2].to_string())
                .or_insert_with(|| tok[tab + 1..].to_vec());
        }
    }
    if c.entry_limit_hit {
        let _ = child.kill();
    }
    let status = child.wait()?;
    if !status.success() && !c.entry_limit_hit {
        return Err(crate::Error::incomplete(
            "git could not enumerate a tagged tree",
        ));
    }
    Ok(())
}

fn collect_changes(
    git: &Path,
    repo: &Path,
    rev_args: &[String],
    limits: &Limits,
) -> crate::Result<Changes> {
    let max_commits = limits.graph_max_nodes;
    let max_entries = limits.graph_max_nodes.saturating_mul(ENTRIES_PER_NODE);
    let mut cmd = gitcmd::command(git, repo);
    cmd.args([
        "log",
        "-z",
        "--raw",
        "--no-abbrev",
        "--no-renames",
        "--root",
        "--diff-merges=first-parent",
        "--format=%x01%H",
    ])
    .arg(format!("--max-count={}", max_commits.saturating_add(1)))
    .args(rev_args)
    .arg("--")
    .stdout(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| crate::Error::internal(format!("cannot run git: {e}")))?;
    let mut rd = BufReader::new(child.stdout.take().expect("piped"));
    let mut c = Changes::new();
    let mut tok = Vec::new();
    // pending: (status letter, new oid) waiting for its path token
    let mut pending: Option<(u8, String)> = None;
    loop {
        tok.clear();
        if rd.read_until(0, &mut tok)? == 0 {
            break;
        }
        if tok.last() == Some(&0) {
            tok.pop();
        }
        if let Some((status, new)) = pending.take() {
            c.entries += 1;
            if is_env_file(&tok) {
                if status == b'D' {
                    c.env_deleted.push(tok.clone());
                } else {
                    c.env_added.push(tok.clone());
                }
            }
            if status != b'D' && !RefUpdate::is_zero(&new) {
                c.added.entry(new).or_insert_with(|| tok.clone());
            }
            if c.entries > max_entries {
                c.entry_limit_hit = true;
                break;
            }
            continue;
        }
        let t = tok.strip_prefix(b"\n").unwrap_or(&tok);
        if t.first() == Some(&1) {
            c.commits += 1;
            if c.commits > max_commits {
                c.node_limit_hit = true;
                c.commits = max_commits;
                break;
            }
        } else if t.first() == Some(&b':') {
            // ":<mode> <mode> <old> <new> <status>"
            let s = String::from_utf8_lossy(t);
            let f: Vec<&str> = s[1..].split(' ').collect();
            if f.len() == 5 && gitcmd::valid_oid(f[3]) {
                // f[1] is the new mode; 160000 is a submodule commit, not a blob.
                let status = if f[1] == "160000" {
                    b'D'
                } else {
                    f[4].bytes().next().unwrap_or(b'M')
                };
                pending = Some((status, f[3].to_string()));
            } else {
                return Err(crate::Error::internal("unexpected git log output"));
            }
        }
    }
    if c.node_limit_hit || c.entry_limit_hit {
        let _ = child.kill();
    }
    let status = child.wait()?;
    if !status.success() && !(c.node_limit_hit || c.entry_limit_hit) {
        return Err(crate::Error::incomplete(
            "git could not enumerate outgoing commits",
        ));
    }
    Ok(c)
}

type ContentHits = Vec<(String, super::detect::Hit)>;

/// Read blobs, deduplicated and bounded. Every byte not examined is returned
/// as an explanation (never silently clean): missing objects, blobs too large
/// to read whole, and blobs that would exceed the byte budget. The full object
/// size is charged against `scan_max_bytes`.
fn scan_blobs(
    git: &Path,
    repo: &Path,
    blobs: &HashMap<String, Vec<u8>>,
    limits: &Limits,
) -> crate::Result<(ContentHits, Vec<String>)> {
    if blobs.is_empty() {
        return Ok((vec![], vec![]));
    }
    let mut oids: Vec<&String> = blobs.keys().collect();
    oids.sort();
    let request = |list: &[&String]| -> Vec<u8> {
        list.iter()
            .flat_map(|o| format!("{o}\n").into_bytes())
            .collect()
    };

    // Pass 1: sizes only, so nothing over budget is ever streamed.
    let sizes = batch(git, repo, "--batch-check", &request(&oids), |rd| {
        let mut out = Vec::new();
        let mut line = String::new();
        for _ in 0..oids.len() {
            line.clear();
            if rd.read_line(&mut line)? == 0 {
                break;
            }
            out.push(line.trim_end().to_string());
        }
        Ok(out)
    })?;
    let mut notes = Vec::new();
    let (mut missing, mut too_large, mut over_budget) = (0usize, 0usize, 0usize);
    let mut spent = 0u64;
    let mut chosen: Vec<&String> = Vec::new();
    missing += oids.len().saturating_sub(sizes.len());
    for (oid, l) in oids.iter().zip(&sizes) {
        let f: Vec<&str> = l.split(' ').collect();
        let size = match (f.as_slice(), f.get(2).map(|s| s.parse::<u64>())) {
            ([o, "blob", _], Some(Ok(n))) if *o == oid.as_str() => n,
            _ => {
                missing += 1;
                continue;
            }
        };
        if size > MAX_BLOB_BYTES {
            too_large += 1;
        } else if spent.saturating_add(size) > limits.scan_max_bytes {
            over_budget += 1;
        } else {
            spent += size;
            chosen.push(oid);
        }
    }
    if missing > 0 {
        notes.push(format!(
            "{missing} outgoing blob(s) are missing or unreadable in this repository; they were not scanned"
        ));
    }
    if too_large > 0 {
        notes.push(format!(
            "{too_large} outgoing blob(s) exceed the {MAX_BLOB_BYTES}-byte single-file scan limit; they were not scanned"
        ));
    }
    if over_budget > 0 {
        notes.push(format!(
            "blob content read budget of {} bytes reached; {over_budget} file(s) were not scanned",
            limits.scan_max_bytes
        ));
    }
    if chosen.is_empty() {
        return Ok((vec![], notes));
    }

    // Pass 2: read the chosen blobs whole. Binary content is scanned lossily
    // as well, so nothing is skipped by a heuristic.
    let mut hits = Vec::new();
    let mut short = false;
    let mut undecoded = 0usize;
    batch(git, repo, "--batch", &request(&chosen), |rd| {
        let mut line = String::new();
        for oid in &chosen {
            line.clear();
            if rd.read_line(&mut line)? == 0 {
                short = true;
                break;
            }
            let f: Vec<&str> = line.trim_end().split(' ').collect();
            let size = match (f.as_slice(), f.get(2).map(|s| s.parse::<u64>())) {
                ([o, "blob", _], Some(Ok(n))) if *o == oid.as_str() => n,
                _ => {
                    short = true; // object vanished between the two passes
                    continue;
                }
            };
            let mut buf = Vec::with_capacity(size as usize);
            rd.by_ref().take(size).read_to_end(&mut buf)?;
            let mut nl = [0u8; 1];
            rd.read_exact(&mut nl)?;
            if buf.len() as u64 != size {
                short = true;
                break;
            }
            let path = String::from_utf8_lossy(&blobs[*oid]).into_owned();
            for h in scan_text(&String::from_utf8_lossy(&buf)) {
                hits.push((path.clone(), h));
            }
            match utf16_view(&buf) {
                Utf16::No => {}
                Utf16::Text(t) => hits.extend(scan_text(&t).into_iter().map(|h| (path.clone(), h))),
                Utf16::Broken(t) => {
                    undecoded += 1;
                    hits.extend(scan_text(&t).into_iter().map(|h| (path.clone(), h)));
                }
            }
        }
        Ok(())
    })?;
    if undecoded > 0 {
        notes.push(format!(
            "{undecoded} outgoing blob(s) look like UTF-16/UTF-32 text that could not be decoded cleanly; they were only partly scanned"
        ));
    }
    if short {
        notes
            .push("some outgoing blobs could not be read completely; they were not scanned".into());
    }
    Ok((hits, notes))
}

enum Utf16 {
    No,
    /// Cleanly decoded copy.
    Text(String),
    /// Decoded lossily (or an encoding we cannot decode): reported incomplete.
    Broken(String),
}

/// Detect UTF-16 by BOM, or by NULs concentrated in one byte parity (ASCII
/// text in UTF-16 has a NUL in every other byte). UTF-32 BOMs are reported,
/// not decoded. Bounded: one pass over a blob that is already in memory.
fn utf16_view(b: &[u8]) -> Utf16 {
    if b.starts_with(&[0xFF, 0xFE, 0, 0]) || b.starts_with(&[0, 0, 0xFE, 0xFF]) {
        return Utf16::Broken(String::new());
    }
    let le = if b.starts_with(&[0xFF, 0xFE]) {
        Some(true)
    } else if b.starts_with(&[0xFE, 0xFF]) {
        Some(false)
    } else if b.len() >= 4 {
        let (mut even, mut odd) = (0usize, 0usize);
        for (i, x) in b.iter().enumerate() {
            if *x == 0 {
                if i % 2 == 0 {
                    even += 1;
                } else {
                    odd += 1;
                }
            }
        }
        let half = b.len() / 2;
        if odd * 10 >= half * 4 && even * 10 <= half {
            Some(true)
        } else if even * 10 >= half * 4 && odd * 10 <= half {
            Some(false)
        } else {
            None
        }
    } else {
        None
    };
    let Some(le) = le else { return Utf16::No };
    let units: Vec<u16> = b
        .chunks(2)
        .filter(|p| p.len() == 2)
        .map(|p| {
            if le {
                u16::from_le_bytes([p[0], p[1]])
            } else {
                u16::from_be_bytes([p[0], p[1]])
            }
        })
        .collect();
    match String::from_utf16(&units) {
        Ok(t) if b.len() & 1 == 0 => Utf16::Text(t),
        _ => Utf16::Broken(String::from_utf16_lossy(&units)),
    }
}

/// Run `git cat-file <mode>` feeding `request`, handing the reader to `f`.
fn batch<T>(
    git: &Path,
    repo: &Path,
    mode: &str,
    request: &[u8],
    f: impl FnOnce(&mut BufReader<std::process::ChildStdout>) -> std::io::Result<T>,
) -> crate::Result<T> {
    let mut cmd = gitcmd::command(git, repo);
    cmd.args(["cat-file", mode])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| crate::Error::internal(format!("cannot run git: {e}")))?;
    let mut stdin = child.stdin.take().expect("piped");
    let req = request.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&req);
    });
    let mut rd = BufReader::new(child.stdout.take().expect("piped"));
    let r = f(&mut rd);
    drop(rd);
    if r.is_err() {
        let _ = child.kill();
    }
    let _ = writer.join();
    let _ = child.wait();
    Ok(r?)
}
