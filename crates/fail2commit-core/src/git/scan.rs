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
    let mut tips: Vec<&str> = Vec::new();
    let mut excludes: Vec<String> = Vec::new();
    for u in updates {
        check_oid(&u.old)?;
        check_oid(&u.new)?;
        if !RefUpdate::is_zero(&u.new) && !tips.contains(&u.new.as_str()) {
            tips.push(&u.new);
        }
        // The remote itself reported `old`, so everything it reaches is
        // already published, provided we have the object to walk from.
        if !RefUpdate::is_zero(&u.old)
            && matches!(
                gitcmd::object_type(git, repo, &u.old)?.as_deref(),
                Some("commit" | "tag")
            )
            && !excludes.contains(&u.old)
        {
            excludes.push(u.old.clone());
        }
    }
    if tips.is_empty() {
        return Ok(vec![]);
    }
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

    let mut rev_args: Vec<String> = tips.iter().map(|s| s.to_string()).collect();
    if !excludes.is_empty() {
        rev_args.push("--not".into());
        rev_args.extend(excludes);
    }

    let changes = collect_changes(git, repo, &rev_args, limits)?;
    let mut out = Vec::new();
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
    let mut c = Changes {
        added: HashMap::new(),
        env_added: vec![],
        env_deleted: vec![],
        commits: 0,
        entries: 0,
        node_limit_hit: false,
        entry_limit_hit: false,
    };
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
        }
        Ok(())
    })?;
    if short {
        notes
            .push("some outgoing blobs could not be read completely; they were not scanned".into());
    }
    Ok((hits, notes))
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
