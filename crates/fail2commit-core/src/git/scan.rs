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
/// shortcut: blobs larger than this are scanned by their first 4 MiB only;
/// raise or stream the rest if large generated text files must be covered.
const MAX_BLOB_PREFIX: u64 = 4 * 1024 * 1024;
const ENTRIES_PER_NODE: u64 = 10;

fn valid_remote_name(n: &str) -> bool {
    !n.is_empty()
        && !n.starts_with('-')
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

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
    remote: Option<&str>,
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
    let remote_excl = remote
        .filter(|n| valid_remote_name(n))
        .filter(|n| {
            gitcmd::run(git, repo, &["config", "--get", &format!("remote.{n}.url")])
                .map(|o| o.ok())
                .unwrap_or(false)
        })
        .map(|n| format!("--remotes={n}"));
    if !excludes.is_empty() || remote_excl.is_some() {
        rev_args.push("--not".into());
        rev_args.extend(excludes);
        rev_args.extend(remote_excl);
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
    let (content, incomplete) = scan_blobs(git, repo, &changes.added, limits)?;
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
    if incomplete {
        out.push(mk(
            FindingKind::IncompleteScan,
            format!(
                "blob content read budget of {} bytes reached; remaining files were not scanned",
                limits.scan_max_bytes
            ),
        ));
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
                pending = Some((f[4].bytes().next().unwrap_or(b'M'), f[3].to_string()));
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

/// Read blobs in one `cat-file --batch` session, deduplicated and bounded.
fn scan_blobs(
    git: &Path,
    repo: &Path,
    blobs: &HashMap<String, Vec<u8>>,
    limits: &Limits,
) -> crate::Result<(ContentHits, bool)> {
    if blobs.is_empty() {
        return Ok((vec![], false));
    }
    let mut oids: Vec<&String> = blobs.keys().collect();
    oids.sort();
    let mut cmd = gitcmd::command(git, repo);
    cmd.args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| crate::Error::internal(format!("cannot run git: {e}")))?;
    let mut stdin = child.stdin.take().expect("piped");
    let request: Vec<u8> = oids
        .iter()
        .flat_map(|o| format!("{o}\n").into_bytes())
        .collect();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&request);
    });
    let mut rd = BufReader::new(child.stdout.take().expect("piped"));
    let mut hits = Vec::new();
    let mut spent = 0u64;
    let mut incomplete = false;
    let mut line = String::new();
    for oid in &oids {
        line.clear();
        if rd.read_line(&mut line)? == 0 {
            incomplete = true;
            break;
        }
        let f: Vec<&str> = line.trim_end().split(' ').collect();
        if f.len() != 3 || f[0] != oid.as_str() {
            continue; // missing object: nothing was sent for it
        }
        let size: u64 = f[2].parse().unwrap_or(0);
        let take = size.min(MAX_BLOB_PREFIX);
        if spent.saturating_add(take) > limits.scan_max_bytes {
            incomplete = true;
            break;
        }
        let mut buf = Vec::with_capacity(take as usize);
        (&mut rd).take(take).read_to_end(&mut buf)?;
        std::io::copy(&mut (&mut rd).take(size - take + 1), &mut std::io::sink())?;
        spent += take;
        if buf[..buf.len().min(8000)].contains(&0) {
            continue; // binary
        }
        let path = String::from_utf8_lossy(&blobs[*oid]).into_owned();
        for h in scan_text(&String::from_utf8_lossy(&buf)) {
            hits.push((path.clone(), h));
        }
    }
    if incomplete {
        let _ = child.kill();
    }
    drop(rd);
    let _ = writer.join();
    let _ = child.wait();
    Ok((hits, incomplete))
}
