//! Defensive tarball pre-checks (SPEC-004): validate every entry path and
//! type before npm sees the archive. This is defence in depth only (CR-008):
//! nothing the reader returns is a content decision; scripts, manifests and
//! findings come from the tree npm extracts (`tree`).

use super::scripts;
use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::io::Read;

const MAX_ENTRIES: usize = 200_000;
const MAX_PATH_LEN: usize = 1024;

/// Normalize one entry path exactly as npm's tar extraction (`strip: 1`)
/// does: the first component goes, whatever it is (`.` included), then empty
/// and `.` components collapse. Anything that could land outside the package
/// directory is rejected.
fn normalize(raw: &std::path::Path) -> Result<Option<String>> {
    let bad = |why: &str| Err(Error::invalid(format!("unsafe archive entry: {why}")));
    let s = raw
        .to_str()
        .ok_or_else(|| Error::invalid("unsafe archive entry: non-UTF-8 path"))?;
    if s.len() > MAX_PATH_LEN {
        return bad("path too long");
    }
    if s.contains(['\\', '\0']) {
        return bad("backslash or NUL in path");
    }
    if s.starts_with('/') {
        return bad("absolute path");
    }
    let mut it = s.split('/');
    if let Some(first) = it.next() {
        if first == ".." || first.contains(':') {
            return bad("`..` component or drive marker");
        }
    }
    let mut parts = Vec::new();
    for c in it {
        match c {
            "" | "." => {}
            ".." => return bad("`..` component"),
            c if c.contains(':') => return bad("drive or stream marker"),
            c if scripts::is_short_name(c) => {
                return Err(Error::invalid(format!(
                    "unsafe archive entry: `{c}` has an 8.3 short-name shape"
                ))
                .with_findings(vec![Finding::new(
                    FindingKind::UnsupportedInput,
                    FindingAction::Deny,
                    "npm.archive",
                    format!("archive entry `{c}` has an 8.3 short-name shape"),
                )]));
            }
            c => parts.push(c),
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join("/")))
}

/// Name as an extractor on a case-insensitive or Windows filesystem sees it:
/// Unicode case folded, trailing dots and spaces dropped per component.
fn fold(rel: &str) -> String {
    rel.split('/')
        .map(|c| c.trim_end_matches(['.', ' ']).to_uppercase().to_lowercase())
        .collect::<Vec<_>>()
        .join("/")
}

fn io_err(e: std::io::Error) -> Error {
    Error::invalid(format!("archive is unreadable or over the size limit: {e}"))
}

/// Stream every entry once: validate its type and path, then hand it to `visit`
/// as `(normalized path, is_dir)`.
fn walk(
    tgz: &[u8],
    max_unpacked: u64,
    mut visit: impl FnMut(&str, bool) -> Result<()>,
) -> Result<()> {
    let gz = flate2::read::MultiGzDecoder::new(tgz).take(max_unpacked.saturating_add(1));
    let mut ar = tar::Archive::new(CountedReader {
        inner: gz,
        read: 0,
        max: max_unpacked,
    });
    let mut count = 0usize;
    for entry in ar.entries().map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        count += 1;
        if count > MAX_ENTRIES {
            return Err(Error::invalid("archive has too many entries"));
        }
        use tar::EntryType as T;
        let ty = entry.header().entry_type();
        if !matches!(ty, T::Regular | T::Continuous | T::Directory) {
            return Err(Error::invalid(format!(
                "unsafe archive entry: link, device or special file ({ty:?})"
            )));
        }
        let path = entry.path().map_err(io_err)?.into_owned();
        let Some(rel) = normalize(&path)? else {
            continue;
        };
        visit(&rel, ty == T::Directory)?;
    }
    Ok(())
}

fn collision(a: &str, b: &str) -> Error {
    let why = format!("archive entries `{a}` and `{b}` collide under case or Windows name folding");
    Error::integrity(why.clone()).with_findings(vec![Finding::new(
        FindingKind::IntegrityMismatch,
        FindingAction::Deny,
        "npm.archive",
        why,
    )])
}

pub fn precheck(tgz: &[u8], max_unpacked: u64) -> Result<()> {
    // folded name -> (exact name, is_dir)
    let mut seen: BTreeMap<String, (String, bool)> = BTreeMap::new();
    walk(tgz, max_unpacked, |rel, dir| match seen.get(&fold(rel)) {
        Some((exact, was_dir)) if !(dir && *was_dir && exact == rel) => Err(collision(rel, exact)),
        Some(_) => Ok(()),
        None => {
            seen.insert(fold(rel), (rel.to_string(), dir));
            Ok(())
        }
    })
}

/// Fails once more than `max` bytes were produced by the decompressor.
struct CountedReader<R> {
    inner: R,
    read: u64,
    max: u64,
}

impl<R: Read> Read for CountedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        if self.read > self.max {
            return Err(std::io::Error::other("unpacked size limit exceeded"));
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tgz(entries: &[(&str, &[u8], Option<tar::EntryType>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, data, ty) in entries {
            let mut h = tar::Header::new_gnu();
            // Write the name bytes directly so hostile paths survive the builder.
            let name = path.as_bytes();
            h.as_old_mut().name[..name.len()].copy_from_slice(name);
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(ty.unwrap_or(tar::EntryType::Regular));
            if matches!(ty, Some(tar::EntryType::Symlink | tar::EntryType::Link)) {
                h.set_link_name("x").unwrap();
            }
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        let raw = b.into_inner().unwrap();
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut e, &raw).unwrap();
        e.finish().unwrap()
    }

    const PJ: &[u8] =
        br#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"node ./setup.js && echo hi"}}"#;

    #[test]
    fn hostile_entries_are_rejected() {
        for p in [
            "package/../evil",
            "../evil",
            "/etc/passwd",
            "package/a/../../evil",
            "package\\evil",
            "C:/evil",
            "package/x:stream",
        ] {
            let t = tgz(&[("package/package.json", PJ, None), (p, b"x", None)]);
            assert!(precheck(&t, 1 << 20).is_err(), "{p}");
        }
        for ty in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::Fifo,
        ] {
            let t = tgz(&[
                ("package/package.json", PJ, None),
                ("package/l", b"", Some(ty)),
            ]);
            assert!(precheck(&t, 1 << 20).is_err(), "{ty:?}");
        }
        assert!(precheck(b"not a tarball", 1 << 20).is_err());
    }

    #[test]
    fn size_limit_applies_to_unpacked_bytes() {
        let big = vec![b'a'; 200_000];
        let t = tgz(&[
            ("package/package.json", PJ, None),
            ("package/big.bin", &big, None),
        ]);
        assert!(precheck(&t, 100_000).is_err());
        assert!(precheck(&t, 1 << 20).is_ok());
    }

    #[test]
    fn folding_collisions_are_rejected() {
        for (a, b) in [
            ("package/package.json", "package/PACKAGE.json"),
            ("package/build.js", "package/BUILD.js"),
            ("package/build.js", "package/build.js."),
            ("package/build.js", "package/build.js "),
            ("package/lib/x.js", "package/LIB/x.js"),
            ("package/build.js", "package/build.js"),
        ] {
            let t = tgz(&[
                ("package/package.json", PJ, None),
                (a, b"1", None),
                (b, b"2", None),
            ]);
            let e = precheck(&t, 1 << 20).unwrap_err();
            assert_eq!(e.code, crate::ResultCode::IntegrityFailure, "{a} {b}");
            assert_eq!(e.findings[0].kind, FindingKind::IntegrityMismatch);
            assert_eq!(e.findings[0].action, FindingAction::Deny);
        }
        // Repeated identical directory entries are fine.
        let t = tgz(&[
            ("package/package.json", PJ, None),
            ("package/lib", b"", Some(tar::EntryType::Directory)),
            ("package/lib", b"", Some(tar::EntryType::Directory)),
        ]);
        assert!(precheck(&t, 1 << 20).is_ok());
    }

    #[test]
    fn names_normalize_like_npm_tar_before_review() {
        // `./package.json` strips to the root manifest and collides with the real one.
        let e = precheck(
            &tgz(&[
                ("package/package.json", PJ, None),
                ("./package.json", PJ, None),
            ]),
            1 << 20,
        )
        .unwrap_err();
        assert_eq!(e.findings[0].kind, FindingKind::IntegrityMismatch);
        // `.` and empty components collapse.
        let t = tgz(&[
            ("package/package.json", PJ, None),
            ("package//a/./b", b"1", None),
            ("package/a/b", b"2", None),
        ]);
        let e = precheck(&t, 1 << 20).unwrap_err();
        assert_eq!(e.findings[0].action, FindingAction::Deny);
        // Unicode case folds; 8.3 shapes are refused.
        let t = tgz(&[
            ("package/package.json", PJ, None),
            ("package/\u{dc}.js", b"1", None),
            ("package/\u{fc}.js", b"2", None),
        ]);
        assert!(precheck(&t, 1 << 20).is_err());
        let t = tgz(&[
            ("package/package.json", PJ, None),
            ("package/BUILD~1.JS", b"1", None),
        ]);
        let e = precheck(&t, 1 << 20).unwrap_err();
        assert_eq!(e.findings[0].kind, FindingKind::UnsupportedInput);
    }
}
