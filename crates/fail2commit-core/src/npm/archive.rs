//! Defensive tarball inspection (SPEC-004): validate every entry path and
//! type, and pull out `package.json` plus the local files that install
//! scripts reference. Nothing is extracted to disk and nothing is executed.

use crate::protocol::{Finding, FindingAction, FindingKind};
use crate::scan::ScriptFile;
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

const MAX_ENTRIES: usize = 200_000;
const MAX_REF_FILE: u64 = 256 * 1024;
const MAX_REF_TOTAL: u64 = 2 * 1024 * 1024;
const MAX_REF_FILES: usize = 32;
const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_PATH_LEN: usize = 1024;

#[derive(Debug, Default)]
pub struct Inspected {
    pub name: String,
    pub version: String,
    /// Install-time lifecycle entries (`preinstall`, `install`, `postinstall`),
    /// plus the implicit `install: node-gyp rebuild` for `binding.gyp`.
    pub scripts: Vec<(String, String)>,
    pub files: Vec<ScriptFile>,
    /// Referenced files that were not read because of a size or count cap.
    pub incomplete: Vec<String>,
}

/// Normalize one entry path: drop the leading package directory and reject
/// anything that could land outside it.
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
    let mut parts = Vec::new();
    for c in s.split('/') {
        match c {
            "" | "." => {}
            ".." => return bad("`..` component"),
            c if c.contains(':') => return bad("drive or stream marker"),
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        return Ok(None);
    }
    parts.remove(0); // npm strips the first component whatever it is called
    Ok((!parts.is_empty()).then(|| parts.join("/")))
}

/// Name as an extractor on a case-insensitive or Windows filesystem sees it:
/// ASCII case folded, trailing dots and spaces dropped per component.
fn fold(rel: &str) -> String {
    rel.split('/')
        .map(|c| c.trim_end_matches(['.', ' ']).to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("/")
}

fn io_err(e: std::io::Error) -> Error {
    Error::invalid(format!("archive is unreadable or over the size limit: {e}"))
}

/// Stream every entry once: validate its type and path, then hand it to `visit`
/// as `(normalized path, is_dir, size, body)`.
fn walk(
    tgz: &[u8],
    max_unpacked: u64,
    mut visit: impl FnMut(&str, bool, u64, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    let gz = flate2::read::GzDecoder::new(tgz).take(max_unpacked.saturating_add(1));
    let mut ar = tar::Archive::new(CountedReader {
        inner: gz,
        read: 0,
        max: max_unpacked,
    });
    let mut count = 0usize;
    for entry in ar.entries().map_err(io_err)? {
        let mut entry = entry.map_err(io_err)?;
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
        let size = entry.header().size().map_err(io_err)?;
        visit(&rel, ty == T::Directory, size, &mut entry)?;
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

pub fn inspect(tgz: &[u8], max_unpacked: u64) -> Result<Inspected> {
    // Pass 1: validate, reject folding collisions, read the manifest.
    let mut manifest: Option<Vec<u8>> = None;
    // folded name -> (exact name, is_dir)
    let mut seen: BTreeMap<String, (String, bool)> = BTreeMap::new();
    walk(tgz, max_unpacked, |rel, dir, size, body| {
        match seen.get(&fold(rel)) {
            Some((exact, was_dir)) if !(dir && *was_dir && exact == rel) => {
                return Err(collision(rel, exact));
            }
            Some(_) => {}
            None => {
                seen.insert(fold(rel), (rel.to_string(), dir));
            }
        }
        if !dir && rel == "package.json" {
            if size > MAX_MANIFEST {
                return Err(Error::invalid("archive package.json is too large"));
            }
            let mut buf = Vec::with_capacity(size as usize);
            body.read_to_end(&mut buf).map_err(io_err)?;
            manifest = Some(buf);
        }
        Ok(())
    })?;
    let Some(manifest) = manifest else {
        return Err(Error::invalid("archive has no package.json"));
    };
    let pj: serde_json::Value = serde_json::from_slice(&manifest)
        .map_err(|e| Error::invalid(format!("archive package.json is invalid: {e}")))?;
    let text = |k: &str| pj.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut out = Inspected {
        name: text("name"),
        version: text("version"),
        ..Default::default()
    };
    if let Some(s) = pj.get("scripts").and_then(|s| s.as_object()) {
        for k in ["preinstall", "install", "postinstall"] {
            if let Some(cmd) = s.get(k).and_then(|c| c.as_str()) {
                out.scripts.push((k.to_string(), cmd.to_string()));
            }
        }
    }
    let gyp = seen.get("binding.gyp").is_some_and(|(_, dir)| !dir);
    let gypfile_off = pj.get("gypfile").and_then(|g| g.as_bool()) == Some(false);
    let has_install = out
        .scripts
        .iter()
        .any(|(k, _)| k == "install" || k == "preinstall");
    if gyp && !gypfile_off && !has_install {
        out.scripts
            .push(("install".into(), "node-gyp rebuild".into()));
    }

    // Every path token of a lifecycle command is a candidate, whatever its
    // extension. Tokens that name no archive file (`node`, `echo`) fall away.
    let mut wanted: BTreeSet<String> = BTreeSet::new();
    if gyp {
        wanted.insert("binding.gyp".into());
    }
    for (_, cmd) in &out.scripts {
        for tok in cmd.split(|c: char| c.is_whitespace() || "&|;<>()\"'`=".contains(c)) {
            let tok = tok.replace('\\', "/");
            let tok = tok.trim_start_matches("./");
            if !tok.is_empty() {
                wanted.insert(fold(tok));
            }
        }
    }
    wanted.retain(|w| seen.get(w).is_some_and(|(_, dir)| !dir));

    // Pass 2: read only the referenced files. A referenced file the caps drop
    // is reported, never silently skipped (CR-004).
    let mut total = 0u64;
    if !wanted.is_empty() {
        walk(tgz, max_unpacked, |rel, dir, size, body| {
            if dir || !wanted.contains(&fold(rel)) {
                return Ok(());
            }
            if size > MAX_REF_FILE
                || total + size > MAX_REF_TOTAL
                || out.files.len() >= MAX_REF_FILES
            {
                out.incomplete.push(rel.to_string());
                return Ok(());
            }
            let mut bytes = Vec::with_capacity(size as usize);
            body.read_to_end(&mut bytes).map_err(io_err)?;
            total += size;
            out.files.push(ScriptFile {
                path: rel.to_string(),
                bytes,
            });
            Ok(())
        })?;
    }
    Ok(out)
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
    fn extracts_scripts_and_referenced_files() {
        let t = tgz(&[
            ("package/package.json", PJ, None),
            ("package/setup.js", b"console.log(1)", None),
            ("package/unrelated.js", b"x", None),
        ]);
        let i = inspect(&t, 1 << 20).unwrap();
        assert_eq!((i.name.as_str(), i.version.as_str()), ("a", "1.0.0"));
        assert_eq!(
            i.scripts,
            vec![("postinstall".into(), "node ./setup.js && echo hi".into())]
        );
        assert_eq!(i.files.len(), 1);
        assert_eq!(i.files[0].path, "setup.js");
    }

    #[test]
    fn implicit_gyp_install() {
        let t = tgz(&[
            (
                "package/package.json",
                br#"{"name":"n","version":"1.0.0"}"#,
                None,
            ),
            ("package/binding.gyp", b"{}", None),
        ]);
        let i = inspect(&t, 1 << 20).unwrap();
        assert_eq!(
            i.scripts,
            vec![("install".into(), "node-gyp rebuild".into())]
        );
        assert_eq!(i.files[0].path, "binding.gyp");
    }

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
            assert!(inspect(&t, 1 << 20).is_err(), "{p}");
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
            assert!(inspect(&t, 1 << 20).is_err(), "{ty:?}");
        }
        assert!(inspect(&tgz(&[("package/readme", b"x", None)]), 1 << 20).is_err());
        assert!(inspect(b"not a tarball", 1 << 20).is_err());
    }

    #[test]
    fn size_limit_applies_to_unpacked_bytes() {
        let big = vec![b'a'; 200_000];
        let t = tgz(&[
            ("package/package.json", PJ, None),
            ("package/big.bin", &big, None),
        ]);
        assert!(inspect(&t, 100_000).is_err());
        assert!(inspect(&t, 1 << 20).is_ok());
    }

    #[test]
    fn extensionless_referenced_script_is_read() {
        let pj = br#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"sh ./run"}}"#;
        let t = tgz(&[
            ("package/package.json", pj, None),
            ("package/run", b"git push --force origin main", None),
        ]);
        let i = inspect(&t, 1 << 20).unwrap();
        assert_eq!(i.files.len(), 1);
        assert_eq!(i.files[0].path, "run");
        assert!(i.incomplete.is_empty());
    }

    #[test]
    fn referenced_files_dropped_by_caps_are_reported() {
        // 33 referenced files: the 33rd exceeds the count cap.
        let cmd: Vec<String> = (0..33).map(|n| format!("./f{n}")).collect();
        let pj = format!(
            r#"{{"name":"a","version":"1.0.0","scripts":{{"postinstall":"sh {}"}}}}"#,
            cmd.join(" ")
        );
        let mut entries: Vec<(String, Vec<u8>)> =
            vec![("package/package.json".into(), pj.into_bytes())];
        for n in 0..33 {
            entries.push((format!("package/f{n}"), b"x".to_vec()));
        }
        let refs: Vec<(&str, &[u8], Option<tar::EntryType>)> = entries
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_slice(), None))
            .collect();
        let i = inspect(&tgz(&refs), 1 << 20).unwrap();
        assert_eq!(i.files.len(), MAX_REF_FILES);
        assert_eq!(i.incomplete.len(), 1);

        // One referenced file over the per-file cap.
        let pj = br#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"sh ./big"}}"#;
        let big = vec![b'a'; MAX_REF_FILE as usize + 1];
        let t = tgz(&[
            ("package/package.json", pj, None),
            ("package/big", &big, None),
        ]);
        let i = inspect(&t, 1 << 20).unwrap();
        assert!(i.files.is_empty());
        assert_eq!(i.incomplete, vec!["big".to_string()]);

        // Referenced files together over the total cap (9 x 256 KiB > 2 MiB).
        let cmd: Vec<String> = (0..9).map(|n| format!("./g{n}")).collect();
        let pj = format!(
            r#"{{"name":"a","version":"1.0.0","scripts":{{"postinstall":"sh {}"}}}}"#,
            cmd.join(" ")
        );
        let body = vec![b'a'; MAX_REF_FILE as usize];
        let mut entries: Vec<(String, Vec<u8>)> =
            vec![("package/package.json".into(), pj.into_bytes())];
        for n in 0..9 {
            entries.push((format!("package/g{n}"), body.clone()));
        }
        let refs: Vec<(&str, &[u8], Option<tar::EntryType>)> = entries
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_slice(), None))
            .collect();
        let i = inspect(&tgz(&refs), 1 << 24).unwrap();
        assert_eq!(i.files.len(), 8);
        assert_eq!(i.incomplete.len(), 1);
    }

    #[test]
    fn unrelated_large_entries_do_not_hide_the_referenced_file() {
        let filler = vec![b'a'; 1024 * 1024];
        let mut entries: Vec<(String, Vec<u8>)> = (0..20)
            .map(|n| (format!("package/a{n}.js"), filler.clone()))
            .collect();
        entries.push(("package/package.json".into(), PJ.to_vec()));
        entries.push(("package/setup.js".into(), b"console.log(1)".to_vec()));
        let refs: Vec<(&str, &[u8], Option<tar::EntryType>)> = entries
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_slice(), None))
            .collect();
        let i = inspect(&tgz(&refs), 1 << 26).unwrap();
        assert_eq!(i.files.len(), 1);
        assert!(i.incomplete.is_empty());
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
            let e = inspect(&t, 1 << 20).unwrap_err();
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
        assert!(inspect(&t, 1 << 20).is_ok());
    }
}
