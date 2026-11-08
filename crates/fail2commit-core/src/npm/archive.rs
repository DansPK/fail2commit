//! Defensive tarball inspection (SPEC-004): validate every entry path and
//! type, and pull out `package.json` plus the local files that install
//! scripts reference. Nothing is extracted to disk and nothing is executed.

use crate::scan::ScriptFile;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::io::Read;

const MAX_ENTRIES: usize = 200_000;
const MAX_REF_FILE: u64 = 256 * 1024;
const MAX_REF_TOTAL: u64 = 2 * 1024 * 1024;
const CANDIDATE_BUDGET: u64 = 16 * 1024 * 1024;
const MAX_PATH_LEN: usize = 1024;

#[derive(Debug, Default)]
pub struct Inspected {
    pub name: String,
    pub version: String,
    /// Install-time lifecycle entries (`preinstall`, `install`, `postinstall`),
    /// plus the implicit `install: node-gyp rebuild` for `binding.gyp`.
    pub scripts: Vec<(String, String)>,
    pub files: Vec<ScriptFile>,
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

pub fn inspect(tgz: &[u8], max_unpacked: u64) -> Result<Inspected> {
    let gz = flate2::read::GzDecoder::new(tgz).take(max_unpacked.saturating_add(1));
    let mut ar = tar::Archive::new(CountedReader {
        inner: gz,
        read: 0,
        max: max_unpacked,
    });
    let mut manifest: Option<Vec<u8>> = None;
    let mut candidates: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut budget = 0u64;
    let mut count = 0usize;
    let io = |e: std::io::Error| {
        Error::invalid(format!("archive is unreadable or over the size limit: {e}"))
    };
    for entry in ar.entries().map_err(io)? {
        let mut entry = entry.map_err(io)?;
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
        let path = entry.path().map_err(io)?.into_owned();
        let Some(rel) = normalize(&path)? else {
            continue;
        };
        if ty == T::Directory {
            continue;
        }
        let size = entry.header().size().map_err(io)?;
        let wanted = rel == "package.json" || rel == "binding.gyp" || is_script_like(&rel);
        if wanted && size <= MAX_REF_FILE.max(1024 * 1024) && budget + size <= CANDIDATE_BUDGET {
            let mut buf = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut buf).map_err(io)?;
            budget += size;
            if rel == "package.json" {
                manifest = Some(buf);
            } else {
                candidates.insert(rel, buf);
            }
        }
    }
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
    let gyp = candidates.contains_key("binding.gyp");
    let gypfile_off = pj.get("gypfile").and_then(|g| g.as_bool()) == Some(false);
    let has_install = out
        .scripts
        .iter()
        .any(|(k, _)| k == "install" || k == "preinstall");
    if gyp && !gypfile_off && !has_install {
        out.scripts
            .push(("install".into(), "node-gyp rebuild".into()));
    }
    let mut total = 0u64;
    let mut wanted: Vec<String> = Vec::new();
    if gyp {
        wanted.push("binding.gyp".into());
    }
    for (_, cmd) in &out.scripts {
        for tok in cmd.split(|c: char| c.is_whitespace() || "&|;<>()\"'`=".contains(c)) {
            let tok = tok.trim_start_matches("./");
            if !tok.is_empty() && !wanted.iter().any(|w| w == tok) {
                wanted.push(tok.to_string());
            }
        }
    }
    for w in wanted {
        if let Some(bytes) = candidates.remove(&w) {
            let len = bytes.len() as u64;
            if len <= MAX_REF_FILE && total + len <= MAX_REF_TOTAL && out.files.len() < 32 {
                total += len;
                out.files.push(ScriptFile { path: w, bytes });
            }
        }
    }
    Ok(out)
}

fn is_script_like(rel: &str) -> bool {
    [
        ".js", ".cjs", ".mjs", ".sh", ".bat", ".cmd", ".ps1", ".py", ".json", ".gyp",
    ]
    .iter()
    .any(|e| rel.ends_with(e))
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
}
