//! Defensive wheel inspection. Nothing is extracted to disk or executed.

use super::interp::normalize;
use std::io::Read;
use std::path::Path;

const MAX_ENTRIES: usize = 200_000;
const MAX_METADATA: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelInfo {
    pub name: String,
    pub version: String,
    pub requires_dist: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WheelError {
    /// Malformed or hostile archive.
    Invalid(String),
    /// A dependency is a direct reference (`name @ url`, VCS, path).
    DirectReference(String),
}

/// `(name, version)` from `name-version(-build)?-py-abi-platform.whl`.
pub fn parse_filename(filename: &str) -> Option<(String, String)> {
    let stem = filename.strip_suffix(".whl")?;
    let parts: Vec<&str> = stem.split('-').collect();
    if !(parts.len() == 5 || parts.len() == 6) || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let ok = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+!".contains(&b))
    };
    if !parts.iter().all(|p| ok(p)) {
        return None;
    }
    Some((normalize(parts[0]), parts[1].to_ascii_lowercase()))
}

fn same_version(a: &str, b: &str) -> bool {
    let n = |s: &str| s.to_ascii_lowercase().replace('-', "_");
    n(a) == n(b)
}

/// Validate the archive at `path` against its advertised `filename`.
pub fn inspect(
    path: &Path,
    filename: &str,
    max_uncompressed: u64,
) -> Result<WheelInfo, WheelError> {
    let bad = |m: String| WheelError::Invalid(m);
    let (fname, fver) =
        parse_filename(filename).ok_or_else(|| bad(format!("bad wheel filename {filename}")))?;
    let file = std::fs::File::open(path).map_err(|e| bad(format!("open: {e}")))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| bad(format!("not a zip archive: {e}")))?;
    if zip.is_empty() || zip.len() > MAX_ENTRIES {
        return Err(bad(format!("{} entries", zip.len())));
    }
    let mut total: u64 = 0;
    let mut metadata_name: Option<String> = None;
    let mut has_wheel = false;
    let mut has_record = false;
    for i in 0..zip.len() {
        let entry = zip
            .by_index_raw(i)
            .map_err(|e| bad(format!("entry {i}: {e}")))?;
        let name = String::from_utf8_lossy(entry.name_raw()).into_owned();
        check_entry_name(&name).map_err(bad)?;
        if entry.is_symlink() || entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            return Err(bad(format!("symlink entry {name}")));
        }
        total = total.saturating_add(entry.size());
        if total > max_uncompressed {
            return Err(bad("uncompressed size exceeds the limit".into()));
        }
        if let Some((dir, leaf)) = name.split_once('/') {
            if dir.ends_with(".dist-info") {
                match leaf {
                    "METADATA" => {
                        if metadata_name.replace(dir.to_string()).is_some() {
                            return Err(bad("more than one METADATA".into()));
                        }
                    }
                    "WHEEL" => has_wheel = true,
                    "RECORD" => has_record = true,
                    _ => {}
                }
            }
        }
    }
    let dist_info = metadata_name.ok_or_else(|| bad("no .dist-info/METADATA".into()))?;
    if !has_wheel || !has_record {
        return Err(bad("missing WHEEL or RECORD".into()));
    }
    let mut text = String::new();
    zip.by_name(&format!("{dist_info}/METADATA"))
        .map_err(|e| bad(format!("METADATA: {e}")))?
        .take(MAX_METADATA)
        .read_to_string(&mut text)
        .map_err(|_| bad("METADATA is not UTF-8".into()))?;
    let info = parse_metadata(&text)?;
    if normalize(&info.name) != fname || !same_version(&info.version, &fver) {
        return Err(bad(format!(
            "METADATA {} {} does not match filename {filename}",
            info.name, info.version
        )));
    }
    Ok(info)
}

/// A file the wheel installs into `purelib`/`platlib` that CPython's `site`
/// module executes at every interpreter start of that environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupFile {
    /// Entry name inside the wheel.
    pub entry: String,
    pub why: &'static str,
}

/// Where in `purelib`/`platlib` this entry would land, if it lands there.
fn site_relative(name: &str) -> Option<&str> {
    let Some((first, rest)) = name.split_once('/') else {
        return Some(name);
    };
    if first.ends_with(".data") {
        let (scheme, rest) = rest.split_once('/')?;
        return matches!(scheme, "purelib" | "platlib").then_some(rest);
    }
    Some(name)
}

/// Files that run at interpreter start-up once installed (W2-001, CR-001):
/// a top-level `*.pth` with an `import` line, `sitecustomize` and
/// `usercustomize` (module, bytecode or package). Nothing is extracted.
pub fn startup_files(path: &Path) -> Result<Vec<StartupFile>, WheelError> {
    let bad = |m: String| WheelError::Invalid(m);
    let file = std::fs::File::open(path).map_err(|e| bad(format!("open: {e}")))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| bad(format!("not a zip archive: {e}")))?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| bad(format!("entry {i}: {e}")))?;
        let name = String::from_utf8_lossy(entry.name_raw()).replace('\\', "/");
        let Some(rel) = site_relative(&name) else {
            continue;
        };
        let lower = rel.to_ascii_lowercase();
        if !lower.contains('/') && lower.ends_with(".pth") {
            let mut head = Vec::new();
            let _ = (&mut entry).take(MAX_METADATA).read_to_end(&mut head);
            // site.py: a line starting with `import` + space/tab is exec()'d.
            let runs = head
                .split(|b| *b == b'\n')
                .any(|l| l.starts_with(b"import ") || l.starts_with(b"import\t"));
            if runs {
                out.push(StartupFile {
                    entry: name,
                    why: ".pth import line run by Python at every start",
                });
            }
            continue;
        }
        let stem = lower.split('/').next().unwrap_or("");
        let stem = stem.split('.').next().unwrap_or("");
        if stem == "sitecustomize" || stem == "usercustomize" {
            out.push(StartupFile {
                entry: name,
                why: "imported by Python at every start",
            });
        }
    }
    Ok(out)
}

fn check_entry_name(name: &str) -> Result<(), String> {
    let p = name.replace('\\', "/");
    if p.starts_with('/')
        || p.split('/').any(|c| c == "..")
        || (p.len() > 1 && p.as_bytes()[1] == b':')
        || p.contains('\0')
    {
        return Err(format!("unsafe entry path {name}"));
    }
    Ok(())
}

/// Headers up to the first blank line; `Requires-Dist` must be registry names.
pub fn parse_metadata(text: &str) -> Result<WheelInfo, WheelError> {
    let (mut name, mut version, mut deps) = (None, None, Vec::new());
    for line in text.lines() {
        if line.trim().is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "name" => name = Some(v.to_string()),
            "version" => version = Some(v.to_string()),
            "requires-dist" => {
                let req = v.split(';').next().unwrap_or("").trim();
                if req.contains('@')
                    || req.contains("://")
                    || req.contains('/')
                    || req.contains('\\')
                {
                    return Err(WheelError::DirectReference(v.to_string()));
                }
                deps.push(v.to_string());
            }
            _ => {}
        }
    }
    match (name, version) {
        (Some(name), Some(version)) => Ok(WheelInfo {
            name,
            version,
            requires_dist: deps,
        }),
        _ => Err(WheelError::Invalid("METADATA lacks Name or Version".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build(entries: &[(&str, &str)]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        let mut z = zip::ZipWriter::new(f.reopen().unwrap());
        let o = zip::write::SimpleFileOptions::default();
        for (n, c) in entries {
            z.start_file(*n, o).unwrap();
            z.write_all(c.as_bytes()).unwrap();
        }
        z.finish().unwrap();
        f
    }

    const MD: &str =
        "Metadata-Version: 2.1\nName: Foo_Bar\nVersion: 1.0\nRequires-Dist: baz (>=1)\n";

    fn ok_entries() -> Vec<(&'static str, &'static str)> {
        vec![
            ("foo_bar-1.0.dist-info/METADATA", MD),
            ("foo_bar-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n"),
            ("foo_bar-1.0.dist-info/RECORD", ""),
            ("foo_bar.py", "x=1\n"),
        ]
    }

    #[test]
    fn accepts_valid_wheel() {
        let f = build(&ok_entries());
        let i = inspect(f.path(), "foo_bar-1.0-py3-none-any.whl", 1 << 20).unwrap();
        assert_eq!((i.name.as_str(), i.requires_dist.len()), ("Foo_Bar", 1));
    }

    #[test]
    fn rejects_hostile_wheels() {
        let mut e = ok_entries();
        e.push(("../evil.py", "x"));
        assert!(matches!(
            inspect(build(&e).path(), "foo_bar-1.0-py3-none-any.whl", 1 << 20),
            Err(WheelError::Invalid(_))
        ));
        // name/version substitution
        assert!(inspect(
            build(&ok_entries()).path(),
            "other-1.0-py3-none-any.whl",
            1 << 20
        )
        .is_err());
        assert!(inspect(
            build(&ok_entries()).path(),
            "foo_bar-2.0-py3-none-any.whl",
            1 << 20
        )
        .is_err());
        // size bound
        assert!(inspect(
            build(&ok_entries()).path(),
            "foo_bar-1.0-py3-none-any.whl",
            4
        )
        .is_err());
        // not a zip
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), b"MZ not a zip").unwrap();
        assert!(inspect(f.path(), "foo_bar-1.0-py3-none-any.whl", 1 << 20).is_err());
        // transitive direct reference
        let md = "Name: foo_bar\nVersion: 1.0\nRequires-Dist: evil @ https://evil.test/e.whl\n";
        let e = vec![
            ("foo_bar-1.0.dist-info/METADATA", md),
            ("foo_bar-1.0.dist-info/WHEEL", "x"),
            ("foo_bar-1.0.dist-info/RECORD", ""),
        ];
        assert!(matches!(
            inspect(build(&e).path(), "foo_bar-1.0-py3-none-any.whl", 1 << 20),
            Err(WheelError::DirectReference(_))
        ));
    }

    #[test]
    fn startup_files_are_found_where_site_would_run_them() {
        let mut e = ok_entries();
        e.push(("x.pth", "import os\n"));
        e.push(("plain.pth", "/some/dir\n# import not a command\n"));
        e.push(("sitecustomize.py", "x=1\n"));
        e.push(("foo_bar-1.0.data/purelib/y.pth", "import sys\n"));
        e.push(("foo_bar-1.0.data/scripts/z.pth", "import sys\n"));
        e.push(("pkg/inner.pth", "import sys\n"));
        let f = build(&e);
        let names: Vec<String> = startup_files(f.path())
            .unwrap()
            .into_iter()
            .map(|s| s.entry)
            .collect();
        assert_eq!(
            names,
            [
                "x.pth",
                "sitecustomize.py",
                "foo_bar-1.0.data/purelib/y.pth"
            ]
        );
        assert!(startup_files(build(&ok_entries()).path())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn filenames() {
        assert_eq!(
            parse_filename("Foo_Bar-1.0-1-cp312-cp312-win_amd64.whl"),
            Some(("foo-bar".into(), "1.0".into()))
        );
        assert_eq!(parse_filename("foo-1.0.tar.gz"), None);
        assert_eq!(parse_filename("foo-1.0.whl"), None);
    }
}
