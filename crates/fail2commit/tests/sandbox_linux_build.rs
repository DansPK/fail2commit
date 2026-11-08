//! TC-007: a legitimate native build succeeds in the sandbox and its
//! declared artifact is exported (FR-007, SPEC-007).
//!
//! Toolchain: the host's root-owned /usr/bin/gcc when present, otherwise a
//! staged relocatable gcc sysroot from `F2C_TEST_GCC_ROOT` (built by
//! scripts/linux/stage-gcc.sh), bound read-only.
#![cfg(target_os = "linux")]

mod sandbox_support;

use fail2commit_core::isolation::JobStatus;
use fail2commit_core::sandbox::{run_job, Bubblewrap};
use sandbox_support::*;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const HELLO_C: &str = include_str!("../../../tests/fixtures/sandbox/native/hello.c");
const EXPECTED: &str = "native build ok (15)";

/// `(script, read_only)` for the available toolchain, or None.
fn toolchain() -> Option<(String, Vec<PathBuf>)> {
    let gcc = Path::new("/usr/bin/gcc");
    if gcc.metadata().is_ok_and(|m| m.uid() == 0) {
        return Some(("gcc -O2 -o hello hello.c && ./hello".into(), vec![]));
    }
    let root = PathBuf::from(std::env::var_os("F2C_TEST_GCC_ROOT")?)
        .canonicalize()
        .ok()?;
    let script = format!(
        "R='{r}'; LD_LIBRARY_PATH=\"$R/f2c-libs\" PATH=\"$R/usr/bin:$PATH\" \
         gcc --sysroot=\"$R\" -O2 -o hello hello.c && ./hello",
        r = root.display()
    );
    Some((script, vec![root]))
}

#[test]
fn native_c_build_succeeds_and_exports_artifact() {
    let Some(b) = backend(Bubblewrap::default(), "native_c_build") else {
        return;
    };
    let Some((script, read_only)) = toolchain() else {
        if required("F2C_REQUIRE_NATIVE_BUILD") {
            panic!("no root-owned /usr/bin/gcc and no F2C_TEST_GCC_ROOT");
        }
        skip("native_c_build", "no gcc toolchain available");
        return;
    };
    let (work, mut spec) = job("/bin/bash", &["-c", &script]);
    std::fs::write(work.path().join("hello.c"), HELLO_C).unwrap();
    spec.read_only = read_only;
    let out_dir = tempfile::tempdir().unwrap();
    spec.exports = vec!["hello".into()];
    spec.export_to = Some(out_dir.path().to_path_buf());
    let out = run_job(&b, &spec).unwrap();
    assert_eq!(
        out.status,
        JobStatus::Exited(0),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert_eq!(text(&out.stdout).trim(), EXPECTED);
    assert_eq!(out.exported, vec![out_dir.path().join("hello")]);
    assert!(out_dir.path().join("hello").metadata().unwrap().len() > 0);
}
