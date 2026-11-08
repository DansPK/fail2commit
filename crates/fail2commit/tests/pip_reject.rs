//! SPEC-005: unreviewable input is rejected before any resolution, fetch or
//! interpreter work.

mod pip_support;

use fail2commit_core::{pip, FindingKind, ResultCode};
use pip_support::*;

fn reject(a: &[&str], files: &[(&str, &str)]) -> (fail2commit_core::Error, usize, usize) {
    let env = Env::new();
    let index = TestIndex::start();
    let wd = env.workdir();
    for (n, c) in files {
        let p = wd.join(n);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, c).unwrap();
    }
    let ctx = env.ctx();
    // A python that does not exist: any attempt to use it would be a bug.
    let py = env.home.path().join("no-such-python");
    let e = pip::install(&ctx, &py, &args(a), &wd, &seams(&index)).unwrap_err();
    (e, index.requests(), env.leftover_runs())
}

#[test]
fn direct_references_and_local_inputs_stop_before_resolution() {
    for bad in [
        "git+https://example.invalid/r.git",
        "pkg @ https://example.invalid/pkg-1-py3-none-any.whl",
        "https://example.invalid/pkg-1-py3-none-any.whl",
        "./pkg",
        "../pkg-1.0.tar.gz",
        "dist/pkg-1-py3-none-any.whl",
        "file:///tmp/pkg",
    ] {
        let (e, reqs, runs) = reject(&[bad], &[]);
        assert_eq!(e.code, ResultCode::InvalidInput, "{bad}");
        assert_eq!(e.findings[0].kind, FindingKind::UnsupportedInput, "{bad}");
        assert_eq!((reqs, runs), (0, 0), "{bad}");
    }
}

#[test]
fn editable_and_index_directives_are_rejected() {
    for bad in [
        &["-e", "."][..],
        &["--editable", "git+https://example.invalid/r.git"],
        &["--index-url", "http://evil.invalid/simple", "pkg"],
        &["--extra-index-url=http://evil.invalid/simple", "pkg"],
        &["-f", "https://evil.invalid/wheels", "pkg"],
        &["--find-links=/tmp/wheels", "pkg"],
        &["--trusted-host", "evil.invalid", "pkg"],
    ] {
        let (e, reqs, _) = reject(bad, &[]);
        assert_eq!(e.findings[0].kind, FindingKind::UnsupportedInput, "{bad:?}");
        assert_eq!(reqs, 0);
    }
}

#[test]
fn requirements_file_directives_and_nesting_are_rejected() {
    for (name, body) in [
        ("index", "--index-url http://evil.invalid/simple\npkg\n"),
        (
            "extra",
            "pkg\n--extra-index-url http://evil.invalid/simple\n",
        ),
        ("find", "-f /tmp/wheels\npkg\n"),
        ("trusted", "--trusted-host evil.invalid\npkg\n"),
        ("editable", "-e ./pkg\n"),
        ("vcs", "pkg @ git+https://example.invalid/r.git\n"),
        ("nested-outside", "-r ../outside.txt\n"),
        ("nested-url", "-r https://evil.invalid/r.txt\n"),
        ("constraint-url", "-c https://evil.invalid/c.txt\npkg\n"),
        ("envvar", "-r ${HOME}/r.txt\n"),
    ] {
        let files = [("proj/req.txt", body), ("outside.txt", "pkg\n")];
        let (e, reqs, runs) = reject(&["-r", "proj/req.txt"], &files);
        assert_eq!(
            e.findings.first().map(|f| f.kind),
            Some(FindingKind::UnsupportedInput),
            "{name}"
        );
        assert_eq!((reqs, runs), (0, 0), "{name}");
    }
}

#[test]
fn nested_file_inside_allowed_tree_can_not_hide_a_direct_reference() {
    let files = [
        ("proj/req.txt", "-r sub/more.txt\n"),
        ("proj/sub/more.txt", "evil @ https://evil.invalid/e.whl\n"),
    ];
    let (e, reqs, _) = reject(&["-r", "proj/req.txt"], &files);
    assert_eq!(e.findings[0].kind, FindingKind::UnsupportedInput);
    assert_eq!(reqs, 0);
}
