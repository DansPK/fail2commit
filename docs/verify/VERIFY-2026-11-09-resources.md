# Verify: NFR-012 resource measurements (TC-012), 2026-11-09

Tested tree: base `3d924c1` (DansPK/f2c-int-wave2 candidate) plus the T-012
changes, committed afterwards as the NFR-012 commit on `DansPK/f2c-t012-resources`.
Numbers and analysis: `docs/resources.md`.

## Result

| Item | Status |
|---|---|
| Windows release binary size, startup, scans, advisory cache, tray idle RAM | Verified (measured) |
| Linux release binary size, startup, scans, advisory cache | Verified (measured, WSL2 Ubuntu) |
| Linux sandbox native-build peak memory | Verified (measured, `rust:1` --privileged, bwrap 0.12, rlimits only) |
| Windows sandbox native-build peak memory | **Pending**: T-007b AppContainer backend not in this branch (`sandbox status` reports `appcontainer: backend not implemented`) |
| Assertion tests (Windows) | resource_bounds 5 passed; resource_process compiles to 0 tests (Linux only) |
| Assertion tests (Linux, real bwrap, `F2C_REQUIRE_SANDBOX=1`) | resource_process 2 passed, 1 ignored (known gap); resource_bounds also bundled |
| One active sandbox build per user | **Finding**: not enforced (see below) |
| Configured limits reported by CLI | **Finding**: not reported by `status` |

## Commands and exit codes

All from the worktree root unless noted.

| Command | Exit |
|---|---|
| `cargo build --release -j 2 -p fail2commit -p fail2commit-tray` (6m38s) | 0 |
| `powershell -NoProfile -File scripts/bench/run.ps1 -Runs 20 -SkipBuild` | 0 |
| `cargo test -j 2 -p fail2commit --test resource_bounds --test resource_process` | 0 |
| `powershell -File scripts/linux/test.ps1 -Volume f2c-t012 -Stage container,wsl -Gcc -NoCheck -Filter '^resource_'` | 0 (`bundle result: PASS`) |
| `docker run --rm -v <repo>:/src -v f2c-t012-target:/target -v f2c-rustup:/usr/local/rustup -v f2c-cargo-registry:/usr/local/cargo/registry -v <repo>/target/bench-linux:/out -e CARGO_TARGET_DIR=/target -w /src rust:1 bash scripts/bench/run.sh build /out` | 0 |
| `wsl -d Ubuntu --exec bash scripts/bench/run.sh measure <target/bench-linux> 20` | 0 |
| `docker run --rm --privileged -v <repo>:/src:ro -v <repo>/target/bench-linux:/out -w /src rust:1 bash scripts/bench/privileged.sh /out 20` | 0 |
| `<resource_process bundle binary> --ignored` in WSL (`F2C_REQUIRE_SANDBOX=1`) | non-zero: `second_concurrent_build_is_queued_or_refused` failed, "builds overlapped (2.27s)" (expected: this records the gap) |

Two earlier attempts are not counted: a background-subshell launch killed when its
shell exited, and a bench run with a corrupt staged gcc tarball (two docker jobs
wrote the same file). Both were rerun cleanly. The native-build leg was first
measured with `getrusage` from outside bwrap, which undercounted (14 MB); the
harness now measures inside the sandbox.

Raw results: `target/bench/windows.json`, `target/bench/tray.json`,
`target/bench-linux/linux.json`, `target/bench-linux/linux-privileged.json`
(not committed; `target/` is ignored). Re-create with the commands above.

## Evidence for the findings

1. Two concurrent `fail2commit run --input <dir> -- /bin/sleep 2` with one
   `FAIL2COMMIT_HOME` took 2.3 s wall (WSL, bubblewrap). Neither was queued or
   refused. `grep` of `crates/` finds no per-user lock in `cmd/run.rs` or
   `sandbox/`. Not fixed here (another task's area).
2. `fail2commit --json status` data has `version`, `integrations`, `sandbox`,
   `paths`; no limits. Pinned by `status_does_not_yet_report_limits`.

## Skipped or simulated

Nothing simulated. Skips: Windows native-build memory (Pending, above); the
`resource_process` tests print `SKIP (pending evidence)` when bwrap is missing,
and did not skip in the WSL run (`F2C_REQUIRE_SANDBOX=1`).
