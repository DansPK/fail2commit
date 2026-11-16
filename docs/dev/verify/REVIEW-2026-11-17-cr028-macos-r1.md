# Review: CR-028 macOS arm64 (fail closed) — origin/DansPK/f2c-014-macos @ e3ccbb9 vs b0deb7b

Reviewer: Opus 5.5, read-only. Host action: `git archive e3ccbb9` into scratchpad + `cargo check -p fail2commit --bins --locked -j 2` with CARGO_TARGET_DIR under %TEMP% (no tests or binaries run).

## Findings (most severe first)

1. CRITICAL: Windows build broken. crates/fail2commit/src/cmd/progress_ui.rs:137 renames `finish(&self, end, ..)` to `_end`, but the `#[cfg(windows)]` body still uses `end` (lines 145, 151, 152). Verified: cargo check on Windows gives `error[E0425]: cannot find value 'end'` x3. Impact: the release Windows job and every Windows build fail. Fix: keep the name `end` and add `#[cfg(not(windows))] let _ = end;` (or `#[cfg_attr(not(windows), allow(unused_variables))]` on the fn).

2. HIGH: Windows sandbox e2e test weakened. crates/fail2commit/tests/e2e_npm_sandbox.rs:70-90. Before, Windows always returned true, so the test ran and failed if AppContainer was missing. Now, if the Windows probe is unavailable, the test falls through to the Linux path and SKIPS with "no usable bubblewrap" unless F2C_REQUIRE_SANDBOX is set. Windows CI never sets that variable, so a broken AppContainer turns into a silent pass. Fix: `if cfg!(windows) { return true; }` before the unavailable branch, so only non-Linux, non-Windows platforms skip.

3. HIGH (evidence integrity): docs/dev/verify/VERIFY-2026-11-17-macos-arm64.md smoke step 7 quotes `thread 'main' panicked at crates/fail2commit/src/cmd/shim.rs: sandbox unavailable: no sandbox backend on macOS yet` with exit code 101. In e3ccbb9, crates/fail2commit/src/cmd/shim.rs does not exist and the string "sandbox unavailable" appears nowhere in src. The expected result is a structured isolation_unavailable error with exit code 14 (exec/mod.rs:115, protocol.rs:47). Either the evidence did not come from this build, or there is a real panic bug. The report also records clippy passing (macOS only) while Windows does not compile. Fix: re-run the smoke test on the Mac mini from the exact commit and record the real output and exit code. If it really panics, fix that. Also add an automated macOS assertion: npm install of a fixture with an install script returns code 14 and the script's marker file is absent. Today the e2e tests just skip on macOS, so the only automated fail-closed check is the unit test run_job(&Unavailable).

4. MEDIUM (docs accuracy): docs/macos.md:19-22, README-MACOS.txt (build.sh) and CR-028 say any operation that needs isolation is refused. That is true only while `sandbox.enabled = true` (the default). With the trusted setting `sandbox.enabled = false`, policy.rs:56-57 returns SkipScripts, or AskHostOnce for required scripts. exec/mod.rs:81-103 then offers "Run on host once" and runs the package scripts unsandboxed after approval. This is the same intentional opt-out as on Linux and Windows, not a code bug. But macOS users who hit fail-closed every time are the most likely to turn the sandbox off. Also, with the sandbox on, any package that HAS scripts is denied (policy.rs:55), not only packages that need them. Fix: document both, and say that turning the sandbox off means approved scripts run with full user access.

5. LOW: README.md:84 names `fail2commit-0.1.4-aarch64-apple-darwin.tar.gz`, but the workspace version is 0.1.3, and build.sh/the verify report produce a 0.1.3 archive. Fix: match the other rows (0.1.3) or bump consistently.

6. LOW: crates/fail2commit/Cargo.toml:17 adds `libc` as a normal `cfg(unix)` dependency, but only tests/approval_support uses it. Move it to `[target.'cfg(unix)'.dev-dependencies]`. On Linux, the setsid change (pre_exec libc::setsid instead of the setsid(1) binary) behaves the same, because the child is never a group leader.

7. LOW: packaging/macos/build.sh:7-8,18 reads the version from `$commit` but `cargo build` compiles the working tree, so commit != HEAD or a dirty tree gives a mislabelled archive. Fix: fail unless `git rev-parse HEAD` equals `$commit` and `git status --porcelain` is empty. `$out` is always joined to `$repo`, so an absolute path breaks. The script also ships the non-Linux `f2c-sandbox-relay` stub if present; that is harmless, but it can be excluded.

8. LOW: hardened/service.rs:6557 `windows_path_comparison_handles_case_and_verbatim_prefix_only` used to run on Linux too (it tests a pure string function) and is now Windows-only. It still runs on its real platform, so this is acceptable; `cfg(any(windows, target_os = "linux"))` would keep the Linux coverage. git_push.rs:256 changing unix to linux is fine, since Linux still runs it.

## Checked, no issue
- Fail-closed trace on macOS: platform_backend gives Unavailable. select_backend: Vm gives UnavailableVm (available=false, no PlatformFallback). Hardened is chosen only when installed, and its serve/probe fail on macOS. run_job_locked refuses when !available. script_decision(true,false) gives Deny(IsolationUnavailable). explicit_run_allowed refuses `fail2commit run`. The real npm always gets `--ignore-scripts` and pip gets `--only-binary=:all:`. I found no env var, `ignore` default or Unavailable-means-skip fallback.
- cfg edits: the `cfg_attr(not(any(linux, windows)), allow(dead_code))` lines have no effect on Linux or Windows. The service.rs import cfg swap changes nothing for Linux or Windows. Unavailable's message change is macOS-only.
- rereview* canonicalize changes fall back to the original strip_prefix, so the assertions are not weakened. The rereview_npmscan extra root only widens the search.
- release.yml: workflow_dispatch only, `permissions: contents: read`, actions pinned by SHA, no secrets, uploads only the *.tar.gz and .sha256 files, and hashes now depends on macos.
- Approval: tray_approver is None on non-Windows, so it falls back to the terminal or fails closed.

## Verdict
REJECT at e3ccbb9 (the Windows build break). It becomes ACCEPT-WITH-FIXES once findings 1-3 are fixed and 4 is documented; 5-8 are optional cleanups.
