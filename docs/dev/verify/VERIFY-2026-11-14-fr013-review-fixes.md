# FR-013 progress review fixes verification

Code commit tested: `c30128bd43dd775dfacabbfc1f09fde711fd9bb0` (based on `6536c6b46a0945070337afd7f652696b19409b12`).

## Finding dispositions

1. **GUI join withheld CLI result:** Removed GUI thread joins from progress completion. Non-clean outcomes are passed to a same-executable result-window process using a bounded (at most 1 KiB UTF-8) hex-encoded argument; the parent queues window closure without waiting, so CLI outcome delivery cannot depend on the GUI thread. The result window is independent of the operation, and closing it does not cancel the operation. The argument contains only generic result text and at most three sanitized display summaries, never raw findings. **Tradeoff:** the bounded encoded payload is visible in the child process command line to principals able to inspect same-user process arguments; if the helper process cannot start, the CLI remains nonblocking and reports the retention failure to interactive stderr, but no persistent window is retained. A live window requires an interactive desktop.
2. **Pip activity absent:** Emits a download/verification phase with unknown initial total, current project/filename while fetching, and increments only on successful fetch, hash verification, and wheel inspection. Once the staged plan is available it reports the final wheel total and completion count.
3. **Npm counter incorrect:** Phase total now counts unique artifacts actually fetched, excluding platform-skipped entries. Concurrent successful verification increments an atomic counter only after success; failures do not count.
4. **ScanOutput timing:** Progress completion is advanced only after `review_output` returns successfully; scan failure leaves the phase incomplete.
5. **YARA findings not live:** Findings from each package scan are sent to the progress sink immediately, before continuing to later package scans.

## Verification

- `cargo fmt --all` — exit 0.
- `cargo fmt --all -- --check` — exit 0.
- `cargo check --tests -p fail2commit -p fail2commit-core` — exit 0.
- `cargo test -p fail2commit-core progress_tests` — exit 0, 6 passed.
- `cargo test -p fail2commit --bin fail2commit progress_ui::tests` — exit 0, 3 passed.
- `cargo build -p fail2commit --bin fail2commit` — exit 0.
- `git diff --check` — exit 0.
- Windows host UI smoke (non-sandbox): launched the result-window child, observed its title, sent close, and confirmed child exited with code 0. This verifies the native window creation and close path, not Windows VM evidence.

## Pending platform evidence

The Windows VM was started but remained at its lock screen. VMware rejected interactive guest execution because no guest user was logged in; the temporary copied smoke executable was deleted. No runtime sandbox tests were run on the host. Windows VM GUI behavior and disposable-VM terminal/sandbox runtime evidence remain pending an interactive VM session. No shared VM was shut down.

## Follow-up runtime verification (source `40c512efa2fee78ad440ca71178a74856a2b4d8f`)

Two focused fixes were committed after the original review commit `c30128bd43dd775dfacabbfc1f09fde711fd9bb0`: `4383611d9c48faaefb9f2aa47efd7fbed4ccbca6` adds an explicit Windows process handle allowlist and null standard handles for the result helper, and defers pip completion counts until the resolver's final plan is known; `40c512efa2fee78ad440ca71178a74856a2b4d8f` also resets the displayed phase to Resolve before marking resolver completion. The result-window child cannot inherit captured parent pipes, so CLI output EOF does not wait for the retained window.

### Passed

- `cargo fmt --all -- --check` — exit 0; `git diff --check` — exit 0.
- `cargo test -p fail2commit --bin fail2commit result_helper_does_not_hold_captured_parent_pipes_open -- --nocapture` — exit 0, 1 passed. The regression observes captured stdout EOF while the result helper remains open.
- `cargo test -p fail2commit --test pip_install backtracked_candidate_activity_does_not_count_as_final_plan_completion -- --nocapture` — exit 0, 1 passed. The local resolver fixture backtracks from beta 2 to beta 1; candidate events remain `0/0`, resolution completes in its own phase, and only the final plan advances download completion.
- `cargo test -p fail2commit-core progress_tests -- --nocapture` — exit 0, 6 passed.
- Built exact source `40c512efa2fee78ad440ca71178a74856a2b4d8f` on disposable Debian 12 guest `debian-f2c` using task-local Rust 1.100.0 dirs: `cargo build --locked -j 2 -p fail2commit --bin fail2commit` — exit 0. Binary SHA-256: `3466be17df64765c8285fb1ae467b413666b73f9fff0f144fac2bfd0ec0f04a8`.
- Linux terminal PTY install with the exact built binary and a local one-wheel pip index — exit 0; first progress paint 11.2 ms; prompt observed and progress line cleared before it. Transcript `pip-r2-pty.log` records pip candidate events at `0/0`, Resolve `1/1`, then final download verification `1/1`; no `1/0` counter. Installation was into a dedicated temporary venv.
- Linux terminal PTY npm install from a local registry with three unique artifacts fetched concurrently — exit 0; first progress paint 9.4 ms; prompt observed and progress line cleared before it. Transcript `npm-concurrent-pty.log` shows verified count increasing `1/3`, `2/3`, `3/3`; install used a dedicated temporary project.
- Fixtures used synthetic local packages only. Linux terminal prompts were approved in the disposable guest; no global install, system package, repository hook, or sandbox lifecycle state was changed. Linux status and API/JSON/redirected-stderr probes were also run; status/API output had no terminal progress. (The final compact capture for status/redirected stderr could not be retrieved through VMware Tools, so those probes are not counted as passed here.)

### Pending platform evidence

- **Windows native progress/result window:** first paint within 1 second, clean auto-close, retained findings while CLI exits, and closing the window without cancelling review remain unverified in a disposable Windows desktop. Win11 was manager-reserved and started for this work; it had no logged-on interactive session, later returned to powered off, and was left untouched. Interactive login/unlock by the owner is the remaining prerequisite. I did not touch win10 or stop any VM.
- **Windows npm/pip integration:** not run because the Windows desktop was unavailable and the guest's sandbox probe reported `CreateAppContainerProfile failed: HRESULT 0x80070002`; do not treat this as a successful package runtime check.
- **Windows prompt/terminal behavior and setting toggle:** JSON/API/headless and redirected-invalid-input silence were observed against an earlier Windows binary at source `4383611d9c48faaefb9f2aa47efd7fbed4ccbca6` (before the later phase-label-only commit), with stderr empty for JSON/API. These do not establish current-source Windows GUI behavior or a visible `ui.progress_window=false` toggle.
- **Linux window behavior:** not applicable to the Windows native progress-window implementation; native terminal PTY behavior was observed on the exact `40c512e` binary above.

Exact-code review regressions and Linux PTY flows pass. Windows native GUI and current-source Windows package flows remain pending the owner unlocking the reserved guest; no host runtime sandbox tests were run.

## Sol r3 follow-up: monotonic pip steps

**Fix commit:** `7b775d10c6cd2d5ec74765d1ae12a1833bd1e403` (based on the review snapshot `1991f1fca09ce346e0027d659c52adb1a6cf0098`). Candidate fetch and verification messages now stay in the already-active `Resolve` step, with `done=0`; pip enters `DownloadVerify` only after it has fixed the final report and publishes the selected wheel total once. No candidate is represented as completed work in the final plan, and the frozen step ordering remains unchanged.

The backtracking integration regression now records the complete event stream. It asserts every step is monotonic, candidate activity is associated with `Resolve` and always has zero completion, rejected beta 2.0 is visible, the final `DownloadVerify` total and immediate completion are exactly 3/3, and resolver completion is separate. The result-helper captured-pipe EOF regression remains intact.

### Exact checks on `7b775d10c6cd2d5ec74765d1ae12a1833bd1e403`

- `cargo fmt --all -- --check` — exit 0.
- `cargo test -p fail2commit --test pip_install backtracked_candidate_activity_does_not_count_as_final_plan_completion -- --nocapture` — exit 0, 1 passed (actual pip resolver backtracking fixture).
- `cargo test -p fail2commit --bin fail2commit result_helper_does_not_hold_captured_parent_pipes_open -- --nocapture` — exit 0, 1 passed (captured parent stdout reaches EOF while the result helper remains alive).
- `cargo test -p fail2commit-core progress_tests -- --nocapture` — exit 0, 6 passed.
- `git diff --check` — exit 0.
- One overlapping cargo invocation initially failed to link because it attempted to overwrite the integration-test executable while the first test was still running (Windows linker reported `Permission denied`); after the first process completed, the focused regression was rerun sequentially and passed. No source change was needed for that transient collision.

Windows native GUI and current-source Windows npm/pip runtime gates remain pending the interactive Win11 guest, as recorded above. No broad build or new VM runtime pass was attempted for this narrowly scoped source fix.
