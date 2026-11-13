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
