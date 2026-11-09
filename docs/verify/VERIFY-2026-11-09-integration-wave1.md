# Verify Report: integration wave 1 (2026-11-09)

> **Requirements covered:** FR-001, FR-002, FR-003, FR-008, FR-009, FR-010 (code and automated tests; platform release gates are tracked separately)
> **Commit / branch:** `5142237` on `DansPK/f2c-int-wave1`, fast-forwarded into `DansPK/f2-commit-coordinator`
> **Verified by:** Orca coordinator (gate run), independent reviewers (security review rounds)

---

## 1. Commands Run

Gate script (coordinator scratchpad `gate.ps1`), run from the candidate worktree:

```text
cargo fmt --all -- --check
cargo clippy -j 3 --workspace --all-targets --locked -- -D warnings
<empty file> | cargo test -j 3 --workspace --locked --no-fail-fast        # Windows, no interactive stdin
python .claude/hooks/trace_check.py
docker run --rm -v <tree>:/src -v f2c-gate-target:/target -e CARGO_TARGET_DIR=/target -w /src rust:1 \
  cargo test -j 3 --workspace --locked --no-fail-fast                      # Linux
```

Host: Windows 11 Pro 10.0.26200, Rust 1.99.1 (x86_64-pc-windows-gnu), Git 2.56.0.windows.2. Linux: `rust:1` (Debian) container, Docker 29.8.2, WSL2 VM capped at 4 CPUs / 16 GB.

## 2. Results

| Check | Exit | Result |
|---|---:|---|
| fmt | 0 | clean |
| clippy `-D warnings` | 0 | clean |
| Windows `cargo test --workspace` | 0 | 151 passed, 0 failed |
| traceability | 0 | OK |
| Linux `cargo test --workspace` | 0 | 139 passed, 0 failed |

Branches in this wave: T-001 `9828da7`, T-002 `6f649d9`, T-003 `24e352c`, T-008 `b46bb45`, T-009 `f4eb8cf`, T-010 `6e0a4ad`, plus the review fixes `63389f4`, `61551a6`, `7c0889d`, `c119212` and `5142237`.

## 3. Security review trail

| Round | Report | Outcome |
|---|---|---|
| Review | `docs/verify/REVIEW-2026-11-09-wave1.md` | W1-001..W1-005 found (3 high) |
| Re-review 1 | `docs/verify/REREVIEW-2026-11-09-wave1.md` | W1-002..005 fixed; W1-001 partial; R1-001..006 found |
| Re-review 2 | `docs/verify/REREVIEW2-2026-11-09-git.md` | R1-001..003 fixed (class closed); R2-001..003 found |
| Fix | `5142237` | R2-001..003 fixed; the reviewer's reproductions `rereview2_git.rs` pass |

Every reviewer reproduction (`review_wave1.rs`, `rereview_wave1.rs`, `rereview2_git.rs`) is a permanent regression test.

## 4. Issues Found

None open in this wave's code. Pending platform evidence (not covered by this gate): real interactive terminal and tray prompts (GUI), clean Windows 11 install/uninstall, VS Code against the built CLI on Windows and WSL, GitHub ruleset behavior. These belong to the release verification.

## 5. Verdict

- [x] Code and automated tests for the wave pass on Windows and Linux at `5142237`
- [ ] Requirement status `Verified`: pending the platform release gates above
