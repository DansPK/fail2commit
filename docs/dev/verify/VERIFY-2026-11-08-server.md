# Verify Report: Protected remote updates (2026-11-08)

> **Requirements covered:** FR-003 (SPEC-003, TC-003)
> **Commit / branch:** DansPK/f2c-t003-server, base fe411ba; tested tree = the commit that adds this file (`git log -1 -- docs/dev/verify/VERIFY-2026-11-08-server.md`)
> **Verified by:** T-003 worker (Claude)

## 1. Commands Run

```text
Windows 11, rust stable x86_64-pc-windows-gnu, Git for Windows 2.56.0:
  cargo fmt --all -- --check                                  exit 0
  cargo clippy --workspace --all-targets -- -D warnings       exit 0
  cargo test --workspace                                      exit 0 (2 + 9 + 19 passed)
Linux, docker rust:1 (Debian, git 2.47.3), target volume f2c-t003-target:
  docker run --rm -v "${PWD}:/src" -v f2c-t003-target:/target -e CARGO_TARGET_DIR=/target -w /src rust:1 \
    sh -c "rustup component add rustfmt clippy; cargo fmt --all -- --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace --no-fail-fast"
  fmt exit 0, clippy exit 0; tests: server_protected 9/9 pass, fail2commit-core 19/19 pass,
  1 failure OUTSIDE this task: main.rs tests::shims_route_to_subcommands (section 4)
```

## 2. Results

| TC / matrix item | Requirement | Windows | Linux | Evidence (crates/fail2commit/tests/server_protected.rs) |
|---|---|---|---|---|
| TC-003 direct bypass (no local hooks, client hook skip flag) rejected | FR-003 | Pass | Pass | `direct_force_push_without_local_hooks_is_rejected` |
| TC-003 approved rewrite succeeds | FR-003 | Pass | Pass | `approved_rewrite_succeeds` (also: token not stored in approvals.json) |
| TC-003 token replay fails | FR-003 | Pass | Pass | `replayed_token_fails` |
| TC-003 concurrent pushes, one token | FR-003 | Pass | Pass | `concurrent_pushes_with_one_token_allow_exactly_one` |
| TC-003 wrong tuples / actor / expired / junk / no actor | FR-003 | Pass | Pass | `token_for_other_tuples_actor_or_expired_fails` |
| TC-003 non-protected refs and fast-forward pass | FR-003 | Pass | Pass | `fast_forward_and_unprotected_refs_pass` |
| TC-003 protected deletion denied (and approvable) | FR-003 | Pass | Pass | `deleting_protected_ref_is_denied_without_approval` |
| Fail closed on missing policy | FR-003 | Pass | Pass | `missing_policy_fails_closed` |
| Secret policy denies, no value leaked | FR-003 | Pass* | Pass* | `configured_secret_policy_denies_and_never_echoes_the_value` |
| Matrix: server receive over disposable protected repo | FR-003 | Pass | Pass | all above: bare repo, installed hook, `file://` pushes |
| Hosted GitHub rulesets | FR-003 | Pending | Pending | Documentation only (docs/server.md); needs a real GitHub repository |
| Quarantine ancestry over ssh/http transport | FR-003 | Pending | Pending | Needs an SSH or HTTP Git server; only `file://` receive-pack (which also quarantines) was exercised |

\* `git::scan_outgoing` is still a T-001 stub, so this verifies "a configured policy that cannot run denies and leaks nothing". The clean-push-passes path with the real scanner is Pending until T-001 integrates.

## 3. Traceability Check

Not run here (`python .claude/hooks/trace_check.py` is a coordinator integration step); no board files were edited.

## 4. Issues Found

- `crates/fail2commit/src/main.rs` `tests::shims_route_to_subcommands` fails on Linux: it feeds the Windows path `C:\b\NPM.exe`, which Linux `Path::file_stem` does not split on a backslash. Frozen coordinator file, not changed by T-003; reported to the coordinator.
- By design a presented token that does not match is burned (documented in docs/server.md).

## 5. Verdict

- [ ] Verified
- [x] Not fully verified: every implemented TC-003 case passes on both platforms; items marked Pending remain.
