# Verify Report: Git protection, T-001 (2026-11-09)

> **Requirements covered:** FR-001 (SPEC-001, TC-001 and the Git rows of the cross-platform matrix)
> **Commit / branch:** base `fe411ba` + T-001 commit on `DansPK/f2c-t001-git` (final SHA is in the worker_done report; a report cannot cite its own commit)
> **Verified by:** T-001 worker (claude-sonnet)

---

## 1. Commands Run

Windows 11 host, Rust stable `x86_64-pc-windows-gnu`, Git for Windows 2.56.0:

```text
cargo fmt --all -- --check                                   -> exit 0
cargo clippy --workspace --all-targets -- -D warnings        -> exit 0
cargo test --workspace                                       -> exit 0
  fail2commit bin unit tests 3 passed; git_push 13 passed; git_setup 6 passed;
  fail2commit-core 25 passed (10 are git::*)
python .claude/hooks/trace_check.py                          -> [guard:trace_check] OK
```

Linux, Docker `rust:1` (Debian, rustc 1.99.1, git), `sh linux.sh` running
`rustup component add rustfmt clippy`, then:

```text
cargo fmt --all -- --check                                   -> exit 0
cargo clippy --workspace --all-targets -- -D warnings        -> exit 0 (no diagnostics)
cargo test --workspace --no-fail-fast
  git_setup 6 passed; fail2commit-core 25 passed
  git_push 14 passed (the 14th, non-UTF-8/newline filenames, is unix-only; confirmed with
  `cargo test -p fail2commit --test git_push` after fixing the fixture)
  FAILED: fail2commit bin tests::shims_route_to_subcommands (see Issues)
```

## 2. Results

| TC / matrix item | Requirement | Windows | Linux | Evidence (test name in `crates/fail2commit/tests/`) |
|---|---|---|---|---|
| TC-001 normal push passes | FR-001 | Pass | Pass | `fast_forward_passes` |
| Forced refspec `+ref`, wildcard | FR-001 | Pass | Pass | `rewrite_blocked_for_force_and_both_lease_styles`, `shim_force_intent_needs_confirmation_even_without_rewrite` |
| Both lease styles, force alias, short flag | FR-001 | Pass | Pass | same two tests (`--force`, `-f`, `-fu`, `--force-with-lease`, `--force-with-lease=ref:oid`, `--force-if-includes`) |
| Configured forced refspec, mirror | FR-001 | Pass | Pass | `configured_forced_refspec_and_mirror_are_intent` |
| Multiple refs, one plan | FR-001 | Pass | Pass | `multiple_refs_are_reviewed_in_one_plan` |
| Tag replacement; deletion (separate findings) | FR-001 | Pass | Pass | `tag_replacement_and_deletion_are_separate_findings` |
| Shallow / missing old object is a finding | FR-001 | Pass | Pass | `missing_old_object_is_a_finding_not_safe` (stale clone lacking the remote's commit; IncompleteScan) |
| SHA-256 repository | FR-001 | Pass | Pass | `sha256_repositories_are_supported` (`git init --object-format=sha256` works on both) |
| First branch; add/delete secret history; deleted `.env` pauses | FR-001 | Pass | Pass | `first_branch_clean_passes_and_secret_env_pauses`, `secrets_in_content_and_add_delete_history_are_found_and_redacted` (value never in output) |
| Bounds -> IncompleteScan | FR-001 | Pass | Pass | `bounds_report_incomplete_scan` (`graph_max_nodes`, `scan_max_bytes`) |
| Non-UTF-8 / newline filenames | FR-001 | N/A (not creatable on NTFS) | Pass | `non_utf8_and_newline_filenames_are_handled` |
| Existing repo hook runs with stdin; failure aborts push | FR-001 | Pass | Pass | `existing_repo_hook_runs_with_stdin_and_failure_aborts` |
| Prior global and local hooksPath chained | FR-001 | Pass | Pass | `previous_global_hookspath_and_local_hookspath_are_chained` |
| Setup/uninstall restore exact values; paths with spaces | FR-001 | Pass | Pass | `setup_installs_owned_changes_and_uninstall_restores_them`, `uninstall_without_prior_hookspath_unsets_it_and_leaves_changed_values` (all temp dirs contain spaces) |
| Worktrees | FR-001 | Pass | Pass | `worktrees_run_the_hook` |
| Shim by argv0; pass-through exit status; `secret-scan` | FR-001 | Pass | Pass | `installed_shim_routes_push_by_argv0`, `non_push_commands_pass_through_with_exact_status`, `secret_scan_command_reports_without_pushing` |
| Approved path / Cancel / one prompt per plan | FR-001 | Pass (unit) | Pass (unit) | `cmd::hook::tests::rewrite_prompts_once_and_cancel_aborts` with scripted approver |
| Real approval channels end to end | FR-001 | **Pending** | **Pending** | Needs T-002 (`approval::approve` is a fail-closed stub). Integration tests assert the push is aborted (fail closed), not that an approved push succeeds through a real prompt. |
| PATH edit on the real Windows registry | FR-001 | **Pending** | n/a | `RegistryEditor` (`reg.exe`) is implemented but only exercised via the injectable `FAIL2COMMIT_PATH_TARGET` file seam; tests must not touch the real registry. Needs a disposable Windows user or VM. |
| Git for Windows shell vs PowerShell, WSL | FR-001 | **Pending** | **Pending** | Tests ran under the Rust harness only. WSL Ubuntu was not run (it has no cargo; the Debian-built binary was not copied there). |

## 3. Traceability Check

`python .claude/hooks/trace_check.py` -> `[guard:trace_check] OK`

## 4. Issues Found

- **Not mine, frozen file:** `crates/fail2commit/src/main.rs` unit test `tests::shims_route_to_subcommands`
  fails on Linux. It feeds the Windows path `C:\b\NPM.exe`, and `Path::file_stem` does not split on
  backslashes on Linux. Passes on Windows. The coordinator owns `main.rs`; a fix is to make the test
  Windows-only or normalize separators in `shim_argv`.
- Known limits (documented in `docs/git-integration.md`): `--no-verify`, other Git clients and
  absolute-path git bypass local hooks (SPEC-003 covers them); blobs over 4 MiB are scanned by their first
  4 MiB; Windows PATH changes are not broadcast (visible after next sign-in).
- No contract change was needed. No dependency added.

## 5. Verdict

- [ ] **Verified**
- [x] **Not verified (partial):** all local-hook behaviour passes on both platforms, but real approval
  channels (T-002), the real registry PATH edit and WSL/PowerShell runs are Pending, so FR-001 is not marked Verified.
