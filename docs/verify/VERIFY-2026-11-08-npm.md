# Verify Report: Guard npm installs (2026-11-08)

> **Requirements covered:** FR-004 (SPEC-004, TC-004)
> **Commit / branch:** tested SHA `c4f3aca2e45b30e5c9a83e3c49ddff9d98916ad8` on branch `DansPK/f2c-t004-npm` (base `fe411ba`)
> **Verified by:** T-004 worker (claude-sonnet-5-5), Orca task `task_e08078510208`

---

## 1. Commands Run

Windows 11 host (Rust stable `x86_64-pc-windows-gnu`, Node v24.22.0, npm 11.19.1 on PATH), from the repository root:

```text
cargo fmt --all -- --check                                                   exit 0
cargo clippy --workspace --all-targets -- -D warnings                        exit 0
cargo test --workspace --no-fail-fast                                        exit 0
python .claude/hooks/trace_check.py                                          exit 0  ("[guard:trace_check] OK")
```

Linux (official `rust:1` Debian container, `apt-get install nodejs npm git`: Node v20.19.2, npm 9.2.0; named volume `f2c-t004-target`; source bind-mounted from the same tree):

```text
docker run --rm -v "${PWD}:/src" -v f2c-t004-target:/target -e CARGO_TARGET_DIR=/target -w /src rust:1 bash -c \
  "apt-get update -qq && apt-get install -y -qq nodejs npm git && rustup component add clippy rustfmt && \
   cargo fmt --all -- --check; cargo clippy --workspace --all-targets -- -D warnings; \
   cargo test -p fail2commit -p fail2commit-core --no-fail-fast"
   fmt exit 0, clippy exit 0, tests: all npm targets pass; 1 unrelated pre-existing failure (section 4)
```

The final Linux run already contained the `npm_cli.rs` change (symlink instead of copy for the shim on Unix, avoiding `ETXTBSY`), which is part of `c4f3aca`; the Windows run in this report is the final-tree run as well.

## 2. Results

Test counts: Windows `npm_flow` 21, `npm_scripts` 7, `npm_cli` 3, `fail2commit-core` unit 30 (15 of them in `npm::`); Linux the same counts.

| TC / matrix item | Requirement | Result | Evidence |
|---|---|---|---|
| TC-004 clean install works | FR-004 | Pass (Win, Linux) | `npm_flow::clean_install_works_and_updates_manifest_and_lock`, `ci_installs_the_lockfile_and_keeps_project_files` (install: manifest + lock updated, exactly one artifact download, no prompt; ci: no resolution, lockfile/manifest bytes unchanged) |
| TC-004 malicious transitive finding pauses | FR-004 | Pass (Win, Linux) | `malicious_transitive_package_pauses_and_cancel_preserves_the_project` (injected advisory source; one approval carrying the Malware finding for the transitive package), `approved_findings_install_once` |
| TC-004 force-push script blocked | FR-004/FR-006 | Pass (injected scanner) | `force_push_script_is_denied_without_a_prompt`: Deny finding stops before any prompt; the referenced script file is handed to `inspect_scripts`. Real `scan::inspect_scripts` is a T-006 stub, so the detection itself is Pending integration. |
| TC-004 cancel preserves project state | FR-004 | Pass (Win, Linux) | Same test: byte-for-byte snapshot of project incl. `node_modules` and lockfile equal before/after; no scratch dirs left |
| Mismatched bytes | FR-004 | Pass | `mismatched_bytes_are_a_hard_integrity_failure` (code `integrity_failure`, not approvable, project unchanged); `manifest_confusion_is_denied` |
| Hostile archive paths | FR-004 | Pass | `hostile_archive_paths_stop_the_install`; unit `npm::archive::tests::hostile_entries_are_rejected` (`..`, absolute, backslash, drive, links, devices, FIFO, size) |
| Stale / offline advisory data reported | FR-004/FR-006 | Pass (injected source) | `stale_or_offline_advisory_data_is_reported_and_pauses`; `the_real_stub_scanner_pauses_in_production_wiring` (stub IncompleteScan pauses). Real OSV/stale logic is T-006. |
| Source / URL / git bypass stopped | FR-004 | Pass | `unsupported_inputs_never_reach_resolution_or_npm` (git, file, URL, link, tarball, alias, workspaces, overrides; registry saw zero requests); `project_npmrc_cannot_redirect_the_registry_or_shell`; `artifacts_off_the_pinned_registry_are_refused`; CLI `npm_cli::unsupported_sources_exit_2_before_any_network_use`; unit `npm::cmdline::tests`, `npm::lockfile::tests::plan_validation` |
| Unsupported input cannot reach an unguarded npm path | FR-004 | Pass | CLI and shim-name tests: `update`, `exec`, `rebuild`, `--registry=`, `-g`, leading options exit 2 and are never forwarded; only a fixed non-installing command list passes through (`npm --version` verified) |
| Changed plan invalidates approval | FR-004 | Pass | `a_changed_plan_changes_the_approved_digest` (new resolution, save options and `--ignore-scripts` change the digest); `project_edited_during_review_invalidates_the_approval` (edit between prompt and apply => `integrity_failure`, user edit kept). The digest-to-response binding itself is `approver::validate_response` (T-002 wiring Pending). |
| Interrupted apply recovers | FR-004 | Pass | `interrupted_apply_recovers_after_{journal,backup,swap,files}` (crash simulated at each commit step; next run restores the original byte-for-byte), `recovery_note_is_reported_by_the_run_that_recovers`; unit `npm::commit::tests` |
| Lifecycle context preserved | FR-004/FR-008 | Pass (sandbox double) | `sandboxed_script_keeps_the_npm_lifecycle_context` (`npm_lifecycle_event/script`, `npm_package_*`, `npm_node_execpath`, `npm_execpath`, `INIT_CWD`, `.bin` on PATH, cwd = package dir inside the scratch tree, no exports, checkout not mounted); the double executes the real script and its output is committed |
| Sandbox unavailable launches nothing | FR-004/FR-008 | Pass | `unavailable_sandbox_launches_nothing_and_changes_nothing` |
| Sandbox off: skip / host-once | FR-004/FR-008 | Pass (FR-008 table via `policy::script_decision`) | `sandbox_off_skips_scripts_that_are_not_required`, `required_script_with_sandbox_off_needs_separate_host_consent`, `user_ignore_scripts_runs_nothing_even_with_a_sandbox`, `failing_script_rolls_everything_back` |
| Optional platform packages | FR-004 | Pass | `optional_platform_packages_are_reviewed_but_not_fetched` |
| npm shim integration | FR-004 | Pass | `npm::shim::tests` (dry run, idempotent, foreign file never replaced/removed); `npm_cli::shim_name_routes_to_the_guard_and_never_to_plain_npm` (argv0 `npm`) |
| Windows: no cmd.exe for user arguments | FR-004 | Pass | npm is launched as `node.exe npm-cli.js` with structured args (`runner.rs`); passthrough `npm --version` on Windows exercised via the shim test |
| Real native module build (node-gyp) | FR-004/FR-007 | **Pending** | Needs the real sandbox backends of T-007 (`sandbox::platform_backend()` is still a stub: `run_job` reports isolation unavailable) and node headers inside the sandbox. Until then the lifecycle path is only proved with a sandbox double. |
| Production approval / scan / authorize path end to end | FR-004 | **Pending** | `approval::approve` (T-002), `scan::*` (T-006) and `exec::authorize_scripts` (T-008) are fail-closed stubs in this base; the binary test `production_wiring_fails_closed_when_approval_is_needed` proves the fail-closed behavior only. Re-run the matrix after integration. |
| Platform behavior marked verified | FR-004 | Windows Pass, Linux Pass (library + CLI); WSL not exercised | The Debian container uses npm 9.2.0, Windows uses npm 11.19.1; both pass. No separate WSL run of this area. |

## 3. Traceability Check

```text
$ python .claude/hooks/trace_check.py
[guard:trace_check] OK
```

## 4. Issues Found

- Not caused by this task: `cargo test` for the `fail2commit` binary fails on Linux in `tests::shims_route_to_subcommands` (`crates/fail2commit/src/main.rs:176`). It asserts that the Windows path `C:\b\NPM.exe` maps to the npm shim, but on Linux `Path::file_stem` does not split on backslashes. `main.rs` is coordinator-owned and frozen, so it was not changed here. Reported to the coordinator.
- `Cargo.lock` changed (5 lines) because of `cargo add` for dev-dependencies of the `fail2commit` crate; the `protected_paths` guard printed a notice but the commit succeeded. No new crates entered the lockfile.
- npm start-up on the Windows host takes about 8 s per run when the machine is busy (3 npm starts per guarded install). The Linux container runs the whole npm suite in about 7 s. Time bounds for NFR-012 belong to T-012.

## 5. Verdict

- [ ] **Verified:** all linked TCs pass; requirement status set to `Verified`
- [x] **Not verified:** TC-004 passes on Windows and Linux against doubles for T-002/T-006/T-007/T-008, but the real native build and the production approval/scan/sandbox path are Pending the prerequisites named above. Status should stay below `Verified` until they are re-run after integration.
