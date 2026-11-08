# Verify Report: pip guard, FR-005 / SPEC-005 / TC-005 (2026-11-09)

> **Requirements covered:** FR-005
> **Commit / branch:** 4048151 on `DansPK/f2c-t005-pip` (base fe411ba); report committed on top
> **Verified by:** T-005 worker (Claude)
> **Platforms:** Windows 11 (x86_64-pc-windows-gnu, Python 3.12.10, pip 25.0.1); Linux (Docker `rust:1`, Debian 13, python3 3.13 + python3-venv + python3-pip)

## 1. Commands Run

```text
cargo fmt --all -- --check                                      -> exit 0 (Windows)
cargo clippy -j 2 --workspace --all-targets -- -D warnings      -> exit 0 (Windows)
cargo test -j 2 --workspace                                     -> exit 0 (Windows): 2+5+18+4+30 passed
python .claude/hooks/trace_check.py                             -> "[guard:trace_check] OK"
docker run --rm -v "${PWD}:/src" -v f2c-t005-target:/target -e CARGO_TARGET_DIR=/target \
  -e CARGO_BUILD_JOBS=2 -w /src rust:1 bash -c "apt-get install -y python3 python3-venv python3-pip; \
  cargo test -j 2 --workspace --no-fail-fast"                   -> exit 101 (Linux), see below
```

Linux result: `pip_cli` 5/5, `pip_install` 18/18, `pip_reject` 4/4, core unit 30/30 pass.
The one failure is `tests::shims_route_to_subcommands` (`crates/fail2commit/src/main.rs:176`, coordinator-owned,
frozen): it asserts that the Windows path `C:\b\NPM.exe` yields stem `npm`, which `Path::file_stem` cannot do on
Linux. It is not pip code and was not touched. `cargo clippy` and `cargo fmt` are not installed in the stock
`rust:1` image, so clippy/fmt ran on Windows only (Pending on Linux: `rustup component add clippy rustfmt`).

## 2. Results

| TC / item | Requirement | Windows | Linux | Evidence (test names) |
|---|---|---|---|---|
| TC-005 clean wheel install works (incl. transitive dep, sdist-only newer version ignored) | FR-005 | Pass | Pass | `clean_wheel_install_works_with_transitive_dependency`, `requirements_file_install_and_hash_pin` |
| TC-005 source-only (sdist) dependency stops | FR-005 | Pass | Pass | `source_only_dependency_is_unsupported_input` (UnsupportedInput, `PyPI:gamma`, venv unchanged) |
| TC-005 direct references stop (direct, VCS, URL, path, archive, editable) | FR-005 | Pass | Pass | `pip_reject::*`, `request::tests`, CLI `rejects_direct_reference_with_json`; zero index requests, no staging dir |
| TC-005 transitive direct reference stops | FR-005 | Pass | Pass | `transitive_direct_reference_is_stopped_before_pip_uses_it`, `wheel::tests::rejects_hostile_wheels` |
| TC-005 no second resolution | FR-005 | Pass | Pass | `apply_does_not_resolve_again` (index shut down before apply, zero requests after plan), `apply::tests::apply_uses_no_index_and_no_resolution` (`--no-index --no-deps --require-hashes --find-links`) |
| Matrix: untrusted index directives in args, files, `PIP_*`, pip config | FR-005 | Pass | Pass | `pip_reject::*`, `interp::tests`, CLI `pip_env_index_directive_is_rejected` |
| Matrix: mismatched hash / pinned `--hash` / oversize | FR-005 | Pass | Pass | `mismatched_hash_fails_closed`, `requirements_file_install_and_hash_pin`, `oversized_artifact_is_refused` |
| Matrix: changed plan invalidates approval | FR-005 | Pass | Pass | `changed_plan_invalidates_approval`, `a_different_plan_has_a_different_digest`, `plan::tests::digest_binds_every_part` |
| Matrix: advisory approval, cancel, deny, incomplete scan | FR-005 | Pass | Pass | `advisory_pauses_for_approval_and_cancel_applies_nothing`, `incomplete_scan_pauses`, `deny_finding_cannot_be_approved_away` |
| Matrix: resolver cancellation | FR-005 | Pass | Pass | `resolver_cancellation_leaves_everything_unchanged` (child killed, venv/staging/journal clean) |
| Matrix: interrupted apply + recovery | FR-005 | Pass | Pass | `interrupted_apply_is_recovered_by_the_next_run`, `cancel_during_apply_stops_between_wheels_and_is_recoverable`, `tampered_reviewed_set_blocks_recovery` |
| Matrix: interpreter/platform/venv binding, wrong-platform wheel | FR-005 | Pass | Pass | `install_is_bound_to_the_selected_interpreter`, `wheel_for_another_platform_is_not_installed` |
| Matrix: unsupported pip commands cannot reach pip; shim routing; read-only passthrough | FR-005 | Pass | Pass | `unsupported_pip_commands_never_reach_pip`, `shim_name_routes_to_guarded_pip`, `end_to_end_install_pauses_without_an_approver_and_changes_nothing` |
| Shim integration install/uninstall | FR-005 | Pass | Pass | `shim::tests::install_status_uninstall` |
| Live pypi.org install, real pip against real wheels, MSVC/other tags | FR-005 | Pending | Pending | No live-internet test written (policy: offline only). Prerequisite: an `#[ignore]` test with network access |
| Advisory scanning on real data | FR-005/FR-006 | Pending | Pending | Needs T-006 `check_advisories`; tests inject the advisory source. The stub reports IncompleteScan, so the binary pauses (covered, exit 11) |
| Real approval channels | FR-005/FR-002 | Pending | Pending | Needs T-002 `approval::approve`; tests inject the approver |
| Linux clippy / fmt | - | n/a | Pending | Install rustfmt+clippy components in the container |

## 3. Traceability Check

```text
python .claude/hooks/trace_check.py
[guard:trace_check] OK
```

## 4. Issues Found

* `crates/fail2commit/src/main.rs` unit test `shims_route_to_subcommands` fails on Linux (Windows path in the
  assertion). Coordinator-owned; not changed. Suggested fix: gate the `C:\\b\\NPM.exe` case with `#[cfg(windows)]`.
* Contract notes: `settings.rs` has no pip section (`deny_unknown_fields`), so the pinned index lives in a trusted
  `config/pip.toml` (see docs/pip.md). No frozen signature changed. New dev-dependencies for tests in
  `crates/fail2commit`: `zip =9.4.2`, `sha2 =0.11.1`, `hex =0.4.3` (and the matching `Cargo.lock` update).
* Design limits (documented in docs/pip.md): recovery is roll-forward only; Ctrl-C relies on default process
  termination (the journal makes it recoverable); the Windows run needed `SYSTEMDRIVE`/`PROGRAMDATA` in the scrubbed
  child environment.

## 5. Verdict

- [ ] **Verified:** all linked TCs pass; requirement status set to `Verified`
- [x] **Not verified (pending evidence only):** every TC-005 behavior passes on Windows and Linux with injected
  approver/advisory seams; the Pending rows above (T-006/T-002 integration, live registry, Linux clippy/fmt) block
  marking FR-005 Verified. The coordinator owns the status change.

## 6. 2026-11-09 fix: wave-2 review W2-001, W2-002, W2-006 (FR-005, FR-008)

Implements CR-001 and CR-002 from `docs/change-requests.md`. Branch `DansPK/f2c-fix-wave2-pip` from `cdb67bd`.

| Finding | Change | Evidence (tests) |
|---|---|---|
| W2-001 | All interpreters run `-I -S` with a `sys.path`/`sys.prefix` prelude (`pip::interp::BOOT`); wheel inspection flags startup files as `HostExecution` approvals (`pip.startup`); `has_scripts` stays `false` with the reasoning documented | `review_wave2_pth::guarded_install_never_runs_wheel_startup_code_and_asks_approval_naming_it`, `declining_the_startup_approval_installs_nothing`, `wheel::tests::startup_files_are_found_where_site_would_run_them` |
| W2-002 | Boundary-only cancel, `cancelled` journal, installs blocked by any journal, `pip recover [--discard]` with a fresh digest | `pip_recover::*` (7 tests), `pip_cli::recover_without_a_journal_and_bad_usage_are_invalid_input` |
| W2-006 | pip shim refuses to replace a foreign file and uninstall leaves it | `shim::tests::foreign_file_is_neither_replaced_nor_removed` |

The old tests `interrupted_apply_is_recovered_by_the_next_run`, `cancel_during_apply_stops_between_wheels_and_is_recoverable` and `tampered_reviewed_set_blocks_recovery` described implicit roll-forward; they are replaced by `pip_recover.rs`. Test helpers query installed packages with `-I -S` as well (a venv is not detected without `site`, so the helper sets `sys.prefix`).

Commands and results (tested tree = this commit's parent plus the fix commit; see the commit SHA reported by the worker):

| Command | Exit | Result |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy -j 2 --workspace --all-targets -- -D warnings` | 0 | clean |
| `cargo test -j 2 --workspace --no-fail-fast` (Windows, empty stdin) | 101 | all pip targets pass: `pip_cli` 6, `pip_install` 15, `pip_recover` 7, `pip_reject` 4, `review_wave2_pth` 3, core lib incl. `pip::` 17. Failures are only the other areas' intentional wave-2 reproductions and one npm test: `review_wave2_scan` (2), the git review reproductions (3) and `npm_flow::the_real_stub_scanner_pauses_in_production_wiring` (1); none touch pip files |
| Linux: `docker run --rm -v "${PWD}:/src" -v f2c-fixpip-target:/target -e CARGO_TARGET_DIR=/target -w /src rust:1 bash -c "apt-get update -qq && apt-get install -y -qq python3-venv python3-pip && cargo test -j 2 -p fail2commit --test review_wave2_pth --test pip_install --test pip_recover --test pip_cli --test pip_reject --no-fail-fast"` | 0 | 3 + 15 + 7 + 6 + 4 tests pass |


## 7. 2026-11-09 fix: pip re-review RP-001..RP-008 (FR-005, FR-008)

Branch `DansPK/f2c-fix-pip-r2` from `ee86252` (re-review `REREVIEW-2026-11-09-pip.md`). Design in `docs/pip.md` (flow step 0, startup files, layout violations, journal).

| Finding | Change | Evidence |
|---|---|---|
| RP-003 | Guard-owned pip snapshot under `cache_dir/pip/guard/<id>` with SHA-256 manifest re-verified before every launch (`IntegrityFailure`); target site dirs are metadata-only (import-blocking finder); `verify_installed` reads dist-info | `rereview_pip_boot::{rp_guard_runs_pip_from_its_snapshot_not_from_the_environment, rp_tampered_snapshot_is_an_integrity_failure_and_nothing_runs, guard_pip_still_sees_installed_distributions, rp_wheel_overlaying_pip_is_denied_and_runs_nothing}`, `guard::tests` |
| RP-004 | Hard `Deny` `pip.layout` for interpreter-layout data entries, scripts named `python*`/`pip*`/interpreter exe/nested, `pip/` and `pip-*.dist-info/` entries (pip itself included, stated), startup files via data scheme; BOOT ignores `<exe dir>/pyvenv.cfg` | `rp_scripts_dir_pyvenv_cfg_and_interpreter_names_are_denied`, `upgrading_pip_through_the_guard_is_denied_and_says_so`, `wheel::tests::layout_entries_are_denied` |
| RP-001 | `.pth` detection like `site.addpackage` (BOM, bare CR and other separators, non-UTF-8 and oversized flagged) | `rp_pth_with_cr_line_separator_is_named`, `rp_pth_with_utf8_bom_is_named`, `wheel::tests::pth_lines_are_detected_like_site_addpackage`, `oversized_pth_is_flagged_not_skipped` |
| RP-002 | `.pth`/`sitecustomize`/`usercustomize` through the data scheme are denied; ordinary data files still install | `rp_pth_through_data_scheme_is_denied`, `rp_sitecustomize_through_data_scheme_is_denied`, `control_ordinary_data_scheme_file_still_installs` |
| RP-006 | Journal and gate keyed by canonical identity (real `sys.prefix`, implementation, major.minor; case-folded on Windows) | `respelled_*`, `recased_*` (Windows), `symlinked_*` (Linux) |
| RP-007, RP-008 | Journal carries plan inputs, digest recomputed, identity, confined `reviewed`/wheel names; remaining wheels re-hashed and re-inspected; forged journal refused with `--discard` offered, `--discard` removes only the journal file | `forged_or_mismatched_journals_are_refused_and_discard_is_offered`, `discard_drops_a_forged_journal_without_touching_what_it_names`, `recover_rehashes_the_remaining_wheels_before_approval`, `recover_rejects_a_journal_*`, `discard_acts_on_the_journal_*` |
| RP-005 | Ownership by setup record plus marker in `state_dir/pip/shim-<name>.json`; refresh on setup, removal on uninstall after an upgrade | `rereview_pip_shim::*` (6) |

Notes: pip itself rejects a wheel carrying a second `.dist-info` before our scan on newer pip, so `pip-*.dist-info` is covered by the unit test only. Interpretation: "matching an existing venv executable" is implemented as the interpreter's own executable name (spelled and resolved) plus `python*`/`pip*`/`activate*`, because denying every existing script name would block upgrading console-script packages. Debian-style unbundled pip is refused. Debug-build test time rose (manifest hashing, one-time precompile).

Commands and results are in the worker report for the commit that carries this section (SHA there).
