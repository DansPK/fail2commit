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
