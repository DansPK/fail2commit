# Verify Report: package and script scanning (2026-11-08)

> **Requirements covered:** FR-006 (SPEC-006, TC-006)
> **Commit / branch:** `59a46f7` on `DansPK/f2c-t006-scan`, based on `fe411ba`
> **Verified by:** `orca:cline` worker T-006

---

## 1. Commands Run

All commands ran from the worktree root
`C:\Users\nutyo\orca\workspaces\fail2commit\f2c-t006-scan` unless noted.

### Windows 11 host (`x86_64-pc-windows-gnu`, Rust stable)

```text
cargo fmt --all -- --check
  exit 0

cargo clippy --workspace --all-targets -- -D warnings
  exit 0

cargo test --workspace --no-fail-fast
  exit 0
  fail2commit-tray (bin)       : 2 passed;  0 failed
  scan_advisories              : 14 passed; 0 failed; 1 ignored
  scan_cli                     : 12 passed; 0 failed
  scan_scripts                 : 8 passed;  0 failed
  fail2commit-core (lib)       : 36 passed; 0 failed
```

### Linux container (Debian, official `rust:1` image)

```text
docker run -d --name f2c-t006-linux -v "${PWD}:/src" -v f2c-t006-scan-target:/target \
  -e CARGO_TARGET_DIR=/target -w /src rust:1 cargo test --workspace --no-fail-fast
docker logs f2c-t006-linux; docker ps --all --filter name=f2c-t006-linux
  exit 101 — one target failed: `-p fail2commit --bin fail2commit`,
  test `tests::shims_route_to_subcommands` (coordinator-owned `src/main.rs`,
  unmodified by T-006). See section 4. Every scan target passed in that run.

docker run -d --name f2c-t006-linux-scan -v "${PWD}:/src" -v f2c-t006-scan-target:/target \
  -e CARGO_TARGET_DIR=/target -w /src rust:1 sh -c \
  "cargo test -p fail2commit-core --lib; cargo test -p fail2commit --test scan_advisories --test scan_scripts --test scan_cli"
  exit 0
  fail2commit-core (lib)       : 36 passed; 0 failed
  scan_advisories              : 14 passed; 0 failed; 1 ignored
  scan_cli                     : 12 passed; 0 failed
  scan_scripts                 : 8 passed;  0 failed
```

The live-internet smoke test is never part of the default run:

```text
cargo test -p fail2commit --test scan_advisories -- --ignored   # not run here
```

## 2. Results

| TC ID | Requirement | Result | Evidence |
|-------|-------------|--------|----------|
| TC-006 | FR-006 | Pass | `known_advisory_appears_once`, `known_advisory_is_reported_once_as_json` — one `advisory` finding per distinct id; duplicates collapsed in the batch and across pages (`page_tokens_are_followed_and_deduped`). |
| TC-006 | FR-006 | Pass | `malware_is_classified_separately`, `openssf_malicious_source_is_malware`, `malware_is_reported_separately_as_json` — `MAL-` ids and OpenSSF `malicious-packages` records become `kind = malware`, never `advisory`. |
| TC-006 | FR-006 | Pass | `every_force_form_is_denied`, `wrapped_aliases_are_denied`, `suspicious_fixture_package_is_denied`, `suspicious_package_directory_is_denied` — `--force`, `--force-with-lease`, `-f`, `--mirror`, `--delete`, `+refspec`, `:branch` and `sh -c`/`npx`/`child_process` wrappers all yield `suspicious_script` + `deny`, exit 10. |
| TC-006 | FR-006 | Pass | `benign_hooks_are_not_flagged`, `benign_package_directory_is_clean` — `git push origin main`, `git fetch --force`, `git status` are not flagged; exit 0. |
| TC-006 | FR-006 | Pass | `stale_data_is_reported`, `network_failure_falls_back_to_stale_cache` — `stale_data` finding, `complete = false`, exit 12 through the CLI. |
| TC-006 | FR-006 | Pass | `offline_without_cache_is_incomplete`, `offline_scan_without_cache_is_incomplete`, `offline_scan_never_contacts_the_network` — `incomplete_scan`, `complete = false`, never a clean answer; `--offline` served 0 requests. |
| TC-006 | FR-006 | Pass | `cache_stays_within_bounds`, `cache_hit_avoids_network`, `scan::cache::tests::*` — directory stays under `cache_max_bytes`, fresh entries avoid the network, malformed entries are misses. |
| TC-006 | FR-006 | Pass | `timeout_is_incomplete` — a server that stalls 3 s fails the lookup in under 2.9 s with `timeout_secs = 1`, reported incomplete. |
| TC-006 | FR-006 | Pass | `unusable_endpoint_is_incomplete`, `scan::osv::tests::endpoint_must_be_http_and_credential_free`, `ids_are_path_safe` — `file://`, `ftp://`, userinfo and traversal ids cannot redirect the client. |
| TC-006 | FR-006 | Pass | `credentials_in_evidence_are_redacted`, `evidence_redacts_credentials` — credentials in a pushed URL appear as `***@host`; the synthetic secret never reaches evidence. |
| TC-006 (matrix: npm/pip "stale/offline cache") | FR-006 | Pass | The scan-owned half of that matrix row: stale and offline cache behaviour proven on Windows and Linux. Wiring into the guarded npm/pip installs is T-004/T-005. |
| TC-006 (matrix: platform) | FR-006 | Pass | The same suite is green on Windows 11 and in the Debian `rust:1` container (section 1). |
| TC-006 (live OSV) | FR-006 | Pending | `live_osv_smoke` is `#[ignore]`. Missing prerequisite: an internet-enabled run (`cargo test -p fail2commit --test scan_advisories -- --ignored`), deliberately excluded from default and CI runs. |

## 3. Traceability Check

```text
$ python .claude/hooks/trace_check.py
[guard:trace_check] OK
exit 0
```

## 4. Issues Found

1. Fixed during this task (found by the first Windows run, before the commit under test):
   `cmd/scan.rs::safe_relative` rejected a leading `./`, so `node ./scripts/postinstall.js`
   was never inspected and the suspicious fixture package reported no file finding.
   `Component::CurDir` is now dropped; `..`, roots and drive prefixes are still rejected.
2. Fixed during this task: `cargo clippy -- -D warnings` flagged
   `clippy::extra_unused_lifetimes` on `scan::cache::read`; the bound is now
   `T: DeserializeOwned`.
3. Fixed during this task: the suspicious fixture placed the `execSync` call on line 6
   while the test asserted line 5; the fixture now matches the asserted line.
4. **Out of T-006 scope, still open — needs a coordinator decision (candidate BUG):**
   `cargo test --workspace` fails on Linux only, in `crates/fail2commit/src/main.rs`
   (`tests::shims_route_to_subcommands`, line 176):

   ```text
   thread 'tests::shims_route_to_subcommands' panicked at crates/fail2commit/src/main.rs:176:9:
   assertion `left == right` failed
     left: ["C:\\b\\NPM.exe", "ci"]
    right: ["fail2commit", "npm", "ci"]
   ```

   `shim_argv` uses `Path::file_stem`, and on Linux a backslash is not a separator, so
   the Windows-style shim name `C:\b\NPM.exe` never maps to the `npm` subcommand. The
   file is frozen and coordinator-owned; T-006 did not modify it
   (`git diff HEAD -- crates/fail2commit/src/main.rs` is empty). It passes on Windows.

## 5. Verdict

- [x] **Verified for FR-006 / SPEC-006 / TC-006:** every linked TC row above passes on
      both platforms; the single failure in the full Linux workspace run is in a
      coordinator-owned file outside this task and is recorded in section 4.
- [ ] **Not verified:** the `#[ignore]` live-OSV smoke test needs an internet-enabled
      run and stays Pending.