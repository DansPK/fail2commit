# Re-review 3: npm review from the extracted tree, CR-008 (FR-004, FR-006)

- Tested SHA: `a88fdef` (`DansPK/f2c-fix-npm-r3`), reviewed from `DansPK/f2c-rereview3-npm`. Scope: `git diff 6d4b833..a88fdef`.
- Host: Windows 11 NTFS, npm 12.2.0, node 24.22.0. Linux paths were read, not run (pending evidence).
- Product code untouched. Reproductions: `crates/fail2commit/tests/rereview3_npm.rs`.

## Verdict: **parser-differential class closed; not clean**

RN2-001..007 cannot recur: content decisions now come from the tree npm wrote, and `ignore-scripts` holds. Four new gaps remain, none a regression of CR-008. Two are about *what the reviewed command really executes* (RN3-001, RN3-002, High). Two are about *what gets committed after review* (RN3-003, RN3-004, Medium/Low). Fix RN3-001/002 before merge.

## Per-area status

| Area | Status | Evidence |
|---|---|---|
| 1. No package code during extraction | **Holds** | `--ignore-scripts` is in the staged userconfig (`config.rs:232`, appended after project keys) and on the command line (`apply.rs:45`). Probe with npm 12.2: package with preinstall/install/postinstall/prepare/prepublish, a `binding.gyp`, `bin` entries and root-project preinstall/install/prepare. Control without the flag: `preinstall` ran (marker written, then npm hung in the gyp build). With the flag on the command line only, in userconfig only, or both: exit 0, no marker, no gyp build, `.bin/*` created but not run. Test `control_extraction_runs_no_package_code`. Git deps are rejected earlier; `npm ci --offline` cannot fetch anything not seeded (ENOTCACHED), so a platform-skipped optional cannot be installed unreviewed. |
| 2. Reviewed == committed | **Partly** | Single extraction; `recheck` re-hashes manifest and referenced files before scripts (`control_referenced_file_changed_after_review_is_stopped`, `control_manifest_changed_*` pass). Staging is under `cache_dir/npm-staging`, 0700 on Unix; on Windows it inherits the user profile ACL (same-user only). Scripts go through `authorize_scripts` and the sandbox with `work_dir = staging tree`. Gaps: RN3-003, RN3-004. |
| 3. Tree completeness | **Holds except `.bin`** | Tarball-shipped `node_modules/evil`, `.hidden`, loose files: denied (`control_tarball_shipped_node_modules_is_denied`). Symlinks denied; `std` reports a Windows junction as a link (`control_windows_junction_is_a_link_for_std`). Scoped/nested/bundled handled by plan match. `.gitignore`/`.npmignore` and case folding are read from disk. Gap: `.bin` contents are never walked (RN3-001). |
| 4. Digest binding | **Holds** | `ArtifactDigest.tree = inputs` (manifest + referenced file hashes), plus registry, project settings, npm version, sandbox flag, final package.json/lockfile, findings (`mod.rs:300-345`). Script approval digest chains the plan digest. Smoke test `control_approval_digest_changes_with_a_referenced_file`. Note: approval is only requested when a finding needs one; a clean graph is not gated (by design). |
| 5. Regressions | **None** | See commands. |

## New findings

| ID | Sev | Status | Where | Scenario | Fix |
|---|---|---|---|---|---|
| RN3-001 | **High** | CONFIRMED | `apply.rs:173,142-160` (`.bin` skipped in `installed` and `deny_links`); `apply.rs:357-368` (PATH) | A tarball ships `package/node_modules/.bin/node` (mode 0755; `node.cmd` on Windows). The lifecycle PATH puts `<pkg>/node_modules/.bin` first, so reviewed `postinstall: node setup.js` runs the shipped file. Review reads `setup.js` only. The same works across packages through any `bin: {node: ...}` of a dependency (probed: npm creates `.bin/node`, `node.cmd`, `node.ps1`). Test `rn3_001_*`. | Deny any non-link file in `.bin` that npm did not create, or any `.bin` entry not derived from a planned package's `bin`; and/or resolve the first word of each lifecycle command against the `.bin` dirs and review that file. |
| RN3-002 | **High (Windows)** | CONFIRMED | `tree.rs:24,98` (candidates use `.js/.cjs/.mjs/.json` only) | `cmd.exe /d /s /c .\setup` runs `setup.bat` (PATHEXT; probed). Review looks for `setup`, `setup.js`, ... and finds nothing, so a hostile `.bat/.cmd/.exe/.com` runs unreviewed (`saw []`). Bare `setup` and `node` resolve through cwd on hosts without `NoDefaultCurrentDirectoryInExePath` (set on this host, so not run). Test `rn3_002_*`. | On Windows add `.bat .cmd .exe .com .ps1 .vbs .wsf` to the candidate extensions (read, or deny binaries as `incomplete_scan`); treat backslash as a separator in `to_rel`. |
| RN3-003 | Medium | CONFIRMED | `tree.rs:344-357` (`recheck` hashes `inputs` only) | A file not named by a lifecycle command changes between review and the move (same-user process, or an earlier script); the changed bytes are committed. Test `rn3_003_*`. | Hash the whole tree (path, mode, bytes) after extraction and re-check it before the move; or re-verify against the tarball contents. |
| RN3-004 | Medium | CONFIRMED | `mod.rs:465-475`, `apply.rs:254-285` | After sandboxed scripts run, the tree is moved without `verify_tree`/`deny_links`/`recheck` again. A script can add a package dir absent from the lockfile and a link/junction; both land in the project's `node_modules`. Also `recheck` runs once before all scripts, so an earlier script can rewrite a later package's referenced files. Pre-CR-008 had the same order (verify before scripts). Test `rn3_004_*`. | Re-run `verify_tree` after scripts (allow only files inside planned package dirs), reject links, and re-run `recheck` before each script. |

### Verified safe or out of scope
- Cross-volume `copy_tree` keeps `.bin` symlinks on Unix and fails closed on Windows.
- A package declared platform-skipped cannot be installed: nothing for it is in the offline cache.
- Linux behaviour (bwrap, mode bits, `sh` PATH lookup) was read, not run.

## Commands

All with empty stdin, cargo `-j 2`, at `a88fdef` plus the new test file.

| Command | Exit | Result |
|---|---|---|
| `cargo test -j 2 -p fail2commit --test npm_cli` | 0 | 3 passed |
| `... --test npm_flow` | 0 | 21 passed |
| `... --test npm_scripts` | 0 | 7 passed |
| `... --test rereview_npmscan` | 0 | 24 passed |
| `... --test rereview2_npm` | 0 | 19 passed (RN2-001..007 repros now pass) |
| `... --test scan_scripts` | 0 | 8 passed |
| `cargo test -j 2 -p fail2commit-core --lib npm::` | 0 | 28 passed |
| `cargo test -j 2 -p fail2commit --test rereview3_npm` | 101 (expected) | 6 controls passed; RN3-001..004 failed |
| npm 12.2 probes (`npm cache add`, `npm ci --offline` with flag on cmdline / userconfig / both / neither) | 0 | markers only in the neither case |
| `cmd.exe /d /s /c .\setup` with `setup.bat` | 0 | batch ran |

The `rn3_*` tests assert the safe behaviour and fail until fixed.
