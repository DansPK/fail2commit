# Re-review: npm and scanner fixes (W2-003/004/005/007/008, CR-003/CR-004)

Reviewer: independent worker. Tested SHA: `95ec493` (+ this report and `crates/fail2commit/tests/rereview_npmscan.rs`). Product code untouched.
Platform: Windows 11 (NTFS, 8.3 names on), node v24.22.0, npm's bundled `tar` used to probe the real extractor. Offline fixtures only.

## Verdict

**Not clean.** The five original repros are fixed, but each fix leaves a trivial bypass of the same rule. W2-007 and W2-008 hold for every realistic input (one narrow truncation edge case, RN-008). W2-003, W2-004 and W2-005 each still have confirmed bypasses (RN-001..RN-007). Fix RN-002, 003, 004 and 006 before merge; RN-001, 005 and 007 are cheap and should ride along.

## Per-finding status

| ID | Status | Notes |
|---|---|---|
| W2-003 | **Partly fixed** | NUL-prefixed (first 8 KiB), undecodable and over-1-MiB-prefix files now give `IncompleteScan` Deny naming the file. UTF-16: node and `sh` cannot run it, PowerShell can; every ASCII char carries a NUL so it is denied as binary (control passes). Referenced files over 256 KiB are denied by the archive caps (control passes). **Gap: RN-001** (NUL past byte 8192 is ignored by `sh`). Transitive `require()` chains are not followed: accepted evidence limit, see Notes. |
| W2-004 | **Partly fixed** | Extension-less `sh ./run`, quoted `"./x"`, backslash paths and cap-dropped candidates now work. `CANDIDATE_BUDGET` is gone, so filler can no longer push a candidate out (pass 2 reads only wanted files; cap overflow is Deny). **Gaps: RN-002, RN-003, RN-004.** |
| W2-005 | **Partly fixed** | ASCII case, trailing dot/space and duplicate-entry collisions are rejected before anything else (unit tests). NTFS ADS (`:`) is rejected by `normalize`. Kelvin sign and long s do **not** fold on NTFS (probed), so they are not real. **Gaps: RN-005 (non-ASCII case), RN-006 (`./package.json`), RN-007 (8.3 short names).** |
| W2-007 | **Fixed** | Truncation sets `complete=false` and adds an `IncompleteScan` finding; `MAL-` ids sort first. Edge case: RN-008. |
| W2-008 / CR-003 | **Fixed** | Malware is `Deny` at the single classification site (`scan/mod.rs:284`). npm (`npm/mod.rs:293`), pip (`pip/mod.rs:258`) and `scan` (`cmd/scan.rs:88`, `Rejected`, exit 10) all gate on `any Deny`. The cache stores only ids and raw OSV records, never actions, so entries written before the change are reclassified on every read. The OpenSSF `database_specific` / `source` classification goes through the same site. `scan_cli::malware_is_reported_separately_as_json` asserts the deny and the exit code. |

## New findings

| ID | Sev | Status | Where | Scenario | Fix |
|---|---|---|---|---|---|
| RN-001 | Medium | CONFIRMED | `scan/mod.rs:443` (`script_text`) | `sh` ignores NUL bytes after the first line (probed: `ec<NUL>ho` runs `echo`). A referenced script with 9 KB of padding followed by a forced `git pu<NUL>sh` has no NUL in the first 8192 bytes, so it is decoded and the rules see a split token: clean. Test `nul_inside_the_command_past_8k_is_not_a_clean_scan`. | Check NUL over the whole inspected prefix (or strip NUL before the rules and Deny if any is present). |
| RN-002 | Medium | CONFIRMED | `npm/archive.rs:183-189` | `node ./setup` runs `setup.js` (also `node .`, `node ./lib` -> `index.js`). The token `setup` matches no entry, so the file is never read: clean install. Test `node_extension_resolution_is_a_candidate`. | Also treat `tok` + `.js/.mjs/.cjs/.json/.node` and `tok/index.*` as candidates; Deny when a lifecycle command names a directory. |
| RN-003 | Medium | CONFIRMED | `npm/archive.rs:183-189` | The tokenizer is lexical and splits on whitespace and quotes: `sh "./my script"` -> `./my`, `script`; `sh .//run` and `sh ./a/../run` never equal `run`; `sh $PWD/run` -> `/run`. Each runs a file that is never read. Tests `quoted_path_with_a_space_is_a_candidate`, `double_slash_is_a_candidate`, `inner_dotdot_is_a_candidate`, `variable_prefixed_path_is_a_candidate`. | Resolve each token against the archive set: normalize `//`, `.` and inner `..`, strip `$VAR`/`$(..)` prefixes, try whitespace-joined runs inside quotes. Fail-closed alternative: when the command uses `$`, a backtick, a glob or a quoted path with a space, Deny as `IncompleteScan` if the archive holds any unreferenced script-like file. |
| RN-004 | Medium | CONFIRMED | `npm/archive.rs:158-164`, `npm/review.rs:196` | Only `preinstall/install/postinstall` reach the inspector. `"postinstall": "npm run build"` with a hostile `scripts.build` is never inspected. Test `npm_run_chain_to_a_non_lifecycle_script_is_inspected`. | Pass every `scripts` entry (or those named by `npm run`, `yarn`, `pnpm`) to `inspect_scripts`. |
| RN-005 | Medium | CONFIRMED (Windows) | `npm/archive.rs:64-69` (`fold`) | NTFS folds non-ASCII case. Probed with npm's own `tar` (`strip:1`): `package/Ü.js` and `package/ü.js` extract to one file, last wins. `fold` is ASCII-only, so the pair passes the collision check, and a lone `Ü.js` is not matched by the token `./ü.js`. Tests `non_ascii_case_collision_is_rejected`, `non_ascii_case_variant_is_a_candidate`. | Fold with Unicode simple case folding, or reject non-ASCII path components outright. |
| RN-006 | High | CONFIRMED | `npm/archive.rs:47-59` (`normalize`) | `normalize` drops `.` components before removing the package directory, so the entry `./package.json` is skipped and never collides with `package/package.json`. npm's `tar` with `strip:1` treats `.` as the stripped component and extracts it to the root, overwriting the reviewed manifest (probed: root `package.json` content was the hostile one). The hostile `scripts` run; the reviewed ones were benign. Test `dot_slash_package_json_is_not_skipped`. | Strip the first component before dropping `.`/empty parts, exactly as `tar strip:1` does, or reject any entry containing `.` or empty components. |
| RN-007 | Low | CONFIRMED (Windows, 8.3 enabled) | `npm/archive.rs:183-191` | `sh ./BUILDH~1.JS` opens `buildhelper.js` on NTFS volumes with 8.3 names (verified here with `dir /x` and `Test-Path`). The token matches no entry. Test `short_name_alias_is_a_candidate`. | Deny any lifecycle token containing `~<digit>`. |
| RN-008 | Low | CONFIRMED (narrow) | `scan/mod.rs:238` | Truncation sorts on the case-sensitive `MAL-` prefix only, while `is_malware` is case-insensitive and also content-based. With more than 128 ids, a lowercase `mal-` id or a non-`MAL-` id whose record is OpenSSF-classified can be dropped, leaving only an approvable `IncompleteScan`. OSV emits upper-case `MAL-` ids, so practical risk is low. Tests `truncation_never_drops_a_lowercase_mal_id`, `truncation_never_drops_a_content_classified_malware_record`. | Sort with a case-insensitive prefix check; make the truncation finding a Deny when more than the limit of ids exist and any dropped id is unclassified. |

### Notes (not findings)

- `require()` chains: `setup.js` -> `require('./lib')` -> `lib.js` is never read. The rules are documented as evidence, not a boundary (`scan/mod.rs:12-16`, `rules.rs`), and following code is unbounded. Acceptable, but `docs/npm.md` should say that only files named in the lifecycle command are read.
- `sh -c "..."` and `node -e "..."` text is covered because quotes are split into tokens; obfuscated string building is not (accepted evidence limit).
- ADS (`file:stream`), Kelvin sign and long s: not exploitable (rejected / not folded by NTFS).

## Commands

| Command | Exit | Result |
|---|---|---|
| `cargo test -j 2 -p fail2commit --test scan_advisories` | 0 | 15 passed, 1 ignored (live OSV) |
| `cargo test -j 2 -p fail2commit --test scan_cli` | 0 | 12 passed |
| `cargo test -j 2 -p fail2commit --test scan_scripts` | 0 | 8 passed |
| `cargo test -j 2 -p fail2commit --test review_wave2_scan` | 0 | 3 passed |
| `cargo test -j 2 -p fail2commit --test npm_cli` | 0 | 3 passed |
| `cargo test -j 2 -p fail2commit --test npm_flow` | 0 | 21 passed |
| `cargo test -j 2 -p fail2commit --test npm_scripts` | 0 | 7 passed |
| `cargo test -j 2 -p fail2commit-core --lib scan::` | 0 | 21 passed |
| `cargo test -j 2 -p fail2commit-core --lib npm::` | 0 | 19 passed |
| `cargo test -j 2 -p fail2commit --test rereview_npmscan` | 101 (expected) | 3 controls pass, 13 reproductions fail (RN-001..RN-008 confirmed) |

All commands ran with empty stdin. The reproductions assert the safe behaviour, so they are expected to fail until the fixes land. Exit codes for the first nine rows were taken from the shell loop's `PIPESTATUS`.
