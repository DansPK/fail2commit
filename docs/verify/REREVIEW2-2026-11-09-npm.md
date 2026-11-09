# Re-review 2: npm archive integrity fixes RN-005 / RN-006 / RN-007 (FR-004)

- Tested SHA: `be9c5a2` (branch `DansPK/f2c-fix-npmscan-r2`), reviewed from `DansPK/f2c-rereview2-npm`.
- Scope: `git diff 12c2f39..be9c5a2` in `crates/fail2commit-core/src/npm/archive.rs` and `npm/review.rs`.
- Reference extractor: `pacote.extract` of npm 12.2.0 on this host (bundled `tar` 7.5.22, `strip: 1`, links dropped, `.gitignore` renamed). Probe scripts were run directly against that code, not against documentation.
- Host: Windows 11, NTFS, 8.3 names enabled. The Linux extractor is the same JavaScript; filesystem-folding results are Windows only.

## Verdict: **not clean**

The three named fixes hold for every *name* variant I tried. The review still reads a different set of bytes than npm extracts, because the Rust reader and npm's `tar` disagree about **where the archive ends and what an entry body is** (RN2-001..003), and about **one rename npm applies** (RN2-004). RN2-001..003 let an attacker replace the reviewed `package.json` with a hostile one at no cost. They are higher severity than anything the three fixes closed. Do not merge until RN2-001..004 are fixed.

## Per-fix status

| Fix | Status | Evidence |
|---|---|---|
| RN-006 (`./package.json`) | **Fixed for names** | `normalize` drops the first component like `tar strip:1` (`archive.rs:42-83`). Tested against npm's extractor: `./`, `.//`, `other/`, `package//`, `package/./` all land on root `package.json` and now collide; `../`, `/`, `//package/`, `\`, `C:`, `a/C:x`, inner `..` are rejected (npm either strips them to the root or writes inside the package). PAX `path`, GNU `L`, ustar `prefix` resolve identically in `tar-rs` and `tar`. PAX *global* `path` is ignored by npm; `tar-rs` does not return it as a Regular entry (not separately tested). Hard and symbolic links: npm drops them, Rust denies (stricter, safe). Test: `control_names_*`, `control_unsafe_names_*`, `control_pax_and_gnu_*`, `control_link_entries_*`. **But see RN2-001..004: the names are right, the bytes are not.** |
| RN-005 (Unicode folding) | **Fixed, sound on NTFS** | I created every valid BMP code point (63,447) as file names on this NTFS volume. 973 pairs collide; `fold` (`to_uppercase().to_lowercase()` per component, trailing `.`/space trimmed) merges **all 973** (0 missed). It also merges about 230 extra characters that NTFS keeps apart (`µ`/`μ`, `Å` Angstrom/`å`, `Ω` Ohm/`ω`, Kelvin `K`/`k`, `ſ`/`s`, `ǅ`/`ǆ`, `ς`/`σ`, `ß`/`ss`, Deseret, ...). That is fail-closed. Matters on NTFS's upcase table: ASCII, Latin-1 (`Ü`/`ü`), Greek, Cyrillic, fullwidth `Ａ`/`ａ`. Does **not** fold: Kelvin, long s, dotless `ı`, `ß`, NFC/NFD (distinct files), and fullwidth never equals ASCII. Cost: a package that ships both `µ.js` and `μ.js` is denied. Test: `control_ntfs_case_pairs_collide`. |
| RN-007 (8.3 names) | **Fixed for entry names and plain tokens; two gaps** | Entry components and every `/`-split token word of a lifecycle command are denied when shaped `X~N[.ext]` (`archive.rs:68`, `scripts.rs:198`). Gaps: RN2-006 (`main`), RN2-007 (trailing dot). |

## New findings

| ID | Sev | Status | Where | Scenario | Fix |
|---|---|---|---|---|---|
| RN2-001 | **High** | CONFIRMED | `archive.rs:105` (`flate2::read::GzDecoder`) | npm's `tar` decodes **every concatenated gzip member**; `GzDecoder` stops after the first. Member 1 = benign `package/package.json` with no end marker, member 2 = hostile `package/package.json` (`postinstall: git push --force`). Rust reviews member 1 only; npm extracts the hostile manifest over it. The lockfile SRI covers the whole file so it passes. Probe: `two members (no EOF in 1st)` extracted `evil.js`. Test `rn2_001_second_gzip_member_is_not_hidden`. | Use `MultiGzDecoder`, or reject any bytes left after the first member (read to EOF and require zero). Prefer rejecting: real `npm pack` output is one member. |
| RN2-002 | **High** | CONFIRMED | `archive.rs:112` (`tar-rs` `entries()`) | `tar-rs` ends at the first all-zero block; npm's `tar` needs **two consecutive** and keeps parsing after one. `[benign pkg.json][1 zero block][hostile pkg.json][2 zero blocks]`: Rust sees one entry, npm extracts the hostile one over it. Probe `one zero block then entry`. Test `rn2_002_single_zero_block_does_not_end_the_archive`. | After the iterator ends, drain the decompressed stream and require only zero bytes. Reject any non-zero byte after the end marker, and reject a lone zero block (`ignore_zeros(false)` does not do this). |
| RN2-003 | **High** | CONFIRMED | `archive.rs:119-130` (entry type + size) | npm's `tar` forces size 0 for type `5`, and rewrites a type-`0` entry whose path ends in `/` to type `5` (`header.js:130,168`). The body is then parsed as the next headers. `tar-rs` skips `size` bytes. An entry `package/x/` (type `0`, size 1024) or `package/d` (type `5`, size 1024) whose body is a complete tar entry smuggles a `package/package.json` that Rust never sees. Probe: both extracted `package.json=HOSTILE`. Tests `rn2_003_*`, `rn2_003b_*`. | Reject directory entries with non-zero size, and Regular/Continuous entries whose raw path ends in `/`. |
| RN2-004 | **Medium** | CONFIRMED | `archive.rs:164-208`, `expand` (name resolution) | pacote renames every `.gitignore` to `.npmignore` unless a `.npmignore` appeared earlier (`pacote/lib/fetcher.js:437-448`; probed: `.gitignore=HOSTILE` extracts as `.npmignore`, also under subdirectories). `postinstall: "sh ./.npmignore"` runs the bytes of the archive's `.gitignore`; the review looks for an entry named `.npmignore`, finds none, reads nothing. Test `rn2_004_gitignore_is_extracted_as_npmignore`. | Apply npm's rename when building `seen`/candidates: treat an entry whose basename is `.gitignore` as also reachable as `.npmignore` (and read it), unless an earlier `.npmignore` exists. Simplest: make a candidate `.npmignore` also read the sibling `.gitignore`. |
| RN2-006 | Low | CONFIRMED (code path; needs 8.3 volume to run) | `archive.rs:314-334` (`expand`, `main`) | `expand` joins a `main` of `BUILDH~1.JS` into the candidate set without the short-name test, so `node .` opens `buildhelper.js` through the alias while the review looks for an entry called `buildh~1.js`. Test `rn2_006_main_field_short_name_alias_is_denied`. | Run `is_short_name` over each `main` component and Deny. |
| RN2-007 | Low | PLAUSIBLE | `scripts.rs:43-47` (`is_short_name`) | Splits at the last `.`, so `BUILDH~1.JS.` has stem `BUILDH~1.JS` and is not flagged. `type BUILDH~1.JS.` in cmd opened the file (probed); `node` rejects the trailing dot, so the exploit needs a cmd builtin or a program that normalizes with Win32 rules. Test `rn2_007_trailing_dot_short_name_token_is_denied`. | Trim trailing `.`/space from the component before testing. |

### Verified safe or out of scope

- **Order of checks (item 3): holds.** Per entry: type check, then `normalize` (path, `..`, drive/ADS marker, backslash, absolute, 8.3), then the fold collision check, and only then the body is read (`archive.rs:112-131`, `155-164`). Nothing is decided from a name before that. A collision or 8.3 name is reported even when the archive has no `package.json` (`control_collision_is_reported_before_a_missing_manifest`, `control_short_name_entries_are_rejected_first`). Pass 2 selects files by `fold(rel)`, which is collision-free by construction. `review.rs` calls `inspect` right after `verify_sri` and uses nothing from the archive before that. The `review.rs` diff only forwards `chained` scripts to the inspector.
- `node ./setup.js::$DATA` opens `setup.js` on NTFS (probed) but the `$` makes the word an unknown expansion and the review denies it (`control_default_stream_suffix_is_denied`).
- Windows device names (`CON`, `NUL`, ...) extract with npm's `\\?\` paths and cannot run; no integrity effect.
- npm filters directories out (it only extracts `*File` types); Rust treats directory names as occupying a name, which only denies more.
- Not exploitable by name today, but fragile: `normalize` allows a trailing-slash path only because `split('/')` drops empty parts. RN2-003's fix should reject it explicitly.

## Commands

All commands ran with empty stdin (`< /dev/null`), cargo `-j 2`, from the repo root at `be9c5a2` plus the new test file.

| Command | Exit | Result |
|---|---|---|
| `cargo test -j 2 -p fail2commit --test npm_cli` | 0 | 3 passed |
| `cargo test -j 2 -p fail2commit --test npm_flow` | 0 | 21 passed |
| `cargo test -j 2 -p fail2commit --test npm_scripts` | 0 | 7 passed |
| `cargo test -j 2 -p fail2commit --test rereview_npmscan` | 0 | 24 passed (no regressions; RN-001..008 repros all pass) |
| `cargo test -j 2 -p fail2commit-core --lib npm::` | 0 | 27 passed |
| `cargo test -j 2 -p fail2commit --test rereview2_npm` | 101 (expected) | 11 passed (controls), 7 failed: RN2-001, 002, 003, 003b, 004, 006, 007 |
| `node probe.js`, `probe2.js`, `probe3.js` (npm 12.2.0 `tar`/`pacote`) | 0 | name, header, member and rename behaviour quoted above |
| `node ntfs.js` + `foldchk.exe` (all BMP code points on NTFS vs `fold`) | 0 | 973 NTFS pairs, 0 missed |

The `rn2_*` tests assert the safe behaviour, so they are expected to fail until the findings are fixed. The probe scripts are not committed (they extract archives to temp directories); the Rust tests encode the same byte layouts and are the committed reproductions.
