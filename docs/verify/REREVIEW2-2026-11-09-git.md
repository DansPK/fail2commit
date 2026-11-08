# Second re-review: Git secret-scan fixes R1-001, R1-002, R1-003, R1-005 (FR-001, FR-003)

Date: 2026-11-09
Candidate: `DansPK/f2c-int-wave1` @ `fdfa893` (fix diff `git diff d40f6f2..7c0889d`)
Earlier reports: `REVIEW-2026-11-09-wave1.md`, `REREVIEW-2026-11-09-wave1.md`
Reproductions: `crates/fail2commit/tests/rereview2_git.rs`. No product code was changed.

**Verdict: R1-001, R1-002 and R1-003 are Fixed. R1-005 is Partially fixed.** Three new findings (R2-001..R2-003), none High. R2-001 and R2-002 are BOM-less UTF-16/UTF-32 cases that still scan as clean. R2-003 is the scanner running a repository-named program. The regression suite is green (46/46). Not blocking for wave 1 on its own, but R2-001/R2-002 should be fixed before FR-001 is called verified.

## Per-fix status

| ID | Status | Evidence |
|---|---|---|
| R1-001 | **Fixed** (class closed for object and graph state; one config-program gap, R2-003) | See the audit below. |
| R1-002 | **Fixed** | `scan.rs:65-83,171-249`; tests `r1_002_annotated_and_nested_tags_are_peeled` and `r1_002_unresolvable_tip_is_incomplete` pass. |
| R1-003 | **Fixed** | `secrets.rs:62-92`; `r1_003_...` passes. |
| R1-005 | **Partially fixed** | BOM and high-NUL UTF-16 are decoded; BOM-less diluted UTF-16 and BOM-less UTF-32 are still clean (R2-001, R2-002). |

### R1-001 audit: does repository state change what the scanner sees?

Every git subprocess in `git/` and `server/` that reads repository content goes through `gitcmd::command`/`gitcmd::run`: `scan.rs` (`walk_direct`, `collect_changes`, `batch`), `gitcmd::object_type`, `classify.rs:33,50`, `receive.rs:117` (`is_ancestor`) and `integ.rs` (`config --global` only). The other `Command::new` sites are not scanning: `integ.rs` (`reg`), `server/install.rs:33,69` (`rev-parse --is-bare-repository`, install-time `config`), and, outside `git/` and `server/`, `cmd/git.rs` (the shim's passthrough and `config` reads of push intent) and `cmd/hook.rs` (tests only). No scanner path bypasses the wrapper.

| Vector | Can the scanner see less than the push publishes? | Basis |
|---|---|---|
| Replace refs | No. `GIT_NO_REPLACE_OBJECTS=1` plus `env_remove(GIT_REPLACE_REF_BASE)`. | `r1_001_replace_ref_*` and `r1_001_server_replace_ref_*` pass. `rev-parse HEAD` in `secret-scan` is not affected by replace refs (R2-003 probe `r2_003...` passes). |
| Grafts (`info/grafts`) | No. Git ignores grafts when replace objects are disabled. | By Git behavior (not separately probed). |
| Shallow file | No. A shallow boundary commit becomes a root; `--root` lists its whole tree, so the scan covers more, never less. | By inspection. |
| Alternates, `GIT_ALTERNATE_OBJECT_DIRECTORIES` | No. Extra objects are visible to the scanner exactly as to pack-objects. On the server the inherited quarantine variables are required, so not scrubbing them is correct. | By inspection. |
| Object whose content does not match its id | No. Pack-objects would send the same bytes the scanner read, and the remote re-hashes. | By inspection. |
| `core.commitGraph`, `core.fsmonitor` | No. Forced off through `GIT_CONFIG_COUNT`, which outranks repository config and any `include.path`/`includeIf`. | `gitcmd.rs:37-41`. |
| `core.hooksPath`, `uploadpack.*` | No effect on the read commands used (`rev-parse`, `cat-file`, `log`, `ls-tree`, `merge-base`). | No hook or upload-pack is invoked. `remote.<name>.uploadpack` matters only for `secret-scan --remote` (see R1-003). |
| Partial clone, promisor remotes | No. `GIT_NO_LAZY_FETCH=1` (Git 2.44+, tested on 2.56) and a missing blob gives the "missing or unreadable" `IncompleteScan` note. Caveat: Git older than 2.44 ignores the variable and may lazy-fetch from a repository-named URL. There is no version check in `git/`. Not reproduced. | PLAUSIBLE, Low, noted rather than numbered. |
| `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` leaking from the caller | Not scrubbed. A wrong `GIT_DIR` points at another repository where the tip is missing, which gives `IncompleteScan`, so it fails closed. The caller's environment is not repository-controlled. | By inspection, no finding. |
| Config that makes `git log` run a program | **Yes, a program runs** (R2-003). It does not hide entries. | Reproduced. |

## Status of R1-002

- Tips are peeled with `rev-parse --verify -q <oid>^{}`, which follows nested tags, then typed with `cat-file -t`. Commits go to the walk; blobs and trees go to `walk_direct`; anything else, or a failed peel, adds an `IncompleteScan` finding.
- `walk_direct` streams `ls-tree -r -z` and stops at `graph_max_nodes × 10` entries (`entry_limit_hit`, then `IncompleteScan`). A tree it cannot list gives `Error::incomplete`.
- Server path: `receive.rs:198-213` turns every scan finding into `Deny` and every scan error into a hard deny, so none of these outcomes can be approved.
- Tests pass: nested tag to tree, nested tag to blob, absent tip.

## Status of R1-003

- Default `secret-scan` uses `old = 0`, scans everything reachable from HEAD, and the output says "local-only: scanned all history reachable from HEAD ...". In a repository larger than the history bound this ends in `IncompleteScan`, which fails closed.
- `--remote` runs `git ls-remote -- <remote> <ref>` with structured arguments. The `--` stops option injection through a malicious name or URL. `ext::` is off by default (`protocol.ext.allow`). A failure of the query is an error, not "clean". The remote name resolved from repository config is the same one a real push would use.
- Residual, not numbered: `ls-remote` uses the fetch URL while a push may use `pushurl`. `remote.<name>.uploadpack` in repository config is executed by `ls-remote` for local/ssh transports, as it would be by `push`. `ls-remote` tail-matches its pattern, so a remote branch named `a/refs/heads/main` can come first; the excluded commit is still one the remote has, so nothing unpublished is hidden. The command also uses a bare `Command::new(git)` instead of the wrapper, which is fine for a network query.

## New findings

### R2-001 — Medium — CONFIRMED: BOM-less UTF-16 with few NULs scans clean

**Location:** `crates/fail2commit-core/src/git/scan.rs:499-520` (`utf16_view` NUL-parity heuristic).
**Scenario:** a UTF-16LE file without a BOM, holding `aws_key=AKIA...` followed by 400 CJK characters. NUL bytes are about 5% of the file, below the 40% threshold, so `utf16_view` returns `Utf16::No`. The UTF-8 lossy view has a NUL between every ASCII character, so no detector matches. `scan_outgoing` returns `[]` (clean). The fix notes say undecodable text gives `IncompleteScan`; this text is decodable but is not recognized. Repro: `r2_001_bomless_utf16_diluted_with_cjk_must_not_be_clean` (got `[]`).
**Fix:** decode and scan the UTF-16LE/BE view of every blob that contains NULs (a second bounded pass costs about 2× the blob in memory, already within the 32 MiB cap), or report any NUL-containing, non-BOM blob that did not decode cleanly as UTF-8 as `IncompleteScan`. Do not rely on a ratio an author can dilute.

### R2-002 — Medium — CONFIRMED: BOM-less UTF-32 scans clean

**Location:** `scan.rs:492-520`.
**Scenario:** UTF-32LE ASCII text has NULs in 3 of 4 bytes, which gives `even*10 > half`, so the heuristic returns `None`. Only a UTF-32 file that starts with a BOM is reported (`r1_005_utf32_is_incomplete_not_clean`). Repro: `r2_002_bomless_utf32_must_not_be_clean` (got `[]`).
**Fix:** same as R2-001. Also scan or flag the UTF-32LE/BE decodings, or treat the NUL ratio ≥ 25% as "unexamined".

### R2-003 — Low — CONFIRMED: the scanner runs a repository-named program (`log.showSignature` + `gpg.program`)

**Location:** `gitcmd.rs:32-49` (forced config limited to `core.commitGraph`, `core.fsmonitor`); consumer `scan.rs:259-273`.
**Scenario:** repository config sets `log.showSignature=true` and `gpg.program=<script>`, and a commit has a (fake) `gpgsig` header. `git log` in `collect_changes` then executes the script. Repro: `r2_004_scan_must_not_run_repository_named_gpg_program` (marker file was created; the test name predates the final numbering). This cannot hide entries (the output only adds tokens, and a malformed token is an error that denies), but it is execution of repository-controlled code inside the guard, the same class as `core.fsmonitor`, which was closed. Config is not transferred by clone or push; it matters for repositories received as archives or worktrees.
**Fix:** add `-c`-equivalent entries `log.showSignature=false` and `gpg.program=` (and pass `--no-show-signature` to `git log`) in `gitcmd::command`.

## Considered, not findings

- `rev-parse HEAD` in `secret-scan` is unhardened but is not affected by replace refs (probe passed).
- Caller `GIT_DIR`/object-directory variables: fail closed (see table).
- `diff.*`, `.gitattributes`, `textconv` and `diff.external` do not apply to `log --raw`.
- Commit and tag messages are not scanned for secrets. This is a design limit from the original scope, not a fix regression.

## Commands run

All Rust commands used `-j 2` and empty stdin. Platform: Windows 11, Git 2.56.0.windows.2. Linux was not exercised, so Linux behavior is pending evidence.

| Command | Exit | Result |
|---|---:|---|
| `cargo test -j 2 -p fail2commit --test git_push --test git_setup --test review_wave1 --test rereview_wave1 --test server_protected` | 0 | 46 passed (git_push 13, git_setup 6, rereview_wave1 8, review_wave1 10, server_protected 9) |
| `cargo test -j 2 -p fail2commit --test rereview2_git` | 101 (expected) | 1 passed (probe `r2_003`), 3 failed as designed: `r2_001`, `r2_002`, `r2_004` (finding R2-003) |
| `rustfmt --edition 2021 crates/fail2commit/tests/rereview2_git.rs` | 0 | formatted |

Tested SHA: `fdfa893` plus this report and `rereview2_git.rs`.
