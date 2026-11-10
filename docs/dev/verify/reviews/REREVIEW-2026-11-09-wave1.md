# Independent re-review: wave-1 security fixes (FR-001, FR-002, FR-009, FR-010)

Date: 2026-11-09
Candidate: `DansPK/f2c-int-wave1` @ `d163faa` (reviewed worktree branch `DansPK/f2c-rereview-wave1`)
Fix diffs: `git diff 0a88dca..63389f4` (W1-001..003), `git show 61551a6` (W1-004/005)
Earlier review: `docs/dev/verify/reviews/REVIEW-2026-11-09-wave1.md`

**Verdict: NOT ready to merge.** W1-002, W1-003, W1-004 and W1-005 are fixed. W1-001 is only partially fixed: the specific `refs/remotes/**` bypass is closed, but the same class (repository state that changes what the scanner sees) remains through replace refs, and through `secret-scan` and non-commit tips. Three new High findings (R1-001..R1-003) have failing reproductions in `crates/fail2commit/tests/rereview_wave1.rs`. No product code was changed.

## Status of the original findings

| ID | Status | Evidence |
|---|---|---|
| W1-001 | **Partially fixed** | `scan.rs:31-82` ignores `_remote` and excludes only `u.old` of the proposed tuples, and only when the object is a local commit/tag. Missing or shallow old objects exclude nothing, so the scan covers more. `review_wave1::repository_controlled_remote_tracking_ref_must_not_hide_outgoing_secret` and `only_the_remote_reported_old_oid_excludes_history` pass. Remaining: replace refs (R1-001), non-commit tips (R1-002), `secret-scan` command (R1-003). |
| W1-002 | **Fixed** | `prepush.rs:95-105` requires the password for `ForceIntent`, `RefRewrite`, `TagReplacement`, `RefDeletion`. `classify.rs:33-69` adds a `RefRewrite` whenever the old object is missing or the ancestry check fails (`merge-base` exit other than 0/1), and for a non-commit old object. Unit test `destructive_updates_require_password_without_shim_intent` covers tag move, delete, missing old and a plain fast-forward (no prompt) on the direct hook path. Ref types: creation is never destructive. Any other ref (`refs/notes/*`, `refs/replace/*`, `refs/pull/*`) is classified by the branch logic (ancestry, or non-commit old, or missing old), so a rewrite there is `RefRewrite`. I found no kind or ref type that rewrites without the password. |
| W1-003 | **Fixed** | `scan.rs:238-340`: two passes (`--batch-check`, then `--batch`) read whole blobs up to 32 MiB; missing, unreadable, oversize, over-budget or short-read blobs each yield an `IncompleteScan` note. Full object size is charged against `scan_max_bytes`. Binary blobs are scanned lossily. Overlong lines are scanned in overlapping 8 KiB windows (`detect.rs`). Submodule entries (mode 160000) are not blobs and are not read. Symlink blobs are scanned as text (their target). LFS pointers are scanned as text; LFS payload is not part of the push. Server path: `receive.rs:199-213` maps every scan finding, including `IncompleteScan`, to `Deny` and any scan error to a hard deny, so `IncompleteScan` is not approvable there. Tests `blob_past_the_old_4mib_prefix_is_scanned`, `missing_blob_is_incomplete_not_clean`, `blob_over_the_single_file_limit_is_incomplete_not_clean`, `secret_inside_an_overlong_line_is_found`, `binary_blob_is_scanned_not_skipped...` pass. Residual (Low, R1-005): UTF-16 text and other encodings are not decoded. |
| W1-004 | **Fixed** | `extension.ts` now routes the argv log line, `progress` messages, `res.code`/`res.message`, error text, notifications, modal summary/details and `fmt()` of findings through `sanitize`. The credentialed-URL test passes. Residual: URL redaction has the gaps in R1-004. |
| W1-005 | **Fixed** | Tray `clean()` now calls `approval::console::sanitize` (`render.rs:8-10`); summary, every detail line and every finding line pass through it. Tests for U+202A/202E/2066/2069/200B pass. VS Code `UNSAFE` covers C0, U+007F-009F, U+200B-200F, U+202A-202E, U+2066-2069 and uses the same URL regex as `redact_url_credentials`, so it matches the Rust sanitizer. Both share the gaps in R1-004. |

## FAIL2COMMIT_HOOK_FAIL_CLOSED

Confirmed stricter-only. `hook.rs:35-41` reads the process environment and, when it is non-empty, replaces the approval channel with `ApproverChoice::None`; `approval::approve` (`approval/mod.rs:36-40`) then returns `ApprovalUnavailable` for any request that reaches it. It runs only after findings exist, so it adds no allow path and skips no check: an empty finding list still returns before it, and every other path is unchanged. A repository cannot set it, because it is process environment, not Git config. A hostile local process could set it only to make pushes fail. No finding.

## New findings

### R1-001 — High — CONFIRMED: replace refs hide secret blobs from the scanner

**Location:** `crates/fail2commit-core/src/git/gitcmd.rs:21-30` (no `GIT_NO_REPLACE_OBJECTS` / `--no-replace-objects`); consumers `scan.rs:143` (`git log`), `scan.rs` `batch()` (`cat-file`).
**Scenario:** the repository holds `refs/replace/<secret-blob> -> <clean-blob>`. `git cat-file --batch` returns the clean content for the secret blob's OID, the scan is empty, while Git's pack generation works from the real object IDs (I did not run a real push; the scanner result is what the test proves). Repro: `r1_001_replace_ref_must_not_hide_secret_blob` (got `[]`). The same applies on the server: `refs/replace/*` is normally an unprotected namespace, so a pusher can plant a replace ref first and then push the secret to a protected branch, defeating `secret_policy` in `receive.rs:199`. This is the "repository-controlled data changes what the scanner sees" class the original W1-001 asked to remove.
**Fix:** set `GIT_NO_REPLACE_OBJECTS=1` in `gitcmd::command`, and use the same hardened environment in `receive.rs::is_ancestor`. Keep the repro as a permanent test.
**Tried, not a bypass:** replacing an ancestor commit does not fake a fast-forward, because `merge-base --is-ancestor` compares original OIDs. A `.git/shallow` file and alternates were considered but not tested; neither obviously lets the scanner see less than the pack would carry.

### R1-002 — High — CONFIRMED: a tag pointing at a blob or tree is never scanned

**Location:** `scan.rs:41-62` (tips), `scan.rs:143` (`git log <tip>`).
**Scenario:** `git log <blob-or-tree-oid>` exits 0 with no output, so a lightweight tag (or annotated tag) to a blob/tree containing a secret produces `[]`. Git and Git servers accept tags to non-commits; creation has `old = 0`, so classification adds nothing. Repro: `r1_002_tag_to_blob_or_tree_must_not_be_unscanned` (got `[]`). The same scan runs for protected tags on the server.
**Fix:** for each tip, peel with `cat-file -t`/`rev-parse <oid>^{}`; if the result is not a commit, either walk the tree and scan its blobs or emit a non-approvable `IncompleteScan`. Fail closed on any tip whose type cannot be established.

### R1-003 — Medium — CONFIRMED: `secret-scan` trusts the repository's remote-tracking ref as the remote's OID

**Location:** `crates/fail2commit/src/cmd/secrets.rs:59-74`.
**Scenario:** the command passes `refs/remotes/<remote>/<branch>` as `old`; the new `scan()` then excludes everything reachable from it. A repository (or an earlier `git update-ref`) that points that ref at `HEAD` makes `fail2commit secret-scan` print "no secrets found" with exit 0 while the push would publish the secret. This command is a preflight report, not the guard, but it reintroduces W1-001 in the user-visible check. Repro: `r1_003_secret_scan_command_must_not_trust_remote_tracking_ref` (exit 0).
**Fix:** run the scan with `old` = zero (scan all history reachable from `HEAD`), or obtain the remote's real value with `git ls-remote`. Say in the output when the result is local-only.

### R1-004 — Low — CONFIRMED (by inspection): invisible and bidi characters outside the escaped set, and imperfect URL-userinfo redaction

**Location:** `console.rs:105-120`, `extensions/vscode/src/sanitize.ts:5-10`.
- Not escaped: U+061C (Arabic letter mark, a bidi control), U+2060-2064 (word joiner and invisible operators), U+FEFF, U+2028/2029 (not `is_control`), U+00AD, U+180E, tag characters U+E0000-E007F. Two refs that differ only by an invisible character look identical in the dialog; the digest still binds the bytes, so this is a spoofing aid, not a bypass.
- Userinfo regex `[^/\s@]+@` stops at the first `@` or `/` or whitespace, so `https://user:p@ss@host/` leaves `ss@host`, and a password containing U+00A0 or `/` is only partly redacted.
**Fix:** use a shared deny-list based on Unicode `Cf`/`Zl`/`Zp` categories (add U+061C, U+2060-206F, U+FEFF, U+2028/9, U+E0000-E007F) and redact userinfo up to the last `@` before the first `/` after the scheme. Add the same cases to both test suites.

### R1-005 — Low — CONFIRMED (by inspection): UTF-16 and other encodings are not decoded

`scan.rs` applies `from_utf8_lossy`, so a UTF-16LE file containing a key (NUL between every character) matches no detector. Not a regression, but the W1-003 claim "no byte goes unexamined" holds for reading, not for decoding. **Fix:** also scan a UTF-16 decoding when the blob has a BOM or a high NUL ratio; or report such blobs as `IncompleteScan`.

### R1-006 — Low — PLAUSIBLE: VS Code QuickPick shows raw remote and branch names

**Location:** `extension.ts` (`pick(await git(...))` for remotes and branches). Branch and remote names may contain bidi controls, so the list item the user picks can be visually spoofed. This is a selection list rather than the output channel, a modal or a notification; the argv still carries the real name. **Fix:** show `sanitize(name)` as the label and keep the raw value separately.

## Question asked about a crafted remote old OID

If the remote reports an `old` OID that exists locally but the remote does not actually have, the walk excludes that OID's history and unpublished secrets in it are not scanned. In the pre-push hook the OID comes from the remote's own advertisement, so a remote that lies only hides data from itself; I consider this inside the trust boundary and not a finding. On the server (`pre_receive`) `old` is the server's real ref value. It would matter if a caller feeds a locally derived OID (R1-003 is that case).

## Commands run

All Rust commands used `-j 2` with empty stdin.

| Command | Exit | Result |
|---|---:|---|
| `cargo test -j 2 -p fail2commit --test review_wave1 --test git_push --test git_setup --test server_protected` | 0 | 38 passed (review_wave1 10, git_push 13, git_setup 6, server_protected 9) |
| `cargo test -j 2 -p fail2commit-tray` | 0 | 3 render tests + 1 AppContainer pipe test passed |
| `npm ci` (extensions/vscode) | 0 | install-scripts warning for `keytar` only |
| `npm run compile` (extensions/vscode) | 0 | `tsc -p .` clean |
| `npm test` (extensions/vscode) | 0 | 10 tests, 10 passed, 0 failed |
| `cargo test -j 2 -p fail2commit --test rereview_wave1` | 101 (expected) | 3 failed, as designed: R1-001, R1-002, R1-003 |
| `rustfmt --edition 2021 crates/fail2commit/tests/rereview_wave1.rs` | 0 | formatted |

Tested SHA: `d163faa` plus this report and `rereview_wave1.rs`. Platform: Windows 11 (Git 2.56.0.windows.2). Linux was not exercised; the findings above do not depend on the OS, but Linux behavior is pending evidence.
