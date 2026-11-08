# Independent security review: integration candidate wave 1

Date: 2026-11-09
Candidate branch: `DansPK/f2c-int-wave1`
Candidate SHA reviewed: `735b4b08b0e5c2a082a1793684cfdc2c314b1388`
Contract base: `fe411ba`
Review diff: `git diff fe411ba..735b4b08b0e5c2a082a1793684cfdc2c314b1388`

The candidate should not be merged without addressing W1-001 through W1-003. The attached `crates/fail2commit/tests/review_wave1.rs` contains three intentionally failing reproductions.

## Findings

### W1-001 — High — CONFIRMED: repository-controlled remote-tracking refs bypass the outgoing secret scan

**Location:** `crates/fail2commit-core/src/git/scan.rs:83`, `crates/fail2commit-core/src/git/scan.rs:90`, `crates/fail2commit-core/src/git/scan.rs:94`; scanner entry from `crates/fail2commit-core/src/git/prepush.rs:80`.

The scanner adds `--not --remotes=<remote>` to the history walk after checking only that `remote.<name>.url` exists. Remote-tracking refs are mutable local repository state and do not prove that the server can reach those commits. The reproduction creates a secret-bearing outgoing commit, points `refs/remotes/origin/attacker` at it, and obtains an empty finding list; the pre-push guard would therefore allow the secret to be published without approval.

**Suggested fix:** Exclude only the old OIDs supplied by Git's proposed ref-update tuples (and other reachability that is independently proven by the remote), never local `refs/remotes/**`. Add the reproduction as a permanent regression test.

### W1-002 — High — CONFIRMED: tag replacement can skip the configured force-push password

**Location:** `crates/fail2commit-core/src/git/prepush.rs:94-97`; tag classification at `crates/fail2commit-core/src/git/classify.rs:27-32`.

`needs_password` recognizes only `ForceIntent` and `RefRewrite`, not `TagReplacement`. A push made by plain Git or the VS Code SCM view still invokes the installed pre-push hook, but it does not carry the shim-only `FAIL2COMMIT_PUSH_INTENT`; replacing an existing tag therefore produces only `TagReplacement`, and a one-click `ApproveOnce` succeeds without the configured password. This bypasses SPEC-002's password requirement for actual rewrites.

**Suggested fix:** Treat tag replacement as a password-requiring rewrite, and conservatively require the password where a destructive update cannot be classified because the old object is missing. Test the direct-hook path without shim intent.

### W1-003 — High — CONFIRMED: unscanned blob content is silently treated as clean

**Location:** `crates/fail2commit-core/src/git/scan.rs:16`, `crates/fail2commit-core/src/git/scan.rs:290-304`; long-line skip at `crates/fail2commit-core/src/git/detect.rs:90-91`; server policy reuse at `crates/fail2commit-core/src/server/receive.rs:199`.

Every blob is capped to its first 4 MiB, but truncation does not set the `incomplete` flag. The reproduction puts a synthetic access key immediately after that prefix and receives an empty finding list. The same block silently skips a missing `cat-file` result and any blob whose first 8,000 bytes contain NUL; the text detector also skips lines longer than 8,192 bytes without reporting incompleteness. Because the protected-remote secret policy reuses this scanner, these clean false negatives affect both local guards and server enforcement.

**Suggested fix:** Scan complete bounded blobs, or emit a non-approvable `IncompleteScan` whenever any bytes, object, binary content, or overlong line are not examined. Account full object size—not only the chosen prefix—against the scan budget.

### W1-004 — Medium — CONFIRMED: VS Code logs raw package arguments, including embedded credentials

**Location:** `extensions/vscode/src/extension.ts:46`; pip input construction at `extensions/vscode/src/extension.ts:89-92`.

Before policy runs, the extension appends the complete argv vector to its persistent output channel. A package entry such as a direct URL containing `user:token@host` is written verbatim even if the CLI later rejects that input, violating the requirement that credentials and secret values never reach logs.

**Suggested fix:** Log only the command family/subcommand, or apply the core-equivalent URL/secret redaction before display. Add an extension test with a credentialed package URL and assert that neither username nor token reaches the output channel.

### W1-005 — Medium — PLAUSIBLE: Unicode bidi controls can spoof tray and VS Code approval text

**Location:** `crates/fail2commit-tray/src/render.rs:8-11`; `extensions/vscode/src/extension.ts:22-24`.

The tray removes `char::is_control()` characters but does not remove Unicode format controls such as U+202E RIGHT-TO-LEFT OVERRIDE; the VS Code modal passes summary/detail text through unchanged. Git accepts U+202E in a refname (`git check-ref-format` returned 0), so an untrusted ref can visually reorder text in the approval dialog even though the digest remains bound to the underlying bytes. The terminal renderer already strips U+202A–U+202E and U+2066–U+2069, demonstrating the intended treatment.

**Suggested fix:** Apply one shared presentation sanitizer to terminal, tray, and VS Code, covering bidi overrides/isolates as well as C0/C1 controls. Add rendering tests for U+202E and U+2066–U+2069.

## Checked and found sound

- Approval replies are bound to protocol version, request ID, nonce, digest and expiry; the originating session is checked before prompting, and consumed nonces are persisted under a lock.
- Password/recovery verifiers use independently salted Argon2id, constant-time hash comparison, serialized persistent rate limiting, atomic writes, and a generation bump that invalidates pending password-protected approvals on reset/change/disable.
- Server approval tokens are 256-bit random values stored only as SHA-256 verifiers, bound to repository ID, actor and the sorted complete update set, and atomically removed before binding validation. Concurrent reuse and replay tests passed.
- The Windows approval pipe rejects remote clients, gives an explicit deny ACE to both AppContainer package SIDs, verifies same-user/non-AppContainer peer process tokens on both ends, bounds wire messages, and revalidates the reply against the request. DACL, squatting and mismatched-reply tests passed.
- Host execution is offered only as `RunOnHostOnce` for the supplied operation digest when sandboxing was off in the command's settings snapshot; sandbox startup failure does not fall back to the host, and flagged scripts remain hard denied.
- The managed pre-push hook copies stdin before review, passes the copy to the prior hook, and propagates a prior-hook failure.

## Verification evidence

All Rust commands used Cargo `-j 2` as required. Test fixtures used disposable repositories and per-test Git configuration.

| Command | Exit | Evidence |
|---|---:|---|
| `cargo test -j 2 -p fail2commit --test review_wave1` | 101 (expected) | Three reproductions failed: remote-tracking exclusion returned `[]`; the post-4-MiB secret returned `[]`; tag replacement did not require the password. |
| `cargo test -j 2 -p fail2commit-core` | 0 | 52 unit tests passed, including binding, replay, expiry, password reset/rate limit, digest, wire bounds and token consumption. |
| `cargo test -j 2 -p fail2commit --test approval_cli --test approval_stdio --test git_push --test git_setup --test sandbox_setting_cli --test sandbox_setting_policy --test server_protected --test ipc_pipe --test ipc_startup` | 1 (reviewer interrupt) | Approval CLI/stdio suites passed (13 tests). Git push tests opened the live controlling console for approval and waited; the run was interrupted rather than counted as pass/fail. |
| `cargo test -j 2 -p fail2commit --test git_setup --test sandbox_setting_cli --test sandbox_setting_policy --test server_protected --test ipc_pipe --test ipc_startup` | 1 (reviewer interrupt) | Four Git setup tests passed; two interactive push cases again waited on the controlling console, so the run was interrupted before later binaries. |
| `cargo test -j 2 -p fail2commit --test server_protected -- --test-threads=2` | 0 | 9 server tests passed, including direct bypass rejection, exact-token approval, expiry, actor/tuple mismatch, replay and concurrent double-use. |
| `cargo test -j 2 -p fail2commit --test sandbox_setting_cli --test sandbox_setting_policy -- --test-threads=2` | 0 | 13 sandbox setting/host-execution tests passed. |
| `cargo test -j 2 -p fail2commit --test ipc_pipe --test ipc_startup -- --test-threads=2` | 0 | 13 pipe DACL/identity/bounds/binding and startup ownership tests passed. |
| `npm test` (from `extensions/vscode`) | 1 (prerequisite missing) | `tsc` was unavailable because dependencies were not installed; extension test execution remains pending in this worktree. |
| `git check-ref-format <ref containing U+202E>` | 0 | Git accepted `refs/heads/release-<U+202E>txt`; U+202E is Unicode category `Format`. |
| `rustfmt --edition 2021 --check crates/fail2commit/tests/review_wave1.rs` | 0 | Review reproduction test is formatted. |
| `python .claude/hooks/trace_check.py` | 0 | Scaffold traceability check passed. |

No Docker build was needed for these Windows-reproduced code paths. The missing VS Code dependencies and the interactive-console incompatibility above are pending evidence, not passes.
