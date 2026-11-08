# Git integration (FR-001, SPEC-001)

## What `fail2commit setup` changes

Each change is recorded in `setup.json` and undone by `fail2commit uninstall-integrations`.

| Change | Where | Uninstall |
|---|---|---|
| Hooks directory with a `pre-push` script | `<state>/hooks/` | files removed |
| User-global `core.hooksPath` pointing at it | `git config --global` | previous value restored (or unset); left alone if you changed it since |
| `git` shim (copy of the fail2commit exe) | `<bin>/git[.exe]` | removed |
| `<bin>` first on the user PATH | Windows `HKCU\Environment\Path` (via `reg.exe`); Linux marked block in `~/.profile` | exact entry/block removed, previous registry value restored |

Setup is idempotent and never records its own value as "previous". Tests redirect the
PATH edit with `FAIL2COMMIT_PATH_TARGET=<file>` and never touch the real registry.
Windows: new processes see the PATH change after the next sign-in or shell restart
(no `WM_SETTINGCHANGE` broadcast is sent).

## How a push is checked

1. **Shim** (`fail2commit git ...`): every non-push command runs the real git unchanged
   (inherited stdio, exact exit status). For `push` it detects explicit force intent
   (`--force`, `-f`, `--force-with-lease*`, `--force-if-includes`, `+` refspecs, `--mirror`,
   `--delete`/`-d`/`:ref`, `--prune`, forced `remote.<n>.push`) and forwards it to the hook.
   It also passes `-c core.hooksPath=<ours>`, so repositories with their own local
   `core.hooksPath` still run our hook, which then chains to theirs.
2. **Hook** (`fail2commit hook pre-push`): reads every `<local ref> <local oid> <remote ref> <remote oid>`
   tuple and reports rewrites (`git merge-base --is-ancestor`), deletions, tag replacement,
   missing old objects (never treated as safe), and secrets in outgoing commits.
3. **One approval** is requested for the whole plan, bound to remote, URL, every tuple and
   every finding. Force intent with no actual rewrite still asks. Cancel or an unavailable
   channel exits non-zero, so Git aborts the push.
4. **Chaining**: after our check the script runs the repository's local `core.hooksPath`,
   else your previous global `core.hooksPath`, else `<git-common-dir>/hooks/pre-push`, with
   the same stdin and the hook's exit status. A failing existing hook aborts the push.

## Secret scan

Scope is `git log <new> --not <remote's reported old oids>`, or everything for a first push.
Only the old OIDs from Git's own ref-update tuples that exist locally exclude history (the
remote reported them, so it has them). Local `refs/remotes/**` and every other
repository-controlled ref are never used: they prove nothing about the remote. A missing
(shallow/stale) old object excludes nothing, so more is scanned, and classification adds
`IncompleteScan` plus a `RefRewrite` (password-requiring) finding.

Added, modified and deleted paths are read from `git log --raw -z` (submodule commits are
not blobs and are skipped); sizes come from `git cat-file --batch-check`, then the chosen
blobs are read whole with `git cat-file --batch`. Bounds come from `Settings.limits`
(`graph_max_nodes`, `scan_max_bytes`) and a 32 MiB single-blob limit. The **full object
size** is charged against `scan_max_bytes`.

**No byte goes unexamined silently.** Each of these yields an `IncompleteScan` finding
(local: one-time approval; server secret policy: deny): history walk bound hit, missing or
unreadable blob, blob over the single-file limit, blob that would exceed the byte budget.
Binary blobs are scanned (lossily) rather than skipped, `.env` names are matched by path,
and lines over 8 KiB are scanned in overlapping 8 KiB windows (512-byte overlap) rather than
skipped.

Force-push password: `ForceIntent`, `RefRewrite`, `TagReplacement` and `RefDeletion`
findings all require the configured password on the direct hook path, with or without the
shim's `FAIL2COMMIT_PUSH_INTENT`.

## Unattended runs

`FAIL2COMMIT_HOOK_FAIL_CLOSED=<non-empty>` makes the hook (and the push it belongs to) skip
every approval channel, so any pause fails closed. It can only tighten policy. The Git
integration tests set it so they never open CONIN$ or `/dev/tty`.

Detectors: `.env` / `.env.*` (not `.example`, `.sample`, `.template`), private key headers,
AWS access keys, GitHub / GitLab / Slack tokens, and `password=` / `secret=` style
assignments with an entropy check. Values are always redacted.

`fail2commit secret-scan [REMOTE]` runs the same scan for the current branch without pushing
(exit 10 on findings, 12 if only incomplete).

## What bypasses local integration

- `git push --no-verify` skips every hook.
- Other Git clients (IDE integrations, libraries, GitHub Desktop, `libgit2`) that do not
  run hooks or use the shim, and a git binary invoked by absolute path.
- Plain `git` in a repository whose local `core.hooksPath` overrides the global one, when
  not launched through the shim.
- Hooks can be edited or removed by anyone with write access to the hooks directory.

These paths are covered only by the protected remote in SPEC-003 (T-003) where deployed.
