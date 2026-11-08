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

Scope is `git rev-list <new> --not <remote's reported old oids> [remote-tracking refs]`,
or everything for a first push. Added, modified and deleted paths are read from
`git log --raw -z`; blobs via one `git cat-file --batch`, deduplicated. Bounds come from
`Settings.limits` (`graph_max_nodes`, `scan_max_bytes`); a blob is scanned by its first
4 MiB. Hitting a bound produces an `IncompleteScan` finding, which pauses.

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
