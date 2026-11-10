# VS Code integration (FR-010, SPEC-010)

The extension lives in `extensions/vscode`. It never implements policy: every command spawns `fail2commit api` and speaks the versioned JSON protocol (`crates/fail2commit-core/src/protocol.rs`).

## Commands

| Command | CLI argv sent in the `Request` |
|---|---|
| Guarded Push | `git push <remote> <branch>` (both chosen from quick picks) |
| Guarded npm install/ci | `npm install` or `npm ci` |
| Guarded pip install | `pip install --python <interpreter> <packages…>` |
| Status | `status` |
| Sandbox On / Off | `sandbox on` / `sandbox off` |
| Show Findings | Opens the "fail2commit" output channel with the last findings |

The pip argv shape (`install --python <interp> …`) is an assumption until T-005 freezes its `Args`; adjust `src/extension.ts` if it differs.

Package names are split on whitespace into argv entries. Nothing is ever passed through a shell or built by string interpolation: `spawn(cli, ["api"], { shell: false })`, and the request travels as one JSON line on stdin.

## Approvals

`approval_request` lines open a modal warning with the summary, details and redacted findings. Buttons are Cancel (default), Approve once and Run on host once, limited to the request's `allowed` list. Dismissing the dialog, an exception, or a decision that was not offered sends Cancel. When `password_required` is set, a password input box is shown; the password is written only into the `approval_response` line on stdin, then dropped. It is never in argv, environment or logs. The response echoes `request_id`, `nonce` and `digest`. Each stdout line is capped at `MAX_MESSAGE_BYTES` (256 KiB); a longer line kills the CLI and fails the command.

## Trusted CLI resolution

1. The setting `fail2commit.cliPath` (`"scope": "machine"`). Only the user-level value is read, so `.vscode/settings.json` cannot set it.
2. Windows `%LOCALAPPDATA%\Programs\fail2commit\fail2commit.exe`; Linux `~/.local/bin`, `/usr/bin`, `/usr/local/bin`.
3. `PATH`.

Any candidate inside an open workspace folder (after resolving symlinks) is rejected.

## Workspace Trust and remotes

`capabilities.untrustedWorkspaces.supported` and `virtualWorkspaces.supported` are `false`; commands also refuse when `workspace.isTrusted` is false. `extensionKind: ["workspace"]` makes VS Code run the extension where the folder lives. In WSL, Remote-SSH or a dev container the extension and the CLI both run on Linux, so the Linux CLI is selected (the Windows path is never used). Install the Linux CLI in the remote.

## SCM view push coverage

The Source Control view runs plain `git push`; it does not go through this extension's commands. Coverage there depends only on whether Git invokes the installed `pre-push` hook (and, for npm/pip, whether the shim is first on `PATH`). Therefore:

- Repos with the fail2commit hook installed (`fail2commit setup`) are covered in the SCM view, with approvals on the hook's own channel (tray or terminal), not the extension modal.
- Repos without the hook, or pushes with hooks bypassed, are not covered. Use the **Guarded Push** command.
- `test/scm-hook.test.ts` proves in a disposable repo with a disposable bare remote that plain `git push` runs `pre-push` and that a failing hook blocks the push. Running the real fail2commit hook belongs to T-001 and T-011.

## Build and test

```
cd extensions/vscode
npm ci
npm test            # offline, uses a fake CLI
npm run package     # compile + vsce package -> fail2commit-0.1.1.vsix (gitignored)
```

An `@vscode/test-electron` smoke test is not included (it downloads VS Code); see the verify report.
