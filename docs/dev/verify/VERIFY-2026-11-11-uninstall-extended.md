# Verify: extended uninstall testing, Windows and Linux (FR-009, CR-021)

Date: 2026-11-11. Follows `VERIFY-2026-11-11-uninstall.md`. Synthetic secrets and disposable repositories only.

## Builds

| Build | Source | Setup SHA-256 |
|---|---|---|
| v0.1.3 release | GitHub release, matched `SHA256SUMS` | (release) |
| test-setup (PR #14) | `4f9a2cd` | `f585004ac2ccb127e2492b5adf264cdd6d0160846e9059af31ec758fc883961d` |
| fix2 | `afe9be2` minus the NSIS fallback | `c6c737ea5994805519ec53b70c1daa1859426fb31fecdb3c3857c410799a628a` |
| fix3 | `afe9be2` | `334c532ec57341dbee0f87a87df386690d7012a68c226ddf1e5a910893c663e3` |

Windows: VM `win11` (Windows 11 Pro 10.0.26200), reverted to `pre-f2c-test`, steps run in the signed-in desktop session through a scheduled task. GUI steps were driven with keystrokes on the VM console. Linux: Docker on the host, `ubuntu:24.04` and `archlinux:latest`, `--privileged` so bubblewrap works, user `tester`.

## Windows

| Run | Scenario | Result |
|---|---|---|
| A | Install, tray running, use (blocked secret push, clean push, guarded `npm install`), `fail2commit run` in the AppContainer, `core-js@3.38.1` with its postinstall run in the sandbox, then `uninstall.exe /S`; reinstall, same, `/S /PURGE`. Full inventory diff. | All exit 0. Tray stopped, install folder gone. After each uninstall `git push`, `npm` and PowerShell profile load work. No fail2commit AppContainer profile or ACL entry left. `/S` keeps only the documented data; `/S /PURGE` leaves nothing from fail2commit. |
| B | Uninstall from the `UninstallString` (as Settings > Apps does), no `/S`. Data question answered No, then (after reinstall) Yes. | No: data kept, everything else removed. Yes: nothing left. The question defaults to No. |
| C | Machine-wide shims installed elevated; GUI uninstall, UAC declined. | Warning shows the exact recovery command; shims stay and `npm` keeps working through them. Recovery command run elevated: PATH entry removed, but its own exe stayed in Program Files (**fixed**: now deleted at the next restart; verified with fix2 and a restart: `PendingFileRenameOperations` listed the exe, `shims` and `fail2commit`, and the folder was gone after the restart). |
| D | User already has a PowerShell profile, a Git Bash `~/.bashrc`, `core.hooksPath` to their own hooks, a user PATH entry and another Run value. Install v0.1.3 release, upgrade to the fix build, use, `/S /PURGE`. | Profile and `.bashrc` byte-identical, `core.hooksPath` restored, the user's own pre-push hook ran throughout (chained), the other Run value untouched. An empty `Documents\PowerShell` stays when the first setup was 0.1.3 (no `dir_existed` record; documented). A blank `;;` user PATH entry was normalized away. |
| E | `fail2commit.exe` deleted by hand, then `/S` (fix2). | Nothing rolled back: `core.hooksPath`, PATH, shim folder and `.bashrc` block stayed. The new hook let `git push` work and said why. **Fixed** in fix3: the uninstaller rolls back with a temporary copy of the shim-folder CLI. Re-run with fix3 and `/S /PURGE`: user state identical to before install, nothing from fail2commit left. |

With fix2 and fix3 the synthetic secret push is still blocked, so the hook's `[ -x "$F2C" ]` check holds under Git for Windows' `sh`.

Remaining lines that are not from fail2commit: the empty `%LOCALAPPDATA%\Programs`, the NSIS `Un.exe` copy in `%TEMP%`, Explorer's `NotifyIconSettings` entry and cached icon for the tray, `UFH\SHC` shortcut history, and Windows churn (services, Store/AppContainer storage values, firewall rule for Web Experience Pack).

## Linux (v0.1.3 release assets)

Every scenario: install, `fail2commit setup`, use (malware list import, blocked secret push, clean push, guarded `npm install`, sandbox on), `uninstall-integrations`, package removal, full filesystem and home diff.

| Scenario | Result |
|---|---|
| Ubuntu `.deb`, `dpkg -r` then `--purge` | Guards removed. Data kept in `~/.local/state/fail2commit`, `~/.cache/fail2commit`; empty `~/.config/fail2commit`, `~/.local/share/fail2commit/bin` (**fixed**: shim folder removed; data removal documented). |
| Existing dotfiles (symlinked `.bashrc`, `.zshrc` 640, own `core.hooksPath`) | `.gitconfig` identical and the user's hook chained, but `$HOME` went 750 to 700, startup files became 0600 and the symlink became a copy (**fixed**, `write_user_file`, unit test on Linux). |
| `dpkg -r` without `uninstall-integrations` | Every `git push` failed ("fail2commit: not found"), shell `npm`/`pip` exit 127 (**fixed**, CR-021: hook and functions fall back; unit test runs the hook with the binary missing). |
| Setup twice, uninstall twice | Idempotent. |
| Arch `pacman -U` / `-R`; standalone binary in `~/bin` | Same leftovers as Ubuntu. |

Linux unit and e2e tests on the fix: `cargo test -p fail2commit-core --lib -- shellinteg fsutil git::integ` (10 passed) and `cargo test -p fail2commit --test e2e_setup --test git_setup` (7 passed), in `rust:1` as a non-root user. Windows: the same unit tests passed, `cargo clippy -p fail2commit-core -p fail2commit --all-targets -D warnings` clean.

## Not covered

- The fixed Linux behaviour was verified by unit and e2e tests, not by re-running the Docker scenarios with a rebuilt `.deb`.
- An upgrade where the old setup is 0.1.3 still leaves its empty `Documents\PowerShell` (documented).
- Outside uninstall, found on Linux and recorded for follow-up: on Arch, `~/.bash_profile` hides the PATH change in `~/.profile`; `git push --no-verify` bypasses the hook when the git shim is not on PATH; Ubuntu login shells get the shim folder on PATH twice.
