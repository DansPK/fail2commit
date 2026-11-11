# Verify: clean uninstall on Windows 11 (FR-009, TC-009)

Date: 2026-11-11. VM `win11` (Windows 11 Pro 10.0.26200), snapshot `pre-f2c-test`, reverted before each run. All steps ran in the signed-in desktop session (scheduled task, interactive logon, not elevated), with synthetic data only.

## Method

1. Baseline prerequisites: portable MinGit and Node 22.23.4 put on the user PATH, with a global Git identity.
2. Inventory A: HKCU, the HKLM uninstall/Run/Environment/AppContainer keys, files under the profile, Program Files, ProgramData and Windows\Temp, user and machine environment, the global Git config, PowerShell profiles, scheduled tasks, services, firewall rules, Start Menu, fail2commit processes, and AppContainer ACL entries.
3. `setup.exe /S`; then use: `malware-list update` and `malware-list status`, a push of a synthetic secret (blocked, nothing sent), a clean push (sent), `npm install is-number@7.0.0` through the guard (installed), `scan --dir`, `status`.
4. `uninstall.exe /S`, waiting for the NSIS `Au_` copy to exit; inventory B; diff A against B.

## Run 1: v0.1.3 release installer

SHA-256 of `fail2commit-0.1.3-setup.exe` matched `SHA256SUMS`. Install exit 0, uninstall exit 0. The app, Git hook path, PATH shims, profile blocks, Run value, shortcut and uninstall key were all removed. Left behind:

| Left behind | Cause |
|---|---|
| `Documents\PowerShell`, `Documents\WindowsPowerShell` (empty) | Setup created them for the profile block; uninstall removed only the file. **Fixed.** |
| `%APPDATA%\fail2commit` (empty), `%LOCALAPPDATA%\fail2commit\bin` (empty) | Not removed by the uninstaller. **Fixed.** |
| `%LOCALAPPDATA%\fail2commit` data (about 12 MB) | Kept by design, with no option to delete it. **Fixed:** opt-in purge. |

## Run 2: fix branch (4f9a2cd), keep and purge

The test installer was built with `packaging\windows\build.ps1` and the pinned NSIS 3.11 from the working tree committed as `4f9a2cd`. Setup SHA-256: `f585004ac2ccb127e2492b5adf264cdd6d0160846e9059af31ec758fc883961d`. There were two rounds on one VM: install, use, `uninstall.exe /S`, inventory; then reinstall, use, `uninstall.exe /S /PURGE`, inventory. Every exit code was 0, and the guard results matched run 1.

- **`/S` (keep):** the empty folders listed above are gone. Only the user data in `%LOCALAPPDATA%\fail2commit` (state, caches, keys, the malware index) remains, as documented.
- **`/S /PURGE`:** no fail2commit file, folder, registry value, environment entry, Git setting, profile, task, service, firewall rule or shortcut remains.

The remaining lines in both diffs are not from fail2commit:
- the empty `%LOCALAPPDATA%\Programs` folder (Windows' per-user Programs known folder);
- `%TEMP%\~nsu1.tmp\Un.exe`, the NSIS uninstaller's running copy, which cannot delete itself;
- Explorer's `UFH\SHC` shortcut history;
- Windows churn: Storage Sense temp cleanup, Copilot and Edge WebView updates, MuiCache, BITS and Defender services.

## Not covered

- The GUI question ("Also delete your fail2commit settings and data?") was compiled but not clicked through; only the silent paths were run.
- No package install script ran, so AppContainer profile cleanup after a sandboxed build was not exercised in this run. The AppContainer ACL inventory was empty before and after.
- Machine-wide shims (an elevated, optional section) were not installed: a silent install skips them.
