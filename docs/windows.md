# fail2commit on Windows

Scope: FR-009 / SPEC-009. Supported target: Windows 11 x64 with PowerShell and Git for Windows. Other editions are not measured; see "Caveats".

## What is installed

The per-user installer (`fail2commit-<version>-setup.exe`, NSIS) needs no administrator rights. It writes only to:

| Location | Content |
|---|---|
| `%LOCALAPPDATA%\Programs\fail2commit` | `fail2commit.exe`, `fail2commit-tray.exe`, `LICENSE`, notices, `docs\windows.md`, `uninstall.exe` |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\fail2commit` | Apps & features entry |
| Start Menu, `fail2commit\fail2commit tray.lnk` | Tray shortcut |
| `HKCU\...\CurrentVersion\Run`, value `fail2commit-tray` | Only if you choose "Start the tray at sign-in" |

The installer offers three optional steps, all visible on the components page:

- **Set up guards** runs `fail2commit setup`. Every change it makes is recorded in `setup.json` under `%LOCALAPPDATA%\fail2commit\state`. If it fails, the installer says so and keeps its log on screen.
- **Guard machine-wide npm and pip** (default on) asks for administrator rights, see below.
- **Start the tray at sign-in** adds the Run value. You can toggle it later from the tray menu.

## Machine-wide npm and pip (administrator)

Windows gives every new process the machine PATH first and the user PATH second. A Node.js or Python installed for all users (the Node.js installer's default, `C:\Program Files\nodejs`) is therefore found before the per-user shims in `%LOCALAPPDATA%\fail2commit\bin`, and plain `npm install` bypasses fail2commit. `fail2commit status` warns when this happens:

```text
warning: `npm` runs C:\Program Files\nodejs\npm.cmd and is NOT guarded. ...
```

`fail2commit machine-shims install`, run as administrator (the installer does this through a UAC prompt), copies the CLI as `npm.exe`, `pip.exe`, `pip3.exe` and `fail2commit.exe` into `C:\Program Files\fail2commit\shims` and puts that directory first on the machine PATH. Program Files is writable only by administrators, which matters: a user-writable directory early on the machine PATH would let any program running as a user plant commands that administrators and services then run. The shims guard npm and pip for every user of the PC, each with their own settings and approvals. `machine-shims status` exits 0 when installed; `machine-shims uninstall` (administrator) removes the entry and the files, and the uninstaller runs it for you.

Still not covered: programs that call `npm.cmd`, `node ...\npm-cli.js` or a Python interpreter by full path. Use `fail2commit npm ...` / `fail2commit pip ...` there.

## Uninstall

Apps & features (or `uninstall.exe`) does this, in order: asks a running tray to exit, runs `fail2commit uninstall-integrations` (restores exactly the recorded changes, including the previous value of the Run entry), removes the Run value if it points into this install, deletes the files listed above, and removes the shortcut and the uninstall key. Third-party hooks, an existing `core.hooksPath`, PATH entries and other Run values are not touched.

Your data in `%LOCALAPPDATA%\fail2commit` and `%APPDATA%\fail2commit` (settings, password verifier, approvals, caches, signing-key records, the offline malware list) is kept unless you ask: the uninstaller asks whether to delete it (default No), and a silent uninstall deletes it only with `/PURGE`:

```powershell
& "$env:LOCALAPPDATA\Programs\fail2commit\uninstall.exe" /S /PURGE
```

Empty folders that setup created (`Documents\PowerShell`, `Documents\WindowsPowerShell`) are removed; a setup made by 0.1.3 or earlier did not record that, so after an upgrade from those versions an empty `Documents\PowerShell` may stay. If `fail2commit.exe` was deleted by hand, the uninstaller rolls back with the copy in the shim folder instead.

Leftovers that belong to Windows or NSIS, not fail2commit: the empty `%LOCALAPPDATA%\Programs` folder, the uninstaller's temporary copy in `%TEMP%` (Windows clears it later), Explorer's record of the tray icon (`HKCU\Control Panel\NotifyIconSettings` and a cached icon in `%TEMP%`), and its Start Menu shortcut history.

If you declined the administrator prompt for the machine-wide shims, run the command the uninstaller shows, as administrator. The running copy cannot delete itself, so Windows deletes it and `C:\Program Files\fail2commit` at the next restart.

## The tray

`fail2commit-tray.exe` is a native Win32 per-user program with a notification-area icon. It uses no timers or polling for approvals: a pipe thread blocks until a request arrives and wakes the UI thread with a window message.

- **Approval request**: a dialog shows the summary, detail lines and redacted findings, with a notification balloon. Buttons: **Cancel** (default; Enter and Esc also cancel), **Approve once**, and **Run on host once** when the request offers it. A password box (hidden input) appears only when the request requires the force-push password. A request that is not answered by its expiry is cancelled.
- **Menu**: pending approvals, "Run build scripts in sandbox" (the same trusted setting as `fail2commit sandbox on/off`), set / change / reset password (opens a console running `fail2commit password ...`, so secrets are typed on hidden console input and never pass through the tray), "Start at sign-in", Exit.
- **One tray per user.** A second start exits immediately because the approval pipe already exists.

### Closing the tray

Guards stay active. With no tray listening, `fail2commit` falls back to the terminal prompt when it has an interactive console, and otherwise rejects with `approval_unavailable` (exit 11). Approval is never assumed.

## Approval pipe

Name: `\\.\pipe\fail2commit-approval-<your user SID>`. Protections:

- `PIPE_REJECT_REMOTE_CLIENTS`; `FILE_FLAG_FIRST_PIPE_INSTANCE` so another process cannot squat the name.
- DACL, in this order: deny `S-1-15-2-1` (ALL APPLICATION PACKAGES), deny `S-1-15-2-2` (ALL RESTRICTED APPLICATION PACKAGES), allow only your user SID. No Administrators or SYSTEM entry.
- The tray checks each client's process token: it must be your SID and not an AppContainer (LowBox) token. The CLI checks that the server process runs as your SID and not in an AppContainer, and opens the pipe with anonymous impersonation.
- Messages are single JSON lines, at most 256 KiB, in the frozen protocol. The tray validates field sizes, request id / nonce / digest format, the session id, the allowed decisions and the expiry window before showing anything. The CLI validates the reply (request id, nonce, digest, decision offered, password present, not expired) before acting.

## Building the installer

```powershell
powershell -File packaging\windows\build.ps1 -Version 0.1.3
```

`build.ps1` builds the release binaries, stages them under `target\dist\stage`, and runs `makensis`. It uses `-Makensis <path>`, else a portable NSIS under `target\nsis\nsis-*`, else `makensis` on PATH. A portable NSIS can be unpacked from the official SourceForge zip without installing anything; the hash used for the recorded build is in `docs/dev/verify/VERIFY-2026-11-08-windows-tray.md`.

## Caveats

- Measured only on Windows 11 Pro (build 26200) x64. Windows 10, Windows Server, ARM64 and Home/Education/Enterprise differences are not tested.
- The binaries are unsigned, so SmartScreen may warn on first run.
- Notification balloons can be hidden by Focus Assist; the dialog is shown at the same time and the tray icon tooltip shows the pending count.
- Clean-machine install / uninstall is checked by the release task (T-011), not by the worker tests.
