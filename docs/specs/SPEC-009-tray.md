# SPEC-009 — Windows desktop integration

FR-009 · TC-009 · Owner paths: fail2commit-tray crate and Windows packaging.

Per-user NSIS Setup.exe installs CLI and native tray, offers integration setup and configurable sign-in startup. The tray waits for approval requests and presents pending operation details, cancel, one-time approval, optional password/recovery management, and the sandbox toggle. A same-user local pipe uses restricted permissions, rejects remote peers, validates request bounds/session and denies AppContainer access. Use no polling. Closing tray keeps guards active and falls back to terminal, or rejects if no UI is available. Uninstall rolls back only owned changes. Test using Windows x64 on supported Windows 11 with PowerShell and Git for Windows. Document measured supported paths and edition caveats.
