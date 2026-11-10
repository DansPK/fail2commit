# Completed work

## 2026-11-09 — MVP release candidate
- All tasks T-001 to T-012 are implemented, independently security-reviewed until each finding class closed, and integrated (`a026090`). Release candidate `4559bab`.
- Final gate (`d15f559`): Windows 503 tests and Linux 494 tests pass; fmt, clippy and traceability clean. Real bubblewrap suites pass in WSL Ubuntu, and the AppContainer attack suite passes on Windows 11.
- Artifacts: Windows Setup.exe and CLI, Debian `.deb`, Linux binary, vendored source tarball, VSIX, with `SHA256SUMS`. The Linux `.deb` and binary are bit-reproducible.
- Verified: `.deb` install, remove and purge; offline source build; VS Code client against both release CLIs; clean Windows 11 install/uninstall preserving third-party hooks and PATH.
- Design changes recorded as CR-001 to CR-012, for example review of the npm-extracted tree, the private pip snapshot, the direct AppContainer backend, and the HMAC single-use approval relay.
- Pending platform gates and their prerequisites are listed in `docs/dev/verify/VERIFY-2026-11-09-release.md` section 6.

## 2026-11-08 — Implementation scaffold
- CHORE-001 baseline prepared from the supplied agent skeleton.
- Requirements, technical specs, tests, traceability and Orca brief are ready.
- Product implementation and runtime verification are pending.
