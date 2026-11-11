# Completed work

## 2026-11-12 - 0.1.4 integration hand-over
- The Linux sandbox, Windows sandbox and scan branches for 0.1.4 are merged into
  `DansPK/f2c-0.1.4`; the tip at hand-over was `6c864bd` with a clean tree and 14 local
  commits ahead of `origin`. Nothing was pushed.
- `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets --locked -- -D warnings` pass.
- Fixed a real defect found by the suite: the bait-oplock release waited on
  `OVERLAPPED::Internal`, which a completion-port handle never leaves at `STATUS_PENDING`
  until its packet is dequeued. The probe therefore reported the whole AppContainer backend
  as unavailable. Release now waits for the request's own port packet, and
  `the_oplock_self_test_releases_a_broken_and_an_idle_oplock` covers it. Evidence:
  `docs/dev/verify/VERIFY-2026-11-12-oplock-release.md`.
- Two end-to-end npm expectations were updated for the merged 0.1.4 behaviour: the stage-root
  state (`profile-records`, `pending-revoke.json`) is no longer counted as a left-over job
  stage, and the Windows hostile-script case now asserts that the job is stopped at its first
  non-public connection (SPEC-014 section 1) with nothing escaped, instead of expecting the
  script to finish.
- The Windows sandbox suites were aligned the same way (`sandbox_hostile_windows`:
  a fresh stage per bait run, and "stopped at the attempt or denied" for loopback and LAN
  targets; `sandbox_windows_matrix`: an empty report with a stopped job is accepted and the
  host-side checks still apply). `sandbox_hostile_windows` is now 18 passed / 3 failed; the
  three open ones are `hb030` (an allowed connection that opens and closes between two 25 ms
  ticks), `hb036` (multicast UDP in Internet mode, which SPEC-014 lists as unobservable) and
  `hb070` (an orphaned AppContainer profile that the next run did not remove). They are
  recorded in the verify report for an owner decision.
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
