# Second re-review: pip snapshot and layout denial (CR-005, RP-001..RP-008; FR-005, FR-008)

Date: 2026-11-09
Reviewed: branch `DansPK/f2c-fix-pip-r2`, tested SHA `d43acc3c5c5b8bbbbc07bbb237d03f3b9defc005` (fix diff `git diff ee86252..d43acc3`).
Reviewer: independent; product code was not modified. Reproductions: `crates/fail2commit/tests/rereview2_pip.rs` only.
Platforms: Windows 11 (venv on CPython 3.12.10) and Linux (`f2c-linux-test:1`, CPython 3.13.5, **container runs as root**, no bwrap needed).

## Verdict

**The "guard runs code a wheel controls" class is closed for the vectors I could drive (snapshot, `sys.path`, planted modules, `.pth` detection). The layout denial is not complete: do not close RP-004 / CR-005 on Windows.**

| Area | Status |
|---|---|
| 1. Snapshot is the only pip the guard runs | **Holds** (two caveats: RP2-005, RP2-007) |
| 2. Layout denial complete | **Not complete**: RP2-001 (High, Windows), RP2-002 (Medium, both) |
| 3. `.pth` detection matches CPython | **Holds** in a 20-file differential (3.12 Windows, 3.13 Linux); Windows alias bypass is RP2-001 |
| 4. Journal gate and `recover` | **Holds** for the existing RP-006/007/008 tests on both platforms; I added no new spellings (pending) |
| 5. Regressions | **Green** on Windows and Linux (tables below) |

## New findings

### RP2-001 — High (Windows) — CONFIRMED: Windows path aliasing defeats the layout deny and the startup finding

**Where:** `wheel.rs` `bad_script` (`leaf == "pyvenv.cfg"`), `DATA_RESERVED` exact match on the first data component, and `scan`'s `first.ends_with(".pth")`. All compare literal strings. Windows resolves trailing dots and spaces in a path component (and `::$DATA`) to the same file, so `pyvenv.cfg.` is not `pyvenv.cfg` to the guard but is on disk.

**Scenarios, all run on Windows:**
- `x.data/scripts/pyvenv.cfg.` was accepted; `Scripts\pyvenv.cfg` exists afterwards. CPython 3.11+ reads that file before the venv's own `..\pyvenv.cfg`. This is the RP-004 file, so RP-004 is reopened.
- `x.data/data/pyvenv.cfg.` was accepted and **replaced the venv's own `pyvenv.cfg`**. With `home = <dir>` the venv launcher starts that directory's `python.exe`; the next probe failed with `did not find executable at 'C:\nowhere\python.exe'` (venv bricked, journal-free). Shipping a `python.exe` in the same wheel at the chosen `home` would turn this into code run by the guard's next interpreter start (PLAUSIBLE, not run).
- A root `alias_a.pth.` became a `*.pth` in site-packages with no `pip.startup` finding.

The `.data/data/Lib./site-packages/x.pth` variant is still denied, only because the basename rule catches the `.pth`; a non-startup file under `Lib.` would not be.

**Repro:** `cargo test -j 2 -p fail2commit --test rereview2_pip rp2_001` (3 fail; the Lib-alias test passes). Linux: no-ops (aliasing is a Windows rule).

**Fix:** normalize every entry component before any comparison: strip trailing `.`/space, drop an `::$DATA` suffix, case-fold. On Windows simply refuse any component with a trailing dot or space, or a `:`. Apply the same normalization in `classify`, `bad_script`, `DATA_RESERVED`, the `pip` check and the `.pth`/customize checks.

### RP2-002 — Medium (Windows and Linux) — CONFIRMED: console scripts from `entry_points.txt` are not checked

**Where:** `wheel.rs scan` only inspects `.data/scripts` entries; nothing in `crates/fail2commit-core/src/pip` parses `entry_points.txt` (grep returns no hits).

**Scenario:** a wheel with `[console_scripts] pip = ep0:main` installs with no prompt and **replaces the venv's `pip`, `pip3` and `pip3.13`** (Windows `pip.exe`, `pip3.exe`, `pip3.13.exe`; Linux `bin/pip*`). The next `pip install` the user runs inside that venv runs the wheel's code, bypassing the guard. In my run the names `python`, `python3`, `activate`, `pyvenv.cfg` and the interpreter's own name did not change a file, so only the `pip` family is confirmed.

**Repro:** `cargo test -j 2 -p fail2commit --test rereview2_pip rp2_002` fails on both platforms.

**Fix:** read `*.dist-info/entry_points.txt` (`console_scripts`, `gui_scripts`) in `scan` and run each name through the same `bad_script` check (with RP2-001 normalization).

### RP2-005 — Low (residual) — CONFIRMED by an `#[ignore]` test (Linux)

The snapshot and `manifest.json` sit in the same directory. Code running as the same user (for example a wheel's code the user later imports) can edit `pip/__init__.py` and rewrite the manifest hash consistently; the next guarded run then executes it, unsandboxed. The manifest catches accidental and non-targeted changes, not a same-user attacker. Linux `guard/` is 0700 (test `rp2_006` passes, as root), Windows relies on the ACL inherited from `%LOCALAPPDATA%` and it is not set explicitly. No in-process fix exists; document it in `docs/pip.md` as a residual, or keep the manifest hash in a store a wheel's code cannot write. Repro: `cargo test -j 2 -p fail2commit --test rereview2_pip -- --ignored rp2_005` (run on Linux only).

### RP2-007 — Informational: the snapshot trusts the first pip it sees

`Guard::build` copies whatever `pip/` the environment has at first use. If an earlier unguarded install overlaid pip, that copy is blessed. A cheap hardening is to verify the environment's `pip-*.dist-info/RECORD` hashes before snapshotting.

### Not run / PLAUSIBLE notes (no reproduction)

- A hypothetical CPython startup-file type besides `.pth`/customize (for example a `.start` file in a newer release) would need adding to `is_startup_name`; today's detection is a fixed list. Not verified against a released interpreter.
- The data scheme into a non-venv prefix writes outside the interpreter-layout names (for example `etc/conda/activate.d/`, `share/jupyter/kernels/`). Those run on later user actions, not in the guard; they are not denied or named.
- RECORD-driven uninstall: a wheel's RECORD can list in-venv paths; `pip uninstall` later deletes them. Deletion only.

## What held

- **Snapshot (area 1).** Planted `keyring`, `brotli`, `truststore`, `socks`, `OpenSSL`, `pkg_resources`, `setuptools`, `distutils`, `_distutils_hack`, `sitecustomize`, `usercustomize`, shadows of 14 stdlib names (`encodings`, `site`, `os`, `abc`, `codecs`, `io`, `enum`, `typing`, `runpy`, `json`, `platform`, `sysconfig`, `importlib`, `zipfile`), a `zz-planted.pth`, and a fake `pip-99.0.dist-info` with a console-script entry point never ran, across install plus `list`, `show`, `freeze`, `check`, `inspect`, `debug`, `help`, `--version` and `uninstall` (`rp2_004`, passes on both platforms). A tampered, added or removed snapshot file is an `IntegrityFailure` before launch (existing `rp_tampered_snapshot...`). BOOT never reads `<exe dir>/pyvenv.cfg`; the snapshot is taken before the first install.
- **`.pth` (area 3).** 20 files (bare CR, CRLF, BOM, NEL, VT, FF, FS/GS/RS, LS/PS, NUL prefix, invalid UTF-8, UTF-16, no trailing newline, comment-only, leading space) in one wheel: every file CPython ran was named by a `pip.startup` finding (`rp2_003`, passes on both). The guard over-flags separators CPython 3.12 does not split on; that is safe.
- **Journal (area 4).** `rereview_pip_journal` (respelling, forged journal, wrong-interpreter journal) is green on both platforms.

## Commands

All from the worktree root, `-j 2`, stdin empty, disposable venvs/state, loopback fixture index. Tested SHA `d43acc3` plus the new untracked `rereview2_pip.rs`.

| Platform | Command | Exit | Result |
|---|---|---:|---|
| both | `git rev-parse HEAD` | 0 | `d43acc3c5c5b8bbbbc07bbb237d03f3b9defc005` |
| Windows | `cargo test -j 2 -p fail2commit --test pip_cli --test pip_install --test pip_recover --test pip_reject --test review_wave2_pth --test rereview_pip_boot --test rereview_pip_journal --test rereview_pip_shim -- --test-threads=1` | 0 | 66 passed (6, 15, 7, 4, 14, 11, 6, 3) |
| Windows | `cargo test -j 2 -p fail2commit-core pip::` | 0 | 22 passed |
| Windows | `cargo test -j 2 -p fail2commit --test rereview2_pip -- --test-threads=1 --nocapture` | 101 (expected) | 3 passed, 4 failed (RP2-001 x3, RP2-002), 1 ignored |
| Linux (`f2c-linux-test:1`) | same integration command | 0 | 67 passed (6, 15, 7, 4, 14, 12, 6, 3) |
| Linux | `cargo test -j 2 -p fail2commit-core pip::` | 0 | 22 passed |
| Linux | `cargo test -j 2 -p fail2commit --test rereview2_pip -- --test-threads=1 --nocapture` | 101 (expected) | 7 passed, 1 failed (RP2-002), 1 ignored; RP2-001 tests are Windows-only no-ops |
| Linux | `... --test rereview2_pip -- --ignored` | 101 (expected) | RP2-005 fails (snapshot plus manifest rewrite runs) |

Pending evidence: the `--ignored` RP2-005 test was not run on Windows; the Linux container runs as root, so non-root file-permission behaviour was not exercised; `trace_check.py` was not run (no scaffold files changed).
