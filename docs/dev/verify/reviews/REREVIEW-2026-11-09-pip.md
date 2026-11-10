# Focused re-review: pip guard fixes for W2-001, W2-002, W2-006 (FR-005, FR-008)

Date: 2026-11-09
Branch reviewed: `DansPK/f2c-fix-wave2-pip`, tested SHA `915f18d8ae2823df64ec7d05a1663cfe78a62816`
Fix diff: `git diff cdb67bd..915f18d`
Reviewer: independent (did not write the fix). Product code was not modified.
Platform exercised: Windows 11, venv on CPython 3.13.14 (3.12.10 also installed). **Linux was not run**, so every
result below is pending evidence for Linux (AGENTS.md: probe both target platforms before marking platform behaviour verified).

## Verdict

**Do not close W2-001.** The three fixes do what their tests say, but two of them leave a path to the original impact.

| Finding | Status | One line |
|---|---|---|
| W2-001 / CR-001 | **Partially fixed** | Every interpreter fail2commit starts is `-I -S`, so `.pth`, `sitecustomize` and `usercustomize` no longer run in the guard. But a wheel can still get its own code run by the guard's next interpreter start (RP-003, RP-004, both High), and the `pip.startup` finding can be evaded (RP-001, RP-002). |
| W2-002 / CR-002 | **Partially fixed** | Cancel, journal gate, fresh `recover` approval and `--discard` all behave as specified. The gate is keyed by the spelling of the interpreter path, so a respelled path walks around it (RP-006). |
| W2-006 | **Fixed** | A foreign `pip`/`pip3` is never replaced or removed. Uninstall after an in-place upgrade of fail2commit leaves its own shims behind (RP-005, Low). |

New findings: RP-003 High, RP-004 High, RP-001 Medium, RP-002 Medium, RP-006 Medium, RP-005 Low, RP-007 Low, RP-008 Low.
All are CONFIRMED by a failing test in `crates/fail2commit/tests/rereview_pip_*.rs` (intentionally red until fixed).

## W2-001 / CR-001 detail

**Holds (evidence in the command table):**

- `interp.rs:72-76` (`python_c`) is the only place a `Command` for an interpreter is built. `probe` (`:101`), `installed`/verify (`:139`), `Interpreter::pip()` (dry-run `mod.rs:193`, apply `apply.rs:271`) and `passthrough` (`mod.rs:608`) all go through `python_c`/`pip_command`, so every start is `-I -S -c <BOOT>`. `cmd/pip.rs` and `recover` reuse these. `default_python` only resolves a path.
- `-S` means `site.main()` never runs. A venv with `include-system-site-packages = true`, plus a planted `*.pth`, `sitecustomize.py` and `usercustomize.py` in its purelib, installs a clean wheel with the marker absent; plain `python` does run the planted `.pth`, so the fixture is meaningful (`system_site_packages_venv_and_planted_startup_files_never_run_in_the_guard`).
- Shadowing `runpy`, `json`, `platform`, `sysconfig`, `site`, `os`, `importlib`, `encodings`, `sys`, `sitecustomize`, `usercustomize` from a wheel's site-packages loses to the stdlib, because BOOT only appends (`interp.rs:62-64`). `PYTHONPATH` and `PYTHONSTARTUP` set in the parent are ignored (`-I` plus `scrub_env`) (`stdlib_modules_cannot_be_shadowed_from_site_packages`).
- The approval path for a plain top-level import-bearing `.pth` works: finding `pip.startup`, `FindingKind::HostExecution`, `Approve`, named in `details` as `startup code: ...`. It is bound into the digest transitively: the finding is a pure function of the wheel bytes, and the digest covers the ordered wheel hashes (`plan.rs` `plan_digest`; `recover_digest` for recover) (`control_plain_top_level_pth_is_named`, `review_wave2_pth`).
- Not separately exercised: a `.pth` planted in the base stdlib dir (would modify the host Python) and `__pycache__` poisoning. The first cannot run because `site.main()` never runs; the second is a special case of RP-003.

### RP-003 — High — CONFIRMED: a wheel that overlays `pip` gets its code run by the guard's own next interpreter start, unsandboxed and unapproved

**Location:** `interp.rs:62-64` and `:67-69` (the guard imports `pip` from the *target* environment's site-packages), `wheel.rs:137-175` (`startup_files` only looks for `.pth`/customize names), `mod.rs:364` (`authorize_scripts` called with `has_scripts: false` because "installing a wheel runs no guard-run package code").

**Scenario:** wheel `evil` ships `pip/__init__.py` (or any file of pip's tree; pip does not stop a wheel overwriting another distribution's files). `pip install evil` succeeds with no prompt (clean advisory scan, no startup file). The next guarded command's probe runs `from pip import __version__` and the wheel's code runs as the user, outside the sandbox, in the guard. This is the W2-001 impact with a different file name; the CR-001 premise "interpreters start without site, so wheel code never runs in the guard" is false while the guard executes the target environment's pip.

**Reproduction:** `cargo test -j 2 -p fail2commit --test rereview_pip_boot rp_wheel_overlaying_pip` (marker file written).

**Fix:** run the guard from a pip the wheels cannot touch (a guard-owned pip, or a copy placed ahead of the environment on `sys.path` and re-hashed before each start), and in addition deny or require host-execution approval for any wheel entry that lands in `pip/`, `pip-*.dist-info/` or any module the guard imports. Setting `has_scripts` truthfully for such wheels would route apply into the SPEC-007 sandbox.

### RP-004 — High — CONFIRMED: a wheel's `.data/scripts/pyvenv.cfg` moves the bootstrap prefix and the guard imports the wheel's `pip`

**Location:** `interp.rs:46-56`. BOOT checks `<dir of sys.executable>/pyvenv.cfg` *before* `<parent>/pyvenv.cfg`. In a venv the first directory is `Scripts`/`bin`, which is exactly where the wheel scheme `scripts` installs files, nested paths included. `sys.prefix = dirname(cfg)` then makes `sysconfig` report `<Scripts>/Lib/site-packages` as purelib, the real site-packages never reaches `sys.path`, and the wheel's `pip` is imported instead.

**Scenario:** wheel entries `x.data/scripts/pyvenv.cfg` (a copy of the venv's own, so the interpreter still starts) and `x.data/scripts/Lib/site-packages/pip/__init__.py` (`lib/pythonX.Y/site-packages` on Linux). Install succeeds (the same command's verify already fails with "not installed as planned", leaving a journal). The next probe fails with `ImportError ... from 'pip' (...\Scripts\Lib\site-packages\pip\__init__.py)`: the wheel's file was imported and its code ran. No `.pth` or customize module is involved, so the startup finding cannot see it.

**Reproduction:** `cargo test -j 2 -p fail2commit --test rereview_pip_boot rp_scripts_dir_pyvenv_cfg`.

**Fix:** do not honour a `pyvenv.cfg` next to the executable in BOOT; CPython's venv layout only needs `<exe dir>/../pyvenv.cfg`, and the probe can pass the verified prefix to later invocations. Also refuse wheel entries named `pyvenv.cfg` or `.data/scripts/**` that contain a directory component.

### RP-001 — Medium — CONFIRMED: the `.pth` import-line detection misses lines CPython still executes

**Location:** `wheel.rs:155-157`. The check splits on `\n` and requires the line to start with `import ` / `import\t`. `site.py` reads the file with universal newlines and, on 3.13, as `utf-8-sig`.

**Scenario (both ran on 3.13.14):** (a) `# pad\rimport pathlib; ...` is one line to the check, two lines to `site`, so the code runs and no `pip.startup` finding or approval appears; (b) a UTF-8 BOM before `import` also runs on 3.13 and is missed.

**Reproduction:** `cargo test -j 2 -p fail2commit --test rereview_pip_boot rp_pth_with_cr_line_separator rp_pth_with_utf8_bom`. Both fail with "ran with NO approval at all".

**Fix:** decode the way `site` does (strip a BOM, split on `\r`, `\r\n`, `\n`, and other `str.splitlines` separators) and flag any line that starts with `import`; when in doubt, flag every `.pth` that is not purely paths.

### RP-002 — Medium — CONFIRMED: startup files installed through the `.data/data` scheme are never named

**Location:** `wheel.rs:123-135` (`site_relative` only maps `.data/purelib` and `.data/platlib`). The `data` scheme installs relative to `sys.prefix`, so `x.data/data/Lib/site-packages/x.pth` (or `lib/pythonX.Y/site-packages/sitecustomize.py`) lands in the venv's site-packages.

**Scenario:** both a `.pth` and a `sitecustomize.py` shipped this way run at the next plain Python start with no approval.

**Reproduction:** `cargo test -j 2 -p fail2commit --test rereview_pip_boot rp_pth_through_data_scheme rp_sitecustomize_through_data_scheme`.

**Fix:** treat any `.data/data/**` or `.data/scripts/**` entry whose base name matches the startup rules (or that resolves into purelib/platlib) as a startup file; simplest is to apply the name rules to the basename of every entry regardless of scheme. For a non-venv interpreter `.data/data` also reaches the base prefix, including the stdlib (PLAUSIBLE, not run: it would modify the host Python).

## W2-002 / CR-002 detail

**Holds:** cancel before apply leaves the venv byte-identical with no journal and no reviewed dir; cancel mid-apply stops at the wheel boundary with `done` consistent and `cancelled: true`; an unrelated install, even after a crash, stops with a message naming `recover`; `recover` asks a fresh approval over `recover_digest` (domain `pip.recover`, interpreter plus remaining wheels, never equal to an install digest) and lists only the remaining wheels; a cancel during that approval changes nothing and keeps the journal byte-identical; `recover --discard` returns before any approval or `resume` call and installs nothing (it still probes the interpreter first); a tampered reviewed set fails `verify_reviewed` with `IntegrityFailure` and keeps the evidence. The journal and hash file live only at `state_dir/pip/journal-<hash>.json` and `hashes-<16 hex>.txt` (name derived from a SHA-256 of the interpreter string and a hex-only digest), so the journal path cannot be redirected by interpreter name; `remove_reviewed` only deletes under `cache_dir/pip/reviewed`.

### RP-006 — Medium — CONFIRMED: the journal gate is keyed by the spelling of the interpreter path

**Location:** `apply.rs:42-48` (`journal_path` hashes the `python` string), `interp.rs:112-122` (when `sys.executable` differs from the path given but canonicalizes to the same file, the *user's spelling* is kept as `executable`), `mod.rs:169` (gate lookup).

**Scenario:** an install is cancelled after wheel 1 of 2. `fail2commit pip --python <venv>/Scripts/../Scripts/python.exe install gamma` (same file) finds no journal, installs `gamma` into the same venv, and the half-applied plan stays pending. CR-002 requires that "a journal blocks every guarded install for that interpreter".

**Reproduction:** `cargo test -j 2 -p fail2commit --test rereview_pip_journal respelled`.

**Fix:** key the journal (and `read_journal`) on the canonicalized executable, or on the probe-reported `sys.executable`/`prefix`, never on the caller's string.

### RP-007 — Low — CONFIRMED: `recover` trusts the journal completely

**Location:** `apply.rs:50-62` (`read_journal` checks only `done <= len` and that the digest is hex), `mod.rs:407-435` (`recover_locked`), `apply.rs:125-150` (`verify_reviewed` hashes against the journal's own list).

**Scenario:** with write access to the trusted state dir, edit `reviewed`/`wheels` to a directory holding a wheel the original plan never contained and that no install ever ran through `wheel::inspect`. `recover` shows `to install: forged==1.0 sha256:...` and, once approved, installs it. The user does see the wheel, so this is not silent, but nothing ties the journal to the digest that was originally approved, and the entries skip inspection.

**Reproduction:** `cargo test -j 2 -p fail2commit --test rereview_pip_journal recover_rejects_a_journal`. Low because the state dir is trusted and the fresh approval shows the content.

**Fix:** store the original plan digest plus a MAC keyed by a state-dir secret, re-run `wheel::inspect` on the remaining wheels in `recover`, and require `reviewed` to lie under `cache_dir/pip/reviewed`.

### RP-008 — Low — CONFIRMED: `recover` never compares `journal.python` with the interpreter it was asked about

**Location:** `apply.rs:76-79` (`discard` removes `journal_path(j.python)`), `:81-84` (progress is written to the journal's own `python` path).

**Scenario:** a journal whose `python` field names another interpreter makes `recover --discard` report `discarded: true` while this interpreter's journal file stays, so installs remain blocked, and later progress writes land in a different journal file.

**Reproduction:** `cargo test -j 2 -p fail2commit --test rereview_pip_journal discard_acts_on_the_journal`.

**Fix:** reject a journal whose `python` differs from `interp.executable` in `read_journal`.

## W2-006 detail

**Holds:** `install` checks both shim slots before placing either, so a foreign `pip` or `pip3` is refused and nothing is half placed; `place` no longer deletes; uninstall skips anything that is not our shim even with a forged ownership record; install twice then uninstall returns an empty bin dir (`foreign_file_survives_setup_and_uninstall`, `install_twice_then_uninstall_restores_an_empty_bin_dir`, unit test `foreign_file_is_neither_replaced_nor_removed`).

### RP-005 — Low — CONFIRMED (Windows): uninstall after an in-place upgrade leaves our own shims, and setup refuses to refresh them

**Location:** `shim.rs:99` compares the shim with the *current* executable (`c.detail["target"]`); the sha256 recorded at setup (`shim.rs:79`) is never used. The npm shim compares with the recorded hash (`npm/shim.rs:67-69`). `shim.rs:59` (same test as npm's install check) also makes `setup` fail with "already exists and is not a fail2commit shim" once the executable changed.

**Scenario:** `setup`, upgrade fail2commit in place, `uninstall`: `pip.exe` and `pip3.exe` remain in the bin dir. Linux symlink mode is not affected by an in-place upgrade (not run here).

**Reproduction:** `cargo test -j 2 -p fail2commit --test rereview_pip_shim` (`uninstall_after_in_place_upgrade_removes_our_shims`, `setup_again_after_upgrade_is_not_blocked_by_our_own_old_shim`).

**Fix:** in `uninstall` use the recorded `sha256` (copy mode) or recorded `target` (symlink mode) as npm does; let `install` refresh a shim whose content equals a hash recorded in the setup file.

## Pending evidence

- Linux: nothing in this report was run on Linux (bwrap or not); the shim symlink mode, `bin`/`lib/pythonX.Y` layouts for RP-002/RP-004 and the 3.12-versus-3.13 `.pth` decoding difference for RP-001 are untested there.
- The `.data/data` write into a non-venv base prefix (stdlib overwrite) is PLAUSIBLE and not run.
- The CLI `recover` command was covered only by the existing `pip_cli` tests, not driven by hand.
- Full workspace test suites other than the pip ones were not run.

## Commands

All from the worktree root with `-j 2`, stdin redirected from empty, disposable temp venvs/state, loopback fixture index only. Tested SHA `915f18d` plus the three new untracked test files.

| Command | Exit | Result |
|---|---:|---|
| `git rev-parse HEAD` | 0 | `915f18d8ae2823df64ec7d05a1663cfe78a62816` |
| `cargo test -j 2 -p fail2commit --test pip_cli --test pip_install --test pip_recover --test pip_reject --test review_wave2_pth` | 0 | 35 passed, 0 failed (pip_cli 6, pip_install 15, pip_recover 7, pip_reject 4, review_wave2_pth 3) |
| `cargo test -j 2 -p fail2commit-core pip::` | 0 | 17 passed, 0 failed |
| `python .claude/hooks/trace_check.py` | 0 | `[guard:trace_check] OK` |
| `cargo test -j 2 -p fail2commit --test rereview_pip_boot -- --test-threads=1` | 101 (expected) | 4 passed, 5 failed: RP-001 (x2), RP-002 (x2), RP-003 fail; the four controls pass (plain `.pth` named, stdlib shadow and `PYTHON*` ignored, system-site-packages planted files never run) |
| `cargo test -j 2 -p fail2commit --test rereview_pip_boot rp_scripts_dir -- --test-threads=1 --nocapture` | 101 (expected) | RP-004 fails. The first run used an invalid `home = nowhere` cfg, which only bricks the interpreter; it is vacuous and is not counted. The committed test copies the venv's own cfg and fails as RP-004. |
| `cargo test -j 2 -p fail2commit --test rereview_pip_journal -- --test-threads=1` | 101 (expected) | 3 passed, 3 failed: RP-006, RP-007, RP-008 fail |
| `cargo test -j 2 -p fail2commit --test rereview_pip_shim` | 101 (expected) | 2 passed, 2 failed: both RP-005 tests fail |
| `rustfmt --edition 2021 --check crates/fail2commit/tests/rereview_pip_*.rs` | 0 | formatted |
| `cargo test -j 2 -p fail2commit --test rereview_pip_boot --test rereview_pip_journal --test rereview_pip_shim --no-run` | 0 | compiles after formatting |

The `rereview_pip_*` tests assert the secure outcome, so each stays red until its finding is fixed. They serialize on a mutex because one test sets `PYTHONPATH`/`PYTHONSTARTUP`.
