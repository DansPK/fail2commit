# Independent review: coordinator's last security fixes (FR-002 relay, FR-005 pip layout denial)

Date: 2026-11-09
Reviewed: `8773c1b` (relay `SO_EXCLUSIVEADDRUSE`), `a8a0cc3` and `5ea0dd1` (wheel name folding, NTFS stream names, entry-point scripts, RP2-001 repro scoping). Base tree `5ea0dd1` on `DansPK/f2c-int-final`.
Reviewer: independent; product code was not modified. Reproductions: `crates/fail2commit/tests/review_coordinator_fixes_pip.rs` only.
Platform run: Windows 11 (10.0.26200), venv on CPython 3.13 (the lab venv), 8.3 short names enabled on `C:`. **Linux was not run** (pending).

## Verdict

- **Relay fix (`8773c1b`): accept with notes.** The FFI is correct, the socket is never double-closed, and non-Windows code is unchanged. The new test cannot detect a regression (CF-004), and the hijack it guards against does not work on this Windows build even without the fix.
- **Pip fix (`a8a0cc3`, `5ea0dd1`): NOT APPROVED. Do not close RP2-002 and keep RP2-001 open for Windows.**
  - CF-001: the `entry_points.txt` check is bypassed by a one-character change (a bare CR, form feed or U+2028 as a line break). A wheel then replaces `pip.exe`, `pip3.exe` and `pip3.13.exe`. CONFIRMED end to end.
  - CF-003: an 8.3 short name (`PIP313~1.EXE`) overwrites the versioned pip launcher. CONFIRMED end to end.
  - The Unicode case-folding concern is **not a gap** on NTFS (probe below).

| Area asked | Result |
|---|---|
| 1. WinSock code: FFI, error paths, byte order, ownership | Correct. Two Low notes (CF-005, CF-006). |
| 1. Does `SO_EXCLUSIVEADDRUSE` stop a co-bind? Window before it is set? | Yes for same-address `SO_REUSEADDR`. No window: the option is set before `bind`. But the pre-fix listener was already not hijackable here (CF-004). |
| 1. Non-Windows unchanged | Yes: same `TcpListener::bind(127.0.0.1:0)` call. Not compiled on Linux here (pending). |
| 2. Unicode lookalikes (Kelvin, dotted/dotless I, long s) | **Not a gap.** 0 of the 63,000+ non-ASCII BMP code points resolve to any ASCII letter file on NTFS. |
| 2. 8.3 short names | **Gap** (CF-003). Aliases exist only for non-8.3 names: `pip3.N.exe`, `deactivate.bat`, `pip-N.dist-info`, `vcruntime140.dll`. `pyvenv.cfg`, `Lib`, `Scripts` are already 8.3 and have no alias. |
| 2. Folding reaches `.dist-info`, `pip`, `.pth` checks | Yes: `classify` folds every component before every check. |
| 3. Entry-point parsing matches pip | **No** (CF-001, CF-002). |
| 3. Bounded read | Sufficient: 4 MiB, over-limit is a deny; unsupported compression fails closed in `by_index`. |
| 3. RECORD-only or other mechanisms | None found: pip ignores `RECORD` for placement. Only `entry_points.txt` and `.data/scripts` create scripts. |
| 4. Test change | Consistent with CR-001; still catches an unnamed alias (CF-007, Info). |

## Findings

| ID | Sev | Status | Where |
|---|---|---|---|
| CF-001 | Medium (RP2-002 stays open) | CONFIRMED | `wheel.rs:354-370` |
| CF-002 | Medium | PLAUSIBLE (not reproduced on Windows) | `wheel.rs:242-255`, `wheel.rs:292` |
| CF-003 | Medium (Windows, 8.3 enabled) | CONFIRMED | `wheel.rs:153-155`, `232-255` |
| CF-004 | Low | CONFIRMED | `relay.rs:272-292` |
| CF-005 | Low | CONFIRMED (read) | `relay.rs:200-204` |
| CF-006 | Info | CONFIRMED (read) | `pip/proxy.rs:71` |
| CF-007 | Info | CONFIRMED (read) | `rereview2_pip.rs:240-272` |
| CF-008 | Info | PLAUSIBLE | `wheel.rs:219-229, 326-335` |

### CF-001 (Medium, CONFIRMED): entry_points.txt is split differently from Python, so a console script named `pip` gets through

**Where:** `console_script_names` (`wheel.rs:354-370`). It uses `str::lines` (splits on `\n` and `\r\n` only) and treats every line starting with `[` as a section header.

**Scenario:** pip reads the file with `importlib.metadata` (3.11+) or `pkg_resources`. Both split with `str.splitlines`, which also splits on a bare CR, VT, FF, FS/GS/RS, NEL, U+2028 and U+2029. `importlib.metadata` treats a line as a header only if it starts with `[` **and** ends with `]`. The Rust code sees `[console_scripts]\rpip = evil:main` as one line whose section name is `console_scripts]\rpip = evil:main`, so `in_scripts` is false and nothing is checked. A `#` comment line ending in a CR hides the header the same way.

Verified with `python -I` on 3.12: `EntryPoints._from_text("[console_scripts]\rpip = evil:main\n")` returns `('console_scripts', 'pip')`. The same holds for ` `, `\x0c`, and for a leading `# note\r` comment. End to end through `pip::install` with auto-approval: variants `cr`, `ls`, `ff`, `comment-cr` were accepted and replaced `pip.exe`, `pip3.exe` and `pip3.13.exe` in the venv's `Scripts`. The `[a = b` bracket-line variant did not change anything on this pip (not reproduced).

**Repro:** `cargo test -j 2 -p fail2commit --test review_coordinator_fixes_pip cf_001` (fails while the bypass works).

**Fix:** parse the way Python does: split on every `str.splitlines` separator, a header only when the stripped line starts with `[` and ends with `]` (name is `trim_matches(['[', ']'])`). For defense in depth, fail closed: deny any `entry_points.txt` that has a CR, VT, FF, FS, GS, RS, NEL, U+2028 or U+2029, or a line starting with `[` that does not end with `]`. Run `bad_script` on the script names of every section if you want to be stricter than pip.

### CF-002 (Medium, PLAUSIBLE): an entry-point name with a path separator is not a file name

**Where:** `wheel.rs:292` passes `&[script]` as a one-element list, so the `rest.len() > 1` nested-path rule in `bad_script` (`wheel.rs:243`) never fires. For `../pyvenv.cfg` the leaf's first dot-piece is empty, so no rule matches. `importlib.metadata` accepts the name (probe: `('console_scripts', '../pyvenv.cfg')`). distlib joins the name onto the scripts directory.

**Scenario:** `[console_scripts]` name `../pyvenv.cfg` or `../lib/python3.N/site-packages/sitecustomize.py` writes a launcher outside `bin`/`Scripts` on Linux (and `..\x.exe` on Windows).

**Not reproduced:** `cf_002_*` passes on Windows (nothing was written to the venv root). Either pip or distlib rejected the name, or the launcher path differs. Linux was not run. Treat as unproven until the Linux run.

**Fix:** treat an entry-point name like a path: split on `/` and `\`, then apply the nested-path rule and the fold/`:`/empty-component rule to every piece; deny `..`.

### CF-003 (Medium, CONFIRMED, Windows with 8.3 enabled): short names reach `pip3.N.exe`

**Where:** `fold` (`wheel.rs:153-155`) removes case and trailing dots and spaces only. `is_pip_script` (`wheel.rs:232-238`) accepts `pip` followed by digits only.

**Scenario:** NTFS gives `pip3.13.exe` the alias `PIP313~1.EXE` (the dir listing on this host also shows `DEACTI~1.BAT` for `deactivate.bat`). A wheel with `x.data/scripts/PIP313~1.EXE` passes `bad_script` (`pip313~1` is not `pip`, not `pip<digits>`) and overwrites `pip3.13.exe`. Result in the lab: `Ok(1)` and `pip3.13.exe` holds the wheel's bytes. The next `pip3.13` the user runs is wheel-controlled and outside the guard. The same applies to the entry-point route (name `PIP313~1`). 8.3 generation is on for the system volume by default (`fsutil behavior query disable8dot3` = 2, "per volume"); it is off by default on other volumes, so the risk depends on where the venv lives. Direct filesystem proof (no pip): writing `PIP312~1.EXE` replaced `pip3.12.exe` in a scratch dir.

**Repro:** `cargo test -j 2 -p fail2commit --test review_coordinator_fixes_pip cf_003`.

**Fix:** on Windows deny any component that matches `~[0-9]` (the short-name pattern), in `.data/scripts` leaves, entry-point names, the first `.data/data` component and the first site-packages component. A tighter check is `GetShortPathNameW` on the target directory, but the pattern rule needs no filesystem access and cannot be raced.

### CF-004 (Low, CONFIRMED): the relay test passes without the fix

**Where:** `reuseaddr_socket_cannot_cobind_the_relay_port` (`relay.rs:272-292`).

**Scenario:** on this Windows build (10.0.26200) a `SO_REUSEADDR` socket cannot co-bind a listener that set **no** option. Probe (P/Invoke WinSock, run in PowerShell): victim without options (listening or not), attacker `SO_REUSEADDR` on `127.0.0.1:P` returns error 10013; it succeeds only when the victim itself set `SO_REUSEADDR`. Rust's `std` does not set `SO_REUSEADDR` on Windows, so the pre-fix listener was already not co-bindable this way, and the test would pass if `SO_EXCLUSIVEADDRUSE` were removed from `bind_loopback`. The control only proves that binding a free port works, not that the attack works against a non-exclusive listener. RR-001's Windows hijack was marked PLAUSIBLE by its reviewer; it is not reproducible here, so the fix is defense in depth. It is harmless and still worth keeping (older Windows semantics, and a future change to `SO_REUSEADDR`).

Also checked: a wildcard squatter (`SO_REUSEADDR` on `0.0.0.0:P` next to the exclusive `127.0.0.1:P`) does bind, but a connection to `127.0.0.1:P` is delivered to the specific listener (the probe's `Poll` showed victim readable, squatter not). No hijack.

**Fix:** make the test discriminate: `getsockopt(SOL_SOCKET, SO_EXCLUSIVEADDRUSE)` on the returned listener must read 1 (or compare with a control socket created without it). Keep the bind test as a second check.

### CF-005 (Low, CONFIRMED by reading): wrong error code when `WSAStartup` fails

**Where:** `relay.rs:202-204`. `WSAStartup` returns the error code and does not set the thread's last error, so `last()` reports a stale or zero value. Use `Error::from_raw_os_error(rc)`. The result is only a misleading message on a fail-closed path.

### CF-006 (Info): `Proxy::start` still binds with the plain std call

`pip/proxy.rs:71` uses `TcpListener::bind("127.0.0.1:0")`. For the reason in CF-004 it is not co-bindable here either, and it carries a per-run token. Mention only so the two loopback listeners are treated alike if the relay approach is generalized.

### CF-007 (Info): RP2-001 test scoping

The new final check, `approved_named || !marker.exists()` (`rereview2_pip.rs:267-272`), fits CR-001. It does not lose power: the per-alias assertion `named || !ran_file` is evaluated after every install and `ran_file` is cumulative, so an installed alias that is not named still fails. Two weaknesses: `named` means any `pip.startup` finding, not one for that entry, and once one alias is named the marker check is nearly vacuous. Cheap improvement: require a finding whose `location` equals the alias entry. The `::$DATA` alias is now denied outright and takes the `continue` path.

### CF-008 (Info, PLAUSIBLE, pre-existing): the data-scheme list does not cover other prefix files

`DATA_RESERVED` (`wheel.rs:219-229`) names directories and `pyvenv.cfg`. For a non-venv prefix the data scheme could also write `vcruntime140.dll` (alias `VCRUNT~1.DLL`) next to `python.exe`, which the next interpreter start loads. Not reproduced and not part of these commits; a venv root has no such file. Worth a line in `docs/pip.md` or a deny of `*.dll`/`*.exe`/`*.pyd` at the prefix root.

## Checked and sound

- **WinSock bring-up:** `WSAStartup(0x0202)` is reference counted, `WSADATA` out parameter is valid, and the socket is `WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT`, the flags std uses. `SO_EXCLUSIVEADDRUSE` is set before `bind`: no window.
- **Byte order:** `sin_port = port.to_be()`; the address is `u32::from_ne_bytes([127,0,0,1])`, which stores the bytes `7f 00 00 01` in network order on any endianness.
- **Error paths:** `socket_with` closes on `setsockopt` failure; `bind_loopback` closes on bind and listen failure; `last()` is evaluated before `closesocket` (argument order), so the code is not overwritten.
- **Ownership:** `TcpListener::from_raw_socket(s as u64)` is the only owner after success; no path closes `s` afterwards. `set_nonblocking`/`local_addr` failures drop the listener, which closes it.
- **Backlog:** `SOMAXCONN` matches std.
- **Folding scope:** `classify` folds before any comparison and returns `Bad` for empty or `:` components, so `.`, `..`, `Lib.`, `x.pth::$DATA` and `x.pth ` are caught. `fold` handles `.dist-info`, `pip` dist names and `.pth`.
- **Unicode:** probe on this NTFS volume created files `a`..`z` and tested all BMP code points above U+007F (surrogates skipped) with `Get-ChildItem -LiteralPath`. Zero resolved to an ASCII file, so Kelvin sign, dotless/dotted I and long s do not alias `pip`, `scripts`, `include`, `.pth`. A volume with a custom `$UpCase` table is not covered.
- **Entry-point reads:** `by_index` errors on unsupported or encrypted entries (scan returns `Err`, install fails closed); over-limit text is a deny; duplicate `entry_points.txt` entries are all scanned.
- **Existing regressions:** `pip::wheel` unit tests and `rereview2_pip` pass (table).

## Commands

All from the worktree root, `-j 2`, stdin empty, disposable venvs and fixture index. Tested SHA `5ea0dd128c13c2e3eb0cf2bb3b9b5e7e4974004e` plus the new untracked `review_coordinator_fixes_pip.rs`.

| # | Platform | Command | Exit | Result |
|---:|---|---|---:|---|
| 1 | Windows | `git rev-parse HEAD` | 0 | `5ea0dd128c13c2e3eb0cf2bb3b9b5e7e4974004e` |
| 2 | Windows | `cargo test -j 2 -p fail2commit-core -- relay pip::wheel` | 0 | 10 passed (incl. `approval::relay::exclusive::tests::reuseaddr_socket_cannot_cobind_the_relay_port` the hmac test and 8 `pip::wheel` tests) |
| 3 | Windows | `cargo test -j 2 -p fail2commit --test rereview2_pip -- --test-threads=1` | 0 | 7 passed, 1 ignored (RP2-005, documented residual) |
| 4 | Windows | `cargo test -j 2 -p fail2commit --test review_coordinator_fixes_pip -- --test-threads=1 --nocapture` | 101 (expected) | CF-001 FAILED (bypass works), CF-003 FAILED (bypass works), CF-002 passed (not reproduced); 148.9 s |
| 5 | Windows | PowerShell: create `a`..`z`, `Get-ChildItem -LiteralPath` for U+0080..U+FFFF | 0 | 0 hits |
| 6 | Windows | PowerShell: `cmd /c dir /x`, write `PIP312~1.EXE` / `DEACTI~1.BAT` in a scratch dir | 0 | both originals replaced |
| 7 | Windows | PowerShell P/Invoke WinSock: victim plain/exclusive/`SO_REUSEADDR`, attacker `SO_REUSEADDR` | 0 | plain and exclusive victims: 10013 for same address; `SO_REUSEADDR` victim: bound; `0.0.0.0` attacker always binds |
| 8 | Windows | PowerShell .NET `Socket`: exclusive victim on `127.0.0.1:P`, wildcard squatter on `0.0.0.0:P`, connect to `127.0.0.1:P` | 0 | victim readable, squatter not |
| 9 | Windows | `python -I` `importlib.metadata.EntryPoints._from_text` on CR, U+2028, FF, bracket-line, `../name` inputs | 0 | CR/LS/FF parse as `console_scripts: pip`; `../pyvenv.cfg` accepted as a name |

Pending evidence: Linux run of `review_coordinator_fixes_pip` (CF-001 and CF-002 are platform independent in the guard; CF-003 is Windows-only); non-Windows compile of `relay.rs` after the import change; `cargo clippy` for `needless_return` in `bind_loopback`; volumes with 8.3 disabled; `trace_check.py` (no scaffold files changed).
