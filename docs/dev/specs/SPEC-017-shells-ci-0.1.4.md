# SPEC-017: shells, hook bypass and CI time (FR-014, FR-015, FR-016, NFR-017)

Status: implemented on `DansPK/f2c-0.1.4` (coordinator). Follows SPEC-001 (Git guard) and CR-015 / CR-021 (shell functions).

## FR-014: login shells on Linux

A login bash reads only the first of `~/.bash_profile`, `~/.bash_login`, `~/.profile` that exists. Arch creates `~/.bash_profile`, so the PATH block in `~/.profile` never ran there.

- `git::integ::default_path_editor()` on Linux returns `ProfilesEditor { files }`: `~/.profile` always, plus `~/.bash_profile` and `~/.bash_login` when they already exist. Missing ones are not created (creating `~/.bash_profile` would hide an existing `~/.profile`).
- `ProfilesEditor::add` writes the same marked block into each file through `ProfileEditor` (symlinks followed, modes kept, CR-021) and records `{"editor":"profiles","files":[<ProfileEditor detail>...]}`. If one file fails, the files already written are rolled back.
- `remove` takes that record, or a 0.1.3 record (one `profile` detail), and removes the block from each recorded file; a file setup created is deleted when only the block was in it.
- zsh: `~/.zshrc` already carries the shell functions (CR-015); PATH for zsh login shells comes from `~/.zprofile` only if the user sources `~/.profile` there, and is otherwise reached through the functions. Not changed.

## FR-015: PATH entry once

The block is now `case ":$PATH:" in *:'<dir>':*) ;; *) export PATH='<dir>':"$PATH" ;; esac`, so a login shell started from another (both reading the block) adds the folder once. If something else was put before it later, the folder is not moved to the front again; the shell functions keep the guard in front for `npm`, `pip`, `pip3` and `git`.

## FR-016: pushes that skip hooks

- `fail2commit git push` drops `--no-verify` and any prefix git would accept for it (`--no-v` up to `--no-verify`) before a `--` separator, and prints `fail2commit: --no-verify is ignored; this push is still checked` to stderr. The hook runs, so the push is checked as FR-001 describes.
- A `-c core.hooksPath=...` given by the user is already overridden: the shim appends its own `-c core.hooksPath=<fail2commit hooks>` after the user's global options, and the later `-c` wins.
- The shell blocks gain a `git` function next to `pip`, `pip3`, `npm`, so `git` typed in bash, zsh, Git Bash or PowerShell goes through `fail2commit git` even when a version manager or another directory puts a different `git` first on PATH. When the fail2commit binary is gone (removed without `uninstall-integrations`), the POSIX function runs `command git` and the PowerShell function runs the first `git` application on PATH, silently (CR-021).
- Not covered: `command git push --no-verify`, a full path to git, and programs that run git themselves (IDEs, scripts) still skip the hook when they pass `--no-verify`. Protected refs rely on the remote policy (SPEC-003, CR-011).

## NFR-017: CI time

`.github/workflows/ci.yml` runs `fmt` (Ubuntu), `clippy` (Windows, Ubuntu) and `test` (Windows, Ubuntu) as parallel jobs. Each matrix job restores a dependency and target cache (`Swatinem/rust-cache@v2`, saved only from `main`), builds without full debug info (`CARGO_PROFILE_{DEV,TEST}_DEBUG=line-tables-only`, `CARGO_INCREMENTAL=0`), and a newer push cancels a running PR run. The commands are the same as at 0.1.3 (`cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -D warnings`, `cargo test --workspace --locked`), so no test is dropped. Measured on the 0.1.4 pull request and the next two (verify report).

## Test cases

| TC | Requirement | Given / When / Then | Test |
|---|---|---|---|
| TC-014-1 | FR-014 | Given a home with `~/.bash_profile`, When the PATH block is added and removed, Then both profiles get it and `~/.bash_profile` is byte-identical afterwards, and `~/.profile` (created) is deleted | `git::integ::tests::login_profiles_get_one_path_entry_and_are_restored` (Unix) |
| TC-014-2 | FR-014 | Given a 0.1.3 setup record, When uninstalling with 0.1.4, Then the block is removed | `git::integ::tests::old_single_profile_record_still_removes` |
| TC-014-3 | FR-014 | Given Arch with the default `~/.bash_profile`, When `bash -l -c 'command -v npm git'` runs after setup, Then both resolve into the fail2commit folder | release pass on Arch (verify report) |
| TC-015-1 | FR-015 | Given the block sourced three times, Then the folder appears once in PATH | `login_profiles_get_one_path_entry_and_are_restored` |
| TC-015-2 | FR-015 | Given Ubuntu after setup, When `bash -l -i -c 'echo $PATH'` runs inside a login session, Then the folder appears once | release pass on Ubuntu |
| TC-016-1 | FR-016 | Given `--no-verify` or `--no-veri` before `--`, Then it is dropped; after `--`, and `--no-`, `-n`, `--verify`, are kept | `cmd::git::tests::no_verify_and_its_prefixes_are_dropped_before_dashes_only` |
| TC-016-2 | FR-016 | Given the POSIX block, When `git --version` runs with the binary present, Then it goes through fail2commit; after the binary is removed, Then the real git answers | `shellinteg::tests::posix_git_function_routes_through_the_guard_and_falls_back` (Unix) |
| TC-016-3 | FR-016 | Given the PowerShell block, Then `git` routes through the quoted exe and falls back to `Get-Command git -CommandType Application` | `shellinteg::tests::powershell_block_quotes_the_exe` |
| TC-016-4 | FR-016 | Given setup on Linux and Windows (PowerShell, Git Bash), When `git push --no-verify` pushes a synthetic secret to a disposable remote, Then the push pauses for approval | release pass (verify report) |
| TC-017-1 | NFR-017 | Given a warm cache, Then the slowest required job takes 12 min or less and the run 15 min or less, on 3 consecutive PRs | CI timings in the verify report |
