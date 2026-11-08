# Guarded pip installs (FR-005, SPEC-005)

fail2commit installs only verified registry **wheels**, bound to one
interpreter, after a reviewable plan. Policy lives in Rust; requirement
text, pip config, package metadata and index responses are untrusted.

## Entry points

```sh
fail2commit pip [--python <interpreter>] install <requirement>... | -r requirements.txt
```

* The `pip` / `pip3` shims (installed by `fail2commit setup`, PATH ordering
  by the Git integration) run exactly this command. Without `--python` the
  interpreter is the Python next to the real `pip` outside the shim dir.
* **A shim cannot intercept `python -m pip` or `py -m pip`.** Use the guarded
  replacement instead:

  ```sh
  fail2commit pip --python python install requests      # instead of: python -m pip install requests
  fail2commit pip --python py install -r requirements.txt
  ```
* Supported `install` options: `-r/--requirement`, `-c/--constraint`,
  `-U/--upgrade`, `--pre`. Anything else is refused.
* Other pip commands: `list show freeze check inspect uninstall help debug`
  and `--version` run through an isolated pip (no index flags). `download`,
  `wheel`, `config`, `index`, … are refused, so no argument reaches an
  unguarded manager path. In `--json` mode their stdout is returned in
  `data.stdout`.

## What is rejected before any resolution (`UnsupportedInput`, exit 2)

Editable installs; VCS and direct URLs; local paths and archives;
`--index-url/-i`, `--extra-index-url`, `--find-links/-f`, `--trusted-host`
in arguments or requirements files; `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`,
`PIP_FIND_LINKS`, `PIP_TRUSTED_HOST` (and `PIP_NO_INDEX`) in the environment;
the same keys in pip config files (user, global, site, `PIP_CONFIG_FILE`);
nested `-r/-c` that are URLs, use `$VAR`, or leave the top-level file's
directory (depth ≤ 4, ≤ 32 files). A value equal to the pinned default index
is tolerated. The resolver never sees the user's text: a sanitized
requirements file is regenerated.

## Pinned index

`https://pypi.org/simple` (files from `files.pythonhosted.org`) unless the
**trusted** `config/pip.toml` under the fail2commit config directory says:

```toml
index_url = "https://pypi.example.org/simple"   # https only (http for loopback tests)
file_hosts = ["files.example.org"]                # extra hosts wheels may come from
```

(`settings.rs` is frozen and rejects unknown keys, so this is a separate
trusted file; it is never read from a workspace.)

## Flow

1. Parse and reject (above); bind to the interpreter via `python -I`
   (`sys.executable`, prefix/venv, platform, pip's vendored
   `packaging.tags.sys_tags()`).
2. **Wheel-only boundary.** A loopback staging index (random-token URL)
   fronts the pinned registry. It lists only `.whl` files that carry a
   SHA-256, hosted on allowed hosts; sdists are never offered. A file is
   served only after it is downloaded (≤ `limits.artifact_max_bytes`),
   matches the index SHA-256, and passes defensive zip checks (path escapes,
   symlinks, entry and uncompressed-size bounds, METADATA name/version equal
   to the filename). A wheel whose `Requires-Dist` is a direct reference
   (`name @ url`, VCS, path) is withheld, which stops transitively supplied
   references before pip can act on them. Redirects fail closed.
3. `python -I -m pip --isolated install --dry-run --report … --only-binary=:all:
   --index-url <staging>` produces the exact versions. Each report entry
   must map to a staged file with the verified hash; anything else is
   `UnsupportedInput`/`IntegrityFailure`. Projects that publish only sdists
   are reported as `UnsupportedInput` (`PyPI:name`). The dry run is never
   trusted for safety: it only ever talks to the staging index.
4. Advisories (`scan::check_advisories`). `Deny` stops. An `Approve`
   finding or an incomplete scan asks for approval of a `Digest` over
   interpreter identity (executable, prefix, tags, platform), the index, the
   requested set and the ordered wheel set with SHA-256. A clean complete
   scan installs without a prompt. `exec::authorize_scripts` is called with
   `has_scripts: false` (wheels run no install-time code; no sandbox).
5. **Apply offline.** Reviewed wheels are copied to a private directory and
   re-hashed; immediately before apply the directory must equal the plan
   byte for byte (changed plan ⇒ `IntegrityFailure`). Each wheel is installed
   with `pip install --no-index --find-links <reviewed> --no-deps
   --require-hashes --only-binary=:all: -r <generated hashes>`. No index, no
   resolution. Afterwards the interpreter's installed set must contain
   every planned name/version.

## Cancel, interrupt, recovery

Cancel before apply changes nothing (the dry run touches no environment).
A cancel token kills the resolver or stops between wheels. Apply writes a
journal (`state/pip/journal-<id>.json`, progress per wheel) and keeps the
reviewed wheels until verification passes. The next guarded run for that
interpreter first rolls the journal forward from the reviewed set (still
hash-checked; tampering ⇒ `IntegrityFailure`, nothing installed), then
continues. Ctrl-C in the CLI terminates the process like any other command;
the journal makes that recoverable.

## Limits / not covered

* Windows/Linux AppContainer/Bubblewrap are not used: wheels execute no code
  at install time. `.pth` files and entry points in installed wheels run
  later, as with any Python package.
* Index trust beyond HTTPS + SHA-256 from the same index (as PEP 503/691
  provide); no signature checking.
* Recovery is roll-forward only; already replaced older versions are not
  restored.
