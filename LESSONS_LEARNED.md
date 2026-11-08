# Lessons Learned - fail2commit

> **Critical patterns and anti-patterns discovered during development**
> **Purpose:** Prevent recurring bugs and document invisible failure modes
> **Last Updated:** 2026-11-08

---

<!-- Add lessons learned entries here as you discover them. -->
<!-- Each entry should follow this template: -->

<!-- ## Pattern Name -->
<!--  -->
<!-- **Problem:** What goes wrong -->
<!--  -->
<!-- **Root Cause:** Why it happens -->
<!--  -->
<!-- **Correct Pattern:** -->
<!-- ```language -->
<!-- // Good code example -->
<!-- ``` -->
<!--  -->
<!-- **Wrong Pattern:** -->
<!-- ```language -->
<!-- // Bad code example -->
<!-- ``` -->
<!--  -->
<!-- **Prevention Checklist:** -->
<!-- - Step 1 -->
<!-- - Step 2 -->
<!--  -->
<!-- **Why it's invisible:** Explanation of silent failure mode -->

## Windows PowerShell 5.1 corrupts UTF-8 files on read-modify-write

**Problem:** `Get-Content -Raw` followed by `Set-Content -Encoding utf8` turned `–` into `â€“` in TODO.md and added a BOM.

**Root Cause:** PowerShell 5.1 reads files without a BOM as the ANSI code page, so UTF-8 multibyte characters are decoded wrongly before being re-encoded.

**Correct Pattern:** edit with the Edit tool, or `Get-Content -Raw -Encoding UTF8` plus `[IO.File]::WriteAllText($p, $s, [Text.UTF8Encoding]::new($false))`.

**Why it's invisible:** ASCII-only files round-trip fine; the damage shows only on non-ASCII characters.

## Agent file writes can turn `\uXXXX` escapes into real characters

**Problem:** a TypeScript regex written as `/[ -‮]/` reached disk with literal U+2028 (a line terminator), which split the regex literal and broke compilation. Other non-ASCII escapes silently became invisible raw characters in the source.

**Correct Pattern:** keep security-relevant character tables pure ASCII, as numeric code-point ranges (`[0x2028, 0x202e]`) or Rust `'\u{2028}'` brace escapes, and check with a script that the file has no characters above 0x7E.

**Why it's invisible:** the source looks right in most editors, and the bug only shows when a line-terminator character lands inside a literal.

## Many parallel Orca worktrees overload a desktop host

**Problem:** about 10 concurrent agent worktrees, each running cargo at full parallelism with Docker builds, made the Windows host lag badly, and agents crashed.

**Correct Pattern:** run at most 3 workers at once with `cargo -j 2` and one Docker build at a time. Release finished workers' terminals promptly.

---

> **See TODO.md for additional rules and checklists**
> **See DONE.md for implementation history and bug fixes**
