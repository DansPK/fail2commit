# Verify Report: <scope> (YYYY-MM-DD)

> Copy to `docs/verify/VERIFY-YYYY-MM-DD-<slug>.md`. Written by the tester or reviewer role, or by the `verify` skill.
> **Requirements covered:** FR-###, NFR-###
> **Commit / branch:** <sha or branch>
> **Verified by:** <agent or person>

---

## 1. Commands Run

```text
<exact commands, e.g. python -m pytest; python .claude/hooks/trace_check.py>
```

## 2. Results

| TC ID | Requirement | Result | Evidence (log line, screenshot, test name) |
|-------|-------------|--------|---------------------------------------------|
| TC-### | FR-### | Pass / Fail / Blocked | |

## 3. Traceability Check

<!-- Paste the output of `python .claude/hooks/trace_check.py`. -->

## 4. Issues Found

<!-- Create a BUG-### row in TODO.md for each failure, and list it here. -->

## 5. Verdict

- [ ] **Verified:** all linked TCs pass; requirement status set to `Verified`
- [ ] **Not verified:** reasons above
