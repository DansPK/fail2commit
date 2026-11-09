---
name: verify
description: Verify implemented requirements. Runs the tests and the traceability check, records the TC results, and writes a verify report. Use after implementation, before closing a task or opening a PR, or when the user says "verify", "check it works", "is FR-### done".
---

# Verify (tester / reviewer role)

## Inputs
- FR/NFR IDs or a SPEC ID to verify, or "everything in progress" in `TODO.md`.

## Steps
1. **Collect** the linked TCs from `docs/traceability.md` and `docs/tests/TEST-PLAN.md`.
2. **Run** the project's test command. It is listed in `AGENTS.md` → Development Commands and in TEST-PLAN §1. Capture the exact command and a summary of its output. Then run the guards:
   ```
   python .claude/hooks/trace_check.py
   python -m unittest discover -s .claude/hooks -p "test_*.py"
   ```
3. **Do manual TCs** where they exist. Follow the steps in TEST-PLAN §4 and record the evidence, such as an output line or a screenshot path.
4. **Record results.**
   - Update the Status column in TEST-PLAN for each TC: Pass, Fail or Blocked.
5. **Write a report.**
   - Copy `docs/verify/VERIFY-template.md` to `docs/verify/VERIFY-YYYY-MM-DD-<slug>.md`.
   - Fill in every section. Evidence must be real output, never paraphrased or assumed.
6. **When every linked TC passes and trace_check is green:**
   - Set the traceability row status to `Verified`.
   - Ask the owner to set the FRD status to `Verified` (requirements are protected).
   - Close the TODO row and add a `DONE.md` entry with `Req IDs` and `Verified by`.
7. **When something fails:**
   - Add a `BUG-###` row to `TODO.md` for each failure.
   - Leave the statuses unchanged.
   - Hand back to the developer with the `handoff` skill.

## Rules
- Write the report per `docs/WRITING_STANDARD.md`: real output, no filler.
- Never mark a TC as Pass without running it. If something was not run, say so.
- Do not fix production code in this role. Report the failure and hand back.
