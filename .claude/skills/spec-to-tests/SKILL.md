---
name: spec-to-tests
description: Turn approved FR/NFR requirements into a technical spec (SPEC-###) and test cases (TC-###), and update the traceability matrix. Use before coding a requirement, or when the user says "write a spec", "design this", "test plan", "test cases for FR-###".
---

# Spec to Tests (architect role)

## Inputs
- One or more FR/NFR IDs whose status is `Approved`. If they are not approved, stop and ask the owner.

## Steps
1. **Read** the FR/NFR blocks in `docs/requirements/FRD.md`, the linked PRD, and the relevant code. Read `LESSONS_LEARNED.md` for the area you are touching.
2. **Create** `docs/specs/SPEC-###-<slug>.md` from `docs/specs/SPEC-template.md`, with the next free SPEC ID.
   - Fill in design, interfaces, data changes and edge cases.
   - Fill **§8 Files Expected to Change**. Task claiming uses this list.
3. **Write test cases.** Give every acceptance criterion at least one TC.
   - Add the rows to `docs/tests/TEST-PLAN.md` §2 with the next free TC IDs.
   - Set the type (unit, integration, e2e or manual), the automated path where you expect it, and `Status: Not run`.
   - Add an edge-case TC for each row in SPEC §5 that matters.
4. **Map** criteria to TCs in SPEC §6.
5. **Update** the row in `docs/traceability.md`: fill the SPEC and TC cells and keep the status as is.
6. **Add a task** to `TODO.md` for the developer: `| T-### | Implement SPEC-### | FR-### | - | ready | - |`.
7. **Run** `python .claude/hooks/trace_check.py`. It must pass.
8. **Hand off** to the developer with the `handoff` skill.

## Rules
- Do not write production code in this role.
- If the FR cannot be specified as written, stop. Add an Open Question to `FRD.md` and set the TODO row to `blocked`.
- Prefer automated TCs. Use manual only when automating is impractical, and say why.
