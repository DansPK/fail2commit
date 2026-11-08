---
name: write-requirements
description: Capture or update business, product and functional requirements (BRD, PRD, FRD) with traceable IDs. Use when the user describes a new feature, project idea, business goal or change in behaviour, or says "write requirements", "BRD", "PRD", "FRD", "user story".
---

# Write Requirements (analyst role)

## Inputs
- The user's description of the need
- Existing `docs/requirements/BRD.md`, `PRD.md`, `FRD.md` and `docs/traceability.md`

## Steps
1. **Read** `docs/requirements/REQUIREMENT_RULES.md` and the three requirement docs. Find the highest existing ID of each type. New IDs continue from it, and IDs are never reused.
2. **Interview** the user in short rounds of no more than 4 questions each. Stop when you can answer:
   - **Why** (BR): the business problem, a measurable objective, and the stakeholders.
   - **What** (PRD): the persona, the story, its priority, and what is out of scope.
   - **Exactly what** (FR/NFR): inputs, outputs, rules, errors, and Given/When/Then acceptance criteria.
3. **Write** the items as `Status: Draft`, using the block formats already in each doc.
   - BR → `BRD.md` §2
   - PRD → `PRD.md` §2, with `Links:` to its BR
   - FR/NFR → `FRD.md`, with `Links:` to its PRD
4. **Check quality** for each FR:
   - It is atomic, with no "and".
   - It is testable and has at least one Given/When/Then.
   - It has no unmeasured adjectives such as "fast" or "easy".
   - It describes no solution, so no tech choices.
5. **Add a row per FR/NFR** to `docs/traceability.md`: `| FR-### | PRD-### | BR-### | - | - | Draft |`.
6. **Run** `python .claude/hooks/trace_check.py`. It must pass.
7. **Report** the new IDs, and list the open questions you added to the docs' *Open Questions* sections.

## Rules
- Never change an item whose status is `Approved` or later. Add a Change Request under *Open Questions* instead and tell the user (see REQUIREMENT_RULES §5).
- Only the human owner sets `Approved`. Ask them to review the Draft items.
- `docs/requirements/` is a protected path, so the guard may ask for confirmation. This is expected for this skill.
