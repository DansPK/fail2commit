# Agent Roles

Each role owns specific artifacts. An agent acts in **one role per task** and edits only what that role may edit. One agent may take several roles in sequence. When it does, it writes a handoff note between roles (`HANDOFF-template.md`).

| Role | Input | Produces | May edit | Must not edit |
|------|-------|----------|----------|---------------|
| **analyst** | stakeholder input | BRD / PRD / FRD drafts, open questions | `docs/requirements/*` (Draft items only) | code, tests, approved requirements |
| **architect** | approved FR/NFR | SPEC, TC rows, traceability rows | `docs/specs/*`, `docs/tests/TEST-PLAN.md`, `docs/traceability.md` | code, requirements |
| **developer** | approved SPEC + TCs | code, automated tests, commits citing IDs | source, tests, `TODO.md` (own rows) | requirements, specs (propose changes instead) |
| **tester** | code + TCs | test results, verify report, BUG rows | tests, `docs/verify/*`, `docs/tests/TEST-PLAN.md` (Status column), `TODO.md` | production code, requirements |
| **reviewer** | diff + verify report | approve / request changes, LESSONS_LEARNED entries | `LESSONS_LEARNED.md`, review comments | anything else (send it back to the owner instead) |
| **human owner** | anything | approvals, priority, answers to open questions | everything | — |

<!-- Add or rename roles to fit your team (e.g. designer, security, ops). Keep the "May edit" column precise: it drives .claude/hooks/config.json. -->

## Escalation

An agent must stop and write an Open Question (in the relevant doc, and in `TODO.md` as `Status: blocked`) when:
- a requirement is ambiguous, contradictory, or missing
- the SPEC cannot be implemented as written
- a test reveals behaviour that contradicts an approved requirement
- the task needs files claimed by another task

Don't guess and keep going.
