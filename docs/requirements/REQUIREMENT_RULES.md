# Requirement Rules

> Every agent and human follows these rules. `.claude/hooks/trace_check.py` and `.claude/hooks/requirement_gate.py` enforce the mechanical parts.

## 1. ID scheme

| Prefix | Lives in | Meaning |
|--------|----------|---------|
| `BR-###` | `docs/requirements/BRD.md` | Business requirement: why we build it |
| `PRD-###` | `docs/requirements/PRD.md` | Product requirement / user story: what the user gets |
| `FR-###` | `docs/requirements/FRD.md` | Functional requirement: exact system behaviour |
| `NFR-###` | `docs/requirements/FRD.md` | Non-functional requirement (performance, security, a11y...) |
| `SPEC-###` | `docs/specs/SPEC-###-<slug>.md` | Technical design for one or more FR/NFR |
| `TC-###` | `docs/tests/TEST-PLAN.md` | Test case proving an FR/NFR |
| `BUG-###` | `TODO.md` | Defect outside the requirement chain |
| `CHORE-###` | `TODO.md` | Tooling, docs, refactor (no behaviour change) |

- IDs are 3+ digits, never reused, never renumbered. A removed requirement is marked `Status: Withdrawn` but keeps its row.
- Write IDs exactly as shown (`FR-001`). The guards find them with the regex `\b(BR|PRD|FR|NFR|SPEC|TC|BUG|CHORE)-\d{3,}\b`.

## 2. Linking (traceability)

- Every `PRD` links to at least one `BR`.
- Every `FR`/`NFR` links to at least one `PRD`.
- Every `FR`/`NFR` with status `Approved` or later has at least one `SPEC` and one `TC` in `docs/traceability.md`.
- Code commits cite the ID they implement (`FR-001: add login rate limit`). Work outside the chain cites a `BUG-` or `CHORE-` ID.

## 3. Writing a good requirement

- **Atomic:** one behaviour per FR. If you need "and", split it.
- **Testable:** acceptance criteria in Given / When / Then. If you cannot write a test, it is not a requirement yet.
- **Measurable:** no "fast", "easy", "user-friendly" without a number ("p95 < 300 ms", "≤ 3 clicks").
- **Solution-free:** BRD and PRD say *what* and *why*; *how* belongs in SPEC.
- **Owned:** every requirement has an owner who can answer questions.

## 4. Status lifecycle

`Draft` → `Review` → `Approved` → `Implemented` → `Verified` (or `Withdrawn`)

- Only a human (product owner) moves a requirement to `Approved`.
- `Implemented` = code merged and cites the ID. `Verified` = TCs pass and listed in a verify report.

## 5. Change control

- Agents **never silently edit** an `Approved` requirement. Add an entry under the doc's **Open Questions / Change Requests** section and stop for a human decision.
- `docs/requirements/` is a protected path (see `.claude/hooks/config.json`); edits trigger a warning or a block.
- Approved changes get a row in the doc's **Change Log** (date, ID, change, approved by).

## 6. Definition of Ready (before coding)

- [ ] FR/NFR is `Approved`
- [ ] SPEC exists and links the FR
- [ ] TC rows exist in `TEST-PLAN.md` and `traceability.md`
- [ ] Task row in `TODO.md` is claimed (see `AGENTS.md` → Multi-agent protocol)

## 7. Definition of Done

- [ ] Tests for every linked TC pass
- [ ] `python .claude/hooks/trace_check.py` passes
- [ ] Verify report written in `docs/verify/`
- [ ] Requirement status updated to `Verified`
- [ ] `DONE.md` entry added; `TODO.md` row closed
