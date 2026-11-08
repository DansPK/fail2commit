---
name: handoff
description: Hand work to the next agent or role with a handoff note, and update the task board. Use when finishing a role's step (analyst → architect → developer → tester → reviewer), when stopping mid-task, when blocked, or when the user says "hand off", "pass to", "wrap up", "next agent".
---

# Handoff

## Steps
1. **Gather** the TODO row ID, the requirement/SPEC/TC IDs, and the files you touched (`git status`, `git diff --stat`). Also gather the commands the next agent should run first.
2. **Write the note.**
   - Copy `docs/agents/HANDOFF-template.md` to `docs/agents/handoffs/YYYY-MM-DD-<TODO ID>.md`, or paste it into the PR description if the team uses PRs.
   - Fill in every section: done, not done, files, how to check, open questions, next step.
   - The next step must be one concrete action.
3. **Update the TODO.md row.**
   - **Owner:** `-` if any agent may pick it up, or the named receiver.
   - **Status:** `handoff→<role>`, or `blocked` if it is waiting on a human answer.
   - Keep the requirement IDs on the row.
4. **Commit** the note and the TODO change together: `<TODO ID>: handoff to <role>`.
5. **Report** to the user: who is next, what they should do, and any open questions that need a human.

## Rules
- Write the note per `docs/WRITING_STANDARD.md`: facts and next action, no filler.
- Never hand off silently. Every exit from a task leaves a note.
- If you are blocked by an ambiguous or conflicting requirement, the note must name the exact question and the doc where it is logged.
- Release the claim. Do not leave `in-progress` with your name on a task you are leaving.
