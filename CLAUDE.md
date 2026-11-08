# CLAUDE.md

@AGENTS.md

---

## Claude Code specifics

The rules above come from `AGENTS.md`, which is shared by all agents. Edit project rules there, not here. Only Claude-specific notes belong in this file.

- **Skills:** `.claude/skills/` is loaded automatically. Prefer `/write-requirements`, `/spec-to-tests`, `/verify` and `/handoff` over doing these steps ad hoc.
- **Hooks:** `.claude/settings.json` runs the scripts in `.claude/hooks/` on `SessionStart` and `PreToolUse`. If you change a script, copy it to `.codex/hooks/` too.
  - A **blocked** call (exit 2) means a rule was hit. Read the `[guard:...]` reason and change the approach. Do not try to work around the guard.
  - A **warn** guard asks the user to confirm.
- **Subagents:** when you spawn subagents for parallel work, give each one a single claimed TODO row and its file list from the SPEC. Each subagent ends with a handoff note.
- **Memory:** project knowledge goes in `LESSONS_LEARNED.md` and `DONE.md`, not only in Claude's private memory, so that other agents can see it.
