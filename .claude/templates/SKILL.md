---
name: my-skill
description: One sentence on what it does AND when to use it (the trigger). Agents pick skills by this line, so name the user phrases that should trigger it.
---

<!-- Copy this folder to .claude/skills/<name>/ and rename `name` to match the folder.
     Or generate one: python .claude/skills/skill-creator/scripts/init_skill.py <name> --path .claude/skills -->

# My Skill

## When to use
- <!-- trigger 1 -->

## Inputs
- <!-- files or IDs the skill needs, e.g. FR-### -->

## Steps
1. <!-- concrete step; name exact files and commands -->
2.

## Output
- <!-- files created or updated, and what to report back -->

## Rules
- Follow `AGENTS.md` and `docs/requirements/REQUIREMENT_RULES.md`.
- <!-- skill-specific do / don't -->
