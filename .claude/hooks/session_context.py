"""SessionStart hook (Claude Code + Codex): put the task board into the new session's context.

Stdout becomes context for the agent, so every session starts from the shared state in TODO.md.
"""
from _guard import read_todo

board = [line for line in read_todo().splitlines() if line.startswith("|")]
print("Task board from TODO.md. Claim a `ready` row (Owner + in-progress) before editing code; see AGENTS.md > Multi-agent Protocol.")
print("\n".join(board) or "(TODO.md has no task table)")
