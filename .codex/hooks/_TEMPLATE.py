"""Template guard. Copy to <name>.py in this folder, add a "<name>" section to config.json, and wire it up (see README.md in this folder).

Claude Code / Codex hook: no args, PreToolUse JSON on stdin ({"tool_name": ..., "tool_input": {...}}).
  For file edits use _guard.hook_paths(hook): it handles Claude Edit/Write and Codex apply_patch.
CLI / git hook: python <hooks>/<name>.py <args>
"""
import sys

from _guard import finish, load_config, read_hook_input


def check(value, cfg):
    """Return a list of problem strings; empty list = OK."""
    problems = []
    # if <bad condition>: problems.append(f"why this is not allowed: {value}")
    return problems


def main(argv):
    cfg = load_config("my_guard")
    hook = None if argv else read_hook_input()
    value = argv or hook.get("tool_input", {})
    finish("my_guard", cfg["mode"], check(value, cfg), hook)


if __name__ == "__main__":
    main(sys.argv[1:])
