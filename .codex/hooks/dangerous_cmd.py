"""Block destructive shell commands.

Claude Code / Codex hook (PreToolUse, matcher Bash): reads the command from stdin JSON.
CLI: python <hooks>/dangerous_cmd.py "<command>"
"""
import re
import sys

from _guard import finish, load_config, read_hook_input


def check(command, patterns):
    return [f"dangerous command matches /{p}/: {command}"
            for p in patterns if re.search(p, command, re.IGNORECASE)]


def main(argv):
    cfg = load_config("dangerous_cmd")
    hook = None if argv else read_hook_input()
    command = " ".join(argv) if argv else hook.get("tool_input", {}).get("command", "")
    finish("dangerous_cmd", cfg["mode"], check(command, cfg.get("patterns", [])), hook)


if __name__ == "__main__":
    main(sys.argv[1:])
