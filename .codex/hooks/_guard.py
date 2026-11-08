"""Shared helpers for guard scripts. Python 3.8+ stdlib only.

Each guard runs in one of two ways:
  * Agent hook (Claude Code or Codex): no CLI args, hook JSON on stdin.
  * CLI / git hook: arguments on the command line, nothing read from stdin.
"""
import fnmatch
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # <repo>/.claude/hooks or <repo>/.codex/hooks
CONFIG_FILE = Path(__file__).resolve().parent / "config.json"
ID_RE = re.compile(r"\b(BR|PRD|FR|NFR|SPEC|TC|BUG|CHORE)-\d{3,}\b")
PATCH_FILE_RE = re.compile(r"^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+?)\s*$", re.MULTILINE)


def load_config(name):
    cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8")).get(name, {})
    cfg.setdefault("mode", "warn")
    return cfg


def autonomous():
    """True when config.json sets autonomous.enabled: warn guards report instead of prompting."""
    return bool(json.loads(CONFIG_FILE.read_text(encoding="utf-8")).get("autonomous", {}).get("enabled"))


def read_todo():
    """TODO.md text with <!-- comments --> removed, so example rows never count as real tasks."""
    todo = ROOT / load_config("requirement_gate").get("todo_file", "TODO.md")
    text = todo.read_text(encoding="utf-8") if todo.exists() else ""
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)


def read_hook_input():
    raw = sys.stdin.read()
    return json.loads(raw) if raw.strip() else {}


def is_codex(hook):
    # Codex PreToolUse payloads carry turn_id; Claude Code's do not.
    return "turn_id" in hook


def hook_paths(hook):
    """Files a Claude Edit/Write or Codex apply_patch call will touch."""
    tool_input = hook.get("tool_input", {})
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if path:
        return [path]
    if hook.get("tool_name") == "apply_patch":
        return PATCH_FILE_RE.findall(tool_input.get("command", ""))
    return []


def rel_path(path):
    """Repo-relative POSIX path, or the original path if it is outside the repo."""
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    try:
        return p.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return Path(path).as_posix()


def matches(path, globs):
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(name, g) for g in globs)


def finish(guard, mode, problems, hook=None):
    """Report problems according to mode and exit. hook = parsed hook payload, or None for CLI/git. Never returns."""
    if not problems or mode == "off":
        sys.exit(0)
    msg = f"[guard:{guard}] " + "\n[guard:{0}] ".format(guard).join(problems)
    if mode == "warn" and hook is not None and not is_codex(hook) and not autonomous():
        # Claude Code: ask the user instead of silently allowing (unless running unattended).
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": msg,
        }}))
        sys.exit(0)
    # shortcut: Codex does not support "ask" yet, so warn there is stderr-only; use block for anything that must stop Codex.
    print(msg, file=sys.stderr)
    if mode == "block":
        sys.exit(2 if hook is not None else 1)
    sys.exit(0)
