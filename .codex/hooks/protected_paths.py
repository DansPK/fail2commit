"""Warn or block edits to protected files (secrets, lockfiles, migrations, approved requirements, the guards themselves).

Claude Code hook (PreToolUse, matcher Edit|Write|MultiEdit|NotebookEdit) or Codex hook (matcher apply_patch): stdin JSON.
Git pre-commit / CLI: python <hooks>/protected_paths.py <file> [<file> ...]
"""
import os
import subprocess
import sys

from _guard import ROOT, finish, hook_paths, load_config, matches, read_hook_input, rel_path


def check(paths, cfg, key="globs"):
    return [f"protected path: {p}" for p in map(rel_path, paths)
            if matches(p, cfg.get(key, [])) and not matches(p, cfg.get("allow", []))]


def main(argv):
    cfg = load_config("protected_paths")
    hook = None if argv else read_hook_input()
    if argv == ["--staged"]:
        staged = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRD", "-z"],
            cwd=ROOT,
        )
        paths = [os.fsdecode(path) for path in staged.split(b"\0") if path]
    else:
        paths = argv or hook_paths(hook)
    if hook is not None:
        # Agent edits of hard-protected paths stop outright; nobody may be around to answer a prompt.
        hard = check(paths, cfg, "agent_block_globs")
        if hard:
            finish("protected_paths", "block", hard, hook)
    finish("protected_paths", cfg["mode"], check(paths, cfg), hook)


if __name__ == "__main__":
    main(sys.argv[1:])
