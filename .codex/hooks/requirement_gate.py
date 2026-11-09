"""Requirement gate: work must be tied to a requirement / task ID.

Git commit-msg / CLI: python <hooks>/requirement_gate.py --commit-msg <file>
    The message must cite an ID (FR-001, BUG-002, CHORE-003, ...) that exists in id_sources.
Claude Code hook (PreToolUse, matcher Edit|Write|MultiEdit) or Codex hook (matcher apply_patch): stdin JSON.
    Editing a file under code_globs requires an "in-progress" row in TODO.md.
"""
import re
import sys

from _guard import ROOT, ID_RE, finish, hook_paths, load_config, matches, read_hook_input, read_todo, rel_path


def known_ids(sources):
    text = []
    for src in sources:
        p = ROOT / src
        files = p.rglob("*.md") if p.is_dir() else [p]
        text += [f.read_text(encoding="utf-8", errors="ignore") for f in files if f.is_file()]
    return {m.group(0) for m in ID_RE.finditer("\n".join(text))}


def check_commit_msg(msg, cfg):
    msg = "\n".join(line for line in msg.splitlines() if not line.startswith("#")).strip()
    if not msg or msg.startswith(tuple(cfg.get("commit_exempt_prefixes", []))):
        return []
    ids = {m.group(0) for m in ID_RE.finditer(msg)}
    if not ids:
        return ["commit message cites no requirement/task ID (e.g. 'FR-001: ...', 'BUG-002: ...', 'CHORE-003: ...')"]
    if cfg.get("require_known_id", True):
        unknown = ids - known_ids(cfg.get("id_sources", ["docs", "TODO.md"]))
        if unknown == ids:
            return [f"ID(s) {', '.join(sorted(ids))} not found in {cfg.get('id_sources')}; add them to TODO.md or the requirement docs first"]
    return []


def check_edit(path, cfg):
    path = rel_path(path)
    if not matches(path, cfg.get("code_globs", [])):
        return []
    text = read_todo()
    # shortcut: any in-progress row unlocks code edits; check the row's owner/files if agents collide.
    if re.search(r"^\|.*\bin-progress\b.*\|", text, re.MULTILINE | re.IGNORECASE):
        return []
    return [f"editing {path} but no task is claimed: set a TODO.md row to Status 'in-progress' with your name as Owner (see AGENTS.md: Multi-agent protocol)"]


def main(argv):
    cfg = load_config("requirement_gate")
    if argv[:1] == ["--commit-msg"] and len(argv) == 2:
        with open(argv[1], encoding="utf-8") as f:
            finish("requirement_gate", cfg["mode"], check_commit_msg(f.read(), cfg))
    hook = read_hook_input()
    problems = [p for path in hook_paths(hook) for p in check_edit(path, cfg)]
    finish("requirement_gate", cfg["mode"], problems, hook)


if __name__ == "__main__":
    main(sys.argv[1:])
