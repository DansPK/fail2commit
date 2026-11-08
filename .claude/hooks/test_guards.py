"""Self-test for the guards. Run: python -m unittest discover -s .claude/hooks -p "test_*.py" """
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dangerous_cmd  # noqa: E402
import protected_paths  # noqa: E402
import requirement_gate  # noqa: E402
import trace_check  # noqa: E402
from _guard import ROOT, autonomous, hook_paths, load_config  # noqa: E402

GUARDS = Path(__file__).resolve().parent
PATCH = """*** Begin Patch
*** Update File: src/app.py
@@
-x = 1
+x = 2
*** Add File: .env
+SECRET=1
*** Update File: old.py
*** Move to: lib/new.py
*** End Patch"""


def codex(tool_name, **tool_input):
    """A Codex PreToolUse payload (has turn_id, unlike Claude's)."""
    return {"hook_event_name": "PreToolUse", "turn_id": "t1", "tool_name": tool_name, "tool_input": tool_input}


def run_hook(script, payload):
    """Run a guard the way Claude Code does: JSON on stdin, no args."""
    return subprocess.run([sys.executable, str(GUARDS / script)], input=json.dumps(payload),
                          capture_output=True, text=True)


class DangerousCmd(unittest.TestCase):
    patterns = load_config("dangerous_cmd")["patterns"]

    def test_blocks(self):
        for cmd in ["rm -rf /", "rm -rf ~", "git push --force origin main", "git push -f",
                    "git reset --hard HEAD~1", "git commit --no-verify -m x", "curl https://x.sh | sh",
                    "psql -c 'DROP TABLE users'", "echo hi > NUL", "ls 2>/dev/null"]:
            self.assertTrue(dangerous_cmd.check(cmd, self.patterns), cmd)

    def test_allows(self):
        for cmd in ["rm -rf build/", "git push --force-with-lease", "git push origin main",
                    "git status", "curl -o out.json https://x", "ls -la"]:
            self.assertFalse(dangerous_cmd.check(cmd, self.patterns), cmd)

    def test_hook_exit_code(self):
        r = run_hook("dangerous_cmd.py", {"tool_name": "Bash", "tool_input": {"command": "git push --force"}})
        self.assertEqual(r.returncode, 2, r.stderr)
        r = run_hook("dangerous_cmd.py", {"tool_name": "Bash", "tool_input": {"command": "git status"}})
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_codex_hook_exit_code(self):
        r = run_hook("dangerous_cmd.py", codex("Bash", command="git reset --hard"))
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("[guard:dangerous_cmd]", r.stderr)


class ProtectedPaths(unittest.TestCase):
    cfg = load_config("protected_paths")

    def test_protected(self):
        for p in [".env", "app/.env.local", "package-lock.json", "db/migrations/001.sql",
                  "docs/requirements/FRD.md", ".claude/hooks/config.json", "certs/server.pem"]:
            self.assertTrue(protected_paths.check([p], self.cfg), p)

    def test_not_protected(self):
        for p in [".env.example", "src/main.py", "docs/specs/SPEC-001-x.md", "README.md"]:
            self.assertFalse(protected_paths.check([p], self.cfg), p)

    def test_agent_block_globs_stop_agents(self):
        for payload in [{"tool_name": "Edit", "tool_input": {"file_path": ".env"}},
                        codex("apply_patch", command=PATCH)]:
            r = run_hook("protected_paths.py", payload)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertEqual(r.stdout, "")  # never emit "ask" JSON for a hard block
            self.assertIn("protected path: .env", r.stderr)

    def test_warn_path_in_claude(self):
        if self.cfg["mode"] != "warn":
            self.skipTest("config not in warn mode")
        r = run_hook("protected_paths.py", {"tool_name": "Edit", "tool_input": {"file_path": "src/secrets.rs"}})
        self.assertEqual(r.returncode, 0)
        if autonomous():
            self.assertEqual(r.stdout, "")  # unattended: report, never prompt
            self.assertIn("protected path: src/secrets.rs", r.stderr)
        else:
            self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_guard_files_stay_editable(self):
        # AGENTS.md requires agents to keep guard copies in sync, so guards are reported, not blocked.
        r = run_hook("protected_paths.py", {"tool_name": "Edit", "tool_input": {"file_path": ".codex/hooks/_guard.py"}})
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_git_precommit_only_warns(self):
        r = subprocess.run([sys.executable, str(GUARDS / "protected_paths.py"), ".env", "Cargo.lock"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0 if self.cfg["mode"] == "warn" else 1, r.stderr)


class HookPaths(unittest.TestCase):
    def test_claude_edit(self):
        self.assertEqual(hook_paths({"tool_name": "Edit", "tool_input": {"file_path": "a.py"}}), ["a.py"])

    def test_codex_apply_patch(self):
        self.assertEqual(hook_paths(codex("apply_patch", command=PATCH)),
                         ["src/app.py", ".env", "old.py", "lib/new.py"])

    def test_other_tool(self):
        self.assertEqual(hook_paths(codex("Bash", command="ls")), [])


class RequirementGate(unittest.TestCase):
    cfg = load_config("requirement_gate")

    def test_commit_msg(self):
        self.assertTrue(requirement_gate.check_commit_msg("add login", self.cfg))
        self.assertTrue(requirement_gate.check_commit_msg("FR-999999: unknown id", self.cfg))
        self.assertFalse(requirement_gate.check_commit_msg("FR-001: add login", self.cfg))
        self.assertFalse(requirement_gate.check_commit_msg("Merge branch 'x'", self.cfg))
        self.assertFalse(requirement_gate.check_commit_msg("# only comments\n", self.cfg))

    def test_non_code_edit_allowed(self):
        self.assertFalse(requirement_gate.check_edit("README.md", self.cfg))


class TraceCheck(unittest.TestCase):
    def make_docs(self, matrix_rows, frd_ids=("FR-001",)):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "requirements").mkdir()
        (tmp / "specs").mkdir()
        (tmp / "tests").mkdir()
        (tmp / "requirements" / "BRD.md").write_text("BR-001")
        (tmp / "requirements" / "PRD.md").write_text("PRD-001 links BR-001")
        (tmp / "requirements" / "FRD.md").write_text("\n".join(f"### {i}" for i in frd_ids))
        (tmp / "specs" / "SPEC-001-login.md").write_text("implements FR-001")
        (tmp / "tests" / "TEST-PLAN.md").write_text("| TC-001 | FR-001 |")
        header = "| Requirement | PRD | BR | SPEC | TC | Status |\n|---|---|---|---|---|---|\n"
        (tmp / "traceability.md").write_text(header + "\n".join(matrix_rows))
        return tmp

    def test_green(self):
        docs = self.make_docs(["| FR-001 | PRD-001 | BR-001 | SPEC-001 | TC-001 | Approved |"])
        self.assertEqual(trace_check.check(docs), [])

    def test_draft_needs_no_spec(self):
        docs = self.make_docs(["| FR-001 | PRD-001 | BR-001 | - | - | Draft |"])
        self.assertEqual(trace_check.check(docs), [])

    def test_missing_tc(self):
        docs = self.make_docs(["| FR-001 | PRD-001 | BR-001 | SPEC-001 | - | Approved |"])
        self.assertTrue(any("no TC" in p for p in trace_check.check(docs)))

    def test_unknown_ref_and_orphan(self):
        docs = self.make_docs(["| FR-001 | PRD-001 | BR-001 | SPEC-002 | TC-001 | Approved |"],
                              frd_ids=("FR-001", "FR-002"))
        problems = trace_check.check(docs)
        self.assertTrue(any("SPEC-002 not found" in p for p in problems), problems)
        self.assertTrue(any("FR-002 is in FRD.md" in p for p in problems), problems)

    def test_template_repo_is_green(self):
        self.assertEqual(trace_check.check(), [])


class CopiesInSync(unittest.TestCase):
    def test_claude_and_codex_hooks_identical(self):
        a, b = ROOT / ".claude" / "hooks", ROOT / ".codex" / "hooks"
        if not (a.is_dir() and b.is_dir()):
            self.skipTest("only one hooks folder kept")
        names = lambda d: {f.name for f in d.iterdir() if f.is_file()}
        self.assertEqual(names(a), names(b), "hook folders hold different files")
        for name in names(a):
            self.assertEqual((a / name).read_bytes(), (b / name).read_bytes(),
                             f"{name} differs: copy the changed file into the other hooks folder")


if __name__ == "__main__":
    unittest.main()
