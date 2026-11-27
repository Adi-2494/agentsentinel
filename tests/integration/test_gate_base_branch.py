"""Integration: the Merge Gate judges the COMMITTED PR code, not the working tree (INV-5).

Regression guard for a past bug (see NOTES.md) where the gate read files from the working
tree instead of the PR's head commit, so a dirtied tree could hide vulnerable committed code.
Uses an in-house secret rule, so it needs neither an LLM nor Semgrep/Gitleaks.
"""

import json
import subprocess

import pytest

from gate import run_gate

pytestmark = pytest.mark.integration

_LEAK = 'KEY = "sk-ant-api03-REALSECRETVALUE1234567890abcdef"\n'
_SAFE = 'KEY = "placeholder"\n'


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr("core.config.DB_PATH", tmp_path / "events.db")


def test_gate_judges_committed_code_not_working_tree(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@t.test")
    _git(repo, "config", "user.name", "t")
    cfg = repo / "config.py"

    cfg.write_text(_SAFE, encoding="utf-8")  # base: safe
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")

    _git(repo, "checkout", "-q", "-b", "pr")  # PR branch: commit a real secret
    cfg.write_text(_LEAK, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "leak")

    _git(repo, "checkout", "-q", "main")  # leave the WORKING TREE on the safe version
    assert "sk-ant" not in cfg.read_text(encoding="utf-8")  # tree is safe; the secret lives only in the pr commit

    out = tmp_path / "r.json"
    code = run_gate.main(["--repo", str(repo), "--base", "main", "--head", "pr", "--no-llm", "--json-out", str(out)])
    rules = {f["rule"] for f in json.loads(out.read_text(encoding="utf-8"))["findings"]}

    # If the gate read the (safe) working tree it would pass; it must read the pr COMMIT and block.
    assert code == 1, f"gate passed a committed secret (did it read the working tree?): {rules}"
    assert "anthropic_key" in rules, rules
