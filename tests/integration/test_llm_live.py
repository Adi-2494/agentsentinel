"""Live Claude tests. Opt-in only (they use your Pro limit):  pytest -m llm"""
import shutil
from pathlib import Path

import pytest

from core.llm import ask_llm
from gate import run_gate

pytestmark = [pytest.mark.llm, pytest.mark.skipif(not shutil.which("claude"), reason="no claude CLI")]
EX = Path(__file__).resolve().parents[2] / "examples"


def test_ask_llm_live():
    assert "ready" in ask_llm("Reply with only the word: ready", "haiku").lower()


@pytest.mark.parametrize("example,expected_exit", [("vulnerable_pr", 1), ("trick_pr", 1), ("safe_pr", 0)])
def test_gate_live(example, expected_exit, tmp_path, monkeypatch):
    monkeypatch.setattr("core.config.DB_PATH", tmp_path / "e.db")
    args = ["--path", str(EX / example)]
    body = EX / example / "PR_DESCRIPTION.md"
    if body.exists():
        args += ["--pr-body-file", str(body)]
    assert run_gate.main(args) == expected_exit
