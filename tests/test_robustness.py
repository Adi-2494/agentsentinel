"""Robustness issues from the scale / fuzz review. Written before the fixes."""
import json
import os
import random
import string
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core import store
from core.detectors import commands
from guard.claude_hook import evaluate

HOOK = Path(__file__).resolve().parent.parent / "guard" / "claude_hook.py"
WEIRD = ["/tmp/a\x00b", "/tmp/\ud800x", "\x00", "\udcff.env", "a\x00.env", "/tmp/\ud83d"]


# ---------------------------------------------------------------- 1. malformed input
@pytest.mark.parametrize("path", WEIRD)
@pytest.mark.parametrize("tool", ["Read", "Write", "Edit", "Grep", "Glob", "NotebookEdit"])
def test_1_weird_paths_do_not_crash_detectors(tool, path):
    inp = {"file_path": path, "path": path, "notebook_path": path, "content": "x", "new_string": "x"}
    evaluate(tool, inp, "/tmp")  # must not raise


@pytest.mark.parametrize("cmd", [f"cat {p}" for p in WEIRD] + ["echo \ud800 | sh", "python3 -c 'open(\"\x00\")'"])
def test_1_weird_commands_do_not_crash_detectors(cmd):
    evaluate("Bash", {"command": cmd}, "/tmp")


def test_1_weird_cwd_does_not_crash():
    evaluate("Bash", {"command": "cat notes.txt"}, "/tmp/\ud800\x00")


def test_1_protected_file_with_weird_bytes_is_still_denied_by_the_detector():
    decision, findings = evaluate("Read", {"file_path": "/proj/.env\x00"}, "/tmp")
    assert decision == "deny" and findings and findings[0].rule == "protected_file"


@pytest.mark.parametrize("payload", [
    {"tool_name": "Read", "tool_input": {"file_path": "/tmp/\ud800x"}},
    {"tool_name": "Read", "tool_input": {"file_path": "/tmp/a\x00b"}},
    {"tool_name": "Write", "tool_input": {"file_path": "/p/\ud800.py", "content": "K = '" + "AKIA" + "Q" * 16 + "'"}},
])
def test_1_hook_process_decides_normally(payload, tmp_path):
    p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload), text=True, capture_output=True,
                       env={**os.environ, "AGENTSENTINEL_DB": str(tmp_path / "r.db")}, timeout=30)
    assert p.returncode == 0
    if p.stdout.strip():
        reason = json.loads(p.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
        assert "could not check" not in reason, reason


def test_1_fuzz_never_raises():
    rnd = random.Random(7)
    alphabet = string.printable + "\x00𐃿‮​\U000E0041é漢"
    for _ in range(2000):
        s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 60)))
        for tool, inp in (("Read", {"file_path": s}), ("Bash", {"command": s}),
                          ("Write", {"file_path": s, "content": s})):
            evaluate(tool, inp, s)


# ---------------------------------------------------------------- 2. big commands
def _big(n):
    rnd = random.Random(1)
    w = lambda k=8: "".join(rnd.choice(string.ascii_lowercase) for _ in range(k))  # noqa: E731
    return 'python3 -c "' + "; ".join(f"x_{w()} = open('{w()}.txt').read()" for _ in range(n // 40)) + '"'


def test_2_command_check_is_fast_on_large_commands():
    cmd = _big(320_000)
    t = time.time()
    commands.check(cmd)
    assert time.time() - t < 0.5, f"{len(cmd)} chars took {time.time() - t:.2f}s"


def test_2_huge_commands_are_bounded_and_not_silently_allowed():
    cmd = _big(1_200_000)
    t = time.time()
    decision, findings = evaluate("Bash", {"command": cmd}, "/tmp")
    assert time.time() - t < 2.0
    assert decision in ("ask", "deny")


def test_2_speedup_keeps_detection():
    assert {"reads_secret_file"} <= {f.rule for f in commands.check(_big(320_000) + " ; cat .env")}


# ---------------------------------------------------------------- 3. log connections
def test_3_log_writes_do_not_accumulate_open_files(tmp_path):
    import gc
    db = tmp_path / "fd.db"
    store.log_event("mcp", "warned", "r", "LOW", {}, db_path=db)
    gc.collect()
    before = len(os.listdir("/dev/fd"))
    gc.disable()
    try:
        for i in range(200):
            store.log_event("mcp", "warned", "r", "LOW", {"i": i}, db_path=db)
        during = len(os.listdir("/dev/fd"))
    finally:
        gc.enable()
    assert during - before <= 3, f"{during - before} file descriptors left open by 200 writes"
    assert len(store.recent_events(db_path=db)) == 201


def test_3_schema_setup_runs_once_per_database(tmp_path, monkeypatch):
    db = tmp_path / "s.db"
    store.log_event("mcp", "warned", "r", "LOW", {}, db_path=db)
    monkeypatch.setattr(store, "SCHEMA", "THIS IS NOT SQL;")  # re-running setup would now fail
    for i in range(20):
        store.log_event("mcp", "warned", "r", "LOW", {"i": i}, db_path=db)
    assert len(store.recent_events(db_path=db)) == 21


def test_3_batch_write_uses_one_connection(tmp_path, monkeypatch):
    opened = []
    real = store.sqlite3.connect
    monkeypatch.setattr(store.sqlite3, "connect", lambda *a, **k: opened.append(1) or real(*a, **k))
    store.log_events([("gate", "failed", f"r{i}", "HIGH", {"i": i}) for i in range(50)], db_path=tmp_path / "b.db")
    assert len(opened) == 1 and len(store.recent_events(db_path=tmp_path / "b.db")) == 50
