"""Dashboard data layer + a full-page smoke test (Streamlit AppTest, no browser)."""
from pathlib import Path

import pytest

from core import store
from dashboard import data

APP = str(Path(__file__).resolve().parent.parent / "dashboard" / "app.py")


@pytest.fixture
def db(tmp_path):
    p = tmp_path / "d.db"
    store.log_event("claude_code", "blocked", "protected_file", "CRITICAL", {"tool": "Read", "preview": ".env"}, p)
    store.log_event("claude_code", "blocked", "pipe_to_shell", "CRITICAL", {"tool": "Bash"}, p)
    store.log_event("claude_code", "warned", "unknown_url", "MEDIUM", {"tool": "Bash"}, p)
    store.log_event("gate", "failed", "aws_access_key", "CRITICAL", {"pr": "PR #1", "category": "secret"}, p)
    store.log_event("gate", "failed", "aadhaar", "HIGH", {"pr": "PR #1", "category": "pii"}, p)
    store.log_event("gate", "failed", "tainted-sql-string", "HIGH", {"pr": "PR #2", "category": "vuln"}, p)
    store.log_event("gate", "failed", "two_view_manipulation", "CRITICAL", {"pr": "PR #2", "reason": "flip"}, p)
    store.log_event("gate", "failed", "gate_run", "HIGH", {"pr": "PR #1", "files": 2, "real": 2, "blocking": 2}, p)
    store.log_event("gate", "passed", "gate_run", "LOW", {"pr": "PR #3", "files": 1, "real": 0}, p)
    return p


def test_metrics(db):
    m = data.metrics(data.load_events(db))
    assert m == {"blocked_actions": 2, "warnings": 1, "secrets_caught": 2, "pii_caught": 1,
                 "prs_checked": 2, "prs_failed": 1, "manipulation_alerts": 1}


def test_categorise():
    assert data.categorise("aws_access_key", {}) == "secret"
    assert data.categorise("pipe_to_shell", {}) == "command"
    assert data.categorise("email", {}) == "pii"
    assert data.categorise("x", {"category": "vuln"}) == "vulnerability"


def test_by_rule_and_over_time(db):
    df = data.load_events(db)
    r = data.by_rule(df)
    assert "gate_run" not in set(r["rule"]) and r["count"].sum() == 7
    series, unit = data.over_time(df)
    assert unit == "hour" and set(series["part"]) == {"Live Guard", "Merge Gate"}
    assert series["count"].sum() == 7


def test_pr_runs(db):
    runs = data.pr_runs(data.load_events(db))
    assert sorted(runs["result"]) == ["failed", "passed"]


def test_missing_db_is_empty(tmp_path):
    df = data.load_events(tmp_path / "nope.db")
    assert df.empty and data.metrics(df)["prs_checked"] == 0


@pytest.mark.parametrize("use_data", [True, False])
def test_app_renders_without_errors(db, tmp_path, monkeypatch, use_data):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setattr("core.config.DB_PATH", db if use_data else tmp_path / "empty.db")
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception, at.exception
    labels = [m.label for m in at.metric]
    assert labels == ["Blocked AI actions", "Secrets caught", "Personal data caught", "PRs failed",
                      "Manipulation alerts"]
    if use_data:
        assert [m.value for m in at.metric] == ["2", "2", "1", "1 / 2", "1"]


def test_demo_log_is_labelled_and_safe(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    from core.detectors import pii, secrets
    from dashboard.seed_demo import seed
    demo = seed(tmp_path / "demo.db")
    import sqlite3
    assert sqlite3.connect(demo).execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    demo.chmod(0o444)  # like the root-owned file inside the container
    df = data.load_events(demo)
    assert len(df) > 20 and df["detail_obj"].map(lambda d: d.get("demo")).all()
    blob = " ".join(df["detail"])
    assert not secrets.scan(blob) and not [f for f in pii.scan(blob) if f.severity == "HIGH"]
    monkeypatch.setattr("core.config.DB_PATH", tmp_path / "missing.db")
    monkeypatch.setenv("AGENTSENTINEL_DEMO_DB", str(demo))
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception and any("Demo data" in w.value for w in at.warning)
