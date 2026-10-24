import json

from core import store


def test_log_and_read(tmp_path):
    db = tmp_path / "t.db"
    store.log_event("claude_code", "blocked", "protected_file", "CRITICAL",
                    {"tool": "Read", "preview": ".env"}, db_path=db)
    store.log_event("gate", "failed", "sqli", "HIGH", "plain text", db_path=db)
    rows = store.recent_events(db_path=db)
    assert [r["rule"] for r in rows] == ["sqli", "protected_file"]  # newest first
    assert json.loads(rows[1]["detail"])["tool"] == "Read"
    assert rows[0]["time"].endswith("+00:00")
