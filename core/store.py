"""SQLite activity log (A6). The dashboard reads this table.

Only masked previews are ever stored in `detail`, so the log never becomes a
copy of the secrets it caught.
"""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from core import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    time     TEXT NOT NULL,   -- ISO-8601 UTC
    source   TEXT NOT NULL,   -- claude_code | cursor | mcp | gate | benchmark
    action   TEXT NOT NULL,   -- blocked | warned | allowed | failed | passed
    rule     TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail   TEXT             -- JSON: tool, masked preview, message, ...
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(time);
"""


def connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    path = Path(db_path or config.DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # hook writes while dashboard reads
    conn.executescript(SCHEMA)
    return conn


def log_event(source: str, action: str, rule: str, severity: str,
              detail: dict | str | None = None, db_path=None) -> None:
    if isinstance(detail, dict):
        detail = json.dumps(detail, ensure_ascii=False)
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO events (time, source, action, rule, severity, detail) VALUES (?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             source, action, rule, severity, detail),
        )


def recent_events(limit: int = 200, db_path=None) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
