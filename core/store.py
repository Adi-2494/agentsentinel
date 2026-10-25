"""SQLite activity log (A6). The dashboard reads this table.

Only masked previews are ever stored in `detail`, so the log never becomes a
copy of the secrets it caught. Every connection is closed after use, and the
schema is set up once per database per process.
"""
import json
import sqlite3
from contextlib import contextmanager
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

_READY: set[str] = set()  # databases whose schema was already set up in this process


def _path(db_path) -> Path:
    path = Path(db_path or config.DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _ensure_schema(conn: sqlite3.Connection, path: Path) -> None:
    key = str(path.resolve())
    if key in _READY:
        return
    conn.execute("PRAGMA journal_mode=WAL")  # hook writes while dashboard reads (persists in the file)
    conn.executescript(SCHEMA)
    _READY.add(key)


def _schema_ready(db_path) -> bool:
    return str(_path(db_path).resolve()) in _READY


def connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    """A ready-to-use connection. The caller must close it (prefer `session()`)."""
    path = _path(db_path)
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn, path)
    return conn


@contextmanager
def session(db_path=None):
    """Open, commit on success, and always close (sqlite3's own `with` does not close)."""
    conn = connect(db_path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _row(source, action, rule, severity, detail):
    if isinstance(detail, dict):
        detail = json.dumps(detail, ensure_ascii=False)
    if detail is not None:  # lone surrogates cannot be stored as UTF-8: keep them as escapes
        detail = str(detail).encode("utf-8", "backslashreplace").decode("utf-8")
    return (datetime.now(timezone.utc).isoformat(timespec="seconds"), source, action, rule, severity, detail)


def log_events(rows: list[tuple], db_path=None) -> None:
    """Write many events through ONE connection: rows of (source, action, rule, severity, detail)."""
    if not rows:
        return
    with session(db_path) as conn:
        conn.executemany(
            "INSERT INTO events (time, source, action, rule, severity, detail) VALUES (?,?,?,?,?,?)",
            [_row(*r) for r in rows])


def log_event(source: str, action: str, rule: str, severity: str,
              detail: dict | str | None = None, db_path=None) -> None:
    log_events([(source, action, rule, severity, detail)], db_path)


def recent_events(limit: int = 200, db_path=None) -> list[dict]:
    with session(db_path) as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
