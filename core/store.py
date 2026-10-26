"""SQLite activity log (A6). The dashboard reads this table.

Only masked previews are ever stored in `detail`, so the log never becomes a
copy of the secrets it caught. The schema is set up once per database per process.

Connections are reused (one per thread, at most MAX_CACHED databases) because a
long-running process like the MCP server logs on every tool call: a fresh connection
cost ~0.74 ms per write, a reused one ~0.07 ms. Reuse is made safe by:
- one connection per THREAD (SQLite connections must not be shared across threads)
- checking the file is still the same file on every use: if the database was deleted or
  replaced, a cached connection would keep writing into the deleted file and lose the log
- dropping the connection on any SQLite error (the next use reconnects)
- closing everything at exit; close_all() for tests (Windows can't delete an open file)
"""

import atexit
import json
import os
import sqlite3
import threading
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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


DbPath = Path | str | None  # None = config.DB_PATH


def _path(db_path: DbPath) -> Path:
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


def _schema_ready(db_path: DbPath) -> bool:
    return str(_path(db_path).resolve()) in _READY


def connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    """A ready-to-use connection. The caller must close it (prefer `session()`)."""
    path = _path(db_path)
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn, path)
    return conn


MAX_CACHED = 4  # databases kept open per thread (normally 1)
_LOCAL = threading.local()  # a thread's cache (and its connections) is freed when the thread ends


def _file_id(path: Path) -> tuple[int, int]:
    st = os.stat(path)
    return st.st_dev, st.st_ino


def _cache() -> "OrderedDict[str, tuple[sqlite3.Connection, tuple[int, int]]]":
    cache = getattr(_LOCAL, "conns", None)
    if cache is None:
        cache = _LOCAL.conns = OrderedDict()
    return cache


def _drop(cache: "OrderedDict[str, tuple[sqlite3.Connection, tuple[int, int]]]", key: str) -> None:
    entry = cache.pop(key, None)
    if entry is not None:
        entry[0].close()


def _cached(db_path: DbPath) -> tuple[str, sqlite3.Connection]:
    path = _path(db_path)
    key = str(path.resolve())
    cache = _cache()
    entry = cache.get(key)
    if entry is not None:
        try:
            same = _file_id(path) == entry[1]
        except OSError:  # deleted
            same = False
        if same:
            cache.move_to_end(key)
            return key, entry[0]
        _drop(cache, key)  # replaced or deleted: never write into the old file
    conn = connect(path)
    cache[key] = (conn, _file_id(path))
    while len(cache) > MAX_CACHED:
        _drop(cache, next(iter(cache)))
    return key, conn


def close_all() -> None:
    """Close this thread's cached connections. Used at exit and by tests."""
    cache = _cache()
    for key in list(cache):
        _drop(cache, key)


atexit.register(close_all)


@contextmanager
def session(db_path: DbPath = None) -> Iterator[sqlite3.Connection]:
    """A reused connection for this thread: commit on success, roll back on error.
    On any SQLite error the connection is dropped, so the next use starts clean."""
    key, conn = _cached(db_path)
    try:
        with conn:
            yield conn
    except sqlite3.Error:
        _drop(_cache(), key)
        raise


def _row(source: str, action: str, rule: str, severity: str, detail: Any) -> tuple[str, ...]:
    if isinstance(detail, dict):
        detail = json.dumps(detail, ensure_ascii=False)
    if detail is not None:  # lone surrogates cannot be stored as UTF-8: keep them as escapes
        detail = str(detail).encode("utf-8", "backslashreplace").decode("utf-8")
    return (datetime.now(UTC).isoformat(timespec="seconds"), source, action, rule, severity, detail)


def log_events(rows: list[tuple[str, str, str, str, Any]], db_path: DbPath = None) -> None:
    """Write many events through ONE connection: rows of (source, action, rule, severity, detail)."""
    if not rows:
        return
    with session(db_path) as conn:
        conn.executemany(
            "INSERT INTO events (time, source, action, rule, severity, detail) VALUES (?,?,?,?,?,?)",
            [_row(*r) for r in rows],
        )


def log_event(
    source: str,
    action: str,
    rule: str,
    severity: str,
    detail: dict[str, Any] | str | None = None,
    db_path: DbPath = None,
) -> None:
    log_events([(source, action, rule, severity, detail)], db_path)


def recent_events(limit: int = 200, db_path: DbPath = None) -> list[dict[str, Any]]:
    with session(db_path) as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
