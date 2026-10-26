"""The activity log reuses one connection per thread, safely (core/store.py)."""

import os
import sqlite3
import sys
import threading

import pytest

from core import store


def _count_connects(monkeypatch) -> list[int]:
    opened: list[int] = []
    real = store.sqlite3.connect
    monkeypatch.setattr(store.sqlite3, "connect", lambda *a, **k: opened.append(1) or real(*a, **k))
    return opened


def test_many_writes_share_one_connection(tmp_path, monkeypatch):
    opened = _count_connects(monkeypatch)
    for i in range(100):
        store.log_event("mcp", "warned", "r", "LOW", {"i": i}, db_path=tmp_path / "a.db")
    assert len(opened) == 1 and len(store.recent_events(limit=500, db_path=tmp_path / "a.db")) == 100


@pytest.mark.skipif(sys.platform == "win32", reason="Windows can't replace a file that is open")
def test_replaced_database_is_not_written_into_the_old_file(tmp_path):
    db = tmp_path / "a.db"
    store.log_event("mcp", "warned", "first", "LOW", db_path=db)
    with store.session(db) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # everything in the main file, not the WAL
    os.link(db, tmp_path / "old.db")  # keep a handle on the ORIGINAL file
    other = tmp_path / "b.db"
    sqlite3.connect(other).close()
    os.replace(other, db)  # e.g. a log reset swaps in a new file
    store._READY.clear()
    store.log_event("mcp", "warned", "second", "LOW", db_path=db)
    store.close_all()
    new = [r[0] for r in sqlite3.connect(db).execute("SELECT rule FROM events")]
    old = [r[0] for r in sqlite3.connect(tmp_path / "old.db").execute("SELECT rule FROM events")]
    assert new == ["second"] and old == ["first"]  # not written into the replaced file


@pytest.mark.skipif(sys.platform == "win32", reason="Windows can't delete a file that is open")
def test_deleted_database_is_recreated(tmp_path):
    db = tmp_path / "a.db"
    store.log_event("mcp", "warned", "first", "LOW", db_path=db)
    for suffix in ("", "-wal", "-shm"):
        p = tmp_path / f"a.db{suffix}"
        if p.exists():
            p.unlink()
    store._READY.clear()  # the new file needs its schema again
    store.log_event("mcp", "warned", "second", "LOW", db_path=db)
    assert [e["rule"] for e in store.recent_events(db_path=db)] == ["second"]


def test_threads_get_their_own_connection(tmp_path):
    db = tmp_path / "t.db"
    store.log_event("mcp", "warned", "init", "LOW", db_path=db)
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            for i in range(50):
                store.log_event("mcp", "warned", f"t{n}", "LOW", {"i": i}, db_path=db)
        except BaseException as e:
            errors.append(e)
        finally:
            store.close_all()

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(store.recent_events(limit=1000, db_path=db)) == 401


def test_an_sqlite_error_drops_the_connection(tmp_path, monkeypatch):
    db = tmp_path / "e.db"
    store.log_event("mcp", "warned", "ok", "LOW", db_path=db)
    opened = _count_connects(monkeypatch)
    with pytest.raises(sqlite3.OperationalError), store.session(db) as conn:
        conn.execute("SELECT * FROM no_such_table")
    store.log_event("mcp", "warned", "after", "LOW", db_path=db)
    assert len(opened) == 1  # reconnected once after the error
    assert [e["rule"] for e in store.recent_events(db_path=db)] == ["after", "ok"]


def test_a_failed_write_is_rolled_back(tmp_path):
    db = tmp_path / "r.db"
    store.log_event("mcp", "warned", "ok", "LOW", db_path=db)
    with pytest.raises(RuntimeError), store.session(db) as conn:
        conn.execute(
            "INSERT INTO events (time, source, action, rule, severity, detail) VALUES (?,?,?,?,?,?)",
            store._row("mcp", "warned", "half", "LOW", None),
        )
        raise RuntimeError("crash mid-write")
    assert [e["rule"] for e in store.recent_events(db_path=db)] == ["ok"]


def test_cache_is_bounded(tmp_path):
    for i in range(store.MAX_CACHED + 3):
        store.log_event("mcp", "warned", "r", "LOW", db_path=tmp_path / f"{i}.db")
    assert len(store._cache()) == store.MAX_CACHED


def test_close_all_closes(tmp_path):
    store.log_event("mcp", "warned", "r", "LOW", db_path=tmp_path / "c.db")
    (conn, _) = next(iter(store._cache().values()))
    store.close_all()
    assert not store._cache()
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")
