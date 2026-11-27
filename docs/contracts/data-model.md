# Contract: data model — SQLite activity log (stable, additive-only)

Source: `core/store.py`. Destructive migration is a human gate (SG-010).

## Schema
```sql
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    time     TEXT NOT NULL,   -- ISO-8601 UTC, seconds
    source   TEXT NOT NULL,   -- claude_code | cursor | mcp | gate | benchmark
    action   TEXT NOT NULL,   -- blocked | warned | allowed | failed | passed
    rule     TEXT NOT NULL,
    severity TEXT NOT NULL,   -- LOW | MEDIUM | HIGH | CRITICAL
    detail   TEXT             -- JSON: tool, masked preview, message, category, cwd, ...
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(time);
```

## Rules
- **Additive-only.** New columns must be nullable / defaulted; never drop or repurpose a column. Introduce a `schema_version` row (meta table or `PRAGMA user_version`) before the first migration; bump on every additive change.
- **WAL mode**, so the hook writes while the dashboard reads. Do not ship a demo DB still in WAL (unreadable on a read-only FS) — checkpoint first.
- `detail` holds **masked previews only** (INV-6). Lone surrogates are stored as `backslashreplace` escapes (valid UTF-8).
- Connections: one per thread, reused, file-identity re-checked each use; dropped on any `sqlite3.Error`; closed at exit (`close_all()` for tests).
- **Multi-process safety:** every hook call is its own process, so many processes set up and write the same DB concurrently. Each connection sets `PRAGMA busy_timeout=5000` so writes wait instead of crashing; `PRAGMA journal_mode=WAL` (which ignores busy_timeout under contention) is retried. A write must never crash a legitimate action. Covered by `test_many_processes_write_without_loss_or_crash` (integration).

## Public API (stable)
```python
log_event(source, action, rule, severity, detail=None, db_path=None)
log_events(rows, db_path=None)          # batch: rows of (source, action, rule, severity, detail)
recent_events(limit=200, db_path=None) -> list[dict]
session(db_path=None)                    # context manager: reused conn, commit/rollback
```
