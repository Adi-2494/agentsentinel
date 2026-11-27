# ADR-0006: SQLite (WAL) for the activity log

- **Status:** accepted
- **Phase:** P00 (back-filled)
- **Deciders:** architect, data-engineer

## Context
The guard, gate, and MCP server all log events; the dashboard reads them concurrently. We need a local, zero-setup, embedded store that survives concurrent writers + a reader, and that a long-running process can write to cheaply.

## Decision
Use **SQLite in WAL mode**. One connection **reused per thread** (file-identity re-checked each use; dropped on any error; closed at exit). Store **masked previews only**. Schema is additive-only with a `schema_version` convention.

## Consequences
- Positive: no server to run; WAL lets the dashboard read while hooks write; reused connections cut per-write cost ~10× (0.74 ms → 0.07 ms).
- Negative: single-file store; concurrency bounded by SQLite. Fine for a laptop/CI tool. A shipped demo DB must be checkpointed out of WAL (else unreadable on a read-only FS).
- Residual risk: none security-relevant (INV-6 keeps secrets out of the log).

## Alternatives considered
- **A client/server DB (Postgres)** — rejected: setup cost, overkill for a local tool.
- **A flat JSON log** — rejected: no concurrent-read story, no indexing.
