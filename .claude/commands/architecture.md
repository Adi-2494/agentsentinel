---
description: Phase 0 — produce the spec, ADRs, data model, interface contracts, repo scaffold and CI skeleton. No application logic.
argument-hint: (no args)
---

Run **Phase 0 (Architecture)** for AgentSentinel. Design only — **do not write application/business logic**.

Follow `CLAUDE.md` and `docs/PHASES.md` (P00). Use the `architect` subagent for the authoring work.

Steps:
1. **Read the sources of truth**: `THREAT_MODEL.md`, `README.md`, `NOTES.md`, existing `core/`, `guard/`, `gate/` module layout. Treat existing code as the reference implementation (SG-001), not greenfield.
2. **Write `docs/SPEC.md`** — the single behavioral spec, back-filled from THREAT_MODEL (authoritative) + README. Cover: Live Guard, Merge Gate, MCP server, dashboard, benchmark. State invariants (fail-closed, no-secret-to-model, rules-only guard, base-branch gate, local-only dashboard).
3. **Back-fill ADRs** in `docs/adr/` from `ADR-0000-template.md`'s backlog (fail-closed, tool-less model, two-view, in-house taint, rules-only guard, SQLite+WAL, no hosting, heuristics naming). One decision per file.
4. **Data model** — document the SQLite schema and add a `schema_version` convention (additive-only; destructive migration = human gate, SG-010).
5. **Contracts** — write `docs/contracts/`: hook stdin/stdout JSON, the `Finding` dataclass, MCP tool signatures, the gate CLI, the GitHub Action interface. Mark each **stable** (breaking = human gate).
6. **Scaffold & CI** — confirm/define the repo structure and a CI skeleton that runs `pytest -m "not llm"` + lint + perf budget. Pin tool versions (SG-012).
7. **Log SPEC-GAPs** for anything unspecified; take conservative defaults.

**Do not commit.** End with: artifacts written, the contract list, new SPEC-GAP IDs, and the recommended build order (P01→P08). Present SPEC-GAPs for the human gate.
