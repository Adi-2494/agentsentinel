# ADR-NNNN: <short decision title>

- **Status:** proposed | accepted | superseded by ADR-XXXX
- **Date:** YYYY-MM-DD
- **Phase:** P0N
- **Deciders:** <roles / humans>

## Context
What forces this decision? What constraint, threat, or requirement from the spec / THREAT_MODEL?

## Decision
The single choice made, stated plainly.

## Consequences
- Positive: …
- Negative / cost: …
- Residual risk (link the known-gap test if security-relevant): …

## Alternatives considered
- **Option A** — why not.
- **Option B** — why not.

---
*ADRs are immutable once accepted. To change a decision, write a new ADR that supersedes this one.*

## Back-fill backlog (retroactive ADRs to write in P00)
1. Fail-closed on hook/gate errors (opt-out env var only)
2. Model runs with no tools / no files; secrets redacted before any call
3. Two-view manipulation check (severity-compared, not verdict-word)
4. In-house taint analysis alongside Semgrep (why not Semgrep-only)
5. Rules-only Live Guard (no LLM on the laptop)
6. SQLite + WAL for the activity log (vs a server DB)
7. No third-party hosting for the dashboard (local-only)
8. `core/heuristics` naming (heuristics, not "detectors" — honest about regex limits)
