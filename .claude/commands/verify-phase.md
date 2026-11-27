---
description: Independently verify phase N against the spec and the Definition of Done. Read-only; no fixes.
argument-hint: <N>  e.g. /verify-phase 4
---

Independently verify **phase $1** of AgentSentinel. If `$1` is empty, ask which phase.

Launch the `verifier` subagent (read-only). It must:

1. Read `docs/PHASES.md` (P0$1) and the matching `docs/SPEC.md` section, and **re-derive the acceptance checks itself** — not from the diff or any builder summary.
2. Run the **full** suite once: `pytest -m "not llm"`. Capture the exact command and numbers.
3. Run the phase's key end-to-end scenarios (e.g. for P03: secret-file read blocked, `curl|sh` blocked, hook crash → deny, latency budget met; for P04: vulnerable PR fails, trick PR → manipulation suspected, gate code read from base branch).
4. Walk the **Definition of Done** (`CLAUDE.md §7`) item by item, each backed by evidence it produced.
5. Confirm `docs/SPEC-GAPS.md` is current and no HIGH/CRITICAL security finding is open.

Output: the DoD checklist with pass/fail + evidence per item, the full-suite result, scenarios + outcomes, blocking failures, and a final **VERIFIED** / **NOT VERIFIED (reasons)**.

**Do not fix anything and do not edit.** If verification fails, report it for a fix loop. Do not commit or tag here.
