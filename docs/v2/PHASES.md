# AgentSentinel v2 — phase roadmap (V0–V4)

Single-owner GitHub App, subscription-only (ADR-0009/0010/0011). Same phase protocol as v1
(`CLAUDE.md §5`): plan → tests first → build → review → fix → verify → human gate → commit.
The engine is **not** touched — v2 is a delivery layer; the 878-test suite guards the engine.

| Phase | Name | Delivers | Key acceptance | Gates |
|---|---|---|---|---|
| **V0** | Architecture | This doc + ADR-0009..0011; webhook/job/Check-Run contracts; backend scaffold choice; threat-model extension | Contracts written; ToS + hosting decisions resolved | **SG-018 (ToS)** and SG-017 (hosting) must be answered before V1 |
| **V1** | Webhook + gate | Webhook receiver (HMAC-verified) → enqueue → run the **unchanged** `gate.run()` on the PR head → log to the existing store | A signed PR event runs the real gate; forged/unsigned events rejected; fails closed on any error | reuses `gate.run()`, `core/store.py` |
| **V2** | GitHub feedback | Post a Check Run (pass/fail) + PR comment via the App install token | Vulnerable PR → failing Check + comment; safe PR → passing Check | reuses `report.build_markdown` |
| **V3** | Install & config | App registration, per-install token handling, one owner config (repos, `FAIL_ON_SEVERITIES`, `REVIEW_ENSEMBLE`) | Install on a repo with no workflow file → it's protected | no multi-tenant schema |
| **V4** | Dashboard tie-in | The existing Streamlit dashboard shows App runs from the shared store | App runs appear in the dashboard; still local-only (INV-7) | reuses the v1 dashboard |

## Delivery decided (SG-017 / SG-018 resolved)

The owner chose **Actions-only hosting** + **Ollama/manual LLM**. That selects the **existing GitHub
Action** as the delivery (no always-on backend), with the gate running **static-only** in CI and the
LLM two-view as a **manual local run** (Option A — see `docs/v2/V3-REPORT.md`). Consequently:
- **V1 (webhook backend) and V2 (GitHub poster) are parked** — committed and tested, but not the
  active path; they're the ready option if a central self-hosted App is ever wanted.
- **V3 = configure the Action** (done): static-only, no Claude token in CI, trimmed setup.
- **V4 (dashboard tie-in)** still applies: the CI gate's runs already log to the store the dashboard
  reads.

## Guardrails (do not drift)
- **Subscription/Ollama only — no paid API, no billing** (ADR-0010). If a feature needs paid/managed
  LLM, it's a different product (SG-019), not this roadmap.
- **Engine unchanged.** v2 adds delivery; any engine change goes through the v1 phases + its suite.
- **Hosting is the owner's own backend only** — not public demo hosting (SG-008 still holds for demos).
- **ToS gate (SG-018) is blocking for V1.** If subscription-in-an-App isn't permitted, V1 runs on
  free local Ollama instead; the architecture is otherwise unchanged.

## Out of scope (explicitly)
Multi-tenancy, teams, billing, public hosting, Java/Spring rewrite — all require a new decision and a
different LLM/business model (ADR-0010, SG-019).
