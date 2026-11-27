# AgentSentinel — phase roadmap (P00–P08)

Phases are **capabilities**, not time boxes. No "Day N" labels anywhere.
Each phase follows the full phase protocol in `CLAUDE.md §5` and ends tagged `pNN-verified`.

| Phase | Name | Delivers | Lead(s) | Key acceptance |
|---|---|---|---|---|
| **P00** | Architecture | `docs/SPEC.md`, back-filled ADRs, data model (SQLite schema + `schema_version`), the contracts in `docs/contracts/`, repo scaffold, CI skeleton | architect | Spec + contracts exist; CI runs the empty suite green |
| **P01** | Heuristics engine | `core/heuristics/*` (secrets, pii, commands, files, injection, similarity, encoding) + the `Finding` model | backend, qa | Each detector has positive + negative tests; no crash on malformed/unicode input |
| **P02** | Platform services | `core/llm.py`, `core/store.py`, `core/config.py`, `core/log.py` — fail-closed, loud config validation, structured logging, one SQLite connection per thread | backend, data | Config errors fail loudly; store survives concurrent writers; LLM errors classified |
| **P03** | Live Guard | `guard/claude_hook.py` (pre + post), `guard/install.py` — deny/ask/allow, output cleaning, **fails closed** | backend, qa, security | Secret-file read, `curl\|sh`, written secret all blocked; hook crash → deny; latency budget met |
| **P04** | Merge Gate | `core/reviewer/*` (taint, static_scan, triage, two_view, injection_check, report) + `gate/run_gate.py` + GitHub Action | backend, devops, security | Vulnerable PR fails; trick PR → manipulation suspected; base-branch gate code; redaction before any LLM call |
| **P05** | Integrations | `guard/cursor_hook.py`, `guard/mcp_server.py` | backend | MCP tools answer; Cursor hook shares detectors; MCP is advisory, not a boundary |
| **P06** | Dashboard | `dashboard/*` (Streamlit, read-only, `127.0.0.1`) + Docker (dashboard only) | frontend, devops, ux | Renders events/PR results; no secrets shown; Docker page actually renders |
| **P07** | Evaluation | `benchmark/*` + real-world eval (GHSA, prompt-injections, OWASP, SecurityEval) + metrics | data, qa | Reproducible numbers (leak rate, precision/recall, false-block rate) with sample sizes |
| **P08** | Hardening | red-team registry, known-bypass tests, perf budget, LLM-degradation matrix, robustness/fuzz, THREAT_MODEL sync | security, qa | Caught cases stay caught; documented gaps are strict known-gap tests; threat model matches code |

## Verification status

Latest pass recorded in `docs/PHASE-REPORT.md`: **P00–P08 all verified** against non-LLM
scenarios + the full suite (now 875 passed, 14 xfailed). Hardening fixes found this pass:
**P01** enclosed-alphanumeric confusable folding; **P02** multi-process store data-loss/crash
(busy_timeout + WAL-pragma retry). **P03** deep pass found no new issues — the Live Guard is solid
(one intentional residual, SG-016). **P04** static/`--no-llm` pass: INV-2 (no secret to LLM) and
taint (7/7 TP, 0 FP) proven; added an explicit INV-5 regression test (judge the commit, not the
tree). Live-LLM confirmation of P04 (human-approved, SG-009) **done**: `trick_pr` and `vulnerable_pr` both
blocked (exit 1) against real Claude; triage/two-view/AI-trap confirmed working end-to-end.
**P05** verified clean — Cursor hook shares the core detectors and fails closed; MCP tools return the
correct contract shape. No code change. **P06** verified + hardened — INV-6 proven end-to-end (no raw
secret shown), read-only DB; fixed a reachable dashboard crash on a lone-surrogate log detail.
**P07** verified clean (offline) — metric math, fake-only data, redaction, reproducible results with
sample sizes all tested. Live benchmark execution (~180 LLM calls) human-gated, not run.
**P08** verified — strict known-gap xfails hold (fixed gaps fail loudly), threat model maps to the
registry; added I-11 (the closed confusable bypass) as a caught case. **Roadmap P00–P08 complete.**
Git tags `pNN-verified` are applied by the human after reviewing each phase (commits are not made
automatically this session).

## Notes
- The current repo already implements P01–P08 to a working degree. This roadmap governs **hardening to v1.0** and any rebuild — treat existing modules as the reference implementation, not greenfield (SPEC-GAP #1).
- Out of scope for this kit: the Java/Spring rewrite and the hosted GitHub-App SaaS (SPEC-GAP #5). Those are separate initiatives.
