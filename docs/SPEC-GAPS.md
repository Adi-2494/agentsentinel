# SPEC-GAP log

Every gap between a prompt and a source of truth lands here — one row, never a silent guess
(`CLAUDE.md §6`). Security-relevant gaps default to **deny / block / redact**.

Format: `ID | phase | question | conservative default taken | status (open / resolved / accepted)`

| ID | Phase | Question | Conservative default | Status |
|---|---|---|---|---|
| SG-001 | P00 | Build from scratch or harden existing ~6k LOC? | Harden existing to v1.0; code = reference impl, not greenfield | accepted |
| SG-002 | P00 | No single spec file | Wrote `docs/SPEC.md` from THREAT_MODEL + README | resolved |
| SG-003 | P00 | No ADRs for decisions already made | Back-filled ADR-0001..0008 in `docs/adr/` | resolved |
| SG-004 | P00 | Phase naming (Day labels forbidden) | Capability phases P00–P08 | accepted |
| SG-005 | P00 | Java/Spring rewrite + SaaS in scope? | v1: out of scope. **v2: reopened** — owner chose to **wrap** the Python engine, not rewrite (ADR-0009); SaaS still out (single-owner, ADR-0010) | updated |
| SG-006 | P00 | Licence undecided | Keep current LICENSE; change is a human gate | accepted |
| SG-007 | P02 | LLM backend / ToS for Pro in CI | `claude_code` default, Ollama fallback; never assume an API key | accepted |
| SG-008 | P06 | Hosting (HF Spaces vs none) | No third-party hosting; local Docker + screenshots | accepted |
| SG-009 | P07 | Live/LLM tests cost Pro limit | Automated runs `-m "not llm"`; `--run-llm` is opt-in + human-gated | accepted |
| SG-010 | P02 | SQLite migration strategy | Additive-only + `schema_version`; destructive migration = human gate | accepted |
| SG-011 | all | Quality bar unquantified | ≥85% line coverage on `core/`, zero self-HIGH/CRITICAL, perf budget in CI | accepted |
| SG-012 | P04 | CI needs Claude Code + pinned scanners | Pin all tool versions; keep `--no-llm` static fallback | accepted |
| SG-013 | P06 | Full frontend/ux roles vs tiny Streamlit UI | Scope frontend + ux-reviewer to the dashboard only | accepted |
| SG-014 | P07 | External GPL/SecurityEval datasets | Pin commit; keep GPL data out of repo, fetch at runtime; redistribution = human gate | accepted |
| SG-015 | P04 | Fork PRs can't use the token | Intended (static-only on forks); document, don't expose the secret | accepted |
| SG-016 | P03 | Post-tool cleaning rewrites only Bash output; non-Bash tools (WebFetch, MCP) get a warning but raw output | Warn-only for non-Bash (current, tested: `test_post_tool_warns_without_rewriting_other_tools`). Redacting needs Claude Code's per-tool `updatedToolOutput` contract — don't guess it. Revisit if/when that contract is confirmed. | accepted |
| SG-017 | v2/V0 | Where the v2 webhook backend runs | **Resolved: Actions-only** (ADR-0011 fallback) — $0, no server, the gate runs in GitHub Actions. The always-on webhook backend (`app/server.py`, `handle()` HTTP path) is **deferred** (kept for a future self-hosted option). | resolved |
| SG-018 | v2/V0 | Is a personal Claude subscription allowed to power an always-on GitHub App? | **Resolved: use free local Ollama** for the automated/CI path (avoids the personal-subscription-in-automation gray area). The Claude subscription is for manual/interactive runs only. No paid API. | resolved |
| SG-019 | v2 | Serving other users/teams (multi-tenant) | Out of scope — needs paid/managed or BYO-key LLM, which the owner forbade. A different product; requires a new decision. | accepted |
