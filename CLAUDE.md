# AgentSentinel — Project Constitution

> This file governs **how** AgentSentinel is built. Agents and humans both follow it.
> When any instruction here conflicts with a prompt, **this file and the spec win** — stop and log a SPEC-GAP.

## 1. Project summary

AgentSentinel is a security layer for AI coding tools. It has two enforcement surfaces and three support surfaces:

- **Live Guard** — Claude Code / Cursor hooks (+ an advisory MCP server) that check every AI action **before** it happens and clean tool output **after**. Rules only, no network, **fails closed**.
- **Merge Gate** — a GitHub Action / local CLI that reviews a pull request with taint analysis + Semgrep + Gitleaks + rules, then a tool-less Claude review and a **two-view** manipulation check.
- **Support:** SQLite activity log, a read-only local Streamlit dashboard, and a benchmark + real-world evaluation harness.

Design non-negotiables: **fail closed**, **never send real secrets to the model**, **rules-only on the laptop**, **the model runs with no tools and no files**, **the dashboard is local-only**.

## 2. Sources of truth (priority order)

Resolve every question in this order. If a lower source contradicts a higher one, the higher wins and you log a SPEC-GAP.

1. **`docs/SPEC.md`** — the authoritative behavioral spec (created in Phase 0).
2. **`THREAT_MODEL.md`** — what is protected, trust boundaries, residual risks. Authoritative for security behavior.
3. **`docs/adr/`** — Architecture Decision Records (one decision each, immutable once accepted).
4. **This `CLAUDE.md`** — process and guardrails.
5. **The code and tests** — reality of what exists. Code is evidence, not a spec: if code disagrees with 1–3, the code is a bug or a SPEC-GAP, not the new truth.

README.md and NOTES.md are **narrative** (for humans); they are not a source of truth. If they drift, fix them to match 1–3.

## 3. Tech stack (v1.0 — do not change without an ADR + human gate)

| Area | Choice |
|---|---|
| Language / runtime | **Python 3.11**, standard-library-first (guard & gate use no third-party deps at runtime) |
| LLM backend | Claude Code headless (`claude -p`, `--tools "" --strict-mcp-config`); **Ollama** documented fallback. No API key assumed. |
| Static analysis | In-house **taint analysis** (`core/reviewer/taint.py`) + **Semgrep** (`p/owasp-top-ten`) + **Gitleaks** (pinned versions) |
| Storage | **SQLite** (WAL), additive-only schema with `schema_version` |
| Dashboard | **Streamlit + pandas**, read-only, bound to `127.0.0.1` |
| Integrations | Claude Code hooks, Cursor hooks, **MCP** server (`mcp>=2.3,<3`, runs on 1.x too) |
| Tests | **pytest**; `-m "not llm"` by default; live tests opt-in with `--run-llm` |
| Packaging / CI | **Docker** (`python:3.11-slim`, dashboard only), **GitHub Actions** |

## 4. Team (subagents)

Launch the right specialist for the work. Builders may edit; **reviewers and the verifier are read-only**.

| Role | Agent | Model | Edits code? | Mandate |
|---|---|---|---|---|
| Architect | `architect` | sonnet | yes (docs/scaffold) | ADRs, data model, contracts, repo scaffold, CI skeleton |
| Backend engineer | `backend-engineer` | sonnet | yes | heuristics, reviewer, llm, store, log, config, guard, gate |
| Frontend engineer | `frontend-engineer` | sonnet | yes (dashboard only) | Streamlit dashboard + its data layer |
| Data engineer | `data-engineer` | sonnet | yes | store schema, benchmark, datasets, eval metrics |
| DevOps engineer | `devops-engineer` | sonnet | yes | Docker, GitHub Action, CI, packaging, pinning |
| QA engineer | `qa-engineer` | **opus** | yes (tests only) | tests **first**, fuzz, perf budget, benchmark validation |
| Security reviewer | `security-reviewer` | **opus** | no | adversarial / red-team review against THREAT_MODEL |
| Code reviewer | `code-reviewer` | **opus** | no | correctness, quality, simplification review |
| UX reviewer | `ux-reviewer` | **opus** | no | dashboard usability & accessibility (read-only) |
| Verifier | `verifier` | **opus** | no | independent, from-scratch verification at the gate |

Run **independent** agents in parallel (e.g. security + code + ux review of the same diff at once).

## 5. Phase protocol (every phase, in order)

```
plan  →  tests first  →  build  →  code + security review  →  fix  →  independent verify  →  human gate  →  commit
```

1. **Plan** — read the spec for this phase; list the units of work and the acceptance checks. Log SPEC-GAPs now.
2. **Tests first** — `qa-engineer` writes failing tests that encode the acceptance checks. No production code yet.
3. **Build** — the relevant builder(s) implement until the new tests pass. Only the affected tests run in this loop.
4. **Review** — `security-reviewer` + `code-reviewer` (+ `ux-reviewer` for dashboard) review the diff **in parallel**, read-only.
5. **Fix** — builders address findings; re-run only the affected tests.
6. **Independent verify** — `verifier` re-derives the acceptance checks from the spec (not from the diff) and runs the **full** suite once.
7. **Human gate** — present the phase summary, the SPEC-GAP list, and anything on the human-gate list. **Wait for approval.**
8. **Commit** — commit with a plain summary, then `git tag pNN-verified`.

Phase roadmap: see **`docs/PHASES.md`** (P00–P08). Phases are capabilities, never days.

## 6. Anti-hallucination rule (hard rule)

> **If it is not in a source of truth, do not invent it. Log a SPEC-GAP and pick the most conservative, safe-by-default behavior — or stop and ask at the gate.**

- A SPEC-GAP is one row appended to **`docs/SPEC-GAPS.md`**: `ID | phase | question | conservative default taken | status`.
- Never guess an interface, a threshold, a host allow-list entry, a severity, or a security decision. Security-relevant gaps **default to deny / block / redact**.
- Collect SPEC-GAPs as you go; **resolve them in a batch at the human gate**, not one interruption at a time.

## 7. Definition of Done (a phase is done only when ALL hold)

- [ ] Every spec item for the phase is implemented and traceable to a test.
- [ ] Tests were written **first** and now pass; the **full** suite (`-m "not llm"`) is green.
- [ ] Security review: **no HIGH/CRITICAL** self-findings against THREAT_MODEL; residual risks are documented as known-gap tests.
- [ ] Code review: no correctness findings open; dead code / duplication cleaned.
- [ ] Performance budget met (Live Guard latency test passes).
- [ ] `verifier` independently reproduced the acceptance checks.
- [ ] Docs updated (SPEC.md, relevant ADRs, README/NOTES narrative, THREAT_MODEL if boundaries moved).
- [ ] All SPEC-GAPs for the phase are logged and dispositioned.
- [ ] Human gate approved.
- [ ] Committed and tagged `pNN-verified`.

## 8. Git rules

- Commit with a **plain** message: `git add <paths>` then `git commit -m "<type: short summary>"` (types: `feat, fix, test, docs, perf, refactor, chore, build`).
- After the human gate, tag the phase: `git tag pNN-verified` (e.g. `p04-verified`).
- **No** co-author lines, `Co-Authored-By`, `Generated-with`, trailers, or signatures. (`includeCoAuthoredBy` is off in settings.)
- **Never** run: `git push`, `git remote …`, `git rebase`, `git reset --hard`, `git commit --amend`, `git filter-branch`. These are denied in settings; if one is truly needed, that is a **human gate** — hand the human the exact command.
- Keep commits phase-scoped and buildable. One logical change per commit where practical.

## 9. Human gates (stop and get explicit approval)

Never do these autonomously — present the command/plan and wait:

- Changing **settings** (`.claude/`, hook registration, `settings.json`), or anything that alters permissions.
- **Paid or external services**, publishing, hosting, or any network push (incl. `git push`, deploys, HF Spaces).
- **Production / real-data** actions, GitHub secrets, or editing the GitHub Action that judges PRs.
- **Deleting or overwriting data** (the SQLite DB, benchmark results, user files), or any destructive DB migration.
- Running **live LLM tests** (`--run-llm`) — they consume the Pro limit.
- **Licence** changes, redistributing third-party / GPL datasets, or anything with legal weight.

## 10. Speed rules

- **Fix loops:** run only the tests for the file(s) you touched. Run the **full** suite **once per phase** (at verify).
- **Parallelism:** independent agents run concurrently (reviews, independent reads). Don't serialize work that has no dependency.
- **Batch interruptions:** accumulate SPEC-GAPs and questions; raise them together at the human gate.
- **No LLM in hot loops:** the Live Guard and all unit tests are rules-only. Keep LLM calls batched and out of inner loops.
- Prefer the dedicated file/search tools over shell; prefer reading the smallest relevant slice.

## 11. Reference docs

`docs/SPEC.md` · `docs/PHASES.md` · `docs/SPEC-GAPS.md` · `docs/adr/` · `THREAT_MODEL.md` · `redteam/README.md`
