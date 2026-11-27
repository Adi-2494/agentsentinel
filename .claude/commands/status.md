---
description: Report project status — phase progress, tests, open SPEC-GAPs, uncommitted changes, human-gate items. Read-only.
argument-hint: (no args)
---

Report AgentSentinel status. **Read-only** — do not change anything. Keep it tight and factual.

Gather and present:

1. **Phase progress** — from `docs/PHASES.md` and git tags (`git tag --list 'p*-verified'`): which phases are verified, which is in progress.
2. **Tests** — run `pytest -m "not llm" -q` and report the pass/fail counts (do not run `--run-llm`; that's human-gated).
3. **Open SPEC-GAPs** — the `open` rows in `docs/SPEC-GAPS.md`.
4. **Uncommitted work** — `git status --short` and a one-line summary of what's changed.
5. **Last commits** — `git log --oneline -5`.
6. **Human-gate items pending** — anything from `CLAUDE.md §9` currently waiting (settings change, licence, deploy, destructive data op, live-LLM run).
7. **Known gaps / residual risks** — a pointer to the current count in `redteam/README.md` (caught vs documented-gap).

Output a short dashboard: `Phase: … | Tests: …/… | Open SPEC-GAPs: … | Uncommitted: … | Pending gates: …`, then the detail. Report only what you actually ran.
