---
description: Build phase N end-to-end using the full phase protocol (plan → tests first → build → review → fix → verify → human gate → commit).
argument-hint: <N>  e.g. /build-phase 4
---

Build **phase $1** of AgentSentinel. If `$1` is empty, ask which phase. Look it up in `docs/PHASES.md` and read the matching section of `docs/SPEC.md`.

Follow the phase protocol in `CLAUDE.md §5` exactly, in order:

1. **Plan** — read the spec for phase $1; list the units of work and acceptance checks. Log any SPEC-GAPs now (conservative defaults). Confirm which existing modules this phase covers.
2. **Tests first** — launch `qa-engineer` to write **failing** tests that encode every acceptance check (positive, negative, fuzz, perf where relevant). No production code yet. Confirm they fail for the right reason.
3. **Build** — launch the right builder(s) for phase $1 (see the Lead column in `docs/PHASES.md`): `backend-engineer`, `data-engineer`, `frontend-engineer`, and/or `devops-engineer`. Implement until the new tests pass. **Run only the affected tests** in this loop.
4. **Review (parallel)** — launch `security-reviewer` + `code-reviewer` together (add `ux-reviewer` if the dashboard or user-facing output changed). Read-only.
5. **Fix** — builders address must-fix findings; re-run only the affected tests. Loop until clean.
6. **Verify** — launch `verifier`: it re-derives acceptance from the spec and runs the **full** `pytest -m "not llm"` suite once. Must return VERIFIED.
7. **Human gate** — present: what was built, DoD checklist (`CLAUDE.md §7`), full-suite result, open SPEC-GAPs (batched), and anything on the human-gate list. **Stop and wait for approval.**
8. **Commit (after approval only)** — `git add <paths>` then `git commit -m "<type: summary>"`, then `git tag p0$1-verified` (zero-pad to two digits). No push, no co-author lines.

Speed: independent agents run in parallel; fix loops run only affected tests; the full suite runs once at verify; collect SPEC-GAPs for the gate. If blocked for the spec, log a SPEC-GAP and take the safe default — never guess.
