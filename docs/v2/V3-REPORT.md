# v2 / V3 — delivery decided: static CI + manual LLM (Option A)

The two gates are resolved (SG-017 Actions-only, SG-018 Ollama/manual), which selects the simplest
delivery: the **existing GitHub Action** is the Actions-only path. No new backend.

## What changed
`.github/workflows/agentsentinel.yml` → the `merge-gate` job:
- **Static-only** on every PR: `run_gate.py --no-llm` (taint + Semgrep + Gitleaks + rules). ~2.9s of
  analysis; the job is otherwise scanner setup.
- **No Claude token in CI** (SG-018): removed `CLAUDE_CODE_OAUTH_TOKEN`, the Node setup, and the
  `npm install @anthropic-ai/claude-code` step.
- `timeout-minutes` 20 → 10.
- Still posts/edits the PR comment and enforces the decision (unchanged).

## How to run the LLM two-view / manipulation check (manual)
The deeper AI-reviewer-manipulation check is now a **local, on-demand** run with your subscription
(or free Ollama) — never in CI:

```
# with your Claude subscription (interactive / personal use):
python gate/run_gate.py --path <changed-dir-or-file> --pr-body-file PR.md

# or fully free / offline:
LLM_BACKEND=ollama python gate/run_gate.py --path <changed-dir-or-file>
```

Use it when a PR actually warrants the two-view check (e.g. persuasive comments/description). The
static gate already caught the structural bugs automatically in CI.

## The hosted path is parked (not deleted)
The `app/` webhook backend + GitHub poster (V1/V2) remain committed and tested, but are **not** the
active delivery under Actions-only. They're the ready-to-go option if you ever self-host a central
GitHub App (revive by: host `app.server`, set `WEBHOOK_SECRET` + `AGENTSENTINEL_REPOS`, point the
App's webhook at it). See `docs/v2/ARCHITECTURE.md` and ADR-0011.

## Verification
- `.github/workflows/agentsentinel.yml` parses as valid YAML; no `claude`/token/node refs remain in
  the gate job.
- Static gate measured: **~2.9s** on a sample PR; correctly blocks a vulnerable PR (`--no-llm`).
- No Python changed this phase → the 898-test suite is unaffected.

## Net result
Every PR gets fast, free, automatic **static** protection (taint ~78% recall) with the comment +
check you already had — and the LLM layer is a deliberate manual step on your subscription, keeping
you firmly inside personal-use and paying nothing.
