# AgentSentinel v2 — architecture (single-owner GitHub App)

> **Design only.** No application code yet. Decisions are in `docs/adr/ADR-0009..0011`.
> v2 **wraps** the v1 Python engine unchanged; it does not rewrite it.

## 1. What v2 is (and is not)

**Is:** the v1 Merge Gate, delivered as **one installable GitHub App** on the owner's own
org/repos, so every repo is protected without a per-repo workflow file — powered by the owner's
**Claude subscription**.

**Is not:** a public multi-tenant SaaS. A personal Claude subscription is personal-use only
(Anthropic Consumer Terms), so v2 serves **one owner's** repos, not other people's PRs. This also
keeps the v1 trust model intact: only the owner's code is ever reviewed with the owner's token.

**LLM constraint (firm):** v2 uses the owner's **Claude subscription only** (via `claude -p` /
`CLAUDE_CODE_OAUTH_TOKEN`), with **free local Ollama** as the sole fallback. **No paid Anthropic API
key, ever** — so there is no billing, no metered cost, and no API-key management in the system. This
is why v2 cannot be a public product (it would need paid/managed LLM) and is scoped to one owner.

Decisions: wrap the Python engine (ADR-0009), single-owner subscription-backed (ADR-0010), a
webhook backend replaces the per-repo Action (ADR-0011).

## 2. What stays identical from v1 (the whole engine)

`core/heuristics/*`, `core/reviewer/*` (taint, static_scan, triage, two_view, injection_check,
report), `gate/run_gate.py:run()`, the `Finding` model, and every invariant — **fail closed**,
**no secret to the model**, **model has no tools**, **judge the commit not the tree**,
**redaction before any LLM call**. v2 adds a delivery layer around this; it changes none of it.
The 878-test suite is the regression guard for the engine.

## 3. Components (new in v2)

```
GitHub (owner's org)                       Owner's host (one small always-on service)
┌─────────────────────────┐   webhook     ┌───────────────────────────────────────┐
│ PR opened / synchronized │──(HMAC)──────►│ 1. Webhook receiver                    │
│                          │               │    - verify X-Hub-Signature-256        │
│                          │               │    - enqueue {repo, pr, head, base}    │
│ Check Run + PR comment   │◄──────────────│ 4. Result poster (App install token)   │
└─────────────────────────┘               │                                        │
                                          │ 2. Gate worker                          │
                                          │    - fetch PR head via API/git          │
                                          │    - run v1 gate: taint+semgrep+gitleaks │
                                          │      +rules, then claude -p (OWNER token)│
                                          │    - fail closed on any error            │
                                          │ 3. Store (reuse core/store.py, SQLite)   │
                                          └───────────────────────────────────────┘
                                                        │ reads
                                                        ▼
                                          Existing Streamlit dashboard (local, 127.0.0.1)
```

- **GitHub App** (registered once). Permissions: `Checks: write`, `Contents: read`,
  `Pull requests: write`. Subscribes to `pull_request` events. Installed on the owner's repos.
- **Webhook receiver** — small HTTP endpoint; verifies the HMAC signature, drops anything else,
  enqueues a job. The only internet-facing surface (see §5).
- **Gate worker** — fetches the PR head (never executes it), runs the **unchanged** `gate.run()`,
  calls `claude -p` with the owner's `CLAUDE_CODE_OAUTH_TOKEN` (same mechanism as v1 CI).
- **Result poster** — posts a GitHub **Check Run** (pass/fail) + a PR comment via the App's
  per-install token.
- **Store + dashboard** — reuse `core/store.py` and the existing dashboard as-is; the App's runs
  flow into the same SQLite log the dashboard already reads.

## 4. Why a backend, not just the v1 Action

The v1 Action needs a workflow file + the token in **every** repo. The App centralizes install,
config, and the token once, and protects new repos automatically. Fallback (lower ops): the App
can instead trigger a **reusable Actions workflow** and skip hosting — kept as ADR-0011's
alternative for when self-hosting isn't wanted.

## 5. Trust boundaries (extends `THREAT_MODEL.md`)

| New surface | Risk | Mitigation |
|---|---|---|
| Internet-facing webhook | forged events, floods | verify `X-Hub-Signature-256` (reject on mismatch); rate-limit; ignore non-`pull_request` |
| Owner's subscription token on the backend | leak | secret store only, never logged, never sent to the model, never to the client |
| PR code analyzed server-side | malicious PR | **never executed** (read via API/`git show`), gate runs engine-only, same as v1 |
| Always-on host | compromise | single-owner, minimal service, no inbound except the signed webhook |

Single-owner means there are **no untrusted forks** using the token — the v1 fork caveat (SG-015)
disappears, because only the owner's installation runs.

## 6. Contracts (new — to be detailed in a v2 Phase 0)

- **Webhook → job:** `{installation_id, repo, pr_number, head_sha, base_ref}` (validated).
- **Job → gate:** reuse `gate.run(files, root, pr_body)` — **no change to the engine contract.**
- **Gate → GitHub:** a Check Run (`conclusion: success|failure`) + a PR comment (the existing
  `report.build_markdown`).
- **Config:** one owner config (protected repos, `FAIL_ON_SEVERITIES`, `REVIEW_ENSEMBLE`) — no
  multi-tenant schema; a single file or the existing SQLite.

## 7. Open decisions (human gates — see SPEC-GAPS)

1. **Anthropic Consumer-Terms check** (SG-018): is an always-on App driven by a personal
   subscription permitted? If not, fall back to **free local Ollama** (never a paid API key — firm
   constraint). **Blocking.**
2. **Hosting** (SG-017): where the webhook backend runs (VPS / Fly / home server / the Actions-only
   fallback). Reverses SG-008 *only* for the owner's own backend — still no public demo hosting.
3. **Scope creep guard** (SG-019): keep v2 single-owner. Serving other people needs managed billing
   or BYO-key — a different product; do not drift into it without a new decision.

## 8. v2 phase roadmap

See `docs/v2/PHASES.md` (V0–V4). V0 is a design Phase 0 (webhook/contracts/ADR detail) mirroring
the v1 `/architecture` step.
