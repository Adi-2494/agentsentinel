# ADR-0011: A webhook backend delivers the gate, with the Action as fallback

- **Status:** accepted
- **Date:** 2026-11-27
- **Phase:** v2 / V0
- **Deciders:** owner, architect

## Context
v1 runs the gate as a GitHub Action, which needs a workflow file plus the token in **every** repo.
A GitHub App can centralize install, config, and the token once, and protect new repos
automatically — but a true App needs an internet-facing webhook receiver the owner hosts.

## Decision
v2's primary delivery is a **small webhook backend** (one always-on service the owner hosts): it
verifies the GitHub webhook signature, runs the unchanged `gate.run()` on the PR head, and posts a
Check Run + comment via the App install token. A **reusable GitHub Actions workflow** is kept as a
documented **fallback** for when the owner does not want to self-host (no backend, token in Actions
secrets, same engine).

## Consequences
- Positive: one install, central config, auto-coverage of new repos; no per-repo workflow file.
- Negative: introduces one internet-facing service (new attack surface — signature verification,
  rate-limiting, minimal exposure; see `docs/v2/ARCHITECTURE.md §5`) and a hosting decision (SG-017).
- Residual risk: the webhook receiver must reject unsigned/forged events; covered by the v2 threat-model
  extension and to be tested like the v1 surfaces.

## Alternatives considered
- **Actions-only (no backend)** — kept as the fallback; lower ops but per-repo token and no central
  config.
- **Polling the GitHub API** — rejected: latency and rate-limit cost versus webhooks.
