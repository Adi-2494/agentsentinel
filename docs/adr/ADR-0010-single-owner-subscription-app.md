# ADR-0010: v2 is a single-owner GitHub App on the Claude subscription (no paid API)

- **Status:** accepted
- **Date:** 2026-11-27
- **Phase:** v2 / V0
- **Deciders:** owner, architect

## Context
v1 uses the owner's Claude subscription via `claude -p` / `CLAUDE_CODE_OAUTH_TOKEN`. The owner wants
v2 to keep using the **subscription only**, with **free local Ollama** as the sole fallback, and
**never a paid Anthropic API key**. A personal subscription is personal-use only under Anthropic's
Consumer Terms, so it cannot lawfully power other people's PRs.

## Decision
v2 is a **single-owner** GitHub App installed on the **owner's own org/repos**. It is LLM-powered by
the owner's Claude subscription (or free local Ollama), with **no paid API and no billing**. It is
explicitly **not** a public multi-tenant SaaS. Only the owner's code is ever reviewed with the
owner's token — preserving the v1 trust model.

## Consequences
- Positive: zero LLM cost and no billing/abuse surface; the v1 "only your own PRs use the token"
  guarantee carries over; the fork-token caveat (SG-015) disappears (no untrusted forks).
- Negative: cannot serve other users/teams as a product without a different LLM model (paid/managed
  or BYO-key) — a separate initiative, not this one (SG-019).
- Residual risk: depends on the Consumer-Terms check (SG-018) allowing subscription use in an
  always-on App; if not, fall back to free local Ollama.

## Alternatives considered
- **Managed (we bill the API)** — rejected: the owner forbade a paid API; adds billing/abuse surface.
- **Bring-your-own-key** — rejected for now: still implies a paid API for users; out of the chosen
  subscription-only constraint.
- **Public multi-tenant SaaS** — rejected: not possible on a personal subscription.
