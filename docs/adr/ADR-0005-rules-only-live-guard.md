# ADR-0005: The Live Guard is rules-only (no LLM, no network)

- **Status:** accepted
- **Phase:** P00 (back-filled)
- **Deciders:** architect

## Context
The Live Guard runs **before every AI tool action** on the developer's laptop. It must be instant and must not itself become an exfiltration or cost risk. It also must work when offline and must not consume the Claude Pro limit.

## Decision
The Live Guard (hooks + MCP server) uses **rules only** — no LLM calls, no network. All LLM usage is confined to the Merge Gate, in batched calls. The guard's job is fast, deterministic deny/ask/allow.

## Consequences
- Positive: instant (within the performance budget), offline-capable, zero Pro-limit cost, no network egress from the guard itself.
- Negative: rules are brittle vs a determined adversary (paraphrase, novel obfuscation). Accepted and documented; the guard is a fast first line, the gate's LLM layer is the deeper check.
- Residual risk: novel phrasings/obfuscation (tracked as known-gap tests).

## Alternatives considered
- **LLM in the guard** — rejected: latency, cost, Pro-limit, offline, and it would put untrusted text in front of a model on every action.
