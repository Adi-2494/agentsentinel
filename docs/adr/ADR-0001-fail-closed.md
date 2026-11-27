# ADR-0001: Fail closed on hook and gate errors

- **Status:** accepted
- **Phase:** P00 (back-filled)
- **Deciders:** architect, security-reviewer

## Context
A security control that crashes is worthless if the crash lets the action through. Early builds of the Live Guard failed *open* (a crash returned "allowed"), which meant a malformed tool event — a path with a null byte or a lone surrogate — was a one-input bypass.

## Decision
Every enforcement surface **fails closed**. A crash, unreadable input, or invalid configuration results in **deny** (guard) or **block / exit non-zero** (gate). The only way to allow-on-error is an explicit, documented opt-out: `AGENTSENTINEL_FAIL_OPEN=1` (guard) and `--allow-llm-outage` (gate, LLM outages only).

## Consequences
- Positive: no error path is a bypass; INV-1 holds.
- Negative: a guard bug can block legitimate work (availability cost). Mitigated by the opt-out and by fuzz tests that assert "never crash into allow".
- Residual risk: a user who sets `AGENTSENTINEL_FAIL_OPEN=1` trades safety for availability — documented, their choice.

## Alternatives considered
- **Fail open** — rejected: turns any crash into a bypass.
- **Fail closed with no opt-out** — rejected: a guard bug could brick a session with no escape hatch.
