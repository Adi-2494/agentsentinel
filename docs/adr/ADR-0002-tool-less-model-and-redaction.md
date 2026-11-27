# ADR-0002: The model runs with no tools / no files, and sees only redacted code

- **Status:** accepted
- **Phase:** P00 (back-filled)
- **Deciders:** architect, security-reviewer

## Context
The Merge Gate asks Claude to review untrusted PR code. Two risks: (1) the model could be induced to *act* (run a command, read a file) if it had tools; (2) sending raw code could leak real secrets/PII to the provider.

## Decision
- The review LLM runs with `--tools "" --strict-mcp-config` in an empty temporary cwd (no project hooks, no `CLAUDE.md`). It can only return text (INV-4).
- All code/text is **redacted for secrets and PII before any LLM call** (INV-2). Untrusted content is wrapped in `<untrusted_…>` tags and the prompt tells the model to treat it as data.

## Consequences
- Positive: prompt injection in the PR cannot make the model act; the provider never sees real secrets.
- Negative: redaction can occasionally hide a vulnerability that lives inside a redacted span (documented residual risk).
- Residual risk: the provider still sees the (redacted) PR code.

## Alternatives considered
- **Give the model tools for richer analysis** — rejected: turns prompt injection into code execution.
- **Send raw code** — rejected: leaks secrets to the provider.
