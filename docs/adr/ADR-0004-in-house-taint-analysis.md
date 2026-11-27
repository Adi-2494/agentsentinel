# ADR-0004: In-house Python taint analysis alongside Semgrep

- **Status:** accepted
- **Phase:** P00 (back-filled)
- **Deciders:** architect, backend-engineer

## Context
Semgrep's `p/owasp-top-ten` missed most real bugs in our evaluation (it is blind to many user-input → dangerous-call flows: SQLi via f-strings, command injection, pickle, path traversal). A pattern matcher without dataflow can't see "this call's argument came from request input."

## Decision
Add an **in-house taint analysis** over the Python syntax tree (`core/reviewer/taint.py`): track user-input sources to dangerous sinks. Keep Semgrep and Gitleaks as complementary layers. Measured recall 77.8% on held-out OWASP Python cases vs 18.5% for Semgrep.

## Consequences
- Positive: catches dataflow bugs Semgrep misses; higher recall on real advisories.
- Negative: Python-only; known limits — state on `self`, closures, `getattr`, globals, lambdas-as-attributes (tracked as T-03…T-07 known-gap tests). Non-Python code has Semgrep only.
- Residual risk: logic bugs only the LLM can see remain the LLM layer's job.

## Alternatives considered
- **Semgrep only** — rejected: too low recall on real bugs.
- **A heavyweight external taint engine** — rejected: runtime-dependency and footprint cost; the guard/gate stay stdlib-first.
