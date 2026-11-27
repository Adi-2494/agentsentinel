# ADR-0007: No third-party hosting — the dashboard is local-only

- **Status:** accepted
- **Phase:** P00 (back-filled)
- **Deciders:** architect, human owner

## Context
The planner originally proposed a public Hugging Face Spaces demo. The dashboard reads a security activity log; hosting it on a third-party platform (with GitHub-OAuth access) would expose activity data and create a token/data-handling surface that isn't worth the risk for a demo.

## Decision
**No third-party hosting.** The dashboard is read-only, binds `127.0.0.1`, and ships as a **local Docker** image. Demos use local runs + screenshots / the recorded GIF. A real hosted deployment is a future product decision behind a human gate.

## Consequences
- Positive: no activity data leaves the machine; no third-party OAuth/token surface; INV-7 holds.
- Negative: no one-click public demo link; reviewers run it locally or watch the GIF.
- Residual risk: none.

## Alternatives considered
- **Hugging Face Spaces / any GitHub-OAuth host** — rejected (data exposure + token surface).
- **Self-hosted public deploy** — deferred to a product phase with a human gate.
