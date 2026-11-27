# ADR-0009: v2 wraps the Python engine; it does not rewrite it

- **Status:** accepted
- **Date:** 2026-11-27
- **Phase:** v2 / V0
- **Deciders:** owner, architect

## Context
The planner proposed rebuilding the core in Java/Spring (a resume motive). The detection engine
(heuristics, taint analysis, reviewer, two-view) is ~6k lines of Python with **878 passing tests**
and is the product's actual value. Rewriting it would discard that proven, security-critical code
and its regression suite, for no functional gain.

## Decision
v2 **wraps** the existing Python engine unchanged and adds only a thin delivery layer (GitHub App +
webhook backend). The engine's modules, the `Finding` contract, and every invariant stay exactly as
they are; the 878-test suite remains the regression guard.

## Consequences
- Positive: no regression risk to the security core; fastest path to a shippable v2; the engine keeps
  evolving in one place for both v1 (Action/CLI) and v2 (App).
- Negative: no Java on the resume from this work (the owner chose engine integrity over that).
- Residual risk: none to the engine.

## Alternatives considered
- **Rewrite in Java/Spring** — rejected: discards a mature, tested security engine; slow; high-risk.
- **Hybrid (Python engine microservice + Java product layer)** — rejected for the MVP as needless
  complexity; revisit only if a Java product layer is ever independently justified.
