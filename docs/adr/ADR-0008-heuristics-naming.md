# ADR-0008: Name the rule layer `heuristics`, not `detectors`

- **Status:** accepted
- **Phase:** P00 (back-filled)
- **Deciders:** architect, security-reviewer

## Context
The rule-based layer (regex + small decoders + similarity) is a fast first line, not a complete detector. Calling it `detectors` oversells it and invites the assumption that a clean result means "safe". Adversarial review showed the rules are bypassable by paraphrase, encoding, and homoglyphs — which is expected for heuristics.

## Decision
Name the package **`core/heuristics/`**. It encodes honest fast checks: secrets, pii, commands, files, injection, plus `similarity` (reworded injections) and `decoded_payloads` (base64/hex/`\xNN`). Documentation states plainly what the heuristics can and cannot catch; deeper detection is the Merge Gate's LLM + taint layers.

## Consequences
- Positive: honest framing; reviewers don't mistake a clean heuristic pass for a safety guarantee.
- Negative: a rename touched imports across the codebase (one-time cost, done).
- Residual risk: none; the naming reduces a *misuse* risk.

## Alternatives considered
- **Keep `detectors`** — rejected: overstates completeness.
