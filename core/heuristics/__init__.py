"""Fast, rule-based heuristics: regexes, keyword lists, entropy and path rules.

Why "heuristics" and not "detectors": these rules are a cheap pre-filter, not a proof.
They run in milliseconds on every agent action, with no network and no LLM, so they can
sit in the hot path of a hook. That speed costs them recall. They catch known shapes
(key formats, risky command patterns, common prompt-injection phrasing, look-alike and
hidden characters, base64 wrapping) but miss paraphrased or novel attacks, secrets
without a recognisable shape, and anything that only means something in context.

Deeper checks (Semgrep taint rules, the Claude triage, the two-view check) run in the
Merge Gate, where a few seconds per PR is affordable. README "What the rules can and
can't catch" lists the limits.
"""
