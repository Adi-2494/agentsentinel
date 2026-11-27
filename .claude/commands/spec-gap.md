---
description: Log a SPEC-GAP — record a gap between a prompt and a source of truth, with the conservative default taken. Never guess silently.
argument-hint: <the question / ambiguity>
---

Log a SPEC-GAP for: $ARGUMENTS

1. Confirm it really is unspecified — check `docs/SPEC.md`, `THREAT_MODEL.md`, `docs/adr/`, then the code. If a source of truth already answers it, apply that instead and say so (no new row needed).
2. If genuinely unspecified, append one row to `docs/SPEC-GAPS.md`:
   `SG-NNN | phase | question | conservative default taken | open`
   — pick the next free `SG-NNN`. **Security-relevant gaps default to deny / block / redact.**
3. Proceed with the conservative default; **do not guess** an interface, threshold, severity, host, or security decision.
4. Report the new ID, the default taken, and note it will be raised at the next human gate for a real decision.

This command only records a gap and takes a safe default — it does not resolve the underlying decision. Resolution happens at the human gate.
