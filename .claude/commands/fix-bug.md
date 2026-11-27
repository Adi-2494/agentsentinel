---
description: Fix a bug test-first — reproduce with a failing test, make it pass, review, verify. No guessing.
argument-hint: <describe the bug or paste the symptom>
---

Fix this bug **test-first**: $ARGUMENTS

Do **not** jump to a patch. Follow this loop:

1. **Reproduce** — understand the report. Launch `qa-engineer` to write the **minimal failing test** in `tests/` that reproduces the bug. Confirm it fails for the right reason. If you can't reproduce it, say so and ask for more detail — do not guess a fix.
2. **Diagnose** — find the root cause (not just the symptom). Note the affected module(s) and whether it's a security-relevant failure (if a control could fail *open*, treat as HIGH).
3. **Fix** — launch the owning builder (`backend-engineer` / `data-engineer` / `frontend-engineer` / `devops-engineer`) to make the failing test pass with the **smallest** correct change. Run **only the affected tests** in the loop.
4. **Guard against regressions** — ensure the new test stays; add neighboring edge cases if the bug class suggests them.
5. **Review** — launch `code-reviewer` (and `security-reviewer` if security-relevant), read-only, on the diff.
6. **Verify** — run the full `pytest -m "not llm"` suite once to confirm nothing else broke.
7. **Report** — root cause, the failing→passing test, files changed, suite result. Log a SPEC-GAP if the correct behavior wasn't actually specified.

**Do not commit** unless asked; if asked, use a plain `git commit -m "fix: <summary>"` — no push, no co-author lines.
