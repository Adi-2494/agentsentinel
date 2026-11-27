# Phase verification report

Record of the build-kit phase pass. Live-LLM scenarios (two-view, live benchmark) are
**human-gated** (SG-009) and were **not** run here to avoid Pro-limit spend; they are covered
offline by `tests/test_llm_degradation.py` and `tests/test_reviewer.py`.

Baseline: `pytest -m "not llm"` → **874 passed, 14 xfailed, 0 failed**; `ruff check`/`format` clean; coverage on `core/heuristics` **92%** (≥85% bar, SG-011).

| Phase | Status | Evidence (non-LLM, reproduced this pass) |
|---|---|---|
| **P00** Architecture | ✅ verified | `docs/SPEC.md`, 6 contracts, ADR-0001..0008, data-model; config validates |
| **P01** Heuristics | ✅ verified + **hardened** | 92% cov; adversarial sweep: all fresh command/secret attacks caught; **found & fixed** one real gap (enclosed-alphanumeric confusables, see below) test-first |
| **P02** Platform | ✅ verified + **hardened** | config fails loudly listing all bad values; logs stay on stderr (hook-protocol safe); `extract_json` robust vs adversarial replies; **found & fixed** multi-process store data-loss/crash (below) |
| **P03** Live Guard | ✅ verified (no change needed) | end-to-end deny for `.env`/`curl\|sh`/written key; **fresh exfil/download sweep all blocked** (`tar\|nc`, `git push` to unknown remote, `--resolve` trick, `iwr\|iex`, `printf`-built curl, `xxd ~/.ssh`); post-tool Bash output cleaned (secret redacted, trap removed, normal kept); non-Bash warn-only is intentional+tested (SG-016); garbage stdin → deny; latency 0.06 ms avg, `test_performance` green |
| **P04** Merge Gate | ✅ verified (static) | `--no-llm` gate: `vulnerable_pr`→exit 1, `safe_pr`→exit 0; trick-PR trap rule fires; LLM two-view covered offline + human-gated to run live |
| **P05** Integrations | ✅ verified | MCP `check_command`→deny, `scan_text_for_injection`→allow; `test_cursor_hook` green |
| **P06** Dashboard | ✅ verified | INV-7 enforced via compose port map `127.0.0.1:8501`; masked previews only; `test_dashboard` green |
| **P07** Evaluation | ✅ verified (artifacts) | 38 cases (10 leak/10 vuln/10 trick/8 safe); results files present; live runs human-gated |
| **P08** Hardening | ✅ verified | red-team registry + known-gap tests present; `test_performance`/`test_robustness`/`test_llm_degradation` green; 14 xfail = documented residual risks |

## P01 hardening — the one code change this pass

**Finding (new, undocumented):** negative-circled (🅐–🅩, U+1F150) and negative-squared (🅰–🆉, U+1F170) enclosed-alphanumeric Latin letters are **not** folded by NFKC, so `i🅖🅝🅞🅡🅔 all previous instructions` evaded the injection rules. (Circled/fullwidth confusables were already caught; squared U+1F130 is folded by NFKC.)

**Fix (test-first, minimal):** added the two negative blocks to `_CONFUSABLES` in `core/heuristics/injection.py`:
```python
_CONFUSABLES.update({base + i: ord("a") + i for base in (0x1F150, 0x1F170) for i in range(26)})
```
**Verification:** new test `test_enclosed_alphanumeric_letters_are_deconfused` (red→green); no false positives (flags/emoji unaffected); full suite 874 passed; threat model updated.

## P02 hardening — the one code change this pass

**Finding (real, deployment-pattern bug):** 12 processes × 200 writes to the shared log → **200 rows lost** and one process crashed with `sqlite3.OperationalError: database is locked` on `PRAGMA journal_mode=WAL`. Each hook call is its own process, and that PRAGMA returns BUSY *without* honoring the connect busy-timeout. In the live hook a store error is caught → **spurious deny** of a legitimate action.

**Fix (test-first, minimal):** in `core/store.py`, set `PRAGMA busy_timeout=5000` per connection and **retry** the WAL pragma (WAL is a persistent file property, so the race is first-setup only).

**Verification:** 12 procs × 200 → 2400/2400, zero crashes. New integration test `test_many_processes_write_without_loss_or_crash` (8 procs × 150). Full suite green; lint + mypy clean.

## Dispositions / notes
- **Live-LLM paths** (P04 two-view, P07 live benchmark): not run (SG-009, Pro-limit, owner away). Run with human approval via `--run-llm` / the gate with a token.
- **Dashboard exposure:** supported path (docker compose) is loopback-only. A manual `docker run -p 8501:8501` would expose it — documented-usage assumption, no code change.
- **Known gaps** remain strict xfail tests (S-04…S-07 split/encoded secrets, LG-13/14 runtime-assembled commands, I-09/I-10 novel wording/languages) — tracked in `redteam/README.md`, unchanged.
