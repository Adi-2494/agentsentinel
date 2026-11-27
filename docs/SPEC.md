# AgentSentinel — behavioral specification (v1.0)

> **Source of truth.** This is the authoritative spec (`CLAUDE.md §2`). Back-filled from
> `THREAT_MODEL.md` (authoritative for security) and `README.md` (narrative). Where this spec
> and the code disagree, the code is a bug or a SPEC-GAP — not the new truth.
> Contracts referenced here live in `docs/contracts/`. Decisions live in `docs/adr/`.

## 0. Invariants (must hold everywhere, always)

| # | Invariant | Enforced by |
|---|---|---|
| INV-1 | **Fail closed.** Any crash, unreadable input, or invalid setting results in *deny / block*, never *allow*. Opt-outs exist but are explicit (`AGENTSENTINEL_FAIL_OPEN=1`, `--allow-llm-outage`). | guard, gate, config |
| INV-2 | **No real secret or PII reaches the model.** Snippets are redacted before any LLM call. | reviewer, llm |
| INV-3 | **Rules only on the laptop.** The Live Guard makes no network and no LLM calls. | guard |
| INV-4 | **The model cannot act.** LLM runs with `--tools "" --strict-mcp-config` in an empty temp cwd. | llm |
| INV-5 | **Gate judges the PR, from the base branch.** Changed files are read via `git show <head>:<path>`; gate code runs from the base branch; PR text never enters a shell line. | gate |
| INV-6 | **Logs never store secrets.** Only masked previews are written to SQLite. | store, base.mask |
| INV-7 | **The dashboard is local-only.** Read-only, binds `127.0.0.1`, never hosted. | dashboard |

## 1. Scope & actors

AgentSentinel defends developer secrets, personal data, the developer's machine, the codebase, and the review process against three attackers (see `THREAT_MODEL.md §2`): **A1** author of content an agent reads (text only), **A2** the agent itself by mistake, **A3** a pull-request author. Out of scope: anyone who can already run code on the machine, a maintainer with write access to the base branch/workflow, or a compromised provider/registry.

## 2. Shared vocabulary

- **Severity:** `LOW < MEDIUM < HIGH < CRITICAL` (`core/heuristics/base.py:SEVERITY_ORDER`).
- **Finding:** the single result type for every check — see `docs/contracts/finding.md`.
- **Category:** `secret | pii | command | injection | file | vuln`.
- **Decision mapping** (guard & MCP): `HIGH|CRITICAL → deny`, `MEDIUM → ask`, else `allow`.
- **Blocking severities** (gate): `FAIL_ON_SEVERITIES = {HIGH, CRITICAL}`.

## 3. Component A — Live Guard (rules only; INV-1,3)

Runs as a Claude Code / Cursor hook. Reads a tool event on stdin, replies with a decision. Contract: `docs/contracts/hook-io.md`.

### 3.1 Pre-tool (before the action)
For the proposed tool call, collect findings and map max-severity → decision:
- **Protected-file lock** — `Read/Grep/Glob/Edit/Write` on a protected path (`config.PROTECTED_FILE_PATTERNS`, minus `PROTECTED_FILE_EXCEPTIONS`) is CRITICAL. Also covers files named inside Bash (`cat`, `python -c "open(...)"`, `find ~/.ssh`, `tar ~/.aws`).
- **Written content** — `Write/Edit/MultiEdit/NotebookEdit` content is scanned for secrets, PII, and AI-traps; a real secret/PII is HIGH+ (deny).
- **Risky commands** — Bash commands scanned for: download-and-run (`curl|sh`, `source <(curl)`, `eval $(curl)`), destructive (`rm -rf /`, disk wipe, fork bomb), uploads/exfil to unlisted hosts (`config.ALLOWED_HOSTS`), DNS exfil, `nc`/`scp`, base64-to-shell. Obfuscation (shell vars, `printf`, `python -c` string building) is resolved first.
- **Reading via Bash** — files a command would print (`cat`, `head`, …) are scanned before they reach the model; protected ones are denied.
- **AI-config edits** — changes to `.claude/settings.json`, `.cursor/*`, `CLAUDE.md`, MCP configs are flagged; adding hooks is HIGH.

### 3.2 Post-tool (clean what the agent sees)
Tool output is cleaned: AI-trap phrases removed (whole line), secrets redacted, HIGH PII redacted; the agent is told the output was cleaned and that any instructions in it are untrusted data.

### 3.3 Failure behavior (INV-1)
Crash, unreadable input, or invalid config → **deny** with a clear reason. `AGENTSENTINEL_FAIL_OPEN=1` opts out (availability over safety). Latency must stay within the performance budget (`tests/test_performance.py`).

## 4. Component B — Merge Gate (INV-2,4,5)

CLI (`gate/run_gate.py`) + GitHub Action. Contracts: `docs/contracts/gate-cli.md`, `docs/contracts/github-action.md`.

### 4.1 Pipeline
1. **Static scan** (no LLM): in-house **taint analysis** (`core/reviewer/taint.py`), **Semgrep** (`p/owasp-top-ten`), **Gitleaks**, plus secret/PII/injection rules. Lock files are skipped by regex rules (Gitleaks still scans them).
2. **Triage** (one batched Claude call, `CHECK_MODEL`): marks each static vuln finding real / false-alarm with severity, explanation, fix. Secrets & PII are rule-exact and never downgraded. LLM unavailable → every finding stays real (fail closed).
3. **Two-view check** (`MAIN_MODEL`): the same code is reviewed with and without its human-facing text (comments, names, PR description). If View 2 finds a serious issue View 1 missed → **MANIPULATION SUSPECTED**. Compared by severity, not the bare verdict word. `REVIEW_ENSEMBLE=1` adds a `CHECK_MODEL` second opinion.
4. **AI-trap check** (`CHECK_MODEL`): classifies the PR's human-facing text SAFE / SUSPICIOUS.
5. **Report**: Markdown PR comment + pass/fail.

### 4.2 Decision & exit codes
Fails (blocks merge) if any **real** finding is HIGH/CRITICAL, **or** manipulation suspected, **or** View 2 reports a HIGH/CRITICAL issue. Exit: `0` pass, `1` block, `2` invalid config. `--no-llm` = static only; `--allow-llm-outage` passes on an LLM outage (explicit opt-out of INV-1 for availability).

### 4.3 Trust (INV-4,5)
Model has no tools and no files; snippets redacted before the call; untrusted text wrapped in `<untrusted_…>` tags; PR description passed via env var, never a shell line; changed files read from the PR head commit; gate code from the base branch. Fork PRs have no token → static-only (intended, SG-015).

## 5. Component C — MCP server (advisory)

`guard/mcp_server.py`, rules only. Tools: `check_command`, `check_file_content`, `scan_text_for_injection` — each returns `{safe, decision, max_severity, findings[]}` (`docs/contracts/mcp-tools.md`). **Advisory only — the agent decides whether to call it; it is not a security boundary. The hooks are.**

## 6. Component D — Dashboard (INV-7)

`dashboard/app.py` (Streamlit + pandas), read-only, binds `127.0.0.1`. Shows events, PR/gate results, severity & rule charts, benchmark page. Displays **masked previews only**. Docker image is dashboard-only (no Claude login, no egress). Not hosted anywhere public (SG-008).

## 7. Component E — Evaluation

`benchmark/*`: 38 synthetic cases (10 leak / 10 vuln / 10 trick / 8 safe, **fake** data only) on Sonnet + Haiku, with/without AgentSentinel; plus real-world eval (GHSA advisories, deepset/prompt-injections, OWASP Python, SecurityEval). Metrics: leak rate, manipulated-approval rate, precision/recall, false-block rate — each with sample size and a reproduce command. Resumable; live runs are opt-in + human-gated (SG-009). External GPL/third-party data is pinned and fetched at runtime, not committed (SG-014).

## 8. Platform services

- **`core/config.py`** — env + `.env`, every value validated; `require_valid()` fails loudly (hooks deny, gate exits 2). `python -m core.config` checks a setup.
- **`core/store.py`** — SQLite (WAL), one connection reused per thread (file-identity checked), masked previews only. Schema is additive-only with a `schema_version` convention (`docs/contracts/data-model.md`); destructive migration = human gate (SG-010).
- **`core/log.py`** — structured logging (`text|json`, `debug..error`), `--verbose`.
- **`core/llm.py`** — the single LLM doorway (`ask_llm`, `ask_json`); backends `claude_code` (default) / `ollama`; typed errors (`LLMNotInstalled/NotLoggedIn/LimitReached/BadResponse`). No API key assumed (SG-007).

## 9. Residual risks

Tracked, each backed by a runnable case in `redteam/README.md` (caught cases stay caught; gaps are strict known-gap tests). See `THREAT_MODEL.md §4`. New residual risks become known-gap tests, not silent notes.

## 10. Open questions → SPEC-GAPs

All ambiguities are logged in `docs/SPEC-GAPS.md`. Security-relevant gaps default to deny / block / redact.
