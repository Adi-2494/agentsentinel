# AgentSentinel threat model

What AgentSentinel protects, from whom, where it draws trust boundaries, and what it does
**not** protect against. Every residual risk below is backed by a runnable case in
[`redteam/README.md`](redteam/README.md) (caught cases stay caught, gaps are strict known-gap
tests), so this document can't quietly drift from the code.

## 1. What is protected

| Asset | Example |
|---|---|
| Developer secrets | `.env`, SSH keys, cloud credentials, API keys in code |
| Personal data | emails, phone numbers, Aadhaar / PAN, card numbers in files and command output |
| The developer's machine | commands an AI agent runs: downloads piped to a shell, `rm -rf`, uploads |
| The codebase | vulnerable code merged through a pull request |
| The review process | AI reviewers being steered into approving a PR |

## 2. Who the attackers are

| | Attacker | Controls | Wants |
|---|---|---|---|
| **A1** | Author of content an AI agent reads (a repo file, README of a dependency, web page, issue) | text only | make the agent leak secrets, run commands, or ignore its user |
| **A2** | The agent itself, by mistake (not malicious) | its own actions | — (reads `.env` "to debug", pastes a key into a file) |
| **A3** | A pull-request author (e.g. an outside contributor) | the PR's code, comments, names, description | get vulnerable code merged, or steer the AI reviewer |

**Out of scope** (AgentSentinel can't help, and doesn't claim to):
- someone who can already run code on the developer's machine, or edit `~/.claude/settings.json` themselves
- a maintainer with write access to the base branch or the workflow file
- a compromised model provider, GitHub, or package registry
- an agent run **without** the hooks installed (the guard can only check what it is shown)

## 3. Trust boundaries

```
 untrusted                        AgentSentinel                         trusted
 ─────────                        ─────────────                         ───────
 files / pages the agent reads ─► Live Guard hook (stdin JSON) ──deny/ask/allow──► AI tool
 the agent's proposed actions  ─►   rules only, no network, fails closed
                                    └─► SQLite activity log (masked previews only)

 PR head commit (code, text)   ─► Merge Gate (code checked out from the BASE branch)
   read with `git show`,            taint + Semgrep + Gitleaks + rules
   never executed                   Claude: runs with NO tools, empty temp folder,
 PR description (env var,           untrusted text inside <untrusted_…> tags,
   never put into a shell line)     secrets redacted BEFORE the call
                                    └─► PR comment + pass/fail check
 CLAUDE_CODE_OAUTH_TOKEN: GitHub Secret, not available to fork PRs (static checks only)
```

## 4. Threats, mitigations and what remains

### Live Guard (Claude Code / Cursor hooks)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Agent reads a secret file (A1, A2) | protected-path rules for Read/Grep/Glob **and** for files named in Bash (`cat`, `python -c "open(...)"`, `find ~/.ssh`, `tar ~/.aws`) | a secret file with an unusual name or location |
| Data sent off the machine | uploads to unlisted hosts, DNS exfiltration of secret files, `nc`, `scp`, gists, pushes to an unlisted git remote | data hidden in an allowed host's ordinary request |
| Destructive or download-and-run commands | `curl … \| sh`, download-then-execute, `rm -rf /`, base64-to-shell | — |
| Obfuscated commands | shell variables and `printf` escapes resolved; `python -c` string building folded; scripts checked when run (and asked about when written) | commands assembled by other programs at run time (LG-13); multi-step plans where each step looks harmless (LG-14) |
| Prompt injection in what the agent reads | AI-trap rules in 8 languages, look-alike letters (Cyrillic, Greek, Armenian), leetspeak, hidden Unicode, base64/hex (2 layers), and a similarity check for rewordings | novel wording (I-09) and other languages (I-10): rules can't know every phrasing |
| Secrets or personal data written into files or shown in command output | rule scan of every write; output is redacted before the AI sees it | deliberately disguised secrets: reversed, ROT13, char codes, split across variables (S-04 … S-07) |
| The hook itself breaks, or settings are wrong | **fails closed**: crashes, unreadable input and invalid settings all deny (opt-out `AGENTSENTINEL_FAIL_OPEN=1`) | the opt-out exists; using it trades safety for availability |
| The agent disables the guard | edits to AI tool configs (`.claude/settings.json`, `.cursor/hooks.json`, `CLAUDE.md`) are flagged; adding hooks is HIGH | a user who approves the change |

### Merge Gate (GitHub Action)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Vulnerable code merged (A3) | Python taint analysis (77.8% recall on held-out OWASP cases vs 18.5% for Semgrep), Semgrep, Gitleaks, secret/PII rules, then a Claude review | logic bugs only the AI can see; taint limits: state on `self`, closures, `getattr`, globals, lambdas as attributes (T-03 … T-07); non-Python code has Semgrep only |
| The AI reviewer is steered by comments, names or the description | **two-view check**: the same code is reviewed with and without its human-facing text, and a verdict that flips is flagged; plus the Claude AI-trap check and the rules | a bug the AI misses in **both** views (second-opinion `REVIEW_ENSEMBLE=1` is a mitigation, not a cure) |
| The PR edits the gate that judges it | gate code comes from the **base branch**; PR files are only read | a maintainer merging a change to the gate itself |
| Shell injection through the PR description | passed in an environment variable, never interpolated into a shell line | — |
| Hiding the attack where the AI doesn't look | every changed text file is reviewed in batches; nothing is cut (a PR description past 5,000 characters used to be, now fixed); oversized PRs fail closed | — |
| The AI is down, at its limit, or answers garbage | **fails closed**: 117 tested failure combinations; a vulnerable PR is blocked in every one; a garbled answer is never a pass | `--allow-llm-outage` passes on outages by choice |
| Leaking the token or secrets to the model | the model has no tools and no files; snippets are redacted before any call; the token lives only in GitHub Secrets | the model provider sees the (redacted) PR code |

### MCP server and dashboard

- The **MCP server** is advisory: the agent decides whether to call it. It is not a security boundary; the hooks are.
- The **dashboard** is read-only, local, and binds to `127.0.0.1`. It is not hosted anywhere public on purpose.

## 5. Assumptions

- The hooks are installed (`python guard/install.py`) and stay installed.
- The base branch is protected, and the workflow runs from it.
- Claude Code honours `--tools ""` and `--strict-mcp-config` (the model can't act).
- Settings come from the user; they are validated, but a valid setting can still be a bad choice (e.g. a huge `ALLOWED_HOSTS`).

## 6. Where the evidence is

| Claim | Evidence |
|---|---|
| Known bypasses, caught or not | `redteam/README.md`, `tests/test_redteam_cases.py` |
| Earlier red-team round (31 attacks) | `tests/test_redteam.py`, `docs/redteam/` |
| Failure handling of every AI layer | `docs/production/llm_degradation_*.txt`, `tests/test_llm_degradation.py` |
| Taint analysis accuracy | `docs/core/taint_after.txt`, `benchmark/owasp_python.py` |
| Settings fail loudly | `docs/production/config_*.txt` |
