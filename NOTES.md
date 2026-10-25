# Build notes

## Done (Checkpoints 1-6)
Project setup, LLM layer + detectors, Claude Code Live Guard, Merge Gate (local + GitHub Action),
dashboard, Docker. 177 tests (unit + integration) and 4 opt-in live tests.

## What broke, and the fix
- `claude -p` loaded claude.ai MCP connectors in review calls: added `--tools "" --strict-mcp-config`.
- Gate (CI mode) read files from the working tree instead of the PR commit, so it could pass silently.
  Now it reads every changed file with `git show <head>:<path>`.
- Env-style secrets leaked into report snippets and triage prompts (line numbers added before redaction).
  Now the whole file is redacted first.
- Two PII items on one line were de-duplicated into one finding.
- False alarms on `package-lock.json` (`"parse-passwd": "^1.0.0"`): lock files are skipped by regex
  rules (Gitleaks still scans them), and version specs are not secrets.
- View-2 line numbers drifted after removing comments: the neutralizer now edits in place.
- CI token gave `401 Invalid bearer token`: the token was regenerated, and the error is now reported as
  an authentication problem.
- Dashboard: Streamlit "magic" printed help text, a theme override disabled dark mode, and the demo DB
  stayed in WAL mode (unreadable on a read-only FS). All fixed and checked with screenshots.
- The Docker health check reports healthy even when the page crashes. Always check the rendered page.

## Also done
- Testing across 3 generated repos (20 PR branches), 4 public repos, live Claude Code and Cursor runs.
- Output check, AI-trap scanner (code-borne + chat jailbreaks, 6 languages), Cursor hook, MCP server.
- Benchmark (38 cases, Sonnet + Haiku) and real-world evaluation (50 GitHub advisories,
  deepset/prompt-injections, SecurityEval).
- Decided against a hosted demo (third-party GitHub OAuth access); local Docker demo + screenshots.

## Left
- Licence decision (all rights reserved vs open source) before selling.
- Pin the repo on the GitHub profile.
- Known gaps: printenv/env rule, JS/TS-aware neutralizer, manual review of "fixed version still blocked".
