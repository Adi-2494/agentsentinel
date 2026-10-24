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

## Left
- A3 output check (scan Write/Edit content) and A5/B4 AI-trap scanner (hidden instructions, invisible Unicode)
- Cursor hook (if available), MCP server with check tools
- Benchmark: 30-40 cases, Sonnet and Haiku, with vs without AgentSentinel (resumable, batched)
- Hugging Face Space (demo data only), final README with benchmark numbers, demo GIF
