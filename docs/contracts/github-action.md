# Contract: GitHub Action (stable)

Source: `.github/workflows/agentsentinel.yml`. Editing the workflow is a human gate (it judges PRs).

## Triggers
`pull_request` (opened, synchronize, reopened, edited) and `push` to `main`.
`permissions: contents: read`. Concurrency-grouped per PR, cancel-in-progress.

## Jobs
| Job | Does | Pinned |
|---|---|---|
| `lint` | `ruff check .` + `ruff format --check .` | ruff `0.17.2` |
| `typecheck` | `mypy` (strict) | mypy `2.4.0` |
| `tests` | `pytest -m "not llm"` on **ubuntu + macos + windows** (bash shell) | gitleaks `8.30.1`, semgrep via `pipx`, `pytest-cov 7.0.0` |

## Rules
- All tool versions **pinned** (SG-012). The Merge-Gate review job reads changed files from the PR head and uses `CLAUDE_CODE_OAUTH_TOKEN` **only** as an env var, with a `--no-llm` fallback.
- **Fork PRs** get no token → static-only (intended, SG-015).
- The token lives only in GitHub Secrets; never echoed or logged.
- No `push`/deploy/hosting steps (human gate; third-party hosting disallowed, SG-008).
