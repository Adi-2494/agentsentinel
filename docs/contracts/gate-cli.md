# Contract: Merge Gate CLI (stable)

Source: `gate/run_gate.py`. Breaking flags/exit codes is a human gate.

## Invocation
```
# local: scan a folder or file
python gate/run_gate.py --path <dir|file> [--pr-body-file PR.md]

# CI: judge a PR between two refs (files read from the HEAD commit via `git show`)
python gate/run_gate.py --base <ref> [--head HEAD] [--repo .] --pr-body-env PR_BODY \
    [--comment-out comment.md] [--json-out result.json] [--label "PR #3"]
```
`--path` XOR `--base` (required). Other flags:
| Flag | Meaning |
|---|---|
| `--head` | PR head ref (default `HEAD`) |
| `--repo` | repo root (default cwd) |
| `--pr-body-file` / `--pr-body-env` | PR description from a file or an env var (never a shell arg) |
| `--no-llm` | static scan only (fallback; no triage / two-view / AI-trap LLM) |
| `--allow-llm-outage` | pass on an LLM outage (explicit opt-out of INV-1) |
| `--comment-out` | write the Markdown PR comment |
| `--json-out` | write machine-readable results |
| `--label` | run name for the dashboard |
| `--verbose`/`-v` | debug logs on stderr |

## Exit codes
`0` = pass · `1` = merge should be blocked · `2` = invalid configuration (`config.require_valid()` failed).

## Fail conditions (exit 1)
Any **real** finding with severity in `{HIGH, CRITICAL}`, OR two-view **manipulation suspected**, OR View 2 reports a HIGH/CRITICAL issue.

## Guarantees
Files judged come from the PR head commit; secrets redacted before any LLM call; PR text never interpolated into a shell line; LLM outage fails closed unless `--allow-llm-outage`.
