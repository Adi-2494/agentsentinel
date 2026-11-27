# v2 / V2 — post results back to GitHub (build report)

Built test-first against a **mocked GitHub transport** (no network, no token spent). The install-token
minting is V3; here the token is passed through.

## Delivered
- **`app/github.py`**
  - `GitHubClient` — stdlib `urllib` behind a single `transport` seam (tests inject a fake).
    - `post_check_run(repo, head_sha, conclusion, title, summary)` → `POST /repos/{repo}/check-runs`
      (`status: completed`, `conclusion: success|failure`).
    - `upsert_comment(repo, pr, markdown)` — finds AgentSentinel's existing comment by `MARKER` and
      **PATCHes** it (no comment spam), else **POSTs** a new one.
  - `GitHubPoster` — satisfies the webhook `Poster` protocol; posts the Check Run + comment.
- **`app/runner.py`** — `JobResult` now carries `conclusion` + `report_markdown` (from the unchanged
  `report.build_markdown`).
- **`app/webhook.py`** — `handle()` gains an injected `poster` seam; posts after the gate runs.
  **A posting failure is logged and flagged (`posted: false`) but never crashes and never changes the
  verdict** — the gate already decided.
- **`app/server.py`** — builds a real `GitHubPoster` when `GITHUB_TOKEN` is set; without it, the gate
  still runs and logs (V1 behaviour).

## Tests (no network)
- `tests/test_github.py` (5): Check Run payload correctness (method/url/headers/conclusion);
  comment **created** when none exists; comment **updated** (PATCH) when one exists; poster posts
  both and carries the failure conclusion.
- `tests/test_webhook.py` (+2): `handle()` posts via an injected poster on a vulnerable PR; and
  **survives a posting failure** (`posted: false`, verdict stands).

## Verification
- 20 app tests green; full suite green; `ruff` + `ruff format` clean; `mypy` clean (app = 5 files).

## Scope boundaries (not in V2)
- **Install-token minting** (JWT → installation access token) → **V3**.
- **Fetching a remote clone** of the PR → **V3**; V2 still runs on a local checkout.
- A **live** post to real GitHub needs V3 auth + a registered App + the SG-017/SG-018 gates.

## What's proven
After the gate runs, AgentSentinel produces a correct GitHub **Check Run** (pass/fail) and an
**idempotent** PR comment (update-in-place), with posting failures isolated from the verdict — all
verified without touching the network.
