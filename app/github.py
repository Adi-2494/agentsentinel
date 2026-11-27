"""Post AgentSentinel results back to GitHub: a Check Run + an upserted PR comment (v2 V2).

All HTTP goes through one `transport` seam, so tests run with no network. The install-token
wiring is V3; here the token is passed in. Posting never changes the gate's verdict — the verdict
is already decided; this only reports it.
"""

import json
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.runner import Job, JobResult

MARKER = "<!-- agentsentinel-report -->"
API = "https://api.github.com"

# transport(method, url, headers, body) -> (status, parsed_json)
Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, Any]]


def _urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, Any]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310 - https API only
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else {})


@dataclass
class GitHubClient:
    token: str
    transport: Transport = _urllib_transport
    api: str = API

    def _req(self, method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AgentSentinel",
        }
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        return self.transport(method, f"{self.api}{path}", headers, body)

    def post_check_run(self, repo: str, head_sha: str, conclusion: str, title: str, summary: str) -> Any:
        _, data = self._req(
            "POST",
            f"/repos/{repo}/check-runs",
            {
                "name": "AgentSentinel",
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": conclusion,  # success | failure | neutral
                "output": {"title": title, "summary": summary[:65000]},
            },
        )
        return data

    def upsert_comment(self, repo: str, pr_number: int, markdown: str) -> Any:
        """Update AgentSentinel's existing PR comment if present (no spam), else create one."""
        _, comments = self._req("GET", f"/repos/{repo}/issues/{pr_number}/comments")
        existing = None
        if isinstance(comments, list):
            existing = next((c for c in comments if isinstance(c, dict) and MARKER in (c.get("body") or "")), None)
        if existing is not None:
            _, data = self._req("PATCH", f"/repos/{repo}/issues/comments/{existing['id']}", {"body": markdown})
        else:
            _, data = self._req("POST", f"/repos/{repo}/issues/{pr_number}/comments", {"body": markdown})
        return data


@dataclass
class GitHubPoster:
    """Satisfies the webhook's Poster protocol: publish a JobResult back to the PR."""

    client: GitHubClient = field(default=None)  # type: ignore[assignment]  # required at call time

    def publish(self, job: Job, result: JobResult) -> None:
        title = "Merge blocked" if result.failed else "No blocking findings"
        summary = f"{result.blocking_count} blocking finding(s)." if result.failed else "AgentSentinel passed."
        self.client.post_check_run(job.repo, job.head_sha, result.conclusion, title, summary)
        self.client.upsert_comment(job.repo, job.pr_number, result.report_markdown)
