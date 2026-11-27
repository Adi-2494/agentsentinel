"""v2 V2: post the result back to GitHub (Check Run + upserted PR comment). No network."""

from app.github import MARKER, GitHubClient, GitHubPoster
from app.runner import Job, JobResult


class FakeTransport:
    """Records calls and returns scripted responses, so no HTTP happens."""

    def __init__(self, comments=None):
        self.calls = []  # (method, url, headers, body_dict)
        self._comments = comments or []

    def __call__(self, method, url, headers, body):
        import json

        self.calls.append((method, url, headers, json.loads(body) if body else None))
        if method == "GET" and url.endswith("/comments"):
            return 200, self._comments
        return 201, {"id": 999}


def _client(comments=None):
    t = FakeTransport(comments)
    return GitHubClient(token="tok", transport=t, api="https://api.github.com"), t


def _result(failed=True):
    return JobResult(
        failed=failed,
        blocking_count=2 if failed else 0,
        exit_code=1 if failed else 0,
        errors=[],
        conclusion="failure" if failed else "success",
        report_markdown=f"{MARKER}\n## report",
    )


def test_check_run_payload_is_correct():
    c, t = _client()
    c.post_check_run("o/r", "deadbeef", "failure", "Merge blocked", "2 blocking.")
    method, url, headers, body = t.calls[-1]
    assert method == "POST" and url == "https://api.github.com/repos/o/r/check-runs"
    assert headers["Authorization"] == "Bearer tok" and headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert body["head_sha"] == "deadbeef" and body["conclusion"] == "failure"
    assert body["status"] == "completed" and body["output"]["title"] == "Merge blocked"


def test_comment_is_created_when_none_exists():
    c, t = _client(comments=[])
    c.upsert_comment("o/r", 7, f"{MARKER} body")
    methods = [m for m, *_ in t.calls]
    assert methods == ["GET", "POST"]  # looked, found none, created
    assert t.calls[-1][1].endswith("/issues/7/comments")


def test_comment_is_updated_when_one_exists():
    c, t = _client(comments=[{"id": 55, "body": f"{MARKER} old"}, {"id": 1, "body": "someone else"}])
    c.upsert_comment("o/r", 7, f"{MARKER} new")
    method, url, _, body = t.calls[-1]
    assert method == "PATCH" and url.endswith("/issues/comments/55")  # updated the existing one
    assert body["body"] == f"{MARKER} new"


def test_poster_posts_check_run_and_comment():
    c, t = _client(comments=[])
    GitHubPoster(client=c).publish(Job("o/r", 7, "sha1", "main"), _result(failed=True))
    paths = [url for _, url, *_ in t.calls]
    assert any("/check-runs" in p for p in paths) and any("/comments" in p for p in paths)
    # the check-run carried the failure conclusion
    check = next(b for m, u, h, b in t.calls if "/check-runs" in u)
    assert check["conclusion"] == "failure"
