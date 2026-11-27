"""GitHub App webhook receiver (v2 V1/V2): verify the signature, turn a pull_request event into a
Job, run the unchanged Merge Gate on the PR head, log it, and (V2) post the result back. Stdlib only.

`handle()` is the testable core. Fails closed: a bad signature, unreadable body, or a gate crash
never looks like a pass. Posting is injected (the `poster` seam) so the core stays testable and a
posting failure can't change the gate's verdict.
"""

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from app.runner import Job, JobResult, run_job
from core import log

PR_ACTIONS = {"opened", "synchronize", "reopened"}
ResolveRepo = Callable[[str], Path | None]


class Poster(Protocol):
    def publish(self, job: Job, result: JobResult) -> None: ...


def verify_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Constant-time check of GitHub's X-Hub-Signature-256. No secret or header => reject."""
    if not secret or not signature_header:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def parse_event(event_type: str, payload: dict[str, Any]) -> Job | None:
    """A reviewable pull_request event -> Job; anything else -> None (ignored)."""
    if event_type != "pull_request" or payload.get("action") not in PR_ACTIONS:
        return None
    pr = payload.get("pull_request") or {}
    repo = (payload.get("repository") or {}).get("full_name")
    head = (pr.get("head") or {}).get("sha")
    base = (pr.get("base") or {}).get("ref")
    number = payload.get("number") or pr.get("number")
    if not (isinstance(repo, str) and isinstance(head, str) and isinstance(base, str) and isinstance(number, int)):
        return None
    return Job(repo=repo, pr_number=number, head_sha=head, base_ref=base, pr_body=pr.get("body") or "")


@dataclass(frozen=True)
class Response:
    code: int  # HTTP status
    status: str  # rejected | ignored | unknown_repo | processed | error
    detail: dict[str, Any]


def handle(
    event_type: str,
    body: bytes,
    signature_header: str | None,
    secret: str,
    resolve_repo: ResolveRepo,
    use_llm: bool = True,
    poster: Poster | None = None,
) -> Response:
    """verify -> parse -> locate repo -> run the gate -> log -> (V2) post back. Fails closed."""
    logger = log.get("webhook")
    if not verify_signature(secret, body, signature_header):
        log.problem(logger, "input", "rejected webhook: bad or missing signature")
        return Response(401, "rejected", {"reason": "invalid signature"})
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("payload is not a JSON object")
    except (ValueError, json.JSONDecodeError) as e:
        log.problem(logger, "input", f"rejected webhook: unreadable body: {e}")
        return Response(400, "rejected", {"reason": "unreadable body"})
    job = parse_event(event_type, payload)
    if job is None:
        return Response(204, "ignored", {"event": event_type})
    repo_root = resolve_repo(job.repo)
    if repo_root is None:
        log.problem(logger, "input", f"no local checkout for {job.repo}")
        return Response(404, "unknown_repo", {"repo": job.repo})
    try:
        result = run_job(job, repo_root, use_llm=use_llm)
    except Exception as e:  # noqa: BLE001 - fail closed: a crash must not look like a pass
        log.problem(logger, "internal", f"gate run failed for {job.repo}#{job.pr_number}: {e}")
        return Response(500, "error", {"repo": job.repo, "pr": job.pr_number, "failed": True})

    posted = None
    if poster is not None:
        try:
            poster.publish(job, result)
            posted = True
        except Exception as e:  # noqa: BLE001 - a posting failure must not crash; the verdict already stands
            log.problem(logger, "internal", f"could not post result for {job.repo}#{job.pr_number}: {e}")
            posted = False

    detail: dict[str, Any] = {
        "repo": job.repo,
        "pr": job.pr_number,
        "failed": result.failed,
        "blocking": result.blocking_count,
    }
    if posted is not None:
        detail["posted"] = posted
    return Response(200, "processed", detail)
