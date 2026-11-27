"""Thin stdlib HTTP glue around app.webhook.handle (v2 V1/V2). Run behind TLS on the owner's host.

    WEBHOOK_SECRET=...  AGENTSENTINEL_REPOS='{"owner/name":"/path/to/clone"}'  \
    GITHUB_TOKEN=...  python -m app.server

All security checks and the gate run live in app.webhook.handle (unit-tested). With GITHUB_TOKEN
set, results are posted back (Check Run + PR comment); without it, the gate still runs and logs.
The token here is passed through; per-install token minting is V3.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.github import GitHubClient, GitHubPoster
from app.webhook import Poster, handle
from core import config, log


def _repo_map() -> dict[str, str]:
    """owner/name -> local checkout path, from AGENTSENTINEL_REPOS (JSON object)."""
    try:
        data = json.loads(os.getenv("AGENTSENTINEL_REPOS", "{}"))
    except json.JSONDecodeError:
        return {}
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def _poster() -> Poster | None:
    token = os.getenv("GITHUB_TOKEN", "")
    return GitHubPoster(GitHubClient(token)) if token else None


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # BaseHTTPRequestHandler API name
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)
        repos = _repo_map()

        def resolve(repo: str) -> Path | None:
            path = repos.get(repo)
            return Path(path) if path else None

        resp = handle(
            self.headers.get("X-GitHub-Event", ""),
            body,
            self.headers.get("X-Hub-Signature-256"),
            os.getenv("WEBHOOK_SECRET", ""),
            resolve,
            poster=_poster(),
        )
        if resp.code == 204:
            self.send_response(204)
            self.end_headers()
            return
        payload = json.dumps({"status": resp.status, **resp.detail}).encode()
        self.send_response(resp.code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:  # we log through core.log, not to stderr
        pass


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    config.require_valid()
    log.get("server").info(f"AgentSentinel webhook listening on {host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    serve(os.getenv("WEBHOOK_HOST", "127.0.0.1"), int(os.getenv("WEBHOOK_PORT", "8787")))
