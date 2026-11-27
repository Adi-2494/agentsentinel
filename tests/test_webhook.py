"""v2 V1: the GitHub App webhook receiver runs the real Merge Gate on a signed PR event.

No live GitHub and no LLM: the gate runs on a local git repo with use_llm=False (static engine).
"""

import hashlib
import hmac
import json
import subprocess

import pytest

from app import webhook
from core import store

SECRET = "testsecret"


def _sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _pr_payload(repo="o/r", number=1, action="opened", body="", head="HEADSHA", base="main"):
    return {
        "action": action,
        "number": number,
        "repository": {"full_name": repo},
        "pull_request": {"number": number, "body": body, "head": {"sha": head}, "base": {"ref": base}},
    }


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


# ------------------------------------------------------------------ signature
def test_verify_signature_valid_invalid_missing():
    body = b'{"a":1}'
    assert webhook.verify_signature(SECRET, body, _sign(body))
    assert not webhook.verify_signature(SECRET, body, _sign(body, "wrong"))
    assert not webhook.verify_signature(SECRET, body, None)
    assert not webhook.verify_signature("", body, _sign(body))  # no secret configured -> reject


# ------------------------------------------------------------------ parse
@pytest.mark.parametrize(
    "event,action,ok",
    [
        ("pull_request", "opened", True),
        ("pull_request", "synchronize", True),
        ("pull_request", "reopened", True),
        ("pull_request", "closed", False),
        ("push", "opened", False),
        ("issues", "opened", False),
    ],
)
def test_parse_event(event, action, ok):
    job = webhook.parse_event(event, _pr_payload(action=action))
    assert (job is not None) == ok
    if ok and job is not None:
        assert job.repo == "o/r" and job.base_ref == "main" and job.head_sha == "HEADSHA"


def test_parse_event_missing_fields_returns_none():
    assert webhook.parse_event("pull_request", {"action": "opened"}) is None


# ------------------------------------------------------------------ handle guards
def test_handle_rejects_bad_signature(tmp_path):
    body = json.dumps(_pr_payload()).encode()
    r = webhook.handle("pull_request", body, "sha256=bad", SECRET, lambda repo: tmp_path)
    assert r.code == 401 and r.status == "rejected"


def test_handle_ignores_non_pr_events(tmp_path):
    body = json.dumps({"action": "created"}).encode()
    r = webhook.handle("issues", body, _sign(body), SECRET, lambda repo: tmp_path)
    assert r.code == 204 and r.status == "ignored"


def test_handle_unknown_repo():
    body = json.dumps(_pr_payload()).encode()
    r = webhook.handle("pull_request", body, _sign(body), SECRET, lambda repo: None)
    assert r.code == 404 and r.status == "unknown_repo"


def test_handle_rejects_unreadable_body(tmp_path):
    body = b"not json"
    r = webhook.handle("pull_request", body, _sign(body), SECRET, lambda repo: tmp_path)
    assert r.code == 400 and r.status == "rejected"


# ------------------------------------------------------------------ end-to-end
def test_signed_pr_event_runs_gate_and_blocks_vulnerable(tmp_path, monkeypatch):
    monkeypatch.setattr("core.config.DB_PATH", tmp_path / "ev.db")
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@t.test")
    _git(repo, "config", "user.name", "t")
    f = repo / "app.py"
    f.write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "pr")
    f.write_text('KEY = "sk-ant-api03-REALSECRETVALUE1234567890abcdef"\n', encoding="utf-8")  # a secret (rules, no LLM)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "leak")

    body = json.dumps(_pr_payload(head="pr", base="main")).encode()
    r = webhook.handle("pull_request", body, _sign(body), SECRET, lambda name: repo, use_llm=False)

    assert r.code == 200 and r.status == "processed"
    assert r.detail["failed"] is True and r.detail["blocking"] >= 1
    assert any(e["source"] == "gate" for e in store.recent_events(db_path=tmp_path / "ev.db"))


class _RecordingPoster:
    def __init__(self, fail=False):
        self.published = []
        self._fail = fail

    def publish(self, job, result):
        if self._fail:
            raise RuntimeError("github down")
        self.published.append((job, result))


def _vuln_repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@t.test")
    _git(repo, "config", "user.name", "t")
    f = repo / "app.py"
    f.write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "pr")
    f.write_text('KEY = "sk-ant-api03-REALSECRETVALUE1234567890abcdef"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "leak")
    return repo


def test_handle_posts_result_when_poster_given(tmp_path, monkeypatch):
    monkeypatch.setattr("core.config.DB_PATH", tmp_path / "ev.db")
    repo = _vuln_repo(tmp_path)
    poster = _RecordingPoster()
    body = json.dumps(_pr_payload(head="pr", base="main")).encode()
    r = webhook.handle("pull_request", body, _sign(body), SECRET, lambda n: repo, use_llm=False, poster=poster)
    assert r.status == "processed" and r.detail["posted"] is True
    assert len(poster.published) == 1
    _job, result = poster.published[0]
    assert result.failed is True and result.conclusion == "failure"


def test_handle_survives_posting_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("core.config.DB_PATH", tmp_path / "ev.db")
    repo = _vuln_repo(tmp_path)
    body = json.dumps(_pr_payload(head="pr", base="main")).encode()
    r = webhook.handle(
        "pull_request", body, _sign(body), SECRET, lambda n: repo, use_llm=False, poster=_RecordingPoster(fail=True)
    )
    assert r.status == "processed" and r.detail["posted"] is False  # logged, not crashed; verdict stands


def test_handle_fails_closed_on_gate_error(tmp_path, monkeypatch):
    monkeypatch.setattr("core.config.DB_PATH", tmp_path / "ev.db")
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")  # empty repo: base/head refs don't exist -> gate errors
    body = json.dumps(_pr_payload(head="nope", base="main")).encode()
    r = webhook.handle("pull_request", body, _sign(body), SECRET, lambda name: repo, use_llm=False)
    assert r.detail.get("failed") is True  # error -> fail closed, never a silent pass
