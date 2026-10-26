"""llm.py logic tested with a fake subprocess: never calls Claude."""

import json
import subprocess

import pytest

from core import llm


class FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def fake_claude(monkeypatch, *replies):
    calls = []
    queue = list(replies)

    def run(cmd, **kw):
        calls.append((cmd, kw))
        return queue.pop(0)

    monkeypatch.setattr(llm.shutil, "which", lambda _: "/usr/bin/claude")
    monkeypatch.setattr(llm.subprocess, "run", run)
    return calls


def ok(result):
    return FakeProc(json.dumps({"type": "result", "is_error": False, "result": result}))


def test_ask_llm_success_and_flags(monkeypatch):
    calls = fake_claude(monkeypatch, ok("ready"))
    assert llm.ask_llm("Reply with ready", "haiku", backend="claude_code") == "ready"
    cmd, kw = calls[0]
    assert kw["input"] == "Reply with ready"  # prompt via stdin
    assert cmd[cmd.index("--model") + 1] == "haiku"
    assert cmd[cmd.index("--tools") + 1] == ""  # no tools for the model
    assert "--strict-mcp-config" in cmd


def test_not_installed(monkeypatch):
    monkeypatch.setattr(llm.shutil, "which", lambda _: None)
    with pytest.raises(llm.LLMNotInstalled):
        llm.ask_llm("hi", backend="claude_code")


def test_limit_reached(monkeypatch):
    fake_claude(
        monkeypatch,
        FakeProc(
            json.dumps({"is_error": True, "result": "Claude usage limit reached. Your limit will reset at 5pm"}),
            returncode=1,
        ),
    )
    with pytest.raises(llm.LLMLimitReached, match="LLM_BACKEND=ollama"):
        llm.ask_llm("hi", backend="claude_code")


def test_not_logged_in(monkeypatch):
    fake_claude(monkeypatch, FakeProc("", "Invalid API key · Please run /login", 1))
    with pytest.raises(llm.LLMNotLoggedIn):
        llm.ask_llm("hi", backend="claude_code")


def test_timeout(monkeypatch):
    monkeypatch.setattr(llm.shutil, "which", lambda _: "/usr/bin/claude")

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("claude", 1)

    monkeypatch.setattr(llm.subprocess, "run", boom)
    with pytest.raises(llm.LLMError, match="timed out"):
        llm.ask_llm("hi", backend="claude_code", timeout=1)


@pytest.mark.parametrize(
    "reply,expected",
    [
        ('{"verdict": "safe"}', {"verdict": "safe"}),
        ('Sure!\n```json\n{"verdict": "vulnerable"}\n```', {"verdict": "vulnerable"}),
        ('Here you go: [{"id": 1}] hope it helps', [{"id": 1}]),
    ],
)
def test_extract_json(reply, expected):
    assert llm.extract_json(reply) == expected


def test_ask_json_retries_once(monkeypatch):
    calls = fake_claude(monkeypatch, ok("not json at all"), ok('{"ok": true}'))
    assert llm.ask_json("give json", backend="claude_code") == {"ok": True}
    assert len(calls) == 2 and "not valid JSON" in calls[1][1]["input"]


def test_ask_json_gives_up_after_retry(monkeypatch):
    fake_claude(monkeypatch, ok("nope"), ok("still nope"))
    with pytest.raises(llm.LLMBadResponse):
        llm.ask_json("give json", backend="claude_code")


def test_invalid_ci_token_is_auth_error(monkeypatch):
    fake_claude(
        monkeypatch,
        FakeProc(
            json.dumps({"is_error": True, "result": "Failed to authenticate. API Error: 401 Invalid bearer token"}),
            returncode=1,
        ),
    )
    with pytest.raises(llm.LLMNotLoggedIn, match="CLAUDE_CODE_OAUTH_TOKEN"):
        llm.ask_llm("hi", backend="claude_code")
