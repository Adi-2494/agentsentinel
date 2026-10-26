"""Live-Claude tests (marker `llm`) use the developer's Claude plan. They run ONLY with an
explicit --run-llm flag, so no -m expression (e.g. -m "not integration") can enable them by accident."""

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-llm", action="store_true", default=False, help="run tests marked llm (makes real Claude calls)"
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-llm"):
        return
    skip = pytest.mark.skip(reason="live Claude test: pass --run-llm to run it")
    for item in items:
        if "llm" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _no_real_llm_calls(request, monkeypatch):
    """Safety net: unless --run-llm is given, starting the real `claude` CLI or calling Ollama fails
    the test loudly. Tests that substitute a fake subprocess / LLM function are unaffected."""
    if request.config.getoption("--run-llm"):
        return
    import os
    import subprocess
    import urllib.request

    from core import config

    real_run, real_urlopen = subprocess.run, urllib.request.urlopen

    def guarded_run(cmd, *args, **kwargs):
        exe = cmd[0] if isinstance(cmd, (list, tuple)) and cmd else ""
        if os.path.basename(str(exe)).lower().startswith("claude"):
            raise AssertionError("real `claude` call attempted in a test (stub the LLM, or run with --run-llm)")
        return real_run(cmd, *args, **kwargs)

    def guarded_urlopen(req, *args, **kwargs):
        url = getattr(req, "full_url", str(req))
        if url.startswith(config.OLLAMA_URL):
            raise AssertionError("real Ollama call attempted in a test (stub the LLM, or run with --run-llm)")
        return real_urlopen(req, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded_run)
    monkeypatch.setattr(urllib.request, "urlopen", guarded_urlopen)


@pytest.fixture(autouse=True)
def _close_cached_db_connections():
    """The activity log reuses connections; close them after each test so temp folders can be
    deleted (Windows refuses to delete an open file) and tests never share a connection."""
    yield
    from core import store

    store.close_all()
