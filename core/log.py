"""Structured logging for every AgentSentinel surface.

Why: hooks speak JSON on stdout to the AI tool, so diagnostics must go to stderr and
must never mix with the protocol. When something goes wrong, people need to know WHAT
kind of thing went wrong, so every problem carries one fixed category (CATEGORIES).

    AGENTSENTINEL_LOG_LEVEL=debug     (or `run_gate.py --verbose`) for timings and decisions
    AGENTSENTINEL_LOG_FORMAT=json     one JSON object per line, for log collectors

Log lines never contain scanned code, prompts or secret values: only names, counts,
sizes, timings and already-masked previews.
"""

import json
import logging
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from core import config

# Every problem has exactly one category, so a log search can answer "what broke?"
CATEGORIES = {
    "config": "a setting is invalid (see python -m core.config)",
    "input": "the hook or gate got input it could not read",
    "llm_unavailable": "the LLM could not be reached or is not installed",
    "llm_limit": "the LLM usage limit was reached",
    "llm_reply": "the LLM answered, but not in the expected format",
    "tool_missing": "Semgrep or Gitleaks is not installed",
    "tool_failed": "Semgrep, Gitleaks or git failed while running",
    "storage": "the SQLite activity log could not be written",
    "internal": "a bug in AgentSentinel itself",
}
# How a gate error message maps to a category (first match wins; checked by tests)
_RULES = [
    ("llm_limit", ("limit reached", "usage limit", "rate limit")),
    ("tool_missing", ("semgrep not installed", "gitleaks not installed")),
    ("input", ("could not parse", "could not read", "binary files not reviewed", "unreadable")),
    ("llm_reply", ("valid json", "unexpected reply", "could not understand")),
    ("llm_unavailable", ("not installed", "not reachable", "timed out", "claude code", "ollama", "incomplete")),
    ("tool_failed", ("semgrep", "gitleaks", "git ")),
]


def categorize(message: str) -> str:
    text = message.lower()
    for category, needles in _RULES:
        if any(n in text for n in needles):
            return category
    return "internal"


_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}
_RESERVED = set(vars(logging.makeLogRecord({})))


class _Json(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        out.update({k: v for k, v in vars(record).items() if k not in _RESERVED and not k.startswith("_")})
        return json.dumps(out, ensure_ascii=False, default=str)


class _Text(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        extra = {k: v for k, v in vars(record).items() if k not in _RESERVED and not k.startswith("_")}
        cat = extra.pop("category", None)
        fields = " ".join(f"{k}={v}" for k, v in extra.items())
        head = f"AgentSentinel {record.levelname.lower()}" + (f" [{cat}]" if cat else "")
        return f"{head}: {record.getMessage()}" + (f" ({fields})" if fields else "")


_configured = False


def setup(level: str | None = None) -> None:
    """Send AgentSentinel logs to stderr. Idempotent; `level` overrides the setting (e.g. --verbose)."""
    global _configured
    root = logging.getLogger("agentsentinel")
    if level is not None:  # an explicit choice (--verbose) always wins
        root.setLevel(_LEVELS[level])
    if _configured:
        return
    if level is None:
        root.setLevel(_LEVELS[config.LOG_LEVEL])
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_Json() if config.LOG_FORMAT == "json" else _Text())
    root.addHandler(handler)
    root.propagate = False
    _configured = True


def get(name: str) -> logging.Logger:
    setup()
    return logging.getLogger(f"agentsentinel.{name}")


def problem(logger: logging.Logger, category: str, message: str, **fields: Any) -> None:
    """Log a problem with its category (warning level; it is handled, not a crash)."""
    if category not in CATEGORIES:
        raise ValueError(f"unknown log category {category!r}")
    logger.warning(message, extra={"category": category, **fields})


@contextmanager
def timed(logger: logging.Logger, step: str, **fields: Any) -> Iterator[None]:
    """Debug-log how long a step took."""
    start = time.perf_counter()
    try:
        yield
    finally:
        logger.debug(f"{step} done", extra={"step": step, "ms": round(1000 * (time.perf_counter() - start)), **fields})
