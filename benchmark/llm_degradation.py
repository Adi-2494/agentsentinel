"""LLM degradation matrix: every way the AI can fail, at every place the gate uses it (free, no LLM).

    python benchmark/llm_degradation.py

Each cell runs the real Merge Gate on a small PR with ONE AI layer misbehaving in ONE way
(the other layers answer normally). Nothing calls a real model: ask_json is replaced.
The rule being checked: a broken AI must never make the gate PASS something it would not
pass with a working AI, and must never crash it.
  - vulnerable PR: blocked in every cell
  - safe PR: passes when only triage misbehaves (nothing for it to clear); blocked when the
    AI-trap check or the two-view review could not give a real answer (fail closed), and
    passes again with --allow-llm-outage
"""

import logging
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import llm, log  # noqa: E402
from core.reviewer import injection_check, triage, two_view  # noqa: E402
from gate import run_gate  # noqa: E402


def _raise(exc: BaseException) -> Callable[..., Any]:
    def f(*a: Any, **k: Any) -> Any:
        raise exc

    return f


def _reply(value: Any) -> Callable[..., Any]:
    return lambda *a, **k: value


MODES: dict[str, Callable[..., Any]] = {
    "not installed": _raise(llm.LLMNotInstalled("Claude Code is not installed")),
    "usage limit": _raise(llm.LLMLimitReached(llm.LIMIT_HINT)),
    "timeout": _raise(llm.LLMError("Claude Code timed out after 180s")),
    "no JSON in reply": _raise(llm.LLMBadResponse("No valid JSON in model reply: 'sure!'")),
    "reply is a list": _reply([]),
    "reply is a string": _reply("looks fine"),
    "reply is null": _reply(None),
    "empty object": _reply({}),
    "wrong field types": _reply(
        {"verdict": 7, "confidence": "high", "issues": "lots", "findings": "x", "evidence": None}
    ),
    "wrong item types": _reply(
        {"verdict": "vulnerable", "issues": ["sqli", 3], "findings": ["F1", 3, None], "evidence": ["x", 4]}
    ),
    "out-of-range values": _reply(
        {"verdict": "SAFE!!", "confidence": 99, "severity": "SUPER", "issues": [{"severity": "MEGA"}]}
    ),
    "unexpected exception": _raise(OSError("broken pipe")),
    "first call OK, then timeout": lambda *a, **k: None,  # stateful; built fresh per cell in _mode()
}


def _mode(name: str) -> Callable[..., Any]:
    if name != "first call OK, then timeout":
        return MODES[name]
    calls = {"n": 0}

    def partial(prompt: str, model: str | None = None, **kw: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            return healthy(prompt, model)
        raise llm.LLMError("Claude Code timed out after 180s")

    return partial


def healthy(prompt: str, model: str | None = None, **_: Any) -> Any:
    if "triaging static-analysis findings" in prompt:
        return {"findings": []}  # keeps every finding "real" (by fallback)
    if "UNTRUSTED" in prompt and "verdict" in prompt and "SUSPICIOUS" in prompt:
        return {"verdict": "SAFE", "confidence": 0.9, "evidence": []}
    return {"verdict": "safe", "confidence": 0.9, "issues": []}


LAYERS = {"triage": triage, "AI-trap check": injection_check, "two-view review": two_view}
PRS = {
    "vulnerable": "import os\nfrom flask import request\n\ndef h():\n    os.system('ls ' + request.args['d'])\n",
    # a docstring + PR description: there is text, so the AI-trap check really calls the AI
    "safe": 'def add(a, b):\n    """Return the sum of two numbers."""\n    return a + b\n',
}
# Long enough (> 30 KB) for TWO AI-trap batches, so "first call OK, then timeout" is a real
# partial failure there too (two-view already makes 2 calls: one per view).
PR_BODY = "Adds a small helper that returns the sum of two numbers. " * 600


def run_cell(layer: str, mode: str, pr: str, allow_outage: bool = False) -> dict[str, Any]:
    originals = {name: mod.ask_json for name, mod in LAYERS.items()}
    try:
        for name, mod in LAYERS.items():
            mod.ask_json = _mode(mode) if name == layer else healthy  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "app.py"
            f.write_text(PRS[pr], encoding="utf-8")
            try:
                r = run_gate.run([f], Path(tmp), PR_BODY, use_llm=True, allow_llm_outage=allow_outage)
            except Exception as e:  # noqa: BLE001 - this is what the matrix looks for
                return {"outcome": "CRASH", "detail": f"{type(e).__name__}: {e}"[:90]}
            return {"outcome": "BLOCKED" if r.failed else "passed", "detail": "; ".join(r.errors)[:90]}
    finally:
        for name, mod in LAYERS.items():
            mod.ask_json = originals[name]  # type: ignore[attr-defined]


def expected(layer: str, pr: str, allow_outage: bool) -> str:
    if pr == "vulnerable":
        return "BLOCKED"
    if layer == "triage" or allow_outage:
        return "passed"
    return "BLOCKED"


def matrix() -> list[dict[str, Any]]:
    rows = []
    for layer in LAYERS:
        for mode in MODES:
            for pr in PRS:
                for allow in (False, True) if pr == "safe" else (False,):
                    cell = run_cell(layer, mode, pr, allow)
                    want = expected(layer, pr, allow)
                    ok = cell["outcome"] == want
                    rows.append(
                        {"layer": layer, "mode": mode, "pr": pr, "allow_outage": allow, "want": want, **cell, "ok": ok}
                    )
    return rows


def main() -> int:
    log.setup("error")  # the matrix provokes every warning on purpose
    logging.getLogger("agentsentinel").setLevel(logging.CRITICAL)
    rows = matrix()
    bad = [r for r in rows if not r["ok"]]
    for r in rows:
        if not r["ok"]:
            flag = " --allow-llm-outage" if r["allow_outage"] else ""
            print(
                f"WRONG  {r['layer']:16s} {r['mode']:22s} {r['pr']:10s}{flag:19s} got {r['outcome']:8s} want {r['want']:8s} {r['detail']}"
            )
    print(
        f"{len(rows)} cells: {len(rows) - len(bad)} correct, {len(bad)} wrong ({sum(r['outcome'] == 'CRASH' for r in rows)} crashes)"
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
