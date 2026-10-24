"""Claude Code PreToolUse hook: the Live Guard (Part A). Rules only, no LLM.

Claude Code sends JSON on stdin ({tool_name, tool_input, ...}); we reply on
stdout with a permission decision:
  CRITICAL/HIGH -> deny   (Claude is told why)
  MEDIUM        -> ask    (the user confirms)
  nothing found -> no output, normal permission flow continues
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import store  # noqa: E402
from core.detectors import commands, files  # noqa: E402
from core.detectors.base import Finding, max_severity  # noqa: E402

SOURCE = "claude_code"
DENY = {"HIGH", "CRITICAL"}


def _paths(tool: str, inp: dict) -> list[str]:
    if tool in ("Read", "Write", "Edit", "MultiEdit"):
        return [inp.get("file_path", "")]
    if tool == "NotebookEdit":
        return [inp.get("notebook_path", "")]
    if tool in ("Grep", "Glob"):
        return [inp.get("path", "") or ""]
    return []


def evaluate(tool: str, inp: dict) -> tuple[str | None, list[Finding]]:
    """Return (decision, findings); decision is 'deny', 'ask' or None."""
    findings: list[Finding] = []
    for path in _paths(tool, inp):
        findings += files.check_path(path)
    if tool == "Bash":
        findings += commands.check(inp.get("command", ""))
    sev = max_severity(findings)
    if sev in DENY:
        return "deny", findings
    if sev == "MEDIUM":
        return "ask", findings
    return None, findings


def _reason(findings: list[Finding]) -> str:
    lines = [f"- [{f.severity}] {f.rule}: {f.message}" for f in findings]
    return "AgentSentinel blocked this action:\n" + "\n".join(lines)


def main() -> int:
    try:
        event = json.load(sys.stdin)
        tool, inp = event.get("tool_name", ""), event.get("tool_input") or {}
        decision, findings = evaluate(tool, inp)
        if not decision:
            return 0
        action = "blocked" if decision == "deny" else "warned"
        for f in findings:
            store.log_event(SOURCE, action, f.rule, f.severity, {
                "tool": tool, "preview": f.preview, "message": f.message,
                "cwd": event.get("cwd", ""),
            })
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": _reason(findings),
        }}))
    except Exception as e:  # fail open: a guard bug must not brick the session
        print(f"AgentSentinel hook error (action allowed): {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
