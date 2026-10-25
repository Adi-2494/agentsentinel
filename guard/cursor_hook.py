"""Cursor hook: the same Live Guard rules, wired to Cursor's hook events.

Cursor sends JSON on stdin (hook_event_name + event fields) and reads
{"permission": "allow"|"deny"|"ask", "user_message", "agent_message"} back.
Rules only, no LLM. Register with:  python guard/install.py --cursor <project>
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import store  # noqa: E402
from core.detectors import files, injection, pii, secrets  # noqa: E402
from core.detectors.base import Finding, max_severity  # noqa: E402
from guard.claude_hook import DENY, MAX_READ_BYTES, _reason, evaluate  # noqa: E402

SOURCE = "cursor"
# events whose response schema accepts "ask"
ASK_OK = {"beforeShellExecution", "beforeMCPExecution"}
AFTER_EVENTS = {"afterShellExecution"}
WRITE_TOOL_HINTS = ("write", "edit", "replace", "create", "patch")


def _strings(value) -> list[str]:
    """All string values inside a (possibly JSON-encoded) tool_input."""
    if isinstance(value, str):
        try:
            return _strings(json.loads(value)) if value[:1] in "{[" else [value]
        except json.JSONDecodeError:
            return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _content_findings(text: str, path: str = "") -> list[Finding]:
    return secrets.scan(text) + pii.scan(text) + injection.scan(text, path)


def evaluate_cursor(event: dict) -> tuple[str | None, list[Finding]]:
    name = event.get("hook_event_name", "")
    if name == "beforeShellExecution":
        return evaluate("Bash", {"command": event.get("command", "")}, event.get("cwd", ""))
    if name == "beforeReadFile":
        path = event.get("file_path", "")
        found = files.check_path(path)
        if not found:
            content = event.get("content") or ""
            if len(content) > MAX_READ_BYTES:  # beforeReadFile cannot "ask": refuse instead of skipping
                return "deny", [Finding(rule="file_too_large_to_scan", category="injection", severity="HIGH",
                                        message=f"File larger than {MAX_READ_BYTES // 1_000_000} MB scan limit",
                                        preview=Path(path).name)]
            found = injection.scan(content) + secrets.scan(content)
    elif name == "preToolUse":
        tool = str(event.get("tool_name", ""))
        if not any(h in tool.lower() for h in WRITE_TOOL_HINTS):
            return None, []
        inp = event.get("tool_input") or {}
        if isinstance(inp, str) and inp[:1] == "{":
            inp = json.loads(inp)
        path = ""
        if isinstance(inp, dict):
            path = inp.get("file_path") or inp.get("path") or inp.get("target_file") or ""
        found = files.check_path(path) or _content_findings("\n".join(_strings(inp)), path)
    elif name == "beforeMCPExecution":
        found = secrets.scan("\n".join(_strings(event.get("tool_input"))))  # secrets leaving via MCP
    else:
        return None, []
    sev = max_severity(found)
    if sev in DENY:
        return "deny", found
    if sev == "MEDIUM":
        return ("ask" if name in ASK_OK else "allow"), found
    return None, found


def after_event(event: dict) -> list[Finding]:
    """afterShellExecution: Cursor can't rewrite output, so log traps/secrets for the dashboard."""
    if event.get("hook_event_name") != "afterShellExecution":
        return []
    out = event.get("output") or ""
    return injection.scan(out) + secrets.scan(out)


def main() -> int:
    try:
        event = json.load(sys.stdin)
        name = event.get("hook_event_name", "")
        if name in AFTER_EVENTS:  # not a permission event: log only, print nothing
            for f in after_event(event):
                store.log_event(SOURCE, "warned", f.rule, f.severity, {
                    "tool": name, "preview": f.preview, "message": f.message + " (in command output)",
                    "category": f.category})
            return 0
        decision, findings = evaluate_cursor(event)
        if not decision:
            print(json.dumps({"permission": "allow"}))
            return 0
        action = {"deny": "blocked", "ask": "warned", "allow": "warned"}[decision]
        for f in findings:
            store.log_event(SOURCE, action, f.rule, f.severity, {
                "tool": name, "preview": f.preview, "message": f.message, "category": f.category,
                "cwd": event.get("cwd", "") or ",".join(event.get("workspace_roots") or [])})
        reason = _reason(findings)
        print(json.dumps({"permission": decision, "user_message": reason, "agent_message": reason}))
    except Exception as e:  # fail open, like the Claude Code hook
        print(f"AgentSentinel cursor hook error (action allowed): {e}", file=sys.stderr)
        print(json.dumps({"permission": "allow"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
