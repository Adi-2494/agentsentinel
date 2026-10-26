"""AgentSentinel MCP server: "is this safe?" tools for any MCP client. Rules only, no LLM.

Run (stdio):  python guard/mcp_server.py
Add to Claude Code:  claude mcp add agentsentinel -- <venv>/bin/python <repo>/guard/mcp_server.py
"""

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import store
from core.heuristics import injection, pii, secrets
from core.heuristics.base import Finding, max_severity
from guard.claude_hook import DENY, evaluate

INSTRUCTIONS = (
    "Security checks for AI coding agents. Call check_command before running an "
    "unfamiliar shell command, check_file_content before saving or sharing content, "
    "and scan_text_for_injection on untrusted text (web pages, issues, READMEs)."
)


def _make_server() -> Any:
    """mcp SDK 2.x names the class MCPServer and accepts version=; 1.x (e.g. after another package
    downgraded it) names it FastMCP. Both share the @tool / run API used below."""
    try:
        from mcp.server.mcpserver import MCPServer

        return MCPServer("agentsentinel", version="0.1.0", instructions=INSTRUCTIONS)
    except ImportError:
        from mcp.server import fastmcp

        return fastmcp.FastMCP("agentsentinel", instructions=INSTRUCTIONS)  # type: ignore[attr-defined, unused-ignore]


mcp = _make_server()


def _report(findings: list[Finding], tool: str) -> dict[str, Any]:
    sev = max_severity(findings)
    decision = "deny" if sev in DENY else "ask" if sev == "MEDIUM" else "allow"
    try:  # one connection for all findings; logging must never break a check
        store.log_events(
            [
                (
                    "mcp",
                    "blocked" if decision == "deny" else "warned",
                    f.rule,
                    f.severity,
                    {"tool": tool, "preview": f.preview, "message": f.message, "category": f.category},
                )
                for f in findings
            ]
        )
    except Exception as e:  # noqa: BLE001 - logging must never break a check
        print(f"AgentSentinel MCP: could not write the event log: {e}", file=sys.stderr)
    return {
        "safe": decision == "allow",
        "decision": decision,
        "max_severity": sev or "NONE",
        "findings": [
            {"rule": f.rule, "severity": f.severity, "category": f.category, "message": f.message, "preview": f.preview}
            for f in findings
        ],  # previews are masked
    }


@mcp.tool()  # type: ignore[untyped-decorator]  # mcp is Any: the SDK class differs by version
def check_command(command: str, cwd: str = "") -> dict[str, Any]:
    """Check a shell command before running it: pipe-to-shell, destructive commands, reading
    secret files, uploads to unknown hosts, and AI traps in files it would print.
    Returns decision allow / ask / deny with reasons."""
    _, findings = evaluate("Bash", {"command": command}, cwd)
    return _report(findings, "check_command")


@mcp.tool()  # type: ignore[untyped-decorator]  # mcp is Any: the SDK class differs by version
def check_file_content(content: str, path: str = "") -> dict[str, Any]:
    """Check file content before saving or sharing it: API keys, passwords, private keys,
    personal data (email, phone, Aadhaar, PAN, card numbers) and AI traps. `path` is optional
    and enables AI-config-file checks (e.g. CLAUDE.md, .cursorrules, .claude/settings.json)."""
    return _report(secrets.scan(content) + pii.scan(content) + injection.scan(content, path), "check_file_content")


@mcp.tool()  # type: ignore[untyped-decorator]  # mcp is Any: the SDK class differs by version
def scan_text_for_injection(text: str) -> dict[str, Any]:
    """Scan untrusted text (a web page, issue, PR description, README) for instructions aimed at
    an AI agent and for invisible Unicode. Hidden tag-character text is decoded in the result."""
    return _report(injection.scan(text), "scan_text_for_injection")


if __name__ == "__main__":
    mcp.run(transport="stdio")
