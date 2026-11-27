# Contract: MCP server tools (stable)

Source: `guard/mcp_server.py`. Rules only, no LLM. **Advisory, not a security boundary.**
Server name `agentsentinel`; stdio transport. Breaking a signature is a human gate.

## Tools
```python
check_command(command: str, cwd: str = "") -> dict      # pipe-to-shell, destructive, secret-file, uploads
check_file_content(content: str, path: str = "") -> dict # secrets, PII, AI-traps (path enables AI-config checks)
scan_text_for_injection(text: str) -> dict               # prompt-injection + invisible Unicode in untrusted text
```

## Response shape (all three)
```json
{ "safe": true | false,
  "decision": "allow" | "ask" | "deny",
  "max_severity": "NONE|LOW|MEDIUM|HIGH|CRITICAL",
  "findings": [ { "rule": "...", "severity": "...", "category": "...",
                  "message": "...", "preview": "<masked>" } ] }
```
- `decision`: `deny` if max-severity HIGH/CRITICAL, `ask` if MEDIUM, else `allow`. `safe == (decision == "allow")`.
- `preview` is masked (INV-6). Logging a check must never break it (wrapped in try/except).
- Shares the same detectors as the hook; a logging failure degrades silently, a check never does.
