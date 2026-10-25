"""Register the Live Guard hooks for Claude Code (.claude/settings.json) or Cursor (.cursor/hooks.json).

Usage: python guard/install.py [--cursor] /path/to/project
Existing settings and other hooks are kept; re-running is safe.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATCHER = "Read|Bash|Write|Edit|MultiEdit|NotebookEdit|Grep|Glob"
# tools whose OUTPUT reaches the model (regex: mcp__.* matches every MCP tool)
POST_MATCHER = "Bash|Read|Grep|WebFetch|WebSearch|mcp__.*"


CURSOR_EVENTS = {  # event -> matcher ("" = everything)
    "beforeShellExecution": "",
    "beforeReadFile": "",
    "preToolUse": "Write|Edit|MultiEdit|StrReplace|Create|ApplyPatch",
    "beforeMCPExecution": "",
    "afterShellExecution": "",
}


def venv_python(root: Path = ROOT, platform: str = sys.platform) -> Path:
    """The project venv's interpreter: Scripts/python.exe on Windows, bin/python elsewhere."""
    return root / ".venv" / ("Scripts/python.exe" if platform.startswith("win") else "bin/python")


def hook_command(script: str = "claude_hook.py") -> str:
    """Forward slashes only: Claude Code on Windows runs hooks through Git Bash, where backslashes
    are escape characters. Python accepts C:/... paths on Windows."""
    python = venv_python()
    python = python if python.exists() else Path(sys.executable)
    return f'"{python.as_posix()}" "{(ROOT / "guard" / script).as_posix()}"'


def install_cursor(project: Path) -> Path:
    path = project / ".cursor" / "hooks.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    config = json.loads(path.read_text()) if path.exists() else {}
    config.setdefault("version", 1)
    cmd = hook_command("cursor_hook.py")
    for event, matcher in CURSOR_EVENTS.items():
        entries = config.setdefault("hooks", {}).setdefault(event, [])
        entries[:] = [e for e in entries if "cursor_hook.py" not in e.get("command", "")]
        entry = {"command": cmd, "timeout": 10, "failClosed": True}  # Cursor blocks if the hook process dies
        if matcher:
            entry["matcher"] = matcher
        entries.append(entry)
    path.write_text(json.dumps(config, indent=2) + "\n")
    return path


def install(project: Path) -> Path:
    settings_path = project / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    cmd = hook_command()
    for event, matcher in (("PreToolUse", MATCHER), ("PostToolUse", POST_MATCHER)):
        groups = settings.setdefault("hooks", {}).setdefault(event, [])
        # drop any older AgentSentinel entry, then add the current one
        groups[:] = [g for g in groups
                     if not any("claude_hook.py" in h.get("command", "") for h in g.get("hooks", []))]
        groups.append({"matcher": matcher, "hooks": [{"type": "command", "command": cmd}]})
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    return settings_path


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--cursor"]
    if len(args) != 1:
        sys.exit(__doc__)
    target = Path(args[0]).expanduser().resolve()
    done = install_cursor(target) if "--cursor" in sys.argv else install(target)
    print(f"Hooks installed in {done}")
