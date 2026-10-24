"""Register the Live Guard hook in a project's .claude/settings.json.

Usage: python guard/install.py /path/to/project
Existing settings and other hooks are kept; re-running is safe.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATCHER = "Read|Bash|Write|Edit|MultiEdit|NotebookEdit|Grep|Glob"


def hook_command() -> str:
    python = ROOT / ".venv" / "bin" / "python"
    return f'"{python if python.exists() else sys.executable}" "{ROOT / "guard" / "claude_hook.py"}"'


def install(project: Path) -> Path:
    settings_path = project / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    pre = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
    cmd = hook_command()
    # drop any older AgentSentinel entry, then add the current one
    pre[:] = [g for g in pre if not any("claude_hook.py" in h.get("command", "") for h in g.get("hooks", []))]
    pre.append({"matcher": MATCHER, "hooks": [{"type": "command", "command": cmd}]})
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    return settings_path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(f"Hook installed in {install(Path(sys.argv[1]).expanduser().resolve())}")
