"""Central settings for AgentSentinel.

Values come from environment variables, falling back to a local `.env` file
(never committed) and then to safe defaults.

Why every value is validated here: a typo in a security tool must not quietly change
what it does ("REVIEW_ENSEMBLE=true" used to mean OFF, "LLM_TIMEOUT_SECONDS=-5" was
accepted, a file:// OLLAMA_URL was handed to urlopen). Problems are collected in ERRORS
with the setting name, the bad value and what is expected; every entry point calls
require_valid() first and fails loudly (hooks deny, the gate exits 2).
Run `python -m core.config` to check a setup.
"""

import os
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines; real env vars take precedence."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(ROOT / ".env")


class ConfigError(ValueError):
    """One or more settings are invalid. The message lists every problem."""


ERRORS: list[str] = []
_TRUE, _FALSE = {"1", "true", "yes", "on"}, {"0", "false", "no", "off", ""}


def _bad(name: str, value: str, expected: str) -> None:
    ERRORS.append(f"{name}={value!r}: {expected}")


def _str(name: str, default: str) -> str:
    value = os.getenv(name, default).strip()
    if not value:
        _bad(name, value, "must not be empty")
        return default
    return value


def _choice(name: str, default: str, choices: tuple[str, ...]) -> str:
    value = os.getenv(name, default).strip()
    if value not in choices:
        _bad(name, value, f"must be one of {', '.join(choices)}")
        return default
    return value


def _int(name: str, default: int, low: int, high: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        value = low - 1
    if not low <= value <= high:
        _bad(name, raw, f"must be a whole number from {low} to {high}")
        return default
    return value


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "1" if default else "0").strip().lower()
    if raw in _TRUE:
        return True
    if raw not in _FALSE:
        _bad(name, raw, "must be 1/0, true/false, yes/no or on/off")
    return default if raw not in _FALSE else False


def _http_url(name: str, default: str) -> str:
    value = os.getenv(name, default).strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        _bad(name, value, "must be an http:// or https:// URL with a host (e.g. http://localhost:11434)")
        return default
    return value


def bad_names() -> list[str]:
    """Names of the invalid settings, for short messages (e.g. a hook's deny reason)."""
    return list(dict.fromkeys(e.split("=", 1)[0] for e in ERRORS))


def require_valid() -> None:
    """Raise ConfigError if any setting was invalid. Every entry point calls this first."""
    if ERRORS:
        raise ConfigError("invalid AgentSentinel settings:\n- " + "\n- ".join(ERRORS))


# --- LLM backend ---------------------------------------------------------
LLM_BACKEND = _choice("LLM_BACKEND", "claude_code", ("claude_code", "ollama"))
MAIN_MODEL = _str("MAIN_MODEL", "sonnet")  # answers, fixes, two-view
CHECK_MODEL = _str("CHECK_MODEL", "haiku")  # quick triage / classification
OLLAMA_MODEL = _str("OLLAMA_MODEL", "qwen2.5-coder:7b")
OLLAMA_URL = _http_url("OLLAMA_URL", "http://localhost:11434")
LLM_TIMEOUT_SECONDS = _int("LLM_TIMEOUT_SECONDS", 180, 1, 3600)
# Second opinion: View 2 is also reviewed by CHECK_MODEL; either model's serious issue blocks.
# On 15 real advisories Haiku and Sonnet each caught 8, together 9. Costs 1 extra call per batch.
REVIEW_ENSEMBLE = _bool("REVIEW_ENSEMBLE", False)

# --- Logging -------------------------------------------------------------
LOG_LEVEL = _choice("AGENTSENTINEL_LOG_LEVEL", "warning", ("debug", "info", "warning", "error"))
LOG_FORMAT = _choice("AGENTSENTINEL_LOG_FORMAT", "text", ("text", "json"))

# --- Storage -------------------------------------------------------------
DB_PATH = Path(_str("AGENTSENTINEL_DB", str(ROOT / "data" / "agentsentinel.db")))

# --- Live Guard ----------------------------------------------------------
# Files the AI must never read (glob patterns, matched against the path).
PROTECTED_FILE_PATTERNS = [
    ".env",
    ".env.*",
    "*.env",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "id_dsa*",
    "*/.ssh/*",
    ".ssh/*",
    "*/.aws/credentials",
    "*/.aws/config",
    "*/.config/gcloud/*",
    "*/.azure/*",
    "*/.kube/config",
    "*/.docker/config.json",
    ".netrc",
    "*/.netrc",
    ".npmrc",
    "*/.npmrc",
    ".pypirc",
    "*/.pypirc",
    "credentials.json",
    "service-account*.json",
    # also common on Windows (and elsewhere)
    "*.ppk",
    ".git-credentials",
    "*/.git-credentials",
    ".pgpass",
    "*/.pgpass",
    "*.kdbx",
    "*/gcloud/credentials.db",
    "*/gcloud/access_tokens.db",
    "*/gcloud/application_default_credentials.json",
    "*/gcloud/legacy_credentials/*",
]
# Template files that look protected but are safe to read.
PROTECTED_FILE_EXCEPTIONS = [".env.example", ".env.sample", ".env.template"]

# Hosts that commands may send data to without being flagged.
ALLOWED_HOSTS = [
    h.strip().lower()
    for h in os.getenv(
        "ALLOWED_HOSTS",
        "github.com,api.github.com,pypi.org,files.pythonhosted.org,registry.npmjs.org,localhost,127.0.0.1",
    ).split(",")
    if h.strip()
]
for _h in ALLOWED_HOSTS:
    if "://" in _h or "/" in _h or "*" in _h or " " in _h:  # "https://github.com" would never match
        _bad("ALLOWED_HOSTS", _h, "each entry must be a bare host name like github.com (no scheme, path or *)")

# --- Merge Gate ----------------------------------------------------------
FAIL_ON_SEVERITIES = {"HIGH", "CRITICAL"}


if __name__ == "__main__":  # python -m core.config: check a setup
    import sys

    if ERRORS:
        print("AgentSentinel settings are INVALID:\n- " + "\n- ".join(ERRORS), file=sys.stderr)
        sys.exit(2)
    for key in ("LLM_BACKEND", "MAIN_MODEL", "CHECK_MODEL", "LLM_TIMEOUT_SECONDS", "REVIEW_ENSEMBLE", "LOG_LEVEL"):
        print(f"{key} = {globals()[key]}")
    print(f"DB_PATH = {DB_PATH}\nALLOWED_HOSTS = {', '.join(ALLOWED_HOSTS)}\nsettings OK")
