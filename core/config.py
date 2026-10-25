"""Central settings for AgentSentinel.

Values come from environment variables, falling back to a local `.env` file
(never committed) and then to safe defaults.
"""
import os
from pathlib import Path

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

# --- LLM backend ---------------------------------------------------------
LLM_BACKEND = os.getenv("LLM_BACKEND", "claude_code")  # claude_code | ollama
MAIN_MODEL = os.getenv("MAIN_MODEL", "sonnet")  # answers, fixes, two-view
CHECK_MODEL = os.getenv("CHECK_MODEL", "haiku")  # quick triage / classification
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "180"))
# Second opinion: View 2 is also reviewed by CHECK_MODEL; either model's serious issue blocks.
# On 15 real advisories Haiku and Sonnet each caught 8, together 9. Costs 1 extra call per batch.
REVIEW_ENSEMBLE = os.getenv("REVIEW_ENSEMBLE", "0") == "1"

# --- Storage -------------------------------------------------------------
DB_PATH = Path(os.getenv("AGENTSENTINEL_DB", ROOT / "data" / "agentsentinel.db"))

# --- Live Guard ----------------------------------------------------------
# Files the AI must never read (glob patterns, matched against the path).
PROTECTED_FILE_PATTERNS = [
    ".env", ".env.*", "*.env",
    "*.pem", "*.key", "*.p12", "*.pfx",
    "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
    "*/.ssh/*", ".ssh/*",
    "*/.aws/credentials", "*/.aws/config",
    "*/.config/gcloud/*", "*/.azure/*",
    "*/.kube/config", "*/.docker/config.json",
    ".netrc", "*/.netrc", ".npmrc", "*/.npmrc", ".pypirc", "*/.pypirc",
    "credentials.json", "service-account*.json",
    # also common on Windows (and elsewhere)
    "*.ppk", ".git-credentials", "*/.git-credentials", ".pgpass", "*/.pgpass", "*.kdbx",
    "*/gcloud/credentials.db", "*/gcloud/access_tokens.db", "*/gcloud/application_default_credentials.json",
    "*/gcloud/legacy_credentials/*",
]
# Template files that look protected but are safe to read.
PROTECTED_FILE_EXCEPTIONS = [".env.example", ".env.sample", ".env.template"]

# Hosts that commands may send data to without being flagged.
ALLOWED_HOSTS = [
    h.strip() for h in os.getenv(
        "ALLOWED_HOSTS",
        "github.com,api.github.com,pypi.org,files.pythonhosted.org,"
        "registry.npmjs.org,localhost,127.0.0.1",
    ).split(",") if h.strip()
]

# --- Merge Gate ----------------------------------------------------------
FAIL_ON_SEVERITIES = {"HIGH", "CRITICAL"}
