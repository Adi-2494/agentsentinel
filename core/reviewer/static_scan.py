"""Static scan (B1/B2): Semgrep + Gitleaks + our own secret/PII rules.

Only the given (changed) files are scanned. No LLM here.
"""
import json
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.detectors import pii, secrets
from core.detectors.base import mask

SEMGREP_CONFIG = "p/owasp-top-ten"
SEMGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
CODE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".c", ".cpp", ".h", ".kt", ".scala", ".rs", ".swift", ".sh", ".sql",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".env", ".tf", ".html",
    ".md", ".txt",
}
# Machine-generated dependency locks: package names like "parse-passwd" look like
# credentials to regex rules. Gitleaks (entropy + allowlists) still scans them.
LOCK_FILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "uv.lock", "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock",
}


@dataclass
class ScanFinding:
    id: str  # F1, F2, ... (stable within one gate run)
    tool: str  # semgrep | gitleaks | agentsentinel
    rule: str
    category: str  # vuln | secret | pii
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    file: str
    line: int
    message: str
    snippet: str = ""  # already redacted, safe to show and to send to the LLM
    triage: dict = field(default_factory=dict)  # filled by triage.py

    def to_dict(self) -> dict:
        return asdict(self)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(path: Path, line: int, context: int = 3) -> str:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return ""
    # redact the whole file first (rules see real line starts), then cut + number
    lines = secrets.redact(pii.redact(text)[0])[0].splitlines()
    lo, hi = max(0, line - 1 - context), min(len(lines), line + context)
    return "\n".join(f"{i + 1:>4}| {lines[i]}" for i in range(lo, hi))


def run_semgrep(files: list[Path], root: Path) -> tuple[list[dict], list[str]]:
    if not files:
        return [], []
    if not shutil.which("semgrep"):
        return [], ["semgrep not installed (brew install semgrep)"]
    proc = subprocess.run(
        ["semgrep", "scan", "--config", SEMGREP_CONFIG, "--json", "--metrics=off",
         "--quiet", *[str(f) for f in files]],
        capture_output=True, text=True, cwd=root, timeout=600,
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [], [f"semgrep failed: {proc.stderr.strip()[:300]}"]
    raw = [e.get("message", str(e)) for e in data.get("errors", [])]
    syntax = [m for m in raw if "Syntax error" in m]
    errors = [m[:200] for m in raw if "Syntax error" not in m]
    if syntax:
        errors.append(f"semgrep could not parse {len(syntax)} file(s); other files were scanned")
    return data.get("results", []), errors


def run_gitleaks(files: list[Path]) -> tuple[list[dict], list[str]]:
    if not files:
        return [], []
    if not shutil.which("gitleaks"):
        return [], ["gitleaks not installed (brew install gitleaks)"]
    results: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "r.json"
        for f in files:  # per file, so only changed files are scanned
            subprocess.run(
                ["gitleaks", "dir", str(f), "--no-banner", "--redact",
                 "--report-format", "json", "--report-path", str(report), "--exit-code", "0"],
                capture_output=True, text=True, timeout=120,
            )
            if report.exists() and report.stat().st_size:
                for r in json.loads(report.read_text()):
                    r["_file"] = f
                    results.append(r)
    return results, []


def scan_files(files: list[Path], root: Path) -> tuple[list[ScanFinding], list[str]]:
    """Scan the given files. Returns (findings, tool errors)."""
    root = root.resolve()
    files = [f.resolve() for f in files if f.is_file() and
             (f.suffix.lower() in CODE_SUFFIXES or f.name.startswith(".env"))]
    rel = lambda p: str(Path(p).resolve().relative_to(root)) if Path(p).resolve().is_relative_to(root) else str(p)  # noqa: E731
    findings: list[ScanFinding] = []
    seen: set[tuple] = set()

    def add(tool, rule, category, severity, path, line, message):
        # same issue reported by two tools / rules -> keep one; but different
        # kinds of personal data on one line are separate findings
        key = (category, rel(path), line, rule if category == "pii" else "")
        if key in seen:
            return
        seen.add(key)
        findings.append(ScanFinding(
            id=f"F{len(findings) + 1}", tool=tool, rule=rule, category=category,
            severity=severity, file=rel(path), line=line, message=message,
            snippet=_snippet(Path(path), line),
        ))

    sg_results, errors = run_semgrep(files, root)
    for r in sg_results:
        add("semgrep", r["check_id"].rsplit(".", 1)[-1], "vuln",
            SEMGREP_SEVERITY.get(r["extra"].get("severity", ""), "MEDIUM"),
            root / r["path"], r["start"]["line"], r["extra"].get("message", "").strip()[:400])

    gl_results, gl_errors = run_gitleaks(files)
    errors += gl_errors
    for r in gl_results:
        add("gitleaks", r.get("RuleID", "secret"), "secret", "CRITICAL",
            r["_file"], r.get("StartLine", 0), r.get("Description", "Secret detected"))

    for f in files:
        if f.name in LOCK_FILES:
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for x in secrets.scan(text):
            add("agentsentinel", x.rule, "secret", x.severity, f, _line_of(text, x.start),
                f"{x.message} ({mask(text[x.start:x.end])})")
        for x in pii.scan(text):
            add("agentsentinel", x.rule, "pii", x.severity, f, _line_of(text, x.start), x.message)
    return findings, errors
