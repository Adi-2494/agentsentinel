"""Secret detection (A2/A3/B2): fast regex rules, no LLM.

In the Merge Gate these rules run alongside Gitleaks (see reviewer/static_scan.py).
"""
import re
from dataclasses import dataclass

from core.detectors.base import Finding, mask, redact_spans


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    severity: str
    message: str
    group: int = 0  # which regex group is the secret (0 = whole match)


_ASSIGN_KEYS = (
    r"password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
    r"auth[_-]?token|client[_-]?secret|private[_-]?key|db[_-]?pass"
)

RULES = [
    Rule("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)?"),
        "CRITICAL", "Private key"),
    Rule("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
         "CRITICAL", "AWS access key ID"),
    Rule("aws_secret_key", re.compile(
        r"(?i)aws_?secret_?(?:access_?)?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
        "CRITICAL", "AWS secret access key", group=1),
    Rule("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
         "CRITICAL", "GitHub token"),
    Rule("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
         "CRITICAL", "Anthropic API key"),
    Rule("openai_key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
         "CRITICAL", "OpenAI API key"),
    Rule("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
         "HIGH", "Google API key"),
    Rule("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
         "HIGH", "Slack token"),
    Rule("stripe_live_key", re.compile(r"\b[rs]k_live_[0-9a-zA-Z]{24,}"),
         "CRITICAL", "Stripe live key"),
    Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
         "MEDIUM", "JSON Web Token"),
    Rule("credentials_in_url", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:([^\s@/'\"]{3,})@[^\s/'\"]+"),
         "HIGH", "Password inside a connection URL", group=1),
    # password = "hunter22" / api_key: 'abc...' (quoted literal)
    Rule("hardcoded_credential", re.compile(
        rf"(?i)\b[\w-]*(?:{_ASSIGN_KEYS})[\w-]*\b['\"]?\s*[:=]\s*(['\"])([^'\"\s]{{6,}})\1"),
        "HIGH", "Hard-coded credential", group=2),
    # DB_PASSWORD=hunter22 (unquoted, .env / shell style)
    Rule("env_credential", re.compile(
        r"(?m)^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY)"
        r"[A-Z0-9_]*\s*=\s*([^\s'\"#$()][^\s'\"#()]{5,})(?=\s|$)"),
        "HIGH", "Credential in environment-style assignment", group=1),
]

# Values that are clearly placeholders, not real secrets.
_PLACEHOLDER = re.compile(
    r"^(?:x+|\*+|\.+|<[^>]*>|\$\{?[A-Z_]+\}?|changeme|change_me|password|secret|"
    r"your[_-].*|example.*|placeholder|dummy|redacted|\[redacted\]|todo|none|null|"
    r"os\.environ.*|process\.env.*|getenv.*)$",
    re.I,
)


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = []
    taken: list[tuple[int, int]] = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            start, end = m.span(rule.group)
            value = m.group(rule.group)
            if rule.group and _PLACEHOLDER.match(value):
                continue
            # skip if an earlier (more specific) rule already covers this span
            if any(s <= start and end <= e for s, e in taken):
                continue
            taken.append((start, end))
            findings.append(Finding(
                rule=rule.name, category="secret", severity=rule.severity,
                message=rule.message, start=start, end=end, preview=mask(value),
            ))
    return findings


def redact(text: str) -> tuple[str, list[Finding]]:
    findings = scan(text)
    return redact_spans(text, findings), findings
