"""Secret detection (A2/A3/B2): fast regex rules, no LLM.

In the Merge Gate these rules run alongside Gitleaks (see reviewer/static_scan.py).
"""

import base64
import binascii
import math
import re
from dataclasses import dataclass

from core.detectors.base import Finding, mask, redact_spans


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    severity: str
    message: str
    group: int = 0  # which regex group is the secret (0 = whole match)


_ASSIGN_KEYS = (
    r"password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
    r"auth[_-]?token|client[_-]?secret|private[_-]?key|db[_-]?pass"
)

RULES = [
    Rule(
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
            r"(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)?"
        ),
        "CRITICAL",
        "Private key",
    ),
    Rule(
        "aws_access_key",
        re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
        "CRITICAL",
        "AWS access key ID",
    ),
    Rule(
        "aws_secret_key",
        re.compile(r"(?i)aws_?secret_?(?:access_?)?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
        "CRITICAL",
        "AWS secret access key",
        group=1,
    ),
    Rule(
        "github_token",
        re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
        "CRITICAL",
        "GitHub token",
    ),
    Rule("anthropic_key", re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{20,}"), "CRITICAL", "Anthropic API key"),
    Rule(
        "openai_key",
        re.compile(r"(?<![A-Za-z0-9])sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
        "CRITICAL",
        "OpenAI API key",
    ),
    Rule("google_api_key", re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}\b"), "HIGH", "Google API key"),
    Rule("slack_token", re.compile(r"(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,}"), "HIGH", "Slack token"),
    Rule("stripe_live_key", re.compile(r"(?<![A-Za-z0-9])[rs]k_live_[0-9a-zA-Z]{24,}"), "CRITICAL", "Stripe live key"),
    Rule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "MEDIUM",
        "JSON Web Token",
    ),
    Rule(
        "credentials_in_url",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:([^\s@/'\"]{3,})@[^\s/'\"]+"),
        "HIGH",
        "Password inside a connection URL",
        group=1,
    ),
    # password = "hunter22" / api_key: 'abc...' (quoted literal)
    Rule(
        "hardcoded_credential",
        re.compile(rf"(?i)\b[\w-]*(?:{_ASSIGN_KEYS})[\w-]*\b['\"]?\s*[:=]\s*(['\"])([^'\"\s]{{6,}})\1"),
        "HIGH",
        "Hard-coded credential",
        group=2,
    ),
    # DB_PASSWORD=hunter22 (unquoted, .env / shell style)
    Rule(
        "env_credential",
        re.compile(
            r"(?m)^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY)"
            r"[A-Z0-9_]*\s*=\s*([^\s'\"#$()][^\s'\"#()]{5,})(?=\s|$)"
        ),
        "HIGH",
        "Credential in environment-style assignment",
        group=1,
    ),
]

# Values that are clearly placeholders, not real secrets.
_PLACEHOLDER = re.compile(
    r"^(?:x+|\*+|\.+|<[^>]*>|\$\{?[A-Z_]+\}?|changeme|change_me|password|secret|"
    r"(?-i:your[_-][a-z0-9_-]*)|(?-i:example[a-z0-9_.-]*)|placeholder|dummy|redacted|\[redacted\]|todo|none|null|"
    r"os\.environ.*|process\.env.*|getenv.*|"
    r"[\^~<>=]+\s*v?\d[\w.+-]*|v?\d+\.\d+(?:\.\d+)*(?:[-+][\w.]+)?)$",  # version specs
    re.I,
)


def scan(text: str, _deep: bool = True) -> list[Finding]:
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
            findings.append(
                Finding(
                    rule=rule.name,
                    category="secret",
                    severity=rule.severity,
                    message=rule.message,
                    start=start,
                    end=end,
                    preview=mask(value),
                )
            )
    if _deep:
        findings += _obfuscated(text, taken)
    return findings


# --- obfuscated secrets (red-team fixes) ------------------------------------------
_CONCAT = re.compile(r"""(['"])([^'"\n]{1,200})\1(?:\s*\+?\s*(['"])([^'"\n]{1,200})\3)+""")
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_QUOTED = re.compile(r"""(['"])([A-Za-z0-9+/=_\-]{32,})\1""")
_PROVIDER = {
    "private_key",
    "aws_access_key",
    "github_token",
    "anthropic_key",
    "openai_key",
    "google_api_key",
    "slack_token",
    "stripe_live_key",
    "jwt",
}


def _entropy(value: str) -> float:
    from collections import Counter

    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


def _decodes_to_plain_text(value: str) -> bool:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    return bool(decoded) and all(ch.isprintable() or ch.isspace() for ch in decoded)


def _obfuscated(text: str, taken: list[tuple[int, int]]) -> list[Finding]:
    found: list[Finding] = []

    def add(rule: str, severity: str, message: str, start: int, end: int, preview: str) -> None:
        if any(s <= start and end <= e for s, e in taken):
            return
        taken.append((start, end))
        found.append(
            Finding(
                rule=rule, category="secret", severity=severity, message=message, start=start, end=end, preview=preview
            )
        )

    # split keys: "AKIA..." + "..." or "AKIA..." "..."
    for m in _CONCAT.finditer(text):
        joined = "".join(piece for _, piece in re.findall(r"""(['"])([^'"\n]*)\1""", m.group(0)))
        for rule in RULES:
            if rule.name in _PROVIDER and rule.pattern.search(joined):
                add(
                    "split_secret",
                    rule.severity,
                    f"{rule.message} split across string pieces",
                    m.start(),
                    m.end(),
                    mask(joined),
                )
                break
    # base64-encoded secrets
    for m in _B64.finditer(text):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and sum(ch.isprintable() for ch in decoded) / len(decoded) > 0.9:
            inner = [f for f in scan(decoded, _deep=False) if f.severity in ("HIGH", "CRITICAL")]
            if inner:
                add(
                    "encoded_secret",
                    "CRITICAL",
                    f"Base64-encoded secret ({inner[0].message})",
                    m.start(),
                    m.end(),
                    mask(blob),
                )
    # long random-looking strings (e.g. an AWS secret key in a plainly named variable)
    for m in _QUOTED.finditer(text):
        value = m.group(2)
        letters = re.sub(r"[-_=]", "", value)
        if re.fullmatch(r"[0-9a-fA-F]+", letters):  # hex: hashes, ids
            continue
        if _decodes_to_plain_text(value):  # base64 of ordinary text (secrets inside are caught above)
            continue
        if value.startswith("/") or value.count("/") >= 3:  # file paths
            continue
        if re.search(r"abcdefg|ABCDEFG|0123456|qwerty", value, re.I):  # alphabets / charsets
            continue
        has_mix = bool(re.search(r"[a-z]", value) and re.search(r"[A-Z]", value) and re.search(r"\d", value))
        if has_mix and _entropy(value) >= (4.2 if len(value) <= 44 else 4.5):
            add(
                "high_entropy_string",
                "MEDIUM",
                "Random-looking string that may be a secret key",
                m.start(2),
                m.end(2),
                mask(value),
            )
    return found


def redact(text: str) -> tuple[str, list[Finding]]:
    findings = scan(text)
    return redact_spans(text, findings), findings
