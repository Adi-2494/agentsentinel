"""Shared result type for every heuristic check."""

from dataclasses import asdict, dataclass
from typing import Any

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    rule: str  # e.g. "aws_access_key"
    category: str  # secret | pii | command | injection | file
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    message: str  # human-readable reason
    start: int = -1  # span in the scanned text (-1 if not applicable)
    end: int = -1
    preview: str = ""  # masked snippet, safe to log

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def mask(value: str, keep: int = 4) -> str:
    """Show only the first few characters, so logs never contain the secret."""
    value = value.strip()
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * min(len(value) - keep, 8)


def redact_spans(text: str, findings: list[Finding], label: str = "[REDACTED]") -> str:
    """Replace every finding span with a label (overlapping spans merged)."""
    spans = sorted((f.start, f.end) for f in findings if f.start >= 0)
    merged: list[list[int]] = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out, pos = [], 0
    for s, e in merged:
        out.append(text[pos:s])
        out.append(label + "\n" * text.count("\n", s, e))  # keep line numbers stable
        pos = e
    out.append(text[pos:])
    return "".join(out)


def max_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_ORDER.get(s, 0))
