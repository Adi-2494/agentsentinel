"""Shared result type for every heuristic check."""

import base64
import binascii
import re
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


# Encoded payloads (base64, hex, \\xNN escapes). Attackers wrap a key or an injection in an
# encoding so plain rules don't see it; we decode and let the caller re-scan the result.
_B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_BLOB = re.compile(r"(?<![0-9A-Fa-f])(?:0x)?((?:[0-9A-Fa-f]{2}){8,})(?![0-9A-Fa-f])")
_ESC_BLOB = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
MAX_DECODED = 64  # bound the work per text: an attacker can't make us decode forever
MAX_BLOB = 65_536


def _readable(raw: bytes) -> str | None:
    """Decoded bytes count only if they are mostly printable UTF-8 text; hashes and random
    ids decode to binary noise and are ignored, which keeps false alarms down."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 8:
        return None
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return text if printable / len(text) > 0.9 else None


def decoded_payloads(text: str) -> list[tuple[int, int, str, str]]:
    """(start, end, encoding, decoded text) for each encoded blob that decodes to readable text."""
    out: list[tuple[int, int, str, str]] = []
    seen: set[tuple[int, int]] = set()

    def add(start: int, end: int, kind: str, raw: bytes) -> None:
        decoded = _readable(raw)
        if decoded is not None and (start, end) not in seen and len(out) < MAX_DECODED:
            seen.add((start, end))
            out.append((start, end, kind, decoded))

    for m in _ESC_BLOB.finditer(text):
        add(m.start(), m.end(), "hex escapes", bytes.fromhex(m.group(0).replace("\\x", "")))
    for m in _HEX_BLOB.finditer(text):
        if len(m.group(1)) <= MAX_BLOB:
            add(m.start(), m.end(), "hex", bytes.fromhex(m.group(1)))
    for m in _B64_BLOB.finditer(text):
        blob = m.group(0)
        if len(blob) > MAX_BLOB:
            continue
        padded = blob.rstrip("=") + "=" * (-len(blob.rstrip("=")) % 4)
        try:
            raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
        except (binascii.Error, ValueError):
            continue
        add(m.start(), m.end(), "base64", raw)
    return out
