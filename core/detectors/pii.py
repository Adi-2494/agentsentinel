"""Personal-data detection (A2/A3/B2): email, Indian phone, Aadhaar, PAN, cards.

Numbers are validated with checksums (Verhoeff for Aadhaar, Luhn for cards)
to keep false alarms low.
"""
import re

from core.detectors.base import Finding, mask, redact_spans

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# RFC 2606 / 6761 reserved names: can never belong to a real person
RESERVED_EMAIL_DOMAIN = re.compile(
    r"@(?:[\w-]+\.)*(?:example\.(?:com|net|org)|[\w-]+\.(?:test|example|invalid|localhost))$", re.I)
# +91 98765 43210 / 09876543210 / 9876543210 / 98765-43210
IN_PHONE = re.compile(r"(?<![\w+])(?:\+91[\s-]?|0)?[6-9](?:[\s-]?\d){9}(?!\d)")
AADHAAR = re.compile(r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)")
# 4th char = holder type (P person, C company, H HUF, F firm, ...)
PAN = re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

# --- checksums -----------------------------------------------------------
_V_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_V_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _V_D[c][_V_P[i % 8][int(ch)]]
    return c == 0


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _card_prefix_ok(d: str) -> bool:
    return (
        d[0] == "4"  # Visa
        or d[:2] in {"34", "37"}  # Amex
        or 51 <= int(d[:2]) <= 55 or 2221 <= int(d[:4]) <= 2720  # Mastercard
        or d[0] == "6"  # Discover / RuPay / Maestro
        or d[:2] in {"35", "36", "38", "30"}  # JCB / Diners
    )


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = []
    taken: list[tuple[int, int]] = []

    def add(m: re.Match, rule: str, severity: str, message: str):
        s, e = m.span()
        if any(a < e and s < b for a, b in taken):  # overlaps a stronger match
            return
        taken.append((s, e))
        findings.append(Finding(rule=rule, category="pii", severity=severity,
                                message=message, start=s, end=e, preview=mask(m.group(), 2)))

    # strongest/most specific first
    for m in CARD.finditer(text):
        d = _digits(m.group())
        if 13 <= len(d) <= 19 and _card_prefix_ok(d) and luhn_valid(d):
            add(m, "card_number", "HIGH", "Payment card number")
    for m in AADHAAR.finditer(text):
        if verhoeff_valid(_digits(m.group())):
            add(m, "aadhaar", "HIGH", "Aadhaar number")
    for m in PAN.finditer(text):
        add(m, "pan", "HIGH", "PAN (Indian tax ID)")
    for m in IN_PHONE.finditer(text):
        add(m, "phone_in", "MEDIUM", "Indian phone number")
    for m in EMAIL.finditer(text):
        if not RESERVED_EMAIL_DOMAIN.search(m.group()):
            add(m, "email", "MEDIUM", "Email address")
    return findings


def redact(text: str) -> tuple[str, list[Finding]]:
    findings = scan(text)
    return redact_spans(text, findings), findings
