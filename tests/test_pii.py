import pytest

from core.detectors import pii
from core.detectors.pii import _V_D, _V_P, luhn_valid, verhoeff_valid

_V_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def make_aadhaar(first11: str) -> str:
    """Append a Verhoeff check digit -> a valid-format but FAKE Aadhaar."""
    c = 0
    for i, ch in enumerate(reversed(first11)):
        c = _V_D[c][_V_P[(i + 1) % 8][int(ch)]]
    return first11 + str(_V_INV[c])


AADHAAR = make_aadhaar("23456789012")
TEST_CARD = "4111 1111 1111 1111"  # standard Visa test number


def rules(text):
    return {f.rule for f in pii.scan(text)}


def test_checksums():
    assert verhoeff_valid(AADHAAR)
    assert luhn_valid(TEST_CARD.replace(" ", ""))
    assert not luhn_valid("4111111111111112")


@pytest.mark.parametrize(
    "text,rule",
    [
        ("contact: priya.sharma@acme-mail.co.in", "email"),
        ("call +91 98765 43210", "phone_in"),
        ("call 9876543210", "phone_in"),
        ("call 09876-543210", "phone_in"),
        (f"aadhaar {AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}", "aadhaar"),
        (f"aadhaar={AADHAAR}", "aadhaar"),
        ("PAN: ABCPE1234F", "pan"),
        (f"card {TEST_CARD}", "card_number"),
        ("card 5555555555554444", "card_number"),
    ],
)
def test_detects_pii(text, rule):
    assert rule in rules(text)


@pytest.mark.parametrize(
    "text",
    [
        "order id 123456789012",  # 12 digits, fails Verhoeff / starts with 1
        "timestamp 1729771234567",  # fails Luhn
        "version 1.2.3, port 8080",
        "call 1234567890",  # Indian mobiles start with 6-9
        "ABCDE1234F",  # 4th char D is not a valid PAN holder type
        "user@localhost",
        "dev@example.com",
        "qa@staging.example.org",
        "bot@ci.test",
    ],
)
def test_ignores_non_pii(text):
    assert pii.scan(text) == []


def test_aadhaar_not_double_counted_as_phone():
    r = rules(f"id {AADHAAR}")
    assert r == {"aadhaar"}


def test_redact():
    out, found = pii.redact(f"Mail a@b.co or {TEST_CARD} now")
    assert out == "Mail [REDACTED] or [REDACTED] now"
    assert len(found) == 2
