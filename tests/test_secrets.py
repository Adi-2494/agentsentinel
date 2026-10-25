"""Fake secrets are assembled at runtime so this file never contains a
secret-shaped string (keeps GitHub push protection and Gitleaks quiet)."""
import pytest

from core.detectors import secrets

FAKE = {
    "aws_access_key": "AKIA" + "Q" * 16,
    "github_token": "ghp_" + "a1B2" * 9,
    "anthropic_key": "sk-" + "ant-api03-" + "x" * 30,
    "openai_key": "sk-" + "proj-" + "y" * 30,
    "google_api_key": "AIza" + "S" * 35,
    "stripe_live_key": "sk_" + "live_" + "z" * 24,
}


def rules(text):
    return {f.rule for f in secrets.scan(text)}


@pytest.mark.parametrize("rule,value", FAKE.items())
def test_detects_provider_keys(rule, value):
    assert rule in rules(f'KEY = "{value}"')


def test_anthropic_key_not_misread_as_openai():
    r = rules(FAKE["anthropic_key"])
    assert "anthropic_key" in r and "openai_key" not in r


def test_private_key_block():
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
    assert "private_key" in rules(pem)


@pytest.mark.parametrize("text", [
    'password = "' + "hunter2butlonger" + '"',
    "db_password: '" + "S3cure!pass" + "'",
    "DB_PASSWORD=" + "S3curePass99",
    "export API_TOKEN=" + "abcd1234efgh",
    "postgres://admin:" + "S3cretPw" + "@db.internal:5432/app",
])
def test_detects_credentials(text):
    assert secrets.scan(text)


@pytest.mark.parametrize("text", [
    'password = os.getenv("DB_PASSWORD")',
    'password = ""',
    'api_key = "your_api_key_here"',
    "PASSWORD=changeme",
    "DB_PASSWORD=${DB_PASSWORD}",
    "token_count = 12345",
    "def get_password(user): ...",
    "AKIAshort",
    "https://github.com/org/repo",
])
def test_ignores_safe_code(text):
    assert secrets.scan(text) == []


def test_redact_replaces_only_secret_value():
    text = f'API_KEY = "{FAKE["openai_key"]}"  # prod'
    out, found = secrets.redact(text)
    assert FAKE["openai_key"] not in out
    assert "[REDACTED]" in out and out.startswith("API_KEY = ")
    assert found and found[0].preview.endswith("*")  # preview is masked


def test_redaction_keeps_line_numbers_for_multiline_secrets():
    pem = "a\n-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE\nAAAA\n-----END RSA PRIVATE KEY-----\nb"
    out, _ = secrets.redact(pem)
    assert out.count("\n") == pem.count("\n") and "MIIE" not in out
    assert out.splitlines()[-1] == "b"


@pytest.mark.parametrize("text", [
    '"parse-passwd": "^1.0.0"',
    '"registry-auth-token": "~3.0.1"',
    '"secret-handshake": ">=2.1.0"',
    'auth_token_version = "1.4.2"',
])
def test_version_specs_are_not_secrets(text):
    assert secrets.scan(text) == []


def test_real_password_still_detected_next_to_versions():
    assert secrets.scan('"password": "' + "Adm1n!pass" + '"')


@pytest.mark.parametrize("text", [
    'sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"',  # hex hash
    'id = "123e4567-e89b-12d3-a456-426614174000"',  # uuid
    'msg = "hello" + " world"',
    'path = "src/" + "app.py"',
    'label = "Background_Color_Primary_Default_Value"',  # long but not random
    'b = "aGVsbG8gd29ybGQgdGhpcyBpcyBqdXN0IHRleHQ="',  # base64 of harmless text
])
def test_obfuscation_checks_ignore_normal_strings(text):
    assert secrets.scan(text) == []


def test_obfuscated_secret_rules():
    import base64 as b64
    key = "".join(["AKIA", "Q" * 16])
    assert {f.rule for f in secrets.scan(f'k = "{key[:6]}" + "{key[6:]}"')} == {"split_secret"}
    enc = b64.b64encode(f"aws_key={key}".encode()).decode()
    assert {f.rule for f in secrets.scan(f'x = "{enc}"')} == {"encoded_secret"}
    assert "aws_access_key" in {f.rule for f in secrets.scan(f'API_KEY = "your_{key}"')}
    assert secrets.scan('API_KEY = "your_api_key_here"') == []


@pytest.mark.parametrize("text", [
    'ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"',
    'p = "/private/var/folders/5s/7j00w08n7mjc3wlpp8xpnsvm0000gn/T/as-x"',
])
def test_entropy_ignores_charsets_and_paths(text):
    assert secrets.scan(text) == []
