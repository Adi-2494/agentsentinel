import pytest

from core.detectors.files import is_protected_path


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "/proj/.env",
        ".env.local",
        "prod.env",
        "~/.ssh/id_rsa",
        ".ssh/id_ed25519",
        "/Users/a/.aws/credentials",
        "server.pem",
        "certs/tls.key",
        "~/.kube/config",
        "service-account-prod.json",
        "~/.netrc",
    ],
)
def test_protected(path):
    assert is_protected_path(path)


@pytest.mark.parametrize(
    "path",
    [
        ".env.example",
        "README.md",
        "src/app.py",
        "environment.py",
        "keys.py",
        "",
        "docs/ssh.md",
    ],
)
def test_not_protected(path):
    assert not is_protected_path(path)
