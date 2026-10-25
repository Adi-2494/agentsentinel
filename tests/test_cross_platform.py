"""Cross-platform (macOS / Windows / Linux) compatibility. Written before the fixes."""
import pytest

from core.detectors import commands
from core.detectors.files import is_protected_path
from guard.claude_hook import evaluate


# ---------------------------------------------------------------- 1. case-insensitive file systems
@pytest.mark.parametrize("path", [
    "/proj/.ENV", "/proj/.Env", "/proj/.env.LOCAL", "/proj/PROD.ENV", "~/.SSH/ID_RSA", "/Users/a/.ssh/ID_ED25519",
    "/Users/a/.AWS/Credentials", "certs/TLS.KEY", "SERVER.PEM", "C:/Users/a/.Kube/Config",
    "C:\\Users\\a\\.ssh\\id_rsa", "Service-Account-prod.JSON",
])
def test_1_secret_files_match_regardless_of_case(path):
    assert is_protected_path(path), path


@pytest.mark.parametrize("path", ["/proj/.ENV.EXAMPLE", "/proj/.Env.Example", "README.MD", "src/App.py"])
def test_1_case_insensitive_matching_keeps_exceptions(path):
    assert not is_protected_path(path), path


@pytest.mark.parametrize("cmd", ["cat .ENV", "python3 -c \"open('.Env').read()\"", "type .ENV", "cp ~/.SSH/ID_RSA /tmp/k"])
def test_1_commands_reading_differently_cased_secrets_are_denied(cmd):
    assert evaluate("Bash", {"command": cmd})[0] == "deny"
