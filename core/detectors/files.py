"""Protected-path check (A1 secret file lock), shared by the guard and commands."""
import fnmatch
import os

from core import config
from core.detectors.base import Finding


def is_protected_path(path: str) -> bool:
    if not path:
        return False
    norm = os.path.expanduser(path.strip().strip("'\"")).replace("\\", "/")
    name = norm.rsplit("/", 1)[-1]
    if name in config.PROTECTED_FILE_EXCEPTIONS:
        return False
    for pattern in config.PROTECTED_FILE_PATTERNS:
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(norm, pattern):
            return True
        # also match patterns like "*/.ssh/*" against relative paths (".ssh/id_rsa")
        if fnmatch.fnmatch("/" + norm.lstrip("/"), pattern):
            return True
    return False


def check_path(path: str) -> list[Finding]:
    if is_protected_path(path):
        return [Finding(
            rule="protected_file", category="file", severity="CRITICAL",
            message=f"Access to secret/credential file blocked: {path}",
            preview=path,
        )]
    return []
