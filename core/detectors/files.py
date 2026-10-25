"""Protected-path check (A1 secret file lock), shared by the guard and commands."""
import fnmatch
import os
import re
from functools import lru_cache

from core import config
from core.detectors.base import Finding


def is_protected_path(path: str) -> bool:
    if not path:
        return False
    # The OS sees a path only up to a NUL byte (".env\x00.txt" opens ".env"); lone surrogates
    # cannot be encoded, so they are replaced before matching.
    path = path.split("\x00", 1)[0].encode("utf-8", "replace").decode("utf-8")
    if not path:
        return False
    return _protected(os.path.expanduser(path.strip().strip("'\"")).replace("\\", "/"))


@lru_cache(maxsize=1)
def _pattern(patterns: tuple[str, ...]) -> re.Pattern:
    """All protected-file globs as ONE case-insensitive regex. macOS (APFS) and Windows (NTFS)
    are case-insensitive: ".ENV" opens ".env", so the lock must not depend on letter case."""
    return re.compile("|".join(f"(?:{fnmatch.translate(p)})" for p in patterns), re.IGNORECASE)


@lru_cache(maxsize=8192)
def _protected(norm: str) -> bool:
    name = norm.rsplit("/", 1)[-1]
    if name.lower() in {e.lower() for e in config.PROTECTED_FILE_EXCEPTIONS}:
        return False
    rx = _pattern(tuple(config.PROTECTED_FILE_PATTERNS))
    # name, full path, and "/"-prefixed relative path (so "*/.ssh/*" matches ".ssh/id_rsa")
    return bool(rx.match(name) or rx.match(norm) or rx.match("/" + norm.lstrip("/")))


def check_path(path: str) -> list[Finding]:
    if is_protected_path(path):
        return [Finding(
            rule="protected_file", category="file", severity="CRITICAL",
            message=f"Access to secret/credential file blocked: {path}",
            preview=path,
        )]
    return []
