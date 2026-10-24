"""Risky shell command detection (A4): rules only, no LLM."""
import re
import shlex

from core import config
from core.detectors.base import Finding
from core.detectors.files import is_protected_path

_SHELLS = r"(?:sudo\s+)?(?:ba|z|da|k|fi)?sh|python[0-9.]*|perl|ruby|node"
_FETCH = r"(?:curl|wget|fetch|iwr|Invoke-WebRequest)"

WHOLE_COMMAND_RULES = [
    ("pipe_to_shell", re.compile(rf"\b{_FETCH}\b[^|;&]*\|\s*(?:{_SHELLS})\b", re.I),
     "CRITICAL", "Downloads a script and runs it directly (curl | sh)"),
    ("shell_from_download", re.compile(
        rf"\b(?:{_SHELLS})\s+(?:-c\s+)?[\"']?(?:<\(|\$\()\s*{_FETCH}\b", re.I),
     "CRITICAL", "Runs a shell on downloaded content"),
    ("encoded_exec", re.compile(rf"base64\s+(?:-d|--decode|-D)\b[^;&]*\|\s*(?:{_SHELLS})\b", re.I),
     "CRITICAL", "Decodes hidden (base64) content and executes it"),
    ("rm_rf_root", re.compile(
        r"\brm\s+(?:-\S+\s+)*-\S*[rR]\S*\s+(?:-\S+\s+)*"
        r"(?:/|/\*|~/?|\$HOME/?|\*|\.\.?/?)(?=\s|$|;|&|\|)"),
     "CRITICAL", "Recursive delete of root, home or the whole directory"),
    ("disk_wipe", re.compile(r"\bmkfs(?:\.\w+)?\b|\bdd\b[^;&|]*\bof=/dev/(?!null\b)"),
     "CRITICAL", "Formats or overwrites a disk"),
    ("fork_bomb", re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
     "CRITICAL", "Fork bomb"),
    ("chmod_world_root", re.compile(r"\bchmod\s+(?:-R\s+)?0?777\s+/(?:\s|$)"),
     "HIGH", "Makes the whole filesystem world-writable"),
]

_URL_HOST = re.compile(r"\b(?:https?|ftp)://(?:[^/\s@'\"]+@)?([^/\s:'\"?#]+)", re.I)
_UPLOAD_FLAG = re.compile(
    r"(?:^|\s)(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|"
    r"--post-data|--post-file|--body-file|-X\s*(?:POST|PUT|PATCH))(?:\s|=|$)", re.I)
_FILE_UPLOAD = re.compile(r"(?:-d|--data(?:-binary)?|-F|--form)\s*['\"]?[\w-]*=?@(?!-)(\S+)|"
                          r"(?:-T|--upload-file|--post-file|--body-file)[\s=]+(\S+)", re.I)
_REMOTE_COPY = re.compile(r"^\s*(?:sudo\s+)?(scp|rsync|sftp)\b")
_REMOTE_TARGET = re.compile(r"(?:^|\s)(?:[\w.-]+@)?([\w.-]+):(?!//)")
_NETCAT = re.compile(r"^\s*(?:sudo\s+)?(nc|ncat|netcat|socat|telnet)\b(.*)")


def host_allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in config.ALLOWED_HOSTS)


def _segments(command: str) -> list[str]:
    return [s.strip() for s in re.split(r"\|\||&&|[|;&\n]", command) if s.strip()]


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def check(command: str) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule, severity, message, preview=""):
        if not any(f.rule == rule and f.preview == preview for f in findings):
            findings.append(Finding(rule=rule, category="command", severity=severity,
                                    message=message, preview=preview[:120]))

    for rule, pattern, severity, message in WHOLE_COMMAND_RULES:
        m = pattern.search(command)
        if m:
            add(rule, severity, message, m.group(0))

    for seg in _segments(command):
        tokens = _tokens(seg)
        # A1 via the shell: any argument that is a secret file
        for tok in tokens:
            path = tok.lstrip("@<>").split("=", 1)[-1]
            if is_protected_path(path):
                add("reads_secret_file", "CRITICAL",
                    f"Command touches a secret/credential file: {path}", path)

        hosts = [h for h in _URL_HOST.findall(seg) if not host_allowed(h)]
        is_fetch = re.match(rf"^\s*(?:sudo\s+)?{_FETCH}\b", seg, re.I)
        if is_fetch and hosts:
            upload = _FILE_UPLOAD.search(seg)
            if upload:
                add("file_upload_unknown_host", "CRITICAL",
                    f"Uploads a local file to an unknown host ({hosts[0]})", seg)
            elif _UPLOAD_FLAG.search(seg):
                add("data_to_unknown_host", "HIGH",
                    f"Sends data to an unknown host ({hosts[0]})", seg)
            else:
                add("unknown_url", "MEDIUM", f"Fetches from an unlisted host ({hosts[0]})", seg)

        if _REMOTE_COPY.match(seg):
            remote = [h for h in _REMOTE_TARGET.findall(seg) if not host_allowed(h)]
            if remote:
                add("remote_copy_unknown_host", "HIGH",
                    f"Copies files to/from an unknown host ({remote[0]})", seg)

        nc = _NETCAT.match(seg)
        if nc:
            args = [a for a in _tokens(nc.group(2)) if not a.startswith("-")]
            if args and not host_allowed(args[0]) and not args[0].isdigit():
                add("raw_socket_unknown_host", "HIGH",
                    f"Opens a raw network connection to {args[0]}", seg)
    return findings
