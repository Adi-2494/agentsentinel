"""Risky shell command detection (A4): rules only, no LLM."""

import re
import shlex
from collections.abc import Callable

from core import config
from core.heuristics.base import Finding
from core.heuristics.files import is_protected_path

_SHELLS = (
    r"(?:sudo\s+)?(?:ba|z|da|k|fi)?sh|python[0-9.]*|perl|ruby|node|"
    r"iex|Invoke-Expression|(?:powershell|pwsh)(?:\.exe)?"
)  # PowerShell runs piped scripts too
_FETCH = r"(?:curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)"

WHOLE_COMMAND_RULES = [
    (
        "pipe_to_shell",
        re.compile(rf"\b{_FETCH}\b[^|;&]*\|\s*(?:{_SHELLS})\b", re.I),
        "CRITICAL",
        "Downloads a script and runs it directly (curl | sh)",
    ),
    (
        "shell_from_download",
        re.compile(
            rf"(?:\b(?:{_SHELLS}|source|eval)|(?:^|[\s;&|])\.)\s+(?:-c\s+)?[\"']?(?:<\(|\$\()\s*{_FETCH}\b", re.I
        ),
        "CRITICAL",
        "Runs a shell on downloaded content",
    ),
    (
        "encoded_exec",
        re.compile(rf"base64\s+(?:-d|--decode|-D)\b[^;&]*\|\s*(?:{_SHELLS})\b", re.I),
        "CRITICAL",
        "Decodes hidden (base64) content and executes it",
    ),
    (
        "rm_rf_root",
        re.compile(
            r"\brm\s+(?:-\S+\s+)*-\S*[rR]\S*\s+(?:-\S+\s+)*"
            r"(?:/|/\*|~/?|\$HOME/?|\*|\.\.?/?)(?=\s|$|;|&|\|)"
        ),
        "CRITICAL",
        "Recursive delete of root, home or the whole directory",
    ),
    (
        "disk_wipe",
        re.compile(r"\bmkfs(?:\.\w+)?\b|\bdd\b[^;&|]*\bof=/dev/(?!null\b)"),
        "CRITICAL",
        "Formats or overwrites a disk",
    ),
    ("fork_bomb", re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "CRITICAL", "Fork bomb"),
    (
        "chmod_world_root",
        re.compile(r"\bchmod\s+(?:-R\s+)?0?777\s+/(?:\s|$)"),
        "HIGH",
        "Makes the whole filesystem world-writable",
    ),
    # --- Windows: PowerShell / cmd --------------------------------------------------------
    (
        "ps_download_execute",
        re.compile(
            r"\b(?:iex|Invoke-Expression)\b[^;\n]{0,40}?(?:New-Object\s+(?:System\.)?Net\.WebClient\)?\s*\.Download"
            r"(?:String|Data)|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b)|"
            r"\.Download(?:String|Data)\s*\([^)]*\)\s*\|\s*(?:iex|Invoke-Expression)\b",
            re.I,
        ),
        "CRITICAL",
        "PowerShell downloads code and runs it (iex ... DownloadString / iwr)",
    ),
    (
        "ps_encoded_command",
        re.compile(
            r"\b(?:powershell|pwsh)(?:\.exe)?\b[^;\n|&]*\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+"
            r"['\"]?[A-Za-z0-9+/=]{8,}",
            re.I,
        ),
        "CRITICAL",
        "Runs a hidden (base64-encoded) PowerShell script",
    ),
    (
        "lolbin_download",
        re.compile(
            r"\bcertutil(?:\.exe)?\b[^;\n]*-urlcache\b|\bbitsadmin(?:\.exe)?\b[^;\n]*/transfer\b|\bStart-BitsTransfer\b",
            re.I,
        ),
        "HIGH",
        "Uses a built-in Windows tool to download files (certutil / bitsadmin)",
    ),
    (
        "windows_destructive",
        re.compile(
            r"\bRemove-Item\b(?=[^;\n]*-Recurse)[^;\n]*?\s(?:[A-Za-z]:\\?\*?|\$env:(?:USERPROFILE|HOMEDRIVE|SystemRoot|windir)"
            r"\\?|~)\s*(?:$|[;\n])|"
            r"\b(?:rd|rmdir)\s+(?:/[sq]\s+)+[A-Za-z]:\\?\*?\s*(?:$|[;&\n])|"
            r"\bdel\s+(?:/[a-z]\s+)+[A-Za-z]:\\\*?\s*(?:$|[;&\n])|"
            r"\bformat\s+[A-Za-z]:",
            re.I,
        ),
        "CRITICAL",
        "Deletes or formats a whole Windows drive or user profile",
    ),
]

_URL_HOST = re.compile(r"\b(?:https?|ftp)://(?:[^/\s@'\"]+@)?([^/\s:'\"?#]+)", re.I)
_UPLOAD_FLAG = re.compile(
    r"(?:^|\s)(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|"
    r"--post-data|--post-file|--body-file|-X\s*(?:POST|PUT|PATCH)|-Method\s+(?:Post|Put|Patch)|-Body)(?:\s|=|$)",
    re.I,
)
_FILE_UPLOAD = re.compile(
    r"(?:-d|--data(?:-binary)?|-F|--form)\s*['\"]?[\w-]*=?@(?!-)(\S+)|"
    r"(?:-T|--upload-file|--post-file|--body-file|-InFile)[\s=]+(\S+)",
    re.I,
)
_REMOTE_COPY = re.compile(r"^\s*(?:sudo\s+)?(scp|rsync|sftp)\b")
_REMOTE_TARGET = re.compile(r"(?:^|\s)(?:[\w.-]+@)?([\w.-]+):(?!//)")
_NETCAT = re.compile(r"^\s*(?:sudo\s+)?(nc|ncat|netcat|socat|telnet)\b(.*)")


_PATHLIKE = re.compile(r"[~$%\w./\\@=:-]+")  # also C:\Users\a\.aws\credentials, %USERPROFILE%\.ssh
# Commands that only mention a file name without reading its content
_NAME_ONLY = {"ls", "test", "[", "echo", "printf", "touch", "stat", "file"}


def _only_mentions_names(tokens: list[str], seg: str) -> bool:
    if "$(" in seg or "`" in seg or "<(" in seg:
        return False  # echo $(cat .env) reads it
    if tokens[:2] in (["git", "check-ignore"], ["git", "rm"]):
        return True
    return bool(tokens) and tokens[0] in _NAME_ONLY and "<" not in seg


_DL_TARGET = re.compile(
    rf"\b{_FETCH}\b[^;&|]*?(?:\s(?:-o|-O|--output|--output-document|-OutFile)[\s=]+|\s>\s*)([^\s;&|]+)", re.I
)
_RUNNERS = r"(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|source|\.|python[0-9.]*|node|perl|ruby)"


def _download_then_execute(command: str, add: Callable[..., None]) -> None:
    """curl URL -o FILE && FILE / sh FILE / chmod +x FILE && ./FILE ..."""
    for m in _DL_TARGET.finditer(command):
        target = m.group(1).strip("'\"")
        name = re.escape(target.rsplit("/", 1)[-1])
        rest = command[m.end() :]
        ran = re.search(rf"(?:^|[;&|])\s*{_RUNNERS}\s+\S*{name}(?:\s|$|[;&|])", rest) or re.search(
            rf"(?:^|[;&|])\s*(?:\./|/|~/)?\S*{name}(?:\s|$|[;&|])", rest
        )
        if ran:
            add(
                "download_then_execute",
                "CRITICAL",
                f"Downloads a file and then runs it ({target})",
                command[m.start() : m.end() + ran.end()],
            )
            return


def host_allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in config.ALLOWED_HOSTS)


def _segments(command: str) -> list[str]:
    return [s.strip() for s in re.split(r"\|\||&&|[|;&\n]", command) if s.strip()]


_TOKEN = re.compile(r"""(?:[^\s'"]+|'[^']*'|"(?:\\.|[^"\\])*")+""")
_SHLEX_MAX = 4096  # shlex builds tokens char by char (quadratic on huge words)


_QUOTED_PART = re.compile(r"'([^']*)'|\"((?:\\.|[^\"\\])*)\"")
_ESCAPE = re.compile(r"\\(.)")


def _unquote(m: re.Match[str]) -> str:
    if m.group(1) is not None:  # '...': literal
        return str(m.group(1))
    return _ESCAPE.sub(r"\1", m.group(2))  # "...": backslash escapes


def _fast_tokens(segment: str) -> list[str]:
    """Linear-time shell-like split: same quoting rules as shlex for the cases we inspect."""
    return [_QUOTED_PART.sub(_unquote, tok) for tok in _TOKEN.findall(segment)]


def _tokens(segment: str) -> list[str]:
    if len(segment) > _SHLEX_MAX:
        return _fast_tokens(segment)
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


MAX_COMMAND_CHARS = 100_000  # far beyond normal agent use; still scanned, but the user confirms


# ---- obfuscation the rules must see through (red-team round 3): the command is also checked
# in the form the shell would actually run, with variables and printf escapes resolved.
_ASSIGN = re.compile(r"(?:^|[\s;&|(])(?:export\s+)?([A-Za-z_]\w*)=(\"[^\"]*\"|'[^']*'|[^\s;&|)]*)")
_VARREF = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
_PRINTF_SUB = re.compile(
    r"\$\(\s*(?:printf|echo\s+-n?e)\s+(\"[^\"]*\"|'[^']*'|[^\s)]+)\s*\)|`\s*(?:printf|echo\s+-n?e)\s+(\"[^\"]*\"|'[^']*'|[^\s`]+)\s*`"
)
_ESCAPES = re.compile(r"\\x([0-9A-Fa-f]{2})|\\([0-7]{1,3})|\\u([0-9A-Fa-f]{4})")
_PY_CODE = re.compile(r"\bpython[0-9.]*(?:\.exe)?\s+(?:-\w+\s+)*-c\s+(\"(?:\\.|[^\"\\])*\"|'[^']*')")
_RECURSIVE_READERS = {"find", "tar", "zip", "7z", "cp", "rsync", "scp", "grep", "rg", "ag", "du", "base64", "xxd"}
_GIT_REMOTE = re.compile(r"^\s*git\s+(?:remote\s+(?:add|set-url)\s+\S+|push)\s+(\S+)")
_SCP_HOST = re.compile(r"^(?:[\w.-]+@)?([\w.-]+):")


# names that are protected only INSIDE a secret folder (not "id_rsa": that is protected anywhere,
# so "any folder/id_rsa" would match every folder)
_SECRET_NAMES = ("x", "credentials", "config", "config.json", "credentials.db")


def _holds_secrets(folder: str) -> bool:
    """A folder whose usual contents are protected (~/.ssh, ~/.aws, ~/.kube, ~/.config/gcloud ...)."""
    base = folder.rstrip("/\\")
    return any(is_protected_path(f"{base}/{name}") for name in _SECRET_NAMES)


def _strip_quotes(v: str) -> str:
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"" else v


def _unescape(text: str) -> str:
    def one(m: re.Match[str]) -> str:
        hex2, octal, uni = m.groups()
        return chr(int(hex2 or uni, 16)) if (hex2 or uni) else chr(int(octal, 8) % 0x110000)

    return _ESCAPES.sub(one, text)


def _python_strings(code: str) -> list[str]:
    """String values `python -c` code builds by joining constants ('cu' + 'rl ...', ''.join([...]))."""
    import ast

    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []

    def fold(e: ast.expr) -> str | None:
        if isinstance(e, ast.Constant) and isinstance(e.value, str):
            return e.value
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
            a, b = fold(e.left), fold(e.right)
            return a + b if a is not None and b is not None else None
        if isinstance(e, ast.JoinedStr):
            parts = [fold(v.value) if isinstance(v, ast.FormattedValue) else fold(v) for v in e.values]
            return "".join(p for p in parts if p is not None) if None not in parts else None
        if (
            isinstance(e, ast.Call)
            and isinstance(e.func, ast.Attribute)
            and e.func.attr == "join"
            and len(e.args) == 1
            and isinstance(e.args[0], ast.List | ast.Tuple)
        ):
            sep, items = fold(e.func.value), [fold(x) for x in e.args[0].elts]
            return sep.join(i for i in items if i is not None) if sep is not None and None not in items else None
        return None

    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp | ast.JoinedStr | ast.Call):
            value = fold(node)
            if value and value not in code and len(value) <= MAX_COMMAND_CHARS:
                out.append(value)
    return out[:20]


def _variants(command: str) -> list[str]:
    """The command as the shell / interpreter would really run it, when that differs."""
    out: list[str] = []
    values: dict[str, str] = {}
    for m in _ASSIGN.finditer(command):
        if len(values) < 50:
            values[m.group(1)] = _strip_quotes(m.group(2))
    expanded = command
    if values:
        expanded = _VARREF.sub(lambda m: values.get(m.group(1) or m.group(2), m.group(0)), command)
        expanded = expanded[: 2 * len(command) + 1000]  # $a$a$a... must not blow up
    decoded = _PRINTF_SUB.sub(lambda m: _unescape(_strip_quotes(m.group(1) or m.group(2))), expanded)
    for v in (expanded, decoded):
        if v != command and v not in out:
            out.append(v)
    for m in _PY_CODE.finditer(command):
        out += [v for v in _python_strings(_unescape(_strip_quotes(m.group(1)))) if v not in out]
    return out


def check(command: str) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule: str, severity: str, message: str, preview: str = "") -> None:
        if not any(f.rule == rule and f.preview == preview for f in findings):
            findings.append(
                Finding(rule=rule, category="command", severity=severity, message=message, preview=preview[:120])
            )

    if len(command) > MAX_COMMAND_CHARS:
        add(
            "command_too_large",
            "MEDIUM",
            f"Command is {len(command) // 1000} KB (limit {MAX_COMMAND_CHARS // 1000} KB); confirm before it runs",
            command[:80],
        )
    for variant in [command, *_variants(command)]:
        _check_one(variant, add)
    return findings


def _check_one(command: str, add: Callable[..., None]) -> None:
    for rule, pattern, severity, message in WHOLE_COMMAND_RULES:
        m = pattern.search(command)
        if m:
            add(rule, severity, message, m.group(0))

    _download_then_execute(command, add)

    for seg in _segments(command):
        tokens = _tokens(seg)
        # A1 via the shell: any path-like text that is a secret file, including inside
        # quoted interpreter code (python3 -c "open('.env')", ruby -e, node -e, ...)
        if not _only_mentions_names(tokens, seg):
            recursive = bool(tokens) and tokens[0] in _RECURSIVE_READERS
            for cand in sorted(set(_PATHLIKE.findall(seg))):
                path = cand.lstrip("@<>").split("=", 1)[-1].strip(",;:)(").rstrip(".")  # keep a leading dot
                if path and (is_protected_path(path) or is_protected_path(cand.lstrip("@<>"))):
                    add("reads_secret_file", "CRITICAL", f"Command touches a secret/credential file: {path}", path)
                elif path and recursive and _holds_secrets(path):
                    # find ~/.ssh -exec cat {} ; / tar czf k.tgz ~/.aws: a whole secret folder
                    add("reads_secret_file", "CRITICAL", f"Command reads a secret/credential folder: {path}", path)

        git = _GIT_REMOTE.match(seg)
        if git:
            target = git.group(1)
            host = (_URL_HOST.findall(target) or [""])[0] or (
                _SCP_HOST.match(target).group(1) if _SCP_HOST.match(target) else ""  # type: ignore[union-attr]
            )
            if host and not host_allowed(host):
                add("git_remote_unknown_host", "MEDIUM", f"Sends the repository to an unlisted git host ({host})", seg)

        all_hosts = _URL_HOST.findall(seg)
        hosts = [h for h in all_hosts if not host_allowed(h)]
        # a download anywhere in the segment, also inside $(...) / <(...) (not only as the first word)
        is_fetch = re.search(rf"(?:^|[\s(`$])(?:sudo\s+)?{_FETCH}\b", seg, re.I)
        upload = _FILE_UPLOAD.search(seg) if is_fetch else None
        if upload and all_hosts and not hosts:
            # the allowlist is for downloads; uploading a local file is never automatically fine
            if re.search(r"(?:api\.github\.com/gists|gist\.github\.com)", seg, re.I):
                add("file_upload_to_gist", "HIGH", "Uploads a local file to a GitHub gist (public paste)", seg)
            else:
                add(
                    "file_upload_allowed_host",
                    "MEDIUM",
                    f"Uploads a local file to {all_hosts[0]}; confirm this is intended",
                    seg,
                )
        if is_fetch and hosts:
            if upload:
                add(
                    "file_upload_unknown_host", "CRITICAL", f"Uploads a local file to an unknown host ({hosts[0]})", seg
                )
            elif _UPLOAD_FLAG.search(seg):
                add("data_to_unknown_host", "HIGH", f"Sends data to an unknown host ({hosts[0]})", seg)
            else:
                add("unknown_url", "MEDIUM", f"Fetches from an unlisted host ({hosts[0]})", seg)

        if re.match(r"^\s*gh\s+gist\s+(?:create|edit)\b", seg):
            add("gist_upload", "MEDIUM", "Publishes local files as a GitHub gist; confirm this is intended", seg)

        if _REMOTE_COPY.match(seg):
            remote = [h for h in _REMOTE_TARGET.findall(seg) if not host_allowed(h)]
            if remote:
                add("remote_copy_unknown_host", "HIGH", f"Copies files to/from an unknown host ({remote[0]})", seg)

        nc = _NETCAT.match(seg)
        if nc:
            args = [a for a in _tokens(nc.group(2)) if not a.startswith("-")]
            if args and not host_allowed(args[0]) and not args[0].isdigit():
                add("raw_socket_unknown_host", "HIGH", f"Opens a raw network connection to {args[0]}", seg)
