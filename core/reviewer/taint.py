"""Python taint analysis for the Merge Gate: does user input reach a dangerous call?

Why this exists next to Semgrep: Semgrep's taint mode works inside one function and only
knows the sources and sinks in its rules. On our own case set it missed flows through
helper functions ("get_param() returns request.args..."), SQL built with %, .format() or
f-strings, and pickle; and it flagged safe code that had been cleaned with int() or
shlex.quote(), or overwritten before use (docs/core/taint_before.txt). This module walks
Python's own syntax tree (stdlib `ast`, no new dependency) and follows values:

- sources: Flask / Django / FastAPI / Starlette request data, web-route parameters,
  input(), sys.argv
- through: assignment (a reassignment clears taint), +=, f-strings, %, .format(), string
  methods, containers, tuple unpacking, loops, with-blocks, attributes such as self.x
- through helper functions, in any file of the PR: each function gets a summary
  ("returns user input", "parameter 0 flows to the return value", "parameter 0 reaches
  os.system"). Summaries are iterated until nothing changes, so multi-hop chains work.
- into sinks: shell commands, eval/exec, unsafe deserialization, SQL text, file paths,
  outgoing HTTP URLs
- cleaned by: int(), float(), shlex.quote(), os.path.basename(), html.escape(), etc.,
  and by passing data as SQL parameters or as a subprocess argument LIST

Limits (also in THREAT_MODEL.md): Python only; no type inference (a call is matched by
its function name); closures and taint stored on self in one method and used in another
are not followed; dynamic tricks (getattr with strings, eval-built names) are invisible.
Findings are category "vuln", so they still go through the Claude triage like Semgrep's.
"""

from __future__ import annotations

import ast
import sys
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

Labels = frozenset[str]  # "SRC:<origin>" for user input, "P<i>" for "parameter i of this function"
EMPTY: Labels = frozenset()

REQUEST_NAMES = {"request", "req"}
REQUEST_DATA = {
    "args",
    "form",
    "values",
    "json",
    "data",
    "files",
    "cookies",
    "headers",
    "GET",
    "POST",
    "body",
    "query_params",
    "path_params",
    "get_data",
    "get_json",
    "stream",
    "FILES",
    "COOKIES",
    "META",
    "match_info",  # aiohttp
    "query",
    "post",
    "rel_url",
}
# `request.args` etc. is web input only in a file that uses a web framework: elsewhere `request`
# is often an OUTGOING request object (requests, urllib3) whose .body is our own data.
WEB_IMPORTS = {
    "flask",
    "django",
    "fastapi",
    "starlette",
    "aiohttp",
    "tornado",
    "bottle",
    "pyramid",
    "falcon",
    "sanic",
    "quart",
    "werkzeug",
    "litestar",
}
WEB_FRAMEWORKS = {"flask", "quart", "bottle", "sanic", "werkzeug"}  # modules exporting a global `request`
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket"}

# Input typed by the person running a script (argv, input()) is attacker-controlled only when the
# script runs it as code or a query; opening a file they named is their right.
OPERATOR_SOURCES = {"SRC:sys.argv", "SRC:input()"}
OPERATOR_OK = {"path", "ssrf"}

SANITIZERS = {
    "int",
    "float",
    "bool",
    "len",
    "abs",
    "round",
    "hash",
    "shlex.quote",
    "pipes.quote",
    "os.path.basename",
    "html.escape",
    "markupsafe.escape",
    "flask.escape",
    "werkzeug.utils.secure_filename",
    "uuid.UUID",
    "ast.literal_eval",
    "re.escape",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "json.dumps",
}

# sink kind -> (severity, what it is)
KINDS = {
    "command": ("CRITICAL", "command injection"),
    "code": ("CRITICAL", "code injection"),
    "deserialization": ("CRITICAL", "unsafe deserialization"),
    "sql": ("HIGH", "SQL injection"),
    "path": ("HIGH", "path traversal"),
    "ssrf": ("HIGH", "server-side request forgery"),
}
SHELL_ALWAYS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput"}
SHELL_IF_FLAG = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell", "pwsh", "/bin/sh", "/bin/bash"}
CODE = {"eval", "exec", "compile"}
DESERIALIZE = {
    "pickle.loads",
    "pickle.load",
    "cPickle.loads",
    "dill.loads",
    "marshal.loads",
    "shelve.open",
    "jsonpickle.decode",
    "yaml.unsafe_load",
    "yaml.full_load",
}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "extra", "text", "from_statement"}
PATH_FUNCS = {
    "open",
    "io.open",
    "codecs.open",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "os.chmod",
    "shutil.rmtree",
    "shutil.copy",
    "shutil.copyfile",
    "shutil.move",
    "flask.send_file",
    "tarfile.open",
    "zipfile.ZipFile",
    # existence / metadata checks leak which files exist, and make/rename change the disk
    "os.path.exists",
    "os.path.isfile",
    "os.path.isdir",
    "os.path.getsize",
    "os.stat",
    "os.listdir",
    "os.scandir",
    "os.mkdir",
    "os.makedirs",
    "os.rename",
    "os.replace",
}
PATH_METHODS = {
    "read_text",
    "read_bytes",
    "write_text",
    "write_bytes",
    "unlink",
    "rmdir",
    "open",
    "exists",
    "is_file",
    "is_dir",
    "stat",
    "mkdir",
    "touch",
    "iterdir",
}  # not "replace"/"rename": str.replace() is everywhere and would look identical
# calls that store their arguments inside the receiver (conf.set("k", x); items.append(x))
MUTATORS = {"append", "extend", "insert", "add", "update", "set", "setdefault", "put", "appendleft", "push"}
HTTP_LIBS = {"requests", "httpx"}
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}
URL_FUNCS = {"urllib.request.urlopen", "urllib.request.Request", "urllib.urlopen"}


@dataclass
class TaintFinding:
    file: str
    line: int
    kind: str
    sink: str
    source: str
    via: str = ""  # helper function the flow passed through, if any

    @property
    def severity(self) -> str:
        return KINDS[self.kind][0]

    @property
    def rule(self) -> str:
        return f"taint-{self.kind}"

    @property
    def message(self) -> str:
        where = f" inside {self.via}()" if self.via else ""
        return f"User input ({self.source}) reaches {self.sink}{where}: possible {KINDS[self.kind][1]}"


@dataclass
class Summary:
    params: list[str]
    returns: Labels = EMPTY  # labels of returned values ("SRC:..." and/or "P<i>")
    param_sinks: dict[int, tuple[str, str]] = field(default_factory=dict)  # param -> (kind, sink)

    def key(self) -> tuple[Labels, tuple[tuple[int, tuple[str, str]], ...]]:
        return self.returns, tuple(sorted(self.param_sinks.items()))


@dataclass
class _Func:
    name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    file: str
    aliases: dict[str, str]
    is_route: bool

    @property
    def web(self) -> bool:
        return any(full.split(".")[0] in WEB_IMPORTS for full in self.aliases.values())


def _aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> full dotted name, from the file's imports."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _dotted(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):  # e.g. request.get_json().get(...): keep the attribute path
        inner = _dotted(node.func)
        return ".".join([inner, *reversed(parts)]) if inner else None
    return None


def _is_route(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for d in fn.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS:
            return True
    return False


_UNKNOWN = object()
_MAX_FOLDED = 10_000  # never build big constants ('a' * 10**9)


def _fold(e: ast.expr, consts: dict[str, object]) -> object:
    """Value of a constant expression (literals, known names, arithmetic, comparisons), or _UNKNOWN."""
    try:
        v = _fold_inner(e, consts)
    except Exception:  # noqa: BLE001 - anything odd (TypeError, ZeroDivisionError, ...) means "not known"
        return _UNKNOWN
    if isinstance(v, str | bytes | tuple | list) and len(v) > _MAX_FOLDED:
        return _UNKNOWN
    return v


class _NotConst(Exception):
    pass


def _fold_inner(e: ast.expr, consts: dict[str, object]) -> object:
    import operator as op

    if isinstance(e, ast.Constant):
        return e.value
    if isinstance(e, ast.Name):
        if e.id in consts:
            return consts[e.id]
        raise _NotConst
    if isinstance(e, ast.Tuple | ast.List):
        return tuple(_fold_inner(x, consts) for x in e.elts)
    if isinstance(e, ast.UnaryOp):
        v = _fold_inner(e.operand, consts)
        unary: dict[type, Callable[[Any], Any]] = {ast.Not: op.not_, ast.USub: op.neg, ast.UAdd: op.pos}
        return unary[type(e.op)](v)
    if isinstance(e, ast.BinOp):
        binary: dict[type, Callable[[Any, Any], Any]] = {
            ast.Add: op.add,
            ast.Sub: op.sub,
            ast.Mult: op.mul,
            ast.FloorDiv: op.floordiv,
            ast.Mod: op.mod,
        }
        a, b = _fold_inner(e.left, consts), _fold_inner(e.right, consts)
        if isinstance(e.op, ast.Mult) and any(isinstance(x, str | bytes | tuple) for x in (a, b)):
            n = b if isinstance(b, int) else a
            if not isinstance(n, int) or n > _MAX_FOLDED:
                raise _NotConst
        return binary[type(e.op)](a, b)
    if isinstance(e, ast.BoolOp):
        values = [_fold_inner(x, consts) for x in e.values]
        return all(values) if isinstance(e.op, ast.And) else any(values)
    if isinstance(e, ast.Compare):
        compare: dict[type, Callable[[Any, Any], Any]] = {
            ast.Eq: op.eq,
            ast.NotEq: op.ne,
            ast.Lt: op.lt,
            ast.LtE: op.le,
            ast.Gt: op.gt,
            ast.GtE: op.ge,
            ast.In: lambda a, b: a in b,
            ast.NotIn: lambda a, b: a not in b,
        }
        left = _fold_inner(e.left, consts)
        for o, right_node in zip(e.ops, e.comparators, strict=True):
            right = _fold_inner(right_node, consts)
            if not compare[type(o)](left, right):
                return False
            left = right
        return True
    if isinstance(e, ast.Subscript) and not isinstance(e.slice, ast.Slice):
        container, index = _fold_inner(e.value, consts), _fold_inner(e.slice, consts)
        return container[index]  # type: ignore[index]
    raise _NotConst


def _case_matches(pattern: ast.pattern, value: object) -> bool | None:
    """Does a match-case pattern accept a constant? None = can't tell."""
    if isinstance(pattern, ast.MatchValue) and isinstance(pattern.value, ast.Constant):
        return bool(pattern.value.value == value)
    if isinstance(pattern, ast.MatchOr):
        results = [_case_matches(p, value) for p in pattern.patterns]
        return True if True in results else None if None in results else False
    if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
        return True  # `case _:` or a capture
    return None


def _exits(body: list[ast.stmt]) -> bool:
    return bool(body) and isinstance(body[-1], ast.Return | ast.Raise | ast.Continue | ast.Break)


def _allowlisted_names(test: ast.expr) -> set[str]:
    """Names checked with `x not in ALLOWED` / `x.hostname not in {...}` (an allowlist, not a string)."""
    out: set[str] = set()
    for n in ast.walk(test):
        if isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], ast.NotIn):
            allow = n.comparators[0]
            is_list = isinstance(allow, ast.Name | ast.Attribute) or (
                isinstance(allow, ast.Set | ast.List | ast.Tuple)
                and all(isinstance(x, ast.Constant) for x in allow.elts)
            )
            left = n.left.value if isinstance(n.left, ast.Attribute) else n.left  # parsed.hostname -> parsed
            if is_list and isinstance(left, ast.Name):
                out.add(left.id)
    return out


def _is_containment_check(test: ast.expr) -> bool:
    """A path check before use: `".." in p`, `not p.startswith(base)`, `p.is_relative_to(base)`."""
    for n in ast.walk(test):
        if isinstance(n, ast.Compare) and any(isinstance(o, ast.In | ast.NotIn) for o in n.ops):
            sides = [n.left, *n.comparators]
            if any(isinstance(x, ast.Constant) and isinstance(x.value, str) and ".." in x.value for x in sides):
                return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr in ("startswith", "is_relative_to", "commonpath"):
                return True
    return False


class _Analyzer:
    """Walks one function body in order, keeping a taint label set per variable."""

    def __init__(self, fn: _Func, summaries: dict[str, Summary], report: bool) -> None:
        self.fn = fn
        self.summaries = summaries
        self.report = report
        self.findings: list[TaintFinding] = []
        self.returns: set[str] = set()
        self.param_sinks: dict[int, tuple[str, str]] = {}
        self.params = [a.arg for a in fn.node.args.posonlyargs + fn.node.args.args + fn.node.args.kwonlyargs]
        self.consts: dict[str, object] = {}  # names holding a known constant (for dead-branch skipping)
        self.shell_lists: set[str] = set()  # list variables whose program is a shell: ["sh", "-c", ...]
        self.parsed_from: dict[str, str] = {}  # parsed = urlparse(url) -> {"parsed": "url"}

    def fold(self, e: ast.expr) -> object:
        return _fold(e, self.consts)

    def keyed_name(self, sub: ast.Subscript) -> str | None:
        """'d["k"]' for a subscript with a constant key on a plain name, else None."""
        base = _dotted(sub.value)
        key = self.fold(sub.slice) if not isinstance(sub.slice, ast.Slice) else _UNKNOWN
        if base and key is not _UNKNOWN and isinstance(key, str | int):
            return f"{base}[{key!r}]"
        return None

    @staticmethod
    def whole(name: str, env: dict[str, Labels]) -> Labels:
        """A container used as a whole carries the taint of every key stored in it."""
        out = set(env.get(name, EMPTY))
        prefix = name + "["
        for k, v in env.items():
            if k.startswith(prefix):
                out |= v
        return frozenset(out)

    def forget_consts(self, body: list[ast.stmt]) -> None:
        for n in ast.walk(ast.Module(body=body, type_ignores=[])):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                self.consts.pop(n.id, None)

    # ---- names
    def resolve(self, name: str) -> str:
        head, _, rest = name.partition(".")
        full = self.fn.aliases.get(head, head)
        return f"{full}.{rest}" if rest else full

    # ---- run
    def run(self) -> None:
        env: dict[str, Labels] = {}
        for i, p in enumerate(self.params):
            if p in ("self", "cls"):
                continue
            if self.fn.is_route and p not in REQUEST_NAMES:
                env[p] = frozenset({f"SRC:route parameter '{p}'"})
            else:
                env[p] = frozenset({f"P{i}"})
        self.block(self.fn.node.body, env)

    def block(self, body: Iterable[ast.stmt], env: dict[str, Labels]) -> None:
        for stmt in body:
            self.stmt(stmt, env)

    @staticmethod
    def merge(a: dict[str, Labels], b: dict[str, Labels]) -> dict[str, Labels]:
        return {k: a.get(k, EMPTY) | b.get(k, EMPTY) for k in a.keys() | b.keys()}

    def stmt(self, s: ast.stmt, env: dict[str, Labels]) -> None:
        if isinstance(s, ast.Assign):
            labels = self.expr(s.value, env)
            v = s.value
            if (
                len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name)
                and isinstance(v, ast.Call)
                and self.resolve(_dotted(v.func) or "").rsplit(".", 1)[-1] in ("urlparse", "urlsplit")
                and v.args
                and isinstance(v.args[0], ast.Name)
            ):
                self.parsed_from[s.targets[0].id] = v.args[0].id
            for t in s.targets:
                self.assign(t, s.value, labels, env)
        elif isinstance(s, ast.AnnAssign) and s.value is not None:
            self.assign(s.target, s.value, self.expr(s.value, env), env)
        elif isinstance(s, ast.AugAssign):
            labels = self.expr(s.value, env) | self.expr(s.target, env)
            self.assign(s.target, s.value, labels, env)
        elif isinstance(s, ast.Return) and s.value is not None:
            self.returns |= self.expr(s.value, env)
        elif isinstance(s, ast.Expr):
            self.expr(s.value, env)
        elif isinstance(s, ast.If):
            self.expr(s.test, env)
            known = self.fold(s.test)
            if known is not _UNKNOWN:  # constant condition: the other branch can never run
                self.block(s.body if known else s.orelse, env)
                return
            a, b = dict(env), dict(env)
            self.block(s.body, a)
            self.block(s.orelse, b)
            env.clear()
            env.update(self.merge(a, b))
            self.forget_consts([*s.body, *s.orelse])
            if not s.orelse and _exits(s.body) and _is_containment_check(s.test):
                for n in ast.walk(s.test):  # `if ".." in name: return`: name is checked from here on
                    if isinstance(n, ast.Name) and n.id in env:
                        env[n.id] = EMPTY
            if not s.orelse and _exits(s.body):
                # `if host not in ALLOWED: return`: host (and the URL it was parsed from) is allowlisted
                for checked in _allowlisted_names(s.test):
                    for name in (checked, self.parsed_from.get(checked)):
                        if name and name in env:
                            env[name] = EMPTY
        elif isinstance(s, ast.For | ast.AsyncFor):
            it = self.expr(s.iter, env)
            for _ in range(2):  # twice: values assigned late in the loop reach its start
                self.assign(s.target, s.iter, it | self.expr(s.target, env), env)
                self.block(s.body, env)
            self.block(s.orelse, env)
        elif isinstance(s, ast.While):
            for _ in range(2):
                self.expr(s.test, env)
                self.block(s.body, env)
            self.block(s.orelse, env)
        elif isinstance(s, ast.With | ast.AsyncWith):
            for item in s.items:
                labels = self.expr(item.context_expr, env)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, item.context_expr, labels, env)
            self.block(s.body, env)
        elif isinstance(s, ast.Try | ast.TryStar):
            start = dict(env)
            self.block(s.body, env)
            merged = dict(env)
            for h in s.handlers:
                branch = self.merge(start, env)
                self.block(h.body, branch)
                merged = self.merge(merged, branch)
            env.clear()
            env.update(merged)
            self.block(s.orelse, env)
            self.block(s.finalbody, env)
        elif isinstance(s, ast.Match):
            self.expr(s.subject, env)
            subject = self.fold(s.subject)
            live = s.cases
            if subject is not _UNKNOWN:  # constant subject: only the first matching case can run
                for case in s.cases:
                    m = _case_matches(case.pattern, subject)
                    if m is True and case.guard is None:
                        live = [case]
                        break
                    if m is None or case.guard is not None:
                        break
            if len(live) == 1 and live is not s.cases:
                self.block(live[0].body, env)
                return
            merged = dict(env)
            for case in live:
                branch = dict(env)
                self.block(case.body, branch)
                merged = self.merge(merged, branch)
            env.clear()
            env.update(merged)
        # nested functions/classes are analysed as their own functions

    def assign(self, target: ast.expr, value: ast.expr, labels: Labels, env: dict[str, Labels]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = labels  # strong update: reassignment clears old taint
            value_const = self.fold(value) if value is not target else _UNKNOWN
            if value_const is _UNKNOWN:
                self.consts.pop(target.id, None)
            else:
                self.consts[target.id] = value_const
        elif isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List) and len(value.elts) == len(target.elts):
                for t, v in zip(target.elts, value.elts, strict=True):
                    self.assign(t, v, self.expr(v, env), env)
            else:
                for t in target.elts:
                    self.assign(t.value if isinstance(t, ast.Starred) else t, value, labels, env)
        elif isinstance(target, ast.Attribute):
            name = _dotted(target)
            if name:
                env[name] = labels
        elif isinstance(target, ast.Subscript):
            keyed = self.keyed_name(target)
            if keyed:  # d["k"] = x: tracked per constant key
                env[keyed] = labels
                return
            base = _dotted(target.value)
            if base:  # d[k] = x with an unknown key taints all of d (never cleans it)
                env[base] = env.get(base, EMPTY) | labels

    # ---- expressions
    def expr(self, e: ast.expr | None, env: dict[str, Labels]) -> Labels:
        if e is None or isinstance(e, ast.Constant):
            return EMPTY
        if isinstance(e, ast.Name):
            if e.id in REQUEST_NAMES and self.resolve(e.id).split(".")[0] in WEB_FRAMEWORKS:
                # the imported framework request object as a whole, e.g. passed to a wrapper helper
                return env.get(e.id, EMPTY) | {"SRC:request"}
            return self.whole(e.id, env)
        if isinstance(e, ast.Attribute):
            src = self.source(e)
            if src:
                return src
            name = _dotted(e)
            if name and name.split(".")[0] in REQUEST_NAMES:
                return EMPTY  # request.user, request.method, ...: not attacker text
            if name and (name in env or any(k.startswith(name + "[") for k in env)):
                return self.whole(name, env)
            return self.expr(e.value, env)
        if isinstance(e, ast.Subscript):
            self.expr(e.slice, env)  # a tainted KEY does not taint the looked-up value (allowlists)
            src = self.source(e.value)
            if src:
                return src
            keyed = self.keyed_name(e)
            if keyed and keyed in env:  # d["a"] read back exactly
                return env[keyed]
            return self.expr(e.value, env)
        if isinstance(e, ast.Call):
            return self.call(e, env)
        if isinstance(e, ast.Compare):
            for x in [e.left, *e.comparators]:
                self.expr(x, env)
            return EMPTY  # a boolean carries no attacker text
        if isinstance(e, ast.IfExp):
            self.expr(e.test, env)
            known = self.fold(e.test)
            if known is not _UNKNOWN:
                return self.expr(e.body if known else e.orelse, env)
            return self.expr(e.body, env) | self.expr(e.orelse, env)
        if isinstance(e, ast.NamedExpr):
            labels = self.expr(e.value, env)
            env[e.target.id] = labels
            return labels
        if isinstance(e, ast.Lambda):
            return EMPTY
        if isinstance(e, ast.Dict):
            return self.union([*(k for k in e.keys if k is not None), *e.values], env)
        if isinstance(e, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self.comprehension(e.generators, [e.elt], env)
        if isinstance(e, ast.DictComp):
            return self.comprehension(e.generators, [e.key, e.value], env)
        # BinOp (+, %), JoinedStr (f-strings), FormattedValue, BoolOp, List, Tuple, Set, Starred, Await, ...
        return self.union([c for c in ast.iter_child_nodes(e) if isinstance(c, ast.expr)], env)

    def union(self, nodes: Iterable[ast.expr], env: dict[str, Labels]) -> Labels:
        out: set[str] = set()
        for n in nodes:
            out |= self.expr(n, env)
        return frozenset(out)

    def comprehension(self, gens: list[ast.comprehension], elts: list[ast.expr], env: dict[str, Labels]) -> Labels:
        inner = dict(env)
        for g in gens:
            self.assign(g.target, g.iter, self.expr(g.iter, inner), inner)
        return self.union(elts, inner)

    def source(self, e: ast.expr) -> Labels:
        name = _dotted(e)
        if not name:
            return EMPTY
        parts = name.split(".")
        full = self.resolve(name)
        if parts[0] in REQUEST_NAMES and len(parts) > 1 and parts[1] in REQUEST_DATA and self.fn.web:
            return frozenset({f"SRC:{'.'.join(parts[:2])}"})
        if full.startswith("sys.argv"):
            return frozenset({"SRC:sys.argv"})
        return EMPTY

    def call(self, c: ast.Call, env: dict[str, Labels]) -> Labels:
        name = _dotted(c.func) or ""
        full = self.resolve(name) if name else ""
        args = [self.expr(a.value if isinstance(a, ast.Starred) else a, env) for a in c.args]
        kwargs = {k.arg: self.expr(k.value, env) for k in c.keywords}
        receiver = self.expr(c.func.value, env) if isinstance(c.func, ast.Attribute) else EMPTY
        src = self.source(c.func) if isinstance(c.func, ast.Attribute) else EMPTY

        self.check_sink(c, full, args, kwargs, receiver)
        if isinstance(c.func, ast.Attribute) and c.func.attr in ("append", "insert") and c.args:
            program = self.fold(c.args[-1])
            if isinstance(program, str) and program in SHELLS and (base_name := _dotted(c.func.value)):
                self.shell_lists.add(base_name)
        if isinstance(c.func, ast.Attribute) and c.func.attr in MUTATORS:
            base = _dotted(c.func.value)
            stored = frozenset().union(*args, *kwargs.values()) if args or kwargs else EMPTY
            if base and stored and base.split(".")[0] not in REQUEST_NAMES:
                env[base] = env.get(base, EMPTY) | stored

        if full == "input" or full == "builtins.input":
            return frozenset({"SRC:input()"})
        if full in SANITIZERS:
            return EMPTY
        summary = self.local_summary(c, name)
        if summary is not None:
            return self.apply_summary(c, summary, args, kwargs, name.rsplit(".", 1)[-1])
        if src:
            return src
        if isinstance(c.func, ast.Attribute) and c.func.attr in ("get", "pop") and c.args:
            base = _dotted(c.func.value)
            key = self.fold(c.args[0])
            if base and isinstance(key, str | int) and f"{base}[{key!r}]" in env:
                return env[f"{base}[{key!r}]"] | (args[1] if len(args) > 1 else EMPTY)
        if isinstance(c.func, ast.Attribute) and c.func.attr in ("get", "pop", "setdefault") and not receiver:
            # dict.get(key, default) on a clean dict returns ITS values, not the key
            return args[1] if len(args) > 1 else kwargs.get("default", EMPTY)
        out: set[str] = set(receiver)
        for labels in [*args, *kwargs.values()]:
            out |= labels
        return frozenset(out)

    def local_summary(self, c: ast.Call, name: str) -> Summary | None:
        short = name.rsplit(".", 1)[-1]
        if short not in self.summaries:
            return None
        if isinstance(c.func, ast.Name):
            return self.summaries[short]
        if isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Name):
            head = c.func.value.id
            if head in ("self", "cls") or head in self.fn.aliases:  # method or helper from an imported module
                return self.summaries[short]
        return None

    def apply_summary(
        self, c: ast.Call, s: Summary, args: list[Labels], kwargs: dict[str | None, Labels], fname: str
    ) -> Labels:
        offset = 1 if s.params[:1] in (["self"], ["cls"]) and isinstance(c.func, ast.Attribute) else 0
        by_param: dict[int, Labels] = {i + offset: a for i, a in enumerate(args)}
        for k, v in kwargs.items():
            if k in s.params:
                by_param[s.params.index(k)] = v
        for i, (kind, sink) in s.param_sinks.items():
            self.hit(c, kind, sink, by_param.get(i, EMPTY), via=fname)
        out = {lbl for lbl in s.returns if lbl.startswith("SRC:")}
        for lbl in s.returns:
            if lbl.startswith("P"):
                out |= by_param.get(int(lbl[1:]), EMPTY)
        return frozenset(out)

    # ---- sinks
    def check_sink(
        self, c: ast.Call, full: str, args: list[Labels], kwargs: dict[str | None, Labels], receiver: Labels
    ) -> None:
        first = args[0] if args else EMPTY
        method = c.func.attr if isinstance(c.func, ast.Attribute) else ""
        if full in SHELL_ALWAYS or full.startswith("os.exec") or full.startswith("os.spawn"):
            self.hit(c, "command", full, first | kwargs.get("cmd", EMPTY))
        elif full in SHELL_IF_FLAG:
            shell = any(
                k.arg == "shell" and not (isinstance(k.value, ast.Constant) and not k.value.value) for k in c.keywords
            )
            program = c.args[0] if c.args else None
            via_shell = (
                isinstance(program, ast.List | ast.Tuple)
                and bool(program.elts)
                and self.fold(program.elts[0]) in SHELLS
            ) or (isinstance(program, ast.Name) and program.id in self.shell_lists)
            if shell:
                self.hit(c, "command", f"{full}(shell=True)", first | kwargs.get("args", EMPTY))
            elif via_shell:  # ["sh", "-c", text]: a shell, even without shell=True
                self.hit(c, "command", f"{full}([shell, '-c', ...])", first)
        elif full in CODE or full in ("builtins.eval", "builtins.exec"):
            self.hit(c, "code", f"{full}()", first)
        elif full in DESERIALIZE:
            self.hit(c, "deserialization", full, first)
        elif full == "yaml.load":
            loader = next((k.value for k in c.keywords if k.arg == "Loader"), c.args[1] if len(c.args) > 1 else None)
            loader_name = (_dotted(loader) or "").rsplit(".", 1)[-1] if loader is not None else ""
            if loader_name not in SAFE_YAML_LOADERS:
                self.hit(c, "deserialization", "yaml.load (unsafe Loader)", first)
        elif method in SQL_METHODS and (args or "sql" in kwargs):
            self.hit(c, "sql", f".{method}()", first | kwargs.get("sql", EMPTY))
        elif full in PATH_FUNCS:
            self.hit(c, "path", f"{full}()", first | kwargs.get("file", EMPTY) | kwargs.get("path", EMPTY))
        elif method in PATH_METHODS and full.split(".")[0] not in ("self",) and receiver:
            self.hit(c, "path", f"Path.{method}()", receiver)
        elif full.split(".")[0] in HTTP_LIBS and full.rsplit(".", 1)[-1] in HTTP_VERBS:
            url = (args[1] if full.endswith(".request") and len(args) > 1 else first) | kwargs.get("url", EMPTY)
            self.hit(c, "ssrf", f"{full}()", url)
        elif full in URL_FUNCS:
            self.hit(c, "ssrf", f"{full}()", first | kwargs.get("url", EMPTY))

    def hit(self, c: ast.Call, kind: str, sink: str, labels: Labels, via: str = "") -> None:
        if kind in OPERATOR_OK:  # whoever runs a CLI already owns their files and network
            labels = frozenset(lbl for lbl in labels if lbl not in OPERATOR_SOURCES)
        for lbl in sorted(labels):
            if lbl.startswith("SRC:") and self.report:
                self.findings.append(TaintFinding(self.fn.file, c.lineno, kind, sink, lbl[4:], via))
                return
        for lbl in sorted(labels):
            if lbl.startswith("P"):
                self.param_sinks.setdefault(int(lbl[1:]), (kind, sink if not via else f"{sink} (via {via}())"))


def _functions(files: dict[str, ast.Module]) -> list[_Func]:
    out: list[_Func] = []
    for file, tree in files.items():
        aliases = _aliases(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                out.append(_Func(node.name, node, file, aliases, _is_route(node)))
        # module-level code (scripts) is analysed as one more "function"
        top = ast.FunctionDef(
            name="<module>",
            args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
            body=tree.body,
            decorator_list=[],
        )
        out.append(_Func("<module>", top, file, aliases, False))
    return out


def _safe_run(a: _Analyzer, errors: list[str]) -> bool:
    try:
        with _deep_stack():
            a.run()
        return True
    except RecursionError:
        msg = f"taint: {a.fn.file}: {a.fn.name}() is nested too deeply to analyse"
        if msg not in errors:
            errors.append(msg)
        return False


@contextmanager
def _deep_stack(limit: int = 20_000) -> Iterator[None]:
    """Deeply nested PR code (one 2,000-term "a + b + ...") must not dodge the analysis.
    Python 3.11+ runs Python-to-Python calls without using the C stack, so a higher limit is safe."""
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old, limit))
    try:
        yield
    finally:
        sys.setrecursionlimit(old)


def analyze_sources(sources: dict[str, str], max_rounds: int = 8) -> tuple[list[TaintFinding], list[str]]:
    """sources: {display path: Python source}. Returns (findings, errors)."""
    trees: dict[str, ast.Module] = {}
    errors: list[str] = []
    for path, text in sources.items():
        try:
            trees[path] = ast.parse(text, filename=path)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
            # e.g. 3,000 chained "+": Python's own parser gives up. Reported, never a crash;
            # the file still goes to the Claude review.
            errors.append(f"taint: could not parse {path} ({type(e).__name__})")
    funcs = _functions(trees)
    summaries: dict[str, Summary] = {}
    for _ in range(max_rounds):  # until summaries stop changing (chains of helpers)
        before = {k: v.key() for k, v in summaries.items()}
        new: dict[str, Summary] = {}
        for f in funcs:
            if f.name == "<module>":
                continue
            a = _Analyzer(f, summaries, report=False)
            if not _safe_run(a, errors):
                continue
            s = new.setdefault(f.name, Summary(a.params))
            s.returns = s.returns | frozenset(a.returns)  # same name in two files: merge (over-approximate)
            for i, v in a.param_sinks.items():
                s.param_sinks.setdefault(i, v)
        summaries = new
        if {k: v.key() for k, v in summaries.items()} == before:
            break
    findings: list[TaintFinding] = []
    seen: set[tuple[str, int, str]] = set()
    for f in funcs:
        a = _Analyzer(f, summaries, report=True)
        _safe_run(a, errors)
        for x in a.findings:
            if (x.file, x.line, x.kind) not in seen:
                seen.add((x.file, x.line, x.kind))
                findings.append(x)
    return sorted(findings, key=lambda x: (x.file, x.line)), errors


def analyze(files: list[Path], display: dict[Path, str] | None = None) -> tuple[list[TaintFinding], list[str]]:
    sources: dict[str, str] = {}
    for f in files:
        if f.suffix == ".py":
            try:
                sources[(display or {}).get(f, str(f))] = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    return analyze_sources(sources)
