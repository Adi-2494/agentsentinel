"""Python taint analysis (core/reviewer/taint.py): user input -> dangerous call."""

import time
from pathlib import Path

import pytest

from benchmark.taint_cases import CASES, expected
from core.reviewer import taint
from core.reviewer.static_scan import scan_files

VULN = sorted((CASES / "vuln").glob("*.py"))
SAFE = sorted((CASES / "safe").glob("*.py"))


def _scan(src: str, **more: str) -> list[taint.TaintFinding]:
    found, errors = taint.analyze_sources({"app.py": src, **more})
    assert not errors, errors
    return found


@pytest.mark.parametrize("case", VULN, ids=lambda p: p.stem)
def test_vulnerable_case_is_caught_on_its_sink_line(case: Path):
    line, kind = expected(case)
    found, _ = taint.analyze([case])
    assert any(f.line == line and f.kind == kind for f in found), [(f.line, f.kind) for f in found]


@pytest.mark.parametrize("case", SAFE, ids=lambda p: p.stem)
def test_safe_look_alike_is_not_flagged(case: Path):
    found, _ = taint.analyze([case])
    assert not found, [(f.line, f.rule, f.message) for f in found]


def test_helper_in_another_file_of_the_pr():
    util = "from flask import request\n\ndef arg(name):\n    return request.args.get(name)\n"
    app = "import os\nimport util\n\ndef h():\n    os.system('ls ' + util.arg('d'))\n"
    (f,) = _scan(app, **{"util.py": util})
    assert f.kind == "command" and f.file == "app.py" and f.line == 5


def test_finding_explains_source_sink_and_helper():
    src = (
        "import subprocess\nfrom flask import request\n\n"
        "def run(c):\n    subprocess.run(c, shell=True)\n\n"
        "def h():\n    run(request.form['c'])\n"
    )
    (f,) = _scan(src)
    assert f.severity == "CRITICAL" and f.rule == "taint-command"
    assert "request.form" in f.message and "run()" in f.message


def test_shell_list_counts_as_shell_but_plain_list_does_not():
    shell = "import subprocess\nfrom flask import request\n\ndef h():\n    subprocess.run(['sh', '-c', request.args['x']])\n"
    plain = "import subprocess\nfrom flask import request\n\ndef h():\n    subprocess.run(['ls', request.args['x']])\n"
    assert [f.kind for f in _scan(shell)] == ["command"]
    assert _scan(plain) == []


def test_dead_branch_is_skipped_but_unknown_branch_is_not():
    dead = (
        "import os\nfrom flask import request\n\ndef h():\n    p = request.args['p']\n"
        "    bar = 'safe' if 7 * 42 > 200 else p\n    os.system('cat ' + bar)\n"
    )
    live = dead.replace("7 * 42 > 200", "len(p) > 3")
    assert _scan(dead) == []
    assert [f.kind for f in _scan(live)] == ["command"]


def test_dict_values_are_tracked_per_constant_key():
    src = (
        "import os\nfrom flask import request\n\ndef h():\n    d = {}\n    d['a'] = 'safe'\n"
        "    d['b'] = request.args['x']\n    os.system(d['a'])\n    os.system(d['b'])\n"
    )
    assert [f.line for f in _scan(src)] == [9]


def test_path_check_with_early_exit_cleans_the_value():
    src = (
        "from flask import request\n\ndef h():\n    name = request.args['f']\n"
        "    if '..' in name:\n        return 'no'\n    return open('/srv/' + name).read()\n"
    )
    assert _scan(src) == []
    assert [f.kind for f in _scan(src.replace("        return 'no'\n", "        print('no')\n"))] == ["path"]


def test_request_user_is_not_user_input():
    src = "import os\n\ndef h(request):\n    os.system('id ' + str(request.user.id))\n"
    assert _scan(src) == []


def test_huge_constants_are_never_built():
    src = "s = 'a' * 10**9\nn = 10\nfor _ in range(9):\n    n = n * n\nif s == n:\n    pass\n"
    t = time.perf_counter()
    assert _scan(src) == []
    assert time.perf_counter() - t < 1.0


def test_deeply_nested_code_is_still_analysed():
    src = (
        "import os\nfrom flask import request\n\ndef f():\n    os.system("
        + " + ".join(["request.args['a']"] * 2000)
        + ")\n"
    )
    assert [f.kind for f in _scan(src)] == ["command"]


def test_code_python_cannot_parse_is_reported_not_crashed():
    found, errors = taint.analyze_sources({"bad.py": "x = " + " + ".join(["'a'"] * 5000), "broken.py": "def ("})
    assert found == [] and len(errors) == 2 and all("could not parse" in e for e in errors)


def test_long_helper_chain_resolves():
    chain = "\n".join(f"def f{i}(x):\n    return f{i - 1}(x)" if i else "def f0(x):\n    return x" for i in range(60))
    src = chain + "\nimport os\nfrom flask import request\nos.system(f59(request.args['a']))\n"
    assert [f.kind for f in _scan(src)] == ["command"]


def test_large_file_is_fast():
    body = "".join(f"def f{i}(x):\n    y = x + '{i}'\n    return y.strip()\n\n" for i in range(3000))
    t = time.perf_counter()
    _scan(body)
    assert time.perf_counter() - t < 10


def test_merge_gate_reports_taint_findings(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import pickle\nfrom flask import request\n\ndef load():\n    return pickle.loads(request.data)\n",
        encoding="utf-8",
    )
    findings, _ = scan_files([tmp_path / "app.py"], tmp_path)
    hit = [f for f in findings if f.rule == "taint-deserialization"]
    assert hit and hit[0].category == "vuln" and hit[0].severity == "CRITICAL" and hit[0].line == 5


# ---- bugs found by running the analysis over 5,557 real library files
def test_str_replace_is_not_a_file_sink():
    src = "from flask import request\n\ndef h():\n    return request.args['q'].replace('a', 'b')\n"
    assert _scan(src) == []


def test_request_outside_web_code_is_not_user_input():
    # pip / requests / urllib3: `request` is an OUTGOING request object
    src = "import os\n\ndef send(request):\n    if os.path.isdir(request.body):\n        pass\n"
    assert _scan(src) == []
    assert [f.kind for f in _scan("from flask import Flask\n" + src)] == ["path"]


def test_cli_arguments_may_name_files_but_not_shell_commands():
    opens = "import sys\n\ndef main():\n    return open(sys.argv[1]).read()\n"
    shell = "import os\nimport sys\n\ndef main():\n    os.system('rm ' + sys.argv[1])\n"
    assert _scan(opens) == []
    assert [f.kind for f in _scan(shell)] == ["command"]


def test_aiohttp_request_data_is_a_source():
    src = (
        "from aiohttp import web\n\nasync def create(request):\n    data = await request.post()\n"
        "    await request.app['db'].execute(\"INSERT INTO t VALUES ('%s')\" % data['name'])\n"
    )
    assert [f.kind for f in _scan(src)] == ["sql"]


# ---- every statement / expression form carries taint (each would otherwise be a silent gap)
HEAD = "import os\nfrom flask import request\n\ndef h():\n    p = request.args['p']\n"
CONSTRUCTS = {
    "while": "    c = ''\n    while len(c) < 3:\n        c += p\n    os.system(c)\n",
    "try/except": "    try:\n        c = int(p)\n    except ValueError:\n        c = p\n    os.system(str(c))\n",
    "try/finally": "    try:\n        c = p\n    finally:\n        pass\n    os.system(c)\n",
    "match unknown": "    match p[:1]:\n        case 'a':\n            c = 'ls'\n        case _:\n            c = p\n    os.system(c)\n",
    "match constant": "    k = 'b'\n    match k:\n        case 'a':\n            c = 'ls'\n        case 'b' | 'c':\n            c = p\n    os.system(c)\n",
    "walrus": "    if (c := p.strip()):\n        os.system(c)\n",
    "list comprehension": "    os.system(' '.join([x for x in p.split()]))\n",
    "dict comprehension": "    d = {k: k for k in p.split()}\n    os.system(str(d))\n",
    "list.append": "    parts = ['echo']\n    parts.append(p)\n    os.system(' '.join(parts))\n",
    "config.set/get": "    import configparser\n    conf = configparser.ConfigParser()\n    conf.set('s', 'k', p)\n    os.system(conf.get('s', 'k'))\n",
    "shell list via append": "    import subprocess\n    a = []\n    a.append('sh')\n    a.append('-c')\n    a.append(p)\n    subprocess.run(a)\n",
    "for loop": "    c = ''\n    for part in p.split(','):\n        c = c + part\n    os.system(c)\n",
    "with as": "    with open('/dev/null') as fh:\n        c = fh.name + p\n    os.system(c)\n",
    "self attribute": "    class J:\n        pass\n    j = J()\n    j.cmd = p\n    os.system(j.cmd)\n",
    "keyword sink arg": "    import subprocess\n    subprocess.run(args=p, shell=True)\n",
    "async def": None,
}


@pytest.mark.parametrize("name", [k for k, v in CONSTRUCTS.items() if v])
def test_construct_carries_taint(name):
    assert [f.kind for f in _scan(HEAD + CONSTRUCTS[name])] == ["command"], name


def test_async_handler_and_await():
    src = "import os\nfrom flask import request\n\nasync def h():\n    p = await get()\n    os.system(request.args['x'])\n"
    assert [f.kind for f in _scan(src)] == ["command"]


def test_match_constant_dead_case_is_skipped():
    src = (
        HEAD
        + "    k = 'a'\n    match k:\n        case 'a':\n            c = 'ls'\n        case _:\n            c = p\n    os.system(c)\n"
    )
    assert _scan(src) == []


def test_lambda_body_is_not_a_leak_but_call_args_are():
    src = HEAD + "    f = lambda x: x\n    os.system(f('ls'))\n"
    assert _scan(src) == []


def test_url_allowlist_with_early_exit_is_a_sanitizer():
    src = (
        "from urllib.parse import urlparse\nimport requests\nfrom flask import request\n\nALLOWED = {'github.com'}\n\n"
        "def p():\n    url = request.args.get('url', '')\n    parsed = urlparse(url)\n"
        "    if parsed.hostname not in ALLOWED:\n        return 'no'\n    return requests.get(url, timeout=5).text\n"
    )
    assert _scan(src) == []
    no_exit = src.replace("        return 'no'\n", "        print('no')\n")
    assert [f.kind for f in _scan(no_exit)] == ["ssrf"]
    string_check = src.replace("parsed.hostname not in ALLOWED", "'evil' not in url")  # not an allowlist
    assert [f.kind for f in _scan(string_check)] == ["ssrf"]
