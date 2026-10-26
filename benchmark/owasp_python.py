"""Python taint analysis vs Semgrep on the OWASP Benchmark for Python (free, no LLM).

    python benchmark/owasp_python.py            # both halves, saves benchmark/results/owasp_python.json
    python benchmark/owasp_python.py --no-semgrep

The OWASP Benchmark labels every test case "real vulnerability: true / false". It is GPL-3,
so it is cloned at runtime at a PINNED commit into benchmark/external_data/ (git-ignored)
and never committed. Only the 5 categories the taint analysis is built for are scored:
path traversal, command injection, SQL injection, code injection and deserialization.

Honest split: cases with an ODD number were the dev set (looked at while improving the
analysis); cases with an EVEN number are held out and are the number to quote.
"""

import argparse
import csv
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmark.external import metrics  # noqa: E402
from core.reviewer import taint  # noqa: E402
from core.reviewer.static_scan import LOCAL_RULES, SEMGREP_CONFIG  # noqa: E402

REPO = "https://github.com/OWASP-Benchmark/BenchmarkPython.git"
COMMIT = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"  # pinned: 2026-05-19, "Benchmark version 0.1"
DATA = ROOT / "benchmark" / "external_data" / "owasp_benchmark_python"
OUT = ROOT / "benchmark" / "results" / "owasp_python.json"
KIND = {"pathtraver": "path", "cmdi": "command", "sqli": "sql", "codeinj": "code", "deserialization": "deserialization"}
CWE = {"pathtraver": {22, 23, 36, 73}, "cmdi": {77, 78}, "sqli": {89}, "codeinj": {94, 95}, "deserialization": {502}}
OWN_RULE_CWE = {"path-traversal": 22, "zip-slip": 22, "sqli": 89, "ssrf": 918}


def fetch() -> Path:
    if not (DATA / ".git").exists():
        DATA.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(DATA)], check=True)
        subprocess.run(["git", "-C", str(DATA), "remote", "add", "origin", REPO], check=True)
    head = subprocess.run(
        ["git", "-C", str(DATA), "rev-parse", "HEAD"], capture_output=True, text=True, encoding="utf-8"
    ).stdout.strip()
    if head != COMMIT:
        subprocess.run(["git", "-C", str(DATA), "fetch", "-q", "--depth", "1", "origin", COMMIT], check=True)
        subprocess.run(["git", "-C", str(DATA), "checkout", "-q", "FETCH_HEAD"], check=True)
    return DATA


def cases(root: Path) -> list[tuple[str, str, bool]]:
    rows = []
    with (root / "expectedresults-0.1.csv").open(encoding="utf-8") as fh:
        for r in csv.reader(fh):
            if r and not r[0].startswith("#") and r[1] in KIND:
                rows.append((r[0], r[1], r[2].strip() == "true"))
    return rows


def run_taint(root: Path, rows: list[tuple[str, str, bool]]) -> dict[str, bool]:
    # the repo's own helpers/ are analysed too, as the context a real PR would import
    helpers = {f"helpers/{p.name}": p.read_text(encoding="utf-8") for p in (root / "helpers").glob("*.py")}
    out = {}
    for name, cat, _ in rows:
        src = (root / "testcode" / f"{name}.py").read_text(encoding="utf-8")
        found, _ = taint.analyze_sources({name: src, **helpers})
        out[name] = any(f.file == name and f.kind == KIND[cat] for f in found)
    return out


def _cwes(result: dict) -> set[int]:
    meta = result.get("extra", {}).get("metadata", {})
    raw = meta.get("cwe", [])
    nums = set()
    for c in raw if isinstance(raw, list) else [raw]:
        digits = str(c).split(":")[0].replace("CWE-", "").strip()
        if digits.isdigit():
            nums.add(int(digits))
    rule = result.get("check_id", "")
    nums |= {cwe for key, cwe in OWN_RULE_CWE.items() if key in rule}
    return nums


def run_semgrep(root: Path, rows: list[tuple[str, str, bool]]) -> dict[str, bool] | None:
    if not shutil.which("semgrep"):
        return None
    files = [str(root / "testcode" / f"{name}.py") for name, _, _ in rows]
    proc = subprocess.run(
        [
            *("semgrep", "scan", "--config", SEMGREP_CONFIG, "--config", str(LOCAL_RULES)),
            *("--json", "--metrics=off", "--quiet", *files),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=1800,
    )
    hits: dict[str, set[int]] = {}
    for r in json.loads(proc.stdout).get("results", []):
        hits.setdefault(Path(r["path"]).stem, set()).update(_cwes(r))
    return {name: bool(hits.get(name, set()) & CWE[cat]) for name, cat, _ in rows}


def score(rows: list[tuple[str, str, bool]], pred: dict[str, bool], half: str) -> dict:
    keep = [r for r in rows if (int(r[0][-5:]) % 2 == 1) == (half == "dev")]
    per_cat = {}
    for cat in KIND:
        c = Counter((real, pred[name]) for name, k, real in keep if k == cat)
        per_cat[cat] = metrics(c[(True, True)], c[(False, True)], c[(True, False)], c[(False, False)])
    c = Counter((real, pred[name]) for name, _, real in keep)
    return {
        "n": len(keep),
        **metrics(c[(True, True)], c[(False, True)], c[(True, False)], c[(False, False)]),
        "per_category": per_cat,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-semgrep", action="store_true")
    args = ap.parse_args()
    root = fetch()
    rows = cases(root)
    tools = {"taint": run_taint(root, rows)}
    if not args.no_semgrep:
        sg = run_semgrep(root, rows)
        if sg is not None:
            tools["semgrep"] = sg
            tools["taint_or_semgrep"] = {k: tools["taint"][k] or sg[k] for k in sg}
    result = {
        "source": {"repo": REPO, "commit": COMMIT, "license": "GPL-3.0 (downloaded at runtime, not redistributed)"},
        "categories": sorted(KIND),
        "split": "odd case numbers = dev (looked at while improving); even = held out",
        **{tool: {"heldout": score(rows, p, "test"), "dev": score(rows, p, "dev")} for tool, p in tools.items()},
    }
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    for tool in tools:
        for half in ("heldout", "dev"):
            m = result[tool][half]
            print(
                f"{tool:17s} {half:8s} recall {m['tp']}/{m['tp'] + m['fn']} = {m['recall_pct']}%   "
                f"false alarms {m['fp']}/{m['fp'] + m['tn']} = {m['false_positive_rate_pct']}%   "
                f"precision {m['precision_pct']}%"
            )
    print(f"saved {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
