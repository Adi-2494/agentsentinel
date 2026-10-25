"""Real vulnerable code from GitHub Security Advisories (reviewed, HIGH/CRITICAL, pip + npm).

For each advisory with a single fix commit, the changed source files are fetched at the
commit's parent (VULNERABLE) and at the fix commit (FIXED). The Merge Gate is run on both:
  caught      = blocked the vulnerable version
  fix-aware   = blocked the vulnerable version AND passed the fixed one
  still-flagged-after-fix = blocked the fixed version too (other issues, or noise)

Only public project data is used (code, advisory id, CWE); no commit author names or emails
are stored. Code is cached in benchmark/external_data/ghsa (git-ignored), never committed.

    python benchmark/ghsa.py collect --per-ecosystem 25
    python benchmark/ghsa.py eval                      # static (free)
    python benchmark/ghsa.py eval --llm 15 --model haiku
"""
import argparse
import json
import random
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import config  # noqa: E402

CACHE = ROOT / "benchmark" / "external_data" / "ghsa"
INDEX = CACHE / "index.json"
OUT = ROOT / "benchmark" / "results" / "ghsa.json"
SUFFIXES = {"pip": {".py"}, "npm": {".js", ".mjs", ".cjs", ".ts"}}
SKIP_PARTS = {"test", "tests", "__tests__", "spec", "docs", "doc", "examples", "example", "benchmark", "fixtures"}
MAX_BYTES = 40_000


def gh(*args: str, raw: bool = False) -> str | None:
    cmd = ["gh", "api", *args] + (["-H", "Accept: application/vnd.github.raw"] if raw else [])
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return p.stdout if p.returncode == 0 else None


def _candidate_files(files: list[dict], eco: str) -> list[str]:
    out = []
    for f in files:
        path = f["filename"]
        parts = set(Path(path.lower()).parts)
        if (f["status"] == "modified" and Path(path).suffix in SUFFIXES[eco] and not parts & SKIP_PARTS
                and not Path(path).name.lower().startswith("test")):
            out.append(path)
    return out


def collect(per_ecosystem: int) -> list[dict]:
    index = json.loads(INDEX.read_text()) if INDEX.exists() else []
    have = {r["ghsa"] for r in index}
    per_repo = Counter(r["repo"] for r in index)
    for eco in ("pip", "npm"):
        got = sum(r["ecosystem"] == eco for r in index)
        for severity in ("critical", "high"):
            page = 1
            while got < per_ecosystem and page <= 10:
                advisories = json.loads(gh(f"/advisories?ecosystem={eco}&type=reviewed&severity={severity}"
                                           f"&per_page=100&page={page}") or "[]")
                page += 1
                if not advisories:
                    break
                for a in advisories:
                    if got >= per_ecosystem:
                        break
                    commits = [u for u in a.get("references", []) if "github.com/" in u and "/commit/" in u]
                    if a["ghsa_id"] in have or len(commits) != 1:
                        continue
                    try:
                        owner, repo, _, sha = commits[0].split("github.com/")[1].split("/")[:4]
                    except ValueError:
                        continue
                    sha = sha.split("#")[0].split("?")[0]
                    full = f"{owner}/{repo}"
                    if per_repo[full] >= 2:
                        continue
                    commit = json.loads(gh(f"repos/{full}/commits/{sha}") or "null")
                    if not commit or not commit.get("parents"):
                        continue
                    paths = _candidate_files(commit.get("files", []), eco)
                    if not 1 <= len(paths) <= 4:
                        continue
                    parent = commit["parents"][0]["sha"]
                    files, ok = {}, True
                    for path in paths:
                        before, after = gh(f"repos/{full}/contents/{path}?ref={parent}", raw=True), \
                            gh(f"repos/{full}/contents/{path}?ref={sha}", raw=True)
                        if before is None or after is None or max(len(before), len(after)) > MAX_BYTES:
                            ok = False
                            break
                        files[path] = {"before": before, "after": after}
                    if not ok:
                        continue
                    d = CACHE / a["ghsa_id"]
                    for path, v in files.items():
                        for state in ("before", "after"):
                            p = d / state / path
                            p.parent.mkdir(parents=True, exist_ok=True)
                            p.write_text(v[state])
                    record = {"ghsa": a["ghsa_id"], "ecosystem": eco, "severity": a["severity"],
                              "cwes": [c["cwe_id"] for c in a.get("cwes", [])], "repo": full,
                              "fix_commit": sha, "files": list(files), "summary": (a.get("summary") or "")[:140]}
                    index.append(record)
                    have.add(a["ghsa_id"])
                    per_repo[full] += 1
                    got += 1
                    INDEX.parent.mkdir(parents=True, exist_ok=True)
                    INDEX.write_text(json.dumps(index, indent=1))
                    print(f"{eco:3} {got:3} {a['ghsa_id']} {full} {record['cwes']} files={len(files)}")
    return index


def _gate(rec: dict, state: str, use_llm: bool) -> dict:
    from gate import run_gate
    with tempfile.TemporaryDirectory(prefix="as-ghsa-") as tmp:
        files = []
        for path in rec["files"]:
            src = CACHE / rec["ghsa"] / state / path
            dst = Path(tmp) / path
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(src.read_text())
            files.append(dst)
        r = run_gate.run(files, Path(tmp), "", use_llm=use_llm)
    errs = [e for e in r.errors if "no-llm" not in e]
    if use_llm and any("limit" in e.lower() for e in errs):
        from core.llm import LLMLimitReached
        raise LLMLimitReached(errs[0])
    return {"blocked": r.failed, "rules": sorted({f.rule for f in r.real if r.severity(f) in config.FAIL_ON_SEVERITIES})}


def _summary(items: list[dict], key: str) -> dict:
    n = len(items)
    pct = lambda k: round(100 * k / n, 1) if n else None  # noqa: E731
    caught = sum(i[key]["before"]["blocked"] for i in items)
    after = sum(i[key]["after"]["blocked"] for i in items)
    aware = sum(i[key]["before"]["blocked"] and not i[key]["after"]["blocked"] for i in items)
    return {"n": n, "caught_vulnerable_pct": pct(caught), "still_flagged_after_fix_pct": pct(after),
            "fix_aware_pct": pct(aware)}


def evaluate(llm_n: int, model: str) -> dict:
    index = json.loads(INDEX.read_text())
    prev = json.loads(OUT.read_text()) if OUT.exists() else {}
    per = {r["ghsa"]: r for r in prev.get("advisories", [])}
    for rec in index:
        row = per.setdefault(rec["ghsa"], {k: rec[k] for k in ("ghsa", "ecosystem", "severity", "cwes", "repo",
                                                              "fix_commit", "files")})
        if "static" not in row:
            row["static"] = {s: _gate(rec, s, False) for s in ("before", "after")}
    if llm_n:
        config.MAIN_MODEL = config.CHECK_MODEL = model
        todo = [r for r in index if f"llm_{model}" not in per[r["ghsa"]]]
        done = sum(f"llm_{model}" in v for v in per.values())
        for rec in random.Random(11).sample(todo, max(0, min(llm_n - done, len(todo)))):
            t0 = time.time()
            per[rec["ghsa"]][f"llm_{model}"] = {s: _gate(rec, s, True) for s in ("before", "after")}
            r = per[rec["ghsa"]][f"llm_{model}"]
            print(f"{rec['ghsa']} {rec['repo']:32} before={r['before']['blocked']} after={r['after']['blocked']} "
                  f"({time.time() - t0:.0f}s)")
            _save(per)
    return _save(per)


def _save(per: dict) -> dict:
    rows = list(per.values())
    out = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "source": "GitHub Advisory Database (reviewed, HIGH/CRITICAL), fix commits; code not redistributed",
           "static": _summary(rows, "static"),
           "static_by_ecosystem": {e: _summary([r for r in rows if r["ecosystem"] == e], "static") for e in ("pip", "npm")},
           "advisories": rows}
    for key in sorted({k for r in rows for k in r if k.startswith("llm_")}):
        sub = [r for r in rows if key in r]
        out[key] = _summary(sub, key)
        out[key + "_static_same_sample"] = _summary(sub, "static")
    cwe_hits = defaultdict(lambda: [0, 0])
    for r in rows:
        for c in r["cwes"] or ["(none)"]:
            cwe_hits[c][0] += r["static"]["before"]["blocked"]
            cwe_hits[c][1] += 1
    out["static_by_cwe"] = {c: {"caught": v[0], "total": v[1]} for c, v in sorted(cwe_hits.items(), key=lambda x: -x[1][1])}
    OUT.write_text(json.dumps(out, indent=2))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--per-ecosystem", type=int, default=25)
    e = sub.add_parser("eval")
    e.add_argument("--llm", type=int, default=0)
    e.add_argument("--model", default="haiku")
    args = ap.parse_args()
    if args.cmd == "collect":
        print(f"{len(collect(args.per_ecosystem))} advisories cached")
        return 0
    from core.llm import LLMLimitReached
    try:
        out = evaluate(args.llm, args.model)
    except LLMLimitReached as e:
        print(f"Pro limit reached: {e}. Progress saved; re-run later.")
        return 3
    print(json.dumps({k: v for k, v in out.items() if k not in ("advisories", "static_by_cwe")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
