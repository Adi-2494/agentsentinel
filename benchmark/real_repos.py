"""Real-world integration run: the Merge Gate on public repos' real commits.

Each recent commit is treated as a PR (parent...commit). Repos are cloned
into a work folder and only READ, never executed. Static mode by default
(no Claude calls); pass --llm to also run triage + two-view (uses Pro limit).

    python benchmark/real_repos.py --workdir /tmp/as-repos --commits 15
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REPOS = [
    # (name, url, kind)
    ("NodeGoat", "https://github.com/OWASP/NodeGoat.git", "vulnerable"),
    ("pygoat", "https://github.com/adeyosemanputra/pygoat.git", "vulnerable"),
    ("dvpwa", "https://github.com/anxolerd/dvpwa.git", "vulnerable"),
    ("markupsafe", "https://github.com/pallets/markupsafe.git", "clean"),
]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True, encoding="utf-8", errors="replace"
    ).stdout


def clone(url: str, dest: Path, depth: int) -> None:
    if not dest.exists():
        subprocess.run(
            ["git", "clone", "--quiet", "--depth", str(depth + 1), "--no-tags", url, str(dest)],
            check=True,
            capture_output=True,
        )


def run_commit(repo: Path, sha: str, use_llm: bool, out_dir: Path) -> dict:
    from gate import run_gate

    out = out_dir / f"{repo.name}-{sha[:8]}.json"
    args = [
        "--repo",
        str(repo),
        "--base",
        f"{sha}^",
        "--head",
        sha,
        "--json-out",
        str(out),
        "--label",
        f"{repo.name}@{sha[:8]}",
    ]
    if not use_llm:
        args.append("--no-llm")
    with open(os.devnull, "w", encoding="utf-8") as devnull:
        stdout, sys.stdout = sys.stdout, devnull
        try:
            code = run_gate.main(args)
        finally:
            sys.stdout = stdout
    data = json.loads(out.read_text(encoding="utf-8"))
    return {
        "sha": sha[:8],
        "subject": git(repo, "log", "-1", "--format=%s", sha).strip()[:80],
        "files": len(git(repo, "diff", "--name-only", "--diff-filter=ACMR", f"{sha}^...{sha}").split()),
        "exit": code,
        "manipulation": data["manipulation"],
        "findings": [
            {
                "rule": f["rule"],
                "tool": f["tool"],
                "category": f["category"],
                "severity": f["triage"].get("severity", f["severity"]),
                "file": f["file"],
            }
            for f in data["findings"]
        ],
        "errors": data["errors"],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", type=Path, required=True, help="where repos are cloned (untrusted)")
    ap.add_argument("--commits", type=int, default=15)
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--out", type=Path, default=ROOT / "benchmark" / "results" / "real_repos.json")
    args = ap.parse_args()
    os.environ.setdefault("AGENTSENTINEL_DB", str(args.workdir / "real_repos.db"))
    args.workdir.mkdir(parents=True, exist_ok=True)

    report = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, url, kind in REPOS:
            repo = args.workdir / name
            clone(url, repo, args.commits)
            shas = git(repo, "rev-list", f"--max-count={args.commits}", "--no-merges", "HEAD").split()
            runs = []
            for sha in shas:
                try:
                    git(repo, "rev-parse", "--verify", f"{sha}^")
                except subprocess.CalledProcessError:
                    continue  # shallow boundary: no parent
                runs.append(run_commit(repo, sha, args.llm, Path(tmp)))
            failed = sum(r["exit"] for r in runs)
            print(
                f"{name:12} ({kind:10}) head={git(repo, 'rev-parse', '--short', 'HEAD').strip()} "
                f"PRs={len(runs):3} blocked={failed:3} findings={sum(len(r['findings']) for r in runs)}"
            )
            report.append(
                {"repo": name, "url": url, "kind": kind, "head": git(repo, "rev-parse", "HEAD").strip(), "prs": runs}
            )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"saved {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
