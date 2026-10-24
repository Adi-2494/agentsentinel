"""Merge Gate entry point (Part B).

Local:  python gate/run_gate.py --path examples/trick_pr --pr-body-file examples/trick_pr/PR_DESCRIPTION.md
CI:     python gate/run_gate.py --base origin/main --head HEAD --pr-body-env PR_BODY --comment-out comment.md
Exit code 1 = merge should be blocked.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import store  # noqa: E402
from core.reviewer import static_scan, triage, two_view  # noqa: E402
from core.reviewer.report import GateResult, build_markdown  # noqa: E402

SKIP_DIRS = {".git", "_gate", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".claude"}
SKIP_NAMES = {"PR_DESCRIPTION.md"}


def files_from_path(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*") if p.is_file() and p.name not in SKIP_NAMES
                  and not SKIP_DIRS.intersection(p.relative_to(path).parts))


def files_from_git(base: str, head: str, repo: Path, dest: Path) -> tuple[list[Path], list[str]]:
    """Write each changed file's content AT `head` into `dest` and return those paths.

    Contents come from the commit itself (git show), never from whatever is
    checked out, so the gate always judges exactly the PR's code.
    """
    out = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...{head}"],
        capture_output=True, text=True, cwd=repo, check=True,
    ).stdout
    files, errors = [], []
    for rel in out.splitlines():
        if not rel.strip() or SKIP_DIRS.intersection(Path(rel).parts):
            continue
        blob = subprocess.run(["git", "show", f"{head}:{rel}"], capture_output=True, cwd=repo)
        if blob.returncode != 0:
            errors.append(f"could not read {rel} at {head}: {blob.stderr.decode(errors='replace')[:200]}")
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob.stdout)
        files.append(target)
    return files, errors


def run(files: list[Path], root: Path, pr_body: str = "", use_llm: bool = True) -> GateResult:
    findings, errors = static_scan.scan_files(files, root)
    tv = None
    if use_llm:
        err = triage.triage(findings)
        if err:
            errors.append(f"triage: {err}")
        code_files = {}
        for f in files:
            if f.suffix.lower() in static_scan.CODE_SUFFIXES - {".md", ".txt", ".json"}:
                try:
                    code_files[str(f.resolve().relative_to(root.resolve()))] = f.read_text(errors="replace")
                except (OSError, ValueError):
                    continue
        if code_files:
            tv = two_view.two_view_check(code_files, pr_body)
            if "incomplete" in tv.reason:
                errors.append(tv.reason)
    else:
        for f in findings:
            f.triage = {"verdict": "real", "severity": f.severity, "by": "no-llm"}
        errors.append("LLM disabled (--no-llm): static scan only, no triage / two-view check")
    return GateResult(findings=findings, two_view=tv, errors=errors, files_scanned=len(files))


def log_result(result: GateResult, label: str) -> None:
    try:
        action = "failed" if result.failed else "passed"
        for f in result.real:
            store.log_event("gate", action, f.rule, result.severity(f),
                            {"pr": label, "file": f.file, "line": f.line, "tool": f.tool, "category": f.category})
        if result.manipulation:
            store.log_event("gate", action, "two_view_manipulation", "CRITICAL",
                            {"pr": label, "reason": result.two_view.reason})
        store.log_event("gate", action, "gate_run", "HIGH" if result.failed else "LOW",
                        {"pr": label, "files": result.files_scanned, "real": len(result.real),
                         "blocking": len(result.blocking), "false_alarms": len(result.false_alarms),
                         "manipulation": result.manipulation})
    except Exception as e:  # logging must never break the gate
        print(f"warning: could not log to SQLite: {e}", file=sys.stderr)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AgentSentinel Merge Gate")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--path", type=Path, help="scan a folder or file (local mode)")
    src.add_argument("--base", help="git base ref (CI mode, with --head)")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--repo", type=Path, default=Path.cwd())
    ap.add_argument("--pr-body-file", type=Path)
    ap.add_argument("--pr-body-env", help="name of an env var holding the PR description")
    ap.add_argument("--no-llm", action="store_true", help="static scan only (fallback)")
    ap.add_argument("--comment-out", type=Path, help="write the Markdown report here")
    ap.add_argument("--json-out", type=Path, help="write machine-readable results here")
    ap.add_argument("--label", default="", help="name for this run in the dashboard (e.g. PR #3)")
    args = ap.parse_args(argv)

    pr_body = ""
    if args.pr_body_file and args.pr_body_file.exists():
        pr_body = args.pr_body_file.read_text()
    elif args.pr_body_env:
        pr_body = os.environ.get(args.pr_body_env, "")

    if args.path:
        root = args.path if args.path.is_dir() else args.path.parent
        result = run(files_from_path(args.path), root, pr_body, use_llm=not args.no_llm)
    else:
        with tempfile.TemporaryDirectory(prefix="agentsentinel-pr-") as tmp:
            files, read_errors = files_from_git(args.base, args.head, args.repo, Path(tmp))
            result = run(files, Path(tmp), pr_body, use_llm=not args.no_llm)
            result.errors = read_errors + result.errors
    md = build_markdown(result)
    print(md)
    if args.comment_out:
        args.comment_out.write_text(md)
    if args.json_out:
        args.json_out.write_text(json.dumps({
            "failed": result.failed, "manipulation": result.manipulation,
            "findings": [f.to_dict() for f in result.findings],
            "two_view": result.two_view.to_dict() if result.two_view else None,
            "errors": result.errors,
        }, indent=2))
    log_result(result, args.label or str(args.path or f"{args.base}...{args.head}"))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
