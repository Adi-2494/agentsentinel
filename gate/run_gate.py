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
from core.reviewer import injection_check, static_scan, triage, two_view  # noqa: E402
from core.reviewer.report import GateResult, build_markdown  # noqa: E402

SKIP_DIRS = {".git", "_gate", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
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
        capture_output=True, text=True, cwd=repo, check=True, encoding="utf-8", errors="replace"
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


def _renumber(findings) -> None:
    for i, f in enumerate(findings, 1):
        f.id = f"F{i}"


def run(files: list[Path], root: Path, pr_body: str = "", use_llm: bool = True,
        allow_llm_outage: bool = False) -> GateResult:
    findings, errors = static_scan.scan_files(files, root)
    incomplete: list[str] = []
    findings += static_scan.scan_pr_text(pr_body)
    _renumber(findings)
    tv = None
    if use_llm:
        err = triage.triage(findings)
        if err:
            errors.append(f"triage: {err}")  # findings stay "real" (fail closed already)
        llm_findings, err = injection_check.check(files, root, pr_body)
        if err:
            errors.append(f"AI-trap check: {err}")
            incomplete.append("AI-trap check")
        findings += llm_findings
        _renumber(findings)
        code_files = {}
        for f in files:  # every text file except dependency lock files (package.json, Makefile, docs...)
            if f.name not in static_scan.LOCK_FILES and static_scan.is_text_file(f):
                try:
                    code_files[f.resolve().relative_to(root.resolve()).as_posix()] = f.read_text(errors="replace", encoding="utf-8")
                except (OSError, ValueError):
                    continue
        if code_files:
            tv = two_view.two_view_check(code_files, pr_body)
            if "incomplete" in tv.reason:
                errors.append(tv.reason)
                incomplete.append("two-view code review")
    else:
        for f in findings:
            f.triage = {"verdict": "real", "severity": f.severity, "by": "no-llm"}
        errors.append("LLM disabled (--no-llm): static scan only, no triage / two-view / AI-trap LLM check")
    return GateResult(findings=findings, two_view=tv, errors=errors, files_scanned=len(files),
                      llm_incomplete=incomplete, allow_llm_outage=allow_llm_outage)


def log_result(result: GateResult, label: str) -> None:
    try:
        action = "failed" if result.failed else "passed"
        rows = [("gate", action, f.rule, result.severity(f),
                 {"pr": label, "file": f.file, "line": f.line, "tool": f.tool, "category": f.category})
                for f in result.real]
        if result.manipulation:
            rows.append(("gate", action, "two_view_manipulation", "CRITICAL",
                         {"pr": label, "reason": result.two_view.reason}))
        rows.append(("gate", action, "gate_run", "HIGH" if result.failed else "LOW",
                     {"pr": label, "files": result.files_scanned, "real": len(result.real),
                      "blocking": len(result.blocking), "false_alarms": len(result.false_alarms),
                      "manipulation": result.manipulation}))
        store.log_events(rows)  # one connection for the whole run
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
    ap.add_argument("--allow-llm-outage", action="store_true",
                    help="do not fail when an AI check could not run (default: fail closed)")
    ap.add_argument("--comment-out", type=Path, help="write the Markdown report here")
    ap.add_argument("--json-out", type=Path, help="write machine-readable results here")
    ap.add_argument("--label", default="", help="name for this run in the dashboard (e.g. PR #3)")
    args = ap.parse_args(argv)

    pr_body = ""
    if args.pr_body_file and args.pr_body_file.exists():
        pr_body = args.pr_body_file.read_text(encoding="utf-8")
    elif args.pr_body_env:
        pr_body = os.environ.get(args.pr_body_env, "")

    if args.path:
        root = args.path if args.path.is_dir() else args.path.parent
        result = run(files_from_path(args.path), root, pr_body, use_llm=not args.no_llm,
                     allow_llm_outage=args.allow_llm_outage)
    else:
        with tempfile.TemporaryDirectory(prefix="agentsentinel-pr-") as tmp:
            files, read_errors = files_from_git(args.base, args.head, args.repo, Path(tmp))
            result = run(files, Path(tmp), pr_body, use_llm=not args.no_llm,
                         allow_llm_outage=args.allow_llm_outage)
            result.errors = read_errors + result.errors
    md = build_markdown(result)
    print(md)
    if args.comment_out:
        args.comment_out.write_text(md, encoding="utf-8")
    if args.json_out:
        args.json_out.write_text(json.dumps({
            "failed": result.failed, "manipulation": result.manipulation,
            "findings": [f.to_dict() for f in result.findings],
            "two_view": result.two_view.to_dict() if result.two_view else None,
            "errors": result.errors,
        }, indent=2), encoding="utf-8")
    log_result(result, args.label or str(args.path or f"{args.base}...{args.head}"))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
