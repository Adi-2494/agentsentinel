"""Run the unchanged Merge Gate for a webhook Job and log it (v2 V1/V2).

The engine is reused verbatim (`gate.run_gate`): files come from the PR head commit via
`git show` (INV-5), the gate fails closed, and the result is written to the same SQLite log the
dashboard reads. V2 also carries the Markdown report + a GitHub check conclusion so the result can
be posted back. Fetching a remote clone (install token) is V3; here `repo_root` is a local
checkout the resolver provides.
"""

import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.reviewer import report
from gate import run_gate


@dataclass(frozen=True)
class Job:
    repo: str  # "owner/name"
    pr_number: int
    head_sha: str  # any ref git can resolve (sha or branch)
    base_ref: str
    pr_body: str = ""


@dataclass(frozen=True)
class JobResult:
    failed: bool
    blocking_count: int
    exit_code: int
    errors: list[str]
    conclusion: str  # GitHub Check Run conclusion: "failure" | "success"
    report_markdown: str  # the PR comment body


def run_job(job: Job, repo_root: Path, use_llm: bool = True) -> JobResult:
    """Run the gate on the PR head and log it. Raises on git/engine failure (caller fails closed)."""
    with tempfile.TemporaryDirectory(prefix="agentsentinel-pr-") as tmp:
        files, read_errors = run_gate.files_from_git(job.base_ref, job.head_sha, Path(repo_root), Path(tmp))
        result = run_gate.run(files, Path(tmp), job.pr_body, use_llm=use_llm)
        result.errors = read_errors + result.errors
        markdown = report.build_markdown(result)
    run_gate.log_result(result, label=f"{job.repo}#{job.pr_number}")
    return JobResult(
        failed=result.failed,
        blocking_count=len(result.blocking),
        exit_code=result.exit_code,
        errors=result.errors,
        conclusion="failure" if result.failed else "success",
        report_markdown=markdown,
    )
