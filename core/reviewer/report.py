"""Security gate report (B5): Markdown PR comment + pass/fail decision."""
from dataclasses import dataclass, field

from core import config
from core.reviewer.static_scan import ScanFinding
from core.reviewer.two_view import TwoViewResult

SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "⬜"}
SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MARKER = "<!-- agentsentinel-report -->"


@dataclass
class GateResult:
    findings: list[ScanFinding]
    two_view: TwoViewResult | None = None
    errors: list[str] = field(default_factory=list)
    files_scanned: int = 0
    llm_incomplete: list[str] = field(default_factory=list)  # AI layers that should have run but did not
    allow_llm_outage: bool = False

    @property
    def real(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.triage.get("verdict", "real") == "real"]

    @property
    def false_alarms(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.triage.get("verdict") == "false_alarm"]

    def severity(self, f: ScanFinding) -> str:
        return f.triage.get("severity", f.severity)

    @property
    def blocking(self) -> list[ScanFinding]:
        return [f for f in self.real if self.severity(f) in config.FAIL_ON_SEVERITIES]

    @property
    def reviewer_blocking(self) -> list[dict]:
        if not self.two_view or self.two_view.view2.verdict != "vulnerable":
            return []
        return [i for i in self.two_view.view2.issues if isinstance(i, dict)
                and str(i.get("severity", "")).upper() in config.FAIL_ON_SEVERITIES]

    @property
    def manipulation(self) -> bool:
        return bool(self.two_view and self.two_view.manipulation_suspected)

    @property
    def failed(self) -> bool:
        return bool(self.blocking or self.manipulation or self.reviewer_blocking or self.outage_blocks)

    @property
    def outage_blocks(self) -> bool:
        """Fail closed: an AI review that did not complete is not a pass."""
        return bool(self.llm_incomplete) and not self.allow_llm_outage

    @property
    def exit_code(self) -> int:
        return 1 if self.failed else 0


def _cell(text: str, limit: int = 220) -> str:
    text = " ".join(str(text).split())
    return (text[:limit] + "…" if len(text) > limit else text).replace("|", "\\|")


def build_markdown(r: GateResult) -> str:
    status = "❌ **FAILED**: merge blocked" if r.failed else "✅ **PASSED**"
    md = [MARKER, f"## 🛡️ AgentSentinel Merge Gate: {status}", ""]
    if r.outage_blocks:
        md += ["### ⛔ AI review did not complete", "",
               "The merge is blocked because these AI checks could not run (fail closed): "
               + ", ".join(r.llm_incomplete) + ". Re-run the check when the AI is available.", ""]
    md.append(f"Scanned **{r.files_scanned}** changed file(s) · "
              f"**{len(r.real)}** real finding(s) · **{len(r.blocking)}** blocking · "
              f"**{len(r.false_alarms)}** false alarm(s) filtered")
    md.append("")

    if r.manipulation:
        md += ["### 🚨 AI reviewer manipulation suspected", "", f"> {r.two_view.reason}", ""]

    if r.two_view:
        tv = r.two_view
        md += ["### Two-view check", "",
               "| View | What the reviewer saw | Verdict |", "|---|---|---|",
               f"| 1 | Code as written + PR description | **{tv.view1.verdict}** |",
               f"| 2 | Comments removed, names neutralised, no PR text | **{tv.view2.verdict}** |", ""]
        if r.reviewer_blocking:
            md += ["**Issues found by the reviewer (view 2):**", ""]
            for i in r.reviewer_blocking:
                md.append(f"- {SEV_ICON.get(str(i.get('severity')).upper(), '')} "
                          f"`{i.get('file', '?')}:{i.get('line', '?')}` **{_cell(i.get('type', ''), 60)}**: "
                          f"{_cell(i.get('explanation', ''))}")
            md.append("")

    if r.real:
        md += ["### Findings", "", "| Sev | Location | Issue | Source | Fix |", "|---|---|---|---|---|"]
        for f in sorted(r.real, key=lambda f: -SEV_RANK.get(r.severity(f), 0)):
            sev = r.severity(f)
            why = f.triage.get("explanation") or f.message
            md.append(f"| {SEV_ICON.get(sev, '')} {sev} | `{f.file}:{f.line}` | **{f.rule}**: {_cell(why)} "
                      f"| {f.tool} | {_cell(f.triage.get('fix', '') or '-')} |")
        md.append("")

    if r.false_alarms:
        md += ["<details><summary>False alarms filtered by AI triage</summary>", ""]
        for f in r.false_alarms:
            md.append(f"- `{f.file}:{f.line}` {f.rule}: {_cell(f.triage.get('explanation', ''))}")
        md += ["", "</details>", ""]

    if r.errors:
        md += ["<details><summary>⚠️ Tool warnings</summary>", ""]
        md += [f"- {_cell(e, 300)}" for e in r.errors]
        md += ["", "</details>", ""]

    md.append("<sub>AgentSentinel · Semgrep + Gitleaks + LLM triage + two-view consistency check</sub>")
    return "\n".join(md)
