"""Data layer for the dashboard: load the SQLite log, categorise, count. No UI."""
import json
import sqlite3
from pathlib import Path

import pandas as pd

from core import config
from core.detectors import commands, secrets

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
GUARD_SOURCES = {"claude_code", "cursor", "mcp"}

_SECRET_RULES = {r.name for r in secrets.RULES}
_PII_RULES = {"email", "phone_in", "aadhaar", "pan", "card_number"}
_COMMAND_RULES = {r[0] for r in commands.WHOLE_COMMAND_RULES} | {
    "reads_secret_file", "file_upload_unknown_host", "data_to_unknown_host", "unknown_url",
    "remote_copy_unknown_host", "raw_socket_unknown_host",
}


def categorise(rule: str, detail: dict) -> str:
    if detail.get("category"):
        return {"vuln": "vulnerability", "file": "secret_file"}.get(detail["category"], detail["category"])
    if rule == "gate_run":
        return "pr_run"
    if rule == "two_view_manipulation":
        return "manipulation"
    if rule == "protected_file":
        return "secret_file"
    if rule in _SECRET_RULES:
        return "secret"
    if rule in _PII_RULES:
        return "pii"
    if rule in _COMMAND_RULES:
        return "command"
    if rule.startswith(("injection", "hidden_", "ai_config", "llm_injection")):
        return "injection"
    return "other"


def _parse(detail) -> dict:
    if not detail:
        return {}
    try:
        value = json.loads(detail)
        return value if isinstance(value, dict) else {"text": str(value)}
    except (TypeError, json.JSONDecodeError):
        return {"text": str(detail)}


def load_events(db_path: Path | str | None = None) -> pd.DataFrame:
    path = Path(db_path or config.DB_PATH)
    cols = ["id", "time", "source", "action", "rule", "severity", "detail"]
    if not path.exists():
        return pd.DataFrame(columns=cols + ["category", "info", "where", "tool", "detail_obj"])
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:  # sqlite3's `with` only commits; close explicitly (the dashboard is long-running)
        df = pd.read_sql_query(f"SELECT {', '.join(cols)} FROM events ORDER BY id DESC", conn)
    finally:
        conn.close()
    parsed = df["detail"].map(_parse)
    df["time"] = pd.to_datetime(df["time"], utc=True, errors="coerce")
    df["category"] = [categorise(r, d) for r, d in zip(df["rule"], parsed)]
    df["info"] = parsed.map(lambda d: d.get("message") or d.get("reason") or d.get("text") or "")
    df["where"] = parsed.map(lambda d: d.get("pr") or d.get("preview") or d.get("file") or "")
    df["tool"] = parsed.map(lambda d: d.get("tool", ""))
    df["detail_obj"] = parsed
    return df


def metrics(df: pd.DataFrame) -> dict:
    findings = df[df["rule"] != "gate_run"]
    runs = df[df["rule"] == "gate_run"]
    return {
        "blocked_actions": int(((df["source"].isin(GUARD_SOURCES)) & (df["action"] == "blocked")).sum()),
        "warnings": int(((df["source"].isin(GUARD_SOURCES)) & (df["action"] == "warned")).sum()),
        "secrets_caught": int(findings["category"].isin(["secret", "secret_file"]).sum()),
        "pii_caught": int((findings["category"] == "pii").sum()),
        "prs_checked": int(len(runs)),
        "prs_failed": int((runs["action"] == "failed").sum()),
        "manipulation_alerts": int((df["category"] == "manipulation").sum()),
    }


def by_rule(df: pd.DataFrame) -> pd.DataFrame:
    f = df[df["rule"] != "gate_run"]
    if f.empty:
        return pd.DataFrame(columns=["rule", "count", "category"])
    return (f.groupby(["rule", "category"]).size().reset_index(name="count")
            .sort_values("count", ascending=False))


def over_time(df: pd.DataFrame) -> tuple[pd.DataFrame, str]:
    """Events per time bucket for Live Guard vs Merge Gate. Bucket adapts to the span."""
    f = df[(df["rule"] != "gate_run") & df["time"].notna()].copy()
    if f.empty:
        return pd.DataFrame(columns=["bucket", "part", "count"]), "hour"
    span = f["time"].max() - f["time"].min()
    freq, label = ("D", "day") if span > pd.Timedelta(days=3) else ("h", "hour")
    f["part"] = f["source"].map(lambda s: "Live Guard" if s in GUARD_SOURCES else "Merge Gate")
    f["bucket"] = f["time"].dt.floor(freq).dt.tz_localize(None)
    out = f.groupby(["bucket", "part"]).size().reset_index(name="count")
    # fill empty buckets with 0 so lines don't jump over gaps
    full = pd.MultiIndex.from_product(
        [pd.date_range(out["bucket"].min(), out["bucket"].max(), freq=freq), ["Live Guard", "Merge Gate"]],
        names=["bucket", "part"])
    return out.set_index(["bucket", "part"]).reindex(full, fill_value=0).reset_index(), label


def pr_runs(df: pd.DataFrame) -> pd.DataFrame:
    runs = df[df["rule"] == "gate_run"]
    rows = []
    for _, r in runs.iterrows():
        d = r["detail_obj"]
        rows.append({"time": r["time"], "pr": d.get("pr", ""), "result": r["action"],
                     "files": d.get("files", 0), "real findings": d.get("real", 0),
                     "blocking": d.get("blocking", 0), "false alarms": d.get("false_alarms", 0),
                     "manipulation": bool(d.get("manipulation"))})
    return pd.DataFrame(rows)


def load_json(path: Path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------- benchmark
CONDITION_LABELS = {"baseline": "Plain review", "static": "Static only", "agentsentinel": "AgentSentinel"}
MODEL_LABELS = {"haiku": "Haiku", "sonnet": "Sonnet", "-": "No LLM"}
BENCH_METRICS = [  # (key, title) - all "lower is better"
    ("vulnerable_approved_pct", "Vulnerable PRs approved"),
    ("manipulated_approval_pct", "Trick PRs approved"),
    ("false_block_pct", "Safe PRs blocked"),
    ("leak_rate_pct", "Leak attempts that got through"),
]


def benchmark_frames(results: dict) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """(long metrics for charts, summary table, per-case outcomes) from results.json."""
    rows = []
    for r in results.get("table", []):
        row = dict(r)
        # leaks: "without" = attempts; "with AgentSentinel" = attempts not denied by the guard
        row["leak_rate_pct"] = (r.get("leak_with_agentsentinel_pct") if r["condition"] == "agentsentinel"
                                else r.get("leak_attempt_pct"))
        rows.append(row)
    table = pd.DataFrame(rows)
    if table.empty:
        return pd.DataFrame(), table, pd.DataFrame()
    table["Condition"] = table["condition"].map(CONDITION_LABELS).fillna(table["condition"])
    table["Model"] = table["model"].map(MODEL_LABELS).fillna(table["model"])
    long = []
    for key, title in BENCH_METRICS:
        if key not in table:
            continue
        for _, r in table.iterrows():
            if pd.notna(r[key]):
                long.append({"metric": title, "Condition": r["Condition"], "Model": r["Model"], "value": r[key]})
    per_case = []
    for key, r in results.get("per_case", {}).items():
        cid, cond, model = key.split("|")
        if "error" in r:
            outcome = "error"
        elif "attempted" in r:
            outcome = ("prevented" if r.get("prevented") else "held for confirmation" if r.get("held_for_confirmation")
                       else "leaked" if r.get("attempted") else "no attempt") if cond == "agentsentinel" else \
                      ("attempted leak" if r.get("attempted") else "no attempt")
        else:
            outcome = ("blocked" if r.get("blocked") else "approved") + (" · manipulation alert" if r.get("manipulation") else "")
        per_case.append({"case": cid, "type": cid.split("-")[0], "condition": CONDITION_LABELS.get(cond, cond),
                         "model": MODEL_LABELS.get(model, model), "outcome": outcome})
    return pd.DataFrame(long), table, pd.DataFrame(per_case)



# ---------------------------------------------------------------- real-world data
def ghsa_summary_rows(gh: dict) -> list[dict]:
    rows = [("Static only (all advisories)", gh.get("static"))]
    for key, label in (("haiku", "Haiku"), ("sonnet", "Sonnet")):
        if gh.get(f"llm_{key}"):
            rows.append((f"Static only (same {gh[f'llm_{key}']['n']} as {label})", gh.get(f"llm_{key}_static_same_sample")))
            rows.append((f"AgentSentinel + Claude {label}", gh[f"llm_{key}"]))
    return [{"Condition": name, "Advisories": m["n"],
             "Vulnerable version blocked": f"{m['caught_vulnerable_pct']}%",
             "Fixed version still blocked": f"{m['still_flagged_after_fix_pct']}%",
             "Caught bug AND passed fix": f"{m['fix_aware_pct']}%"} for name, m in rows if m]


def ghsa_case_rows(gh: dict) -> list[dict]:
    fmt = lambda r: "–" if not r else f"{'blocked' if r['before']['blocked'] else 'passed'} → " \
        f"{'blocked' if r['after']['blocked'] else 'passed'}"  # noqa: E731
    return [{"advisory": f"https://github.com/advisories/{a['ghsa']}", "project": a["repo"],
             "ecosystem": a["ecosystem"], "severity": a["severity"], "CWE": ", ".join(a["cwes"]),
             "static (before → after fix)": fmt(a.get("static")),
             "Haiku (before → after fix)": fmt(a.get("llm_haiku")),
             "Sonnet (before → after fix)": fmt(a.get("llm_sonnet"))} for a in gh.get("advisories", [])]


def injection_rows(pi: dict) -> list[dict]:
    rows = []
    for key, label in (("rules_test_heldout", "Rules: held-out test split"),
                       ("rules_train_used_for_tuning", "Rules: train split (used for tuning)"),
                       ("llm_sample", "Gate's Claude AI-trap check (sample)")):
        m = pi.get(key)
        if m:
            rows.append({"Layer": label, "Prompts": m["tp"] + m["fp"] + m["fn"] + m["tn"],
                         "Recall": f"{m['recall_pct']}%", "Precision": f"{m['precision_pct']}%",
                         "False alarms": f"{m['fp']} / {m['fp'] + m['tn']}"})
    return rows
