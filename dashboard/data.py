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
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        df = pd.read_sql_query(f"SELECT {', '.join(cols)} FROM events ORDER BY id DESC", conn)
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
