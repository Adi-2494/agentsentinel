"""AgentSentinel dashboard (Part C).  Run:  streamlit run dashboard/app.py

Read-only: it only reads the SQLite log and saved result files. No LLM calls.
"""
import os
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import config  # noqa: E402
from dashboard import data  # noqa: E402

# Fixed colors (validated reference palette). Status colors are reserved for severity.
PART_COLORS = {"Live Guard": "#2a78d6", "Merge Gate": "#eb6834"}
SEV_COLORS = {"CRITICAL": "#d03b3b", "HIGH": "#ec835a", "MEDIUM": "#fab219", "LOW": "#8a8986"}
SEV_ICON = {"CRITICAL": "⛔", "HIGH": "🔶", "MEDIUM": "⚠️", "LOW": "·"}
BAR_COLOR = "#2a78d6"

st.set_page_config(page_title="AgentSentinel", page_icon="🛡️", layout="wide")


@st.cache_data(ttl=5)
def load(db: str) -> pd.DataFrame:
    return data.load_events(db)


def sev_label(s: str) -> str:
    return f"{SEV_ICON.get(s, '')} {s}"


def bar_by_rule(df: pd.DataFrame):
    counts = data.by_rule(df).head(15)
    if counts.empty:
        return None
    base = alt.Chart(counts).encode(
        y=alt.Y("rule:N", sort="-x", title=None, axis=alt.Axis(labelLimit=220)),
        x=alt.X("count:Q", title="Events", axis=alt.Axis(tickMinStep=1, grid=True, gridOpacity=0.3)),
        tooltip=[alt.Tooltip("rule:N", title="Rule"), alt.Tooltip("category:N", title="Category"),
                 alt.Tooltip("count:Q", title="Events")],
    )
    bars = base.mark_bar(color=BAR_COLOR, cornerRadiusEnd=4, height={"band": 0.7})
    labels = base.mark_text(align="left", dx=4, color="gray").encode(text="count:Q")
    return (bars + labels).properties(height=alt.Step(28))


def line_over_time(df: pd.DataFrame):
    series, unit = data.over_time(df)
    if series.empty:
        return None
    hover = alt.selection_point(fields=["bucket"], nearest=True, on="pointerover", empty=False)
    color = alt.Color("part:N", title=None, legend=alt.Legend(orient="top"),
                      scale=alt.Scale(domain=list(PART_COLORS), range=list(PART_COLORS.values())))
    base = alt.Chart(series).encode(
        x=alt.X("bucket:T", title=None), y=alt.Y("count:Q", title=f"Events per {unit}",
                                                 axis=alt.Axis(tickMinStep=1, gridOpacity=0.3)), color=color)
    lines = base.mark_line(strokeWidth=2)
    few = series["bucket"].nunique() <= 24  # sparse data: keep points visible
    points = base.mark_point(size=60, filled=True).encode(
        opacity=alt.condition(hover, alt.value(1), alt.value(0.9 if few else 0)))
    rule = alt.Chart(series).mark_rule(color="gray", opacity=0.4).encode(
        x="bucket:T",
        tooltip=[alt.Tooltip("bucket:T", title=unit.title(), format="%d %b %H:%M"),
                 alt.Tooltip("part:N", title="Part"), alt.Tooltip("count:Q", title="Events")],
    ).transform_filter(hover)
    hit = alt.Chart(series).mark_rule(opacity=0, strokeWidth=20).encode(x="bucket:T").add_params(hover)
    return (lines + points + rule + hit).properties(height=260)


def events_table(df: pd.DataFrame):
    view = df[df["rule"] != "gate_run"][["time", "source", "action", "severity", "rule", "category", "tool",
                                        "where", "info"]].copy()
    view["severity"] = view["severity"].map(sev_label)
    st.dataframe(view, hide_index=True, use_container_width=True, column_config={
        "time": st.column_config.DatetimeColumn("Time (UTC)", format="D MMM, HH:mm:ss"),
        "where": st.column_config.TextColumn("Target / PR", width="large"),
        "info": st.column_config.TextColumn("Reason", width="large"),
    })


# ---------------------------------------------------------------- layout
st.title("🛡️ AgentSentinel")
st.caption("Live Guard for AI coding tools · Merge Gate for pull requests · everything below is read from the local log")

db_path = st.sidebar.text_input("Event log (SQLite)", str(config.DB_PATH))
if st.sidebar.button("Refresh"):
    load.clear()
demo_db = os.environ.get("AGENTSENTINEL_DEMO_DB", "")
if not Path(db_path).exists() and demo_db and Path(demo_db).exists():
    db_path = demo_db  # fresh clone / public Space: fall back to the labelled demo log
events = load(db_path)
if not events.empty and events["detail_obj"].map(lambda d: bool(d.get("demo"))).any():
    st.warning("**Demo data.** Everything on this page is synthetic sample data, not real activity. "
               "Run AgentSentinel locally to see your own events.", icon="🧪")

if events.empty:
    st.info("No events yet. Trigger the Live Guard in Claude Code or run `python gate/run_gate.py --path examples/vulnerable_pr`.")

# filters: one row, above the charts
c1, c2, c3 = st.columns([2, 2, 1])
sev_pick = c1.multiselect("Severity", data.SEVERITIES, default=data.SEVERITIES)
src_opts = sorted(events["source"].dropna().unique()) if not events.empty else []
src_pick = c2.multiselect("Source", src_opts, default=src_opts)
span = c3.selectbox("Time range", ["All", "Last 24 h", "Last 7 days"])

df = events[events["severity"].isin(sev_pick) & events["source"].isin(src_pick)] if not events.empty else events
if span != "All" and not df.empty:
    cutoff = pd.Timestamp.now(tz="UTC") - (pd.Timedelta(hours=24) if span == "Last 24 h" else pd.Timedelta(days=7))
    df = df[df["time"] >= cutoff]

tab_over, tab_guard, tab_gate, tab_real, tab_bench = st.tabs(
    ["Overview", "Live Guard", "Merge Gate", "Real-world repos", "Benchmark"])

with tab_over:
    m = data.metrics(df)
    cols = st.columns(5)
    cols[0].metric("Blocked AI actions", m["blocked_actions"], help=f"{m['warnings']} more were sent to the user to confirm")
    cols[1].metric("Secrets caught", m["secrets_caught"])
    cols[2].metric("Personal data caught", m["pii_caught"])
    cols[3].metric("PRs failed", f"{m['prs_failed']} / {m['prs_checked']}")
    cols[4].metric("Manipulation alerts", m["manipulation_alerts"])

    left, right = st.columns(2)
    with left:
        st.subheader("Events by rule")
        chart = bar_by_rule(df)
        if chart:
            st.altair_chart(chart, use_container_width=True)
        else:
            st.caption("No events in this filter.")
    with right:
        st.subheader("Events over time")
        chart = line_over_time(df)
        if chart:
            st.altair_chart(chart, use_container_width=True)
        else:
            st.caption("No events in this filter.")

    st.subheader("Recent events")
    events_table(df)

with tab_guard:
    g = df[df["source"].isin(data.GUARD_SOURCES)]
    st.caption("Actions the AI coding tool tried that AgentSentinel blocked (deny) or sent to you to confirm (ask).")
    if g.empty:
        st.info("No Live Guard events yet.")
    else:
        events_table(g)

with tab_gate:
    runs = data.pr_runs(df)
    st.caption("Each Merge Gate run (local or GitHub Action). Findings are in the Overview table.")
    if runs.empty:
        st.info("No gate runs yet.")
    else:
        runs["result"] = runs["result"].map({"failed": "❌ failed", "passed": "✅ passed"}).fillna(runs["result"])
        runs["manipulation"] = runs["manipulation"].map({True: "🚨 yes", False: "no"})
        st.dataframe(runs, hide_index=True, use_container_width=True,
                     column_config={"time": st.column_config.DatetimeColumn("Time (UTC)", format="D MMM, HH:mm")})

with tab_real:
    real = data.load_json(ROOT / "benchmark" / "results" / "real_repos.json")
    st.caption("The Merge Gate run on real commits of public repos (static mode). See benchmark/real_repos.py.")
    if not real:
        st.info("No results yet. Run `python benchmark/real_repos.py --workdir <folder>`.")
    else:
        rows = [{"repo": r["repo"], "kind": r["kind"], "commits checked": len(r["prs"]),
                 "blocked": sum(p["exit"] for p in r["prs"]),
                 "findings": sum(len(p["findings"]) for p in r["prs"]),
                 "head": r["head"][:8]} for r in real]
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        pick = st.selectbox("Commits for", [r["repo"] for r in real])
        rep = next(r for r in real if r["repo"] == pick)
        st.dataframe(pd.DataFrame([{
            "commit": p["sha"], "subject": p["subject"], "files": p["files"],
            "result": "❌ blocked" if p["exit"] else "✅ passed",
            "rules": ", ".join(sorted({f["rule"] for f in p["findings"]})),
        } for p in rep["prs"]]), hide_index=True, use_container_width=True)

with tab_bench:
    bench = data.load_json(ROOT / "benchmark" / "results" / "results.json")
    if not bench:
        st.info("Benchmark results will appear here after Block 9 (`python benchmark/run_benchmark.py`).")
    else:
        st.json(bench)
