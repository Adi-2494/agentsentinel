"""Performance budget for the Live Guard: it runs before every agent action.

Budgets (benchmark/hook_latency.py prints the measured numbers). CI machines are slower and
noisier, so CI sets PERF_SLACK=3; locally the budgets apply as written.
"""

import os
import statistics
import sys

import pytest

from benchmark.hook_latency import BUDGET_MS, CASES, ROOT, p95, process_ms, timings
from guard.claude_hook import evaluate

SLACK = float(os.environ.get("PERF_SLACK", "1"))

# Under coverage (or a debugger) every line is traced and runs several times slower, so a
# timing would measure the tracer, not AgentSentinel. CI runs this file in its own step.
pytestmark = pytest.mark.skipif(sys.gettrace() is not None, reason="timings are meaningless under a tracer (coverage)")


@pytest.mark.parametrize("name", list(CASES))
def test_hook_check_is_within_budget(name):
    budget, tool, inp = CASES[name]
    ts = timings(lambda: evaluate(tool, inp, str(ROOT)), 30)
    assert p95(ts) < BUDGET_MS[budget] * SLACK, f"{name}: p95 {p95(ts):.1f} ms > {BUDGET_MS[budget] * SLACK:.0f} ms"


def test_whole_hook_process_is_within_budget():
    ts = process_ms(runs=8)
    assert statistics.median(ts) < BUDGET_MS["process"] * SLACK, f"median {statistics.median(ts):.0f} ms"
