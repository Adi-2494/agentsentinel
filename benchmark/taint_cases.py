"""Score the Python taint analysis on the hand-written case set (free, no LLM).

    python benchmark/taint_cases.py

tests/fixtures/taint/vuln/*.py each mark one sink line with "# SINK <kind>"; a finding of
that kind on that line counts as caught. tests/fixtures/taint/safe/*.py are look-alikes
that must produce no finding at all.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.reviewer import taint  # noqa: E402

CASES = ROOT / "tests" / "fixtures" / "taint"


def expected(path: Path) -> tuple[int, str]:
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if "# SINK" in line:
            return i, line.split("# SINK", 1)[1].split()[0]
    raise ValueError(f"{path} has no # SINK marker")


def score() -> dict[str, object]:
    caught, missed, false_alarms = [], [], []
    for f in sorted((CASES / "vuln").glob("*.py")):
        line, kind = expected(f)
        found, _ = taint.analyze([f])
        (caught if any(x.line == line and x.kind == kind for x in found) else missed).append(f.name)
    for f in sorted((CASES / "safe").glob("*.py")):
        found, _ = taint.analyze([f])
        if found:
            false_alarms.append((f.name, [(x.line, x.rule) for x in found]))
    n_safe = len(list((CASES / "safe").glob("*.py")))
    return {"caught": caught, "missed": missed, "false_alarms": false_alarms, "n_safe": n_safe}


def main() -> int:
    r = score()
    caught, missed, fa = r["caught"], r["missed"], r["false_alarms"]
    assert isinstance(caught, list) and isinstance(missed, list) and isinstance(fa, list)
    for name in caught:
        print(f"  CAUGHT  {name}")
    for name in missed:
        print(f"  MISSED  {name}")
    for name, hits in fa:
        print(f"  FALSE ALARM  {name} {hits}")
    total = len(caught) + len(missed)
    print(f"taint: {len(caught)}/{total} vulnerable caught; safe look-alikes flagged: {len(fa)}/{r['n_safe']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
