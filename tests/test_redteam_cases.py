"""Every case in redteam/cases.py runs against the real code: caught stays caught, a gap is a
strict known-gap test (when a gap gets closed, this fails until the registry is updated)."""

from pathlib import Path

import pytest

from guard.claude_hook import evaluate
from redteam import cases

ROOT = Path(__file__).resolve().parent.parent


def _param(c: cases.Case):
    marks = [pytest.mark.xfail(strict=True, reason=f"KNOWN GAP: {c.note}")] if c.status == "gap" else []
    return pytest.param(c, id=c.id, marks=marks)


@pytest.mark.parametrize("case", [_param(c) for c in cases.CASES])
def test_case(case: cases.Case, tmp_path):
    assert cases.run(case, str(tmp_path)), f"{case.id} {case.technique}: not caught"


def test_registry_is_well_formed():
    ids = [c.id for c in cases.CASES]
    assert len(ids) == len(set(ids))
    assert all(c.status in ("caught", "gap") and c.note for c in cases.CASES)


def test_generated_readme_is_up_to_date(tmp_path):
    results = {c.id: c.status == "caught" for c in cases.CASES}  # the tests above prove these hold
    readme = (ROOT / "redteam" / "README.md").read_text(encoding="utf-8")
    assert readme == cases.markdown(results), "run: python -m redteam.cases --markdown > redteam/README.md"


# The secret-folder rule once denied every recursive command (`grep -rn TODO .`): never again.
NORMAL = [
    "tar czf backup.tgz src",
    "cp -r docs /tmp/d",
    "grep -rn TODO .",
    'find . -name "*.py"',
    "du -sh ~/.cache",
    "rsync -a ./ build/",
    "git push origin main",
    "git push",
    "git remote add upstream https://github.com/x/y.git",
    "git push git@github.com:me/r.git",
    "a=1; echo $a",
    "X=build; rm -rf $X",
    "python3 -c \"print('a' + 'b')\"",
    "bash scripts/build.sh",
    "export PATH=$HOME/bin:$PATH; make",
]


@pytest.mark.parametrize("command", NORMAL)
def test_normal_commands_stay_allowed(command):
    assert evaluate("Bash", {"command": command}, "/tmp")[0] is None, command


def test_variable_expansion_cannot_blow_up():
    command = "a=" + "x" * 1000 + "; " + "$a" * 5000
    assert len(command) < 20_000
    evaluate("Bash", {"command": command}, "/tmp")  # bounded: must simply return
