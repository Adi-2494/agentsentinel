"""Live-Claude tests (marker `llm`) use the developer's Claude plan. They run ONLY with an
explicit --run-llm flag, so no -m expression (e.g. -m "not integration") can enable them by accident."""
import pytest


def pytest_addoption(parser):
    parser.addoption("--run-llm", action="store_true", default=False,
                     help="run tests marked llm (makes real Claude calls)")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-llm"):
        return
    skip = pytest.mark.skip(reason="live Claude test: pass --run-llm to run it")
    for item in items:
        if "llm" in item.keywords:
            item.add_marker(skip)
