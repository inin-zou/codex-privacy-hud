#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

PYTEST_ARGS = [
    "-q", "-p", "no:cacheprovider", "-m", "not slow",
    "--durations=10", "tests",
]


class FastBudget:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.started = clock()

    def pytest_sessionfinish(self, session, exitstatus):
        elapsed = self.clock() - self.started
        exceeded = elapsed > 120
        status = "exceeded" if exceeded else "within"
        message = f"fast tier: {elapsed:.2f}s; {status} 120s budget"
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(message)
        else:
            print(message)
        if exceeded and exitstatus == 0:
            session.exitstatus = 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the complete serial fast tier with a 120-second budget."
    )
    parser.parse_args(argv)
    if os.environ.get("PYTEST_ADDOPTS", "").strip():
        raise SystemExit(
            "test-fast: unset PYTEST_ADDOPTS so the declared tier runs unchanged"
        )
    os.chdir(Path(__file__).resolve().parents[1])
    import pytest

    return int(pytest.main(PYTEST_ARGS, plugins=[FastBudget()]))


if __name__ == "__main__":
    raise SystemExit(main())
