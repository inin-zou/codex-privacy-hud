# tests/conftest.py
"""Shared fixtures and path setup for the whole suite."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from privacy_hud import dispatch, engine

# `mcp/server.py` is a script, not a module in a package — deliberately, so a
# top-level `mcp` package cannot shadow the real `mcp` distribution. Tests
# reach it by putting its directory on the path, not by importing `mcp.server`.
#
# `append`, not `insert(0, ...)`: this runs at collection time for the whole
# suite, and putting a directory ahead of site-packages changes what EVERY
# import in EVERY test resolves to. Appending is enough — nothing installed
# is called `server` — and if something ever is, the installed one wins,
# which is the failure that announces itself rather than the one that does
# not.
sys.path.append(str(Path(__file__).resolve().parent.parent / "mcp"))

import runtime_helpers  # noqa: E402  (after the path setup above)


@pytest.fixture(autouse=True)
def release_writer_leases():
    """Give back every writer lease `runtime_helpers.writer_lease` handed
    out (#66 Pair 3).

    A lease is a file descriptor holding an `flock`, and a test that
    abandons its ledger abandons the descriptor with it. One per test is
    nothing; a whole suite run's worth is a descriptor limit. Autouse so
    the accounting is not a thing each test has to remember.
    """
    yield
    runtime_helpers.release_leases()


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    st = dispatch.new_state(
        tmp_path, writer_lease=runtime_helpers.writer_lease(tmp_path))
    yield st
    st.ledger.conn.close()


@pytest.fixture(autouse=True)
def drain_the_egress_deep_scan_slot():
    """Wait out any egress deep scan a test abandoned, suite-wide.

    `engine._TIER3_EGRESS_SLOT` is module-global. At most one egress scan
    worker is admitted at a time. Admission is nonblocking; the worker
    retains its slot until it exits, including after caller abandonment. A test that times out on
    purpose therefore leaks a busy slot into whichever test runs next, which
    with random ordering is a different one each run — and the symptom is a
    scan reporting `busy` in a test that never mentioned concurrency.

    Autouse and suite-wide rather than in one file: the leak crosses module
    boundaries, and the first version of this lived in
    `test_engine_tier_scheduling.py` while `test_engine.py` went red.

    It doubles as an assertion every test makes: the slot always comes back.
    """
    yield
    assert engine._TIER3_EGRESS_SLOT.acquire(timeout=10), (
        "an egress deep scan never released its admission slot")
    engine._TIER3_EGRESS_SLOT.release()
