# tests/conftest.py
"""Shared fixtures and path setup for the whole suite."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from privacy_hud import dispatch

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


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    st = dispatch.new_state(tmp_path)
    yield st
    st.ledger.conn.close()
