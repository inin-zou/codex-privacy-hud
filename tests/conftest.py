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
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp"))


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    st = dispatch.new_state(tmp_path)
    yield st
    st.ledger.conn.close()
