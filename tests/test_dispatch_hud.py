# tests/test_dispatch_hud.py
"""The three places dispatch.py publishes contract A (spec §5.1).

Drives `dispatch()` with real hook payloads against a real State in a temp
PLUGIN_DATA and reads the snapshot back through `read_snapshot`, so what is
asserted is the end-to-end fact the status line depends on: a hook event
lands, the file changes. The last test pins I6 -- a publisher that raises
must not fail the hook.
"""
from __future__ import annotations

import pytest

from privacy_hud import dispatch, hud_snapshot as hs

SID = "0199abcd-1111-2222-3333-444455556666"


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    st = dispatch.new_state(tmp_path)
    yield st
    st.ledger.conn.close()


def _start(state, sid=SID):
    return dispatch.dispatch(state, {"hook_event_name": "SessionStart",
                                     "session_id": sid, "cwd": "/w", "model": "m"})


def _prompt(state, text, sid=SID):
    return dispatch.dispatch(state, {"hook_event_name": "UserPromptSubmit",
                                     "session_id": sid, "cwd": "/w",
                                     "prompt": text})


def test_session_start_publishes_a_zero_snapshot(state, tmp_path):
    _start(state)
    snap = hs.read_snapshot(tmp_path, SID)
    assert snap is not None and snap.percent == 0 and snap.blocked == 0


def test_an_observation_republishes_the_ledger_numbers(state, tmp_path):
    _start(state)
    _prompt(state, "my key is AKIAIOSFODNN7EXAMPLE and mail me at a@b.co")
    snap = hs.read_snapshot(tmp_path, SID)
    summary = state.ledger.summary(SID)
    coverage = state.ledger.coverage(SID)
    assert snap.percent == summary.percent
    assert snap.blocked == summary.prevented
    assert snap.unverified == (not coverage.verified)


def test_session_end_retires_the_snapshot(state, tmp_path):
    _start(state)
    dispatch.dispatch(state, {"hook_event_name": "SessionEnd", "session_id": SID})
    assert not hs.snapshot_path(tmp_path, SID).exists()


def test_new_state_marks_the_daemon_and_sweeps(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    hs.hud_dir(tmp_path).mkdir()
    (hs.hud_dir(tmp_path) / "stray.json.tmp").write_text("{")
    st = dispatch.new_state(tmp_path)
    try:
        assert hs.read_daemon_marker(tmp_path) in (True, False)
        assert not (hs.hud_dir(tmp_path) / "stray.json.tmp").exists()
    finally:
        st.ledger.conn.close()


def test_a_broken_publisher_never_fails_the_hook(state, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(state.hud, "publish", boom)
    monkeypatch.setattr(state.hud, "retire", boom)
    assert _start(state) == dispatch._allow()
    out = _prompt(state, "hello")
    assert isinstance(out, dict)
    end = dispatch.dispatch(state, {"hook_event_name": "SessionEnd", "session_id": SID})
    assert "systemMessage" in end
