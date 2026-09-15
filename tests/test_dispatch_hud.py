# tests/test_dispatch_hud.py
"""The three places dispatch.py publishes contract A (spec §5.1).

Drives `dispatch()` with real hook payloads against a real State in a temp
PLUGIN_DATA and reads the snapshot back through `read_snapshot`, so what is
asserted is the end-to-end fact the status line depends on: a hook event
lands, the file changes. The last test pins I6 -- a publisher that raises
must not fail the hook.
"""
from __future__ import annotations

import logging
import time
from types import SimpleNamespace

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


def test_a_heartbeat_keeps_a_quiet_session_visible(state, tmp_path, monkeypatch):
    """Spec §4.1's heartbeat rule, from the hook side. A session starts, then
    nothing happens for longer than STALE_AFTER -- the user is reading, or
    away. Before the heartbeat existed the status item vanished at 30 s and
    stayed gone until the next tool call, which is the daemon reporting
    "gone" about itself while it was sitting right there."""
    _start(state)
    later = time.time() + hs.STALE_AFTER + 5
    assert hs.read_snapshot(tmp_path, SID, now=later) is None, \
        "fixture no longer reproduces the staleness this test is about"
    monkeypatch.setattr(hs, "time", SimpleNamespace(time=lambda: later))
    state.hud.heartbeat([SID])
    snap = hs.read_snapshot(tmp_path, SID, now=later)
    assert snap is not None and snap.percent == 0


def test_a_heartbeat_keeps_the_daemon_marker_readable(state, tmp_path, monkeypatch):
    """`new_state` writes `_daemon.json` once; without a heartbeat it went
    stale 30 s later and `ambient.py` stopped rendering the
    unattributed-gaps line for the rest of the daemon's life."""
    before = hs.read_daemon_marker(tmp_path)
    assert before in (True, False)
    later = time.time() + hs.STALE_AFTER + 5
    assert hs.read_daemon_marker(tmp_path, now=later) is None
    monkeypatch.setattr(hs, "time", SimpleNamespace(time=lambda: later))
    state.hud.heartbeat([])
    assert hs.read_daemon_marker(tmp_path, now=later) is before


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


def test_a_swallowed_hud_failure_is_logged_without_its_payload(
        state, monkeypatch, caplog):
    """I6 says the hook survives; it does not say the failure vanishes. The
    message names the exception class and nothing else -- an exception's own
    text is untrusted content here (an OSError's is a path), so it is the
    one thing that must not reach a log line."""
    def boom(*a, **k):
        raise RuntimeError("sk-proj-NOTAREALKEY at /Users/someone/creds.env")

    monkeypatch.setattr(state.hud, "publish", boom)
    with caplog.at_level(logging.DEBUG, logger="privacy_hud.dispatch"):
        _start(state)
    messages = [r.getMessage() for r in caplog.records]
    assert any("hud publish failed" in m and "RuntimeError" in m
               for m in messages), messages
    assert not any("NOTAREALKEY" in m or "creds.env" in m for m in messages)


def test_a_session_first_met_without_session_start_gets_a_zero_snapshot(state, tmp_path):
    # The hook that spawns the daemon is the one it never hears: SessionStart
    # goes unanswered while the model loads, so the first event the daemon
    # sees for that session is a prompt or a tool call. Starting the engine
    # is the moment the daemon learns the session exists, and the item must
    # not stay blank until something is scored.
    with state.lock:
        dispatch._get_or_start_engine(state, SID, cwd="/w", model="m")
    snap = hs.read_snapshot(tmp_path, SID)
    assert snap is not None and snap.percent == 0 and snap.blocked == 0
