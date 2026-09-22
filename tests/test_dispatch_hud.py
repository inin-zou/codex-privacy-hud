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

# `state` is defined in tests/conftest.py, shared with the whole suite.


def _start(state, sid=SID):
    return dispatch.dispatch(state, {"hook_event_name": "SessionStart",
                                     "session_id": sid, "cwd": "/w", "model": "m"})


def _prompt(state, text, sid=SID):
    return dispatch.dispatch(state, {"hook_event_name": "UserPromptSubmit",
                                     "session_id": sid, "cwd": "/w",
                                     "prompt": text})


def _hook(state, event, **fields):
    return dispatch.dispatch(
        state, {"hook_event_name": event, "session_id": SID, "cwd": "/w",
                "model": "gpt-5", "turn_id": "t1", **fields})


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
    assert snap.percent == summary.legacy_percent
    assert snap.blocked == summary.legacy_prevented_rows
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


def test_a_file_read_records_the_path_as_the_source(state):
    _hook(state, "SessionStart")
    _hook(state, "PostToolUse", tool_name="Bash",
          tool_input={"command": "cat .env"},
          tool_response="OPENAI_API_KEY=sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm")
    row = state.ledger.conn.execute(
        "SELECT source, source_kind FROM events").fetchone()
    assert (row["source"], row["source_kind"]) == (".env", "path")


def test_a_command_with_no_readable_path_records_its_program_name(state):
    _hook(state, "SessionStart")
    _hook(state, "PostToolUse", tool_name="Bash",
          tool_input={"command": "env"},
          tool_response="OPENAI_API_KEY=sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm")
    row = state.ledger.conn.execute(
        "SELECT source, source_kind FROM events").fetchone()
    assert (row["source"], row["source_kind"]) == ("env", "command")


def test_a_payload_with_no_origin_keeps_the_tool_name(state):
    # The finding has to come from a CHEAP tier: this fixture builds the real
    # detector stack, and CI installs no `transformers`, so tier 3 finds
    # nothing there. An email (tier 3 only) made this pass locally and fail on
    # every CI Python -- the row it asserts on was never written.
    _hook(state, "SessionStart")
    _hook(state, "PostToolUse", tool_name="WebFetch",
          tool_response="OPENAI_API_KEY=sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm")
    row = state.ledger.conn.execute(
        "SELECT source, source_kind FROM events").fetchone()
    assert (row["source"], row["source_kind"]) == ("WebFetch", None)


def test_a_local_read_of_a_path_reaches_the_ledger(state):
    """Before #36 a local PreToolUse returned early and was never scored.
    The read itself is now an observation, so that the engine can decide
    about it -- with the guard off it is simply allowed and recorded, and
    since this is the session's first sensitive read it also carries the
    once-per-session read-guard notice (fix round 1: this notice used to be
    silently dropped by `_decision_to_output`)."""
    _hook(state, "SessionStart")
    reply = _hook(state, "PreToolUse", tool_name="Bash",
                  tool_input={"command": "cat .env"})
    assert "$privacy read on" in reply.get("systemMessage", "")
    row = state.ledger.conn.execute(
        "SELECT kind, source, source_kind FROM events").fetchone()
    assert row is not None, "a local read now produces a row"
    assert (row["kind"], row["source"], row["source_kind"]) == \
        ("local_access", ".env", "path")


@pytest.mark.parametrize("command", ["env", "python -c \"open('.env')\""])
def test_a_local_command_with_no_path_still_returns_early(state, command):
    """A COMMAND origin or none at all must not build an Observation: there
    is nothing to decide, and `Engine.observe` would raise UnknownKey."""
    _hook(state, "SessionStart")
    assert _hook(state, "PreToolUse", tool_name="Bash",
                 tool_input={"command": command}) == {}
    assert state.ledger.conn.execute(
        "SELECT count(*) FROM events").fetchone()[0] == 0


def test_a_non_shell_tool_carrying_a_path_is_not_read_guarded(state, tmp_path):
    """Known limit 14's first clause, pinned as a DECISION rather than left
    to be found. `extract_origin` does resolve a path here -- PATH_KEYS runs
    for any tool, ahead of the command parsing -- so the guard could act on
    it. It deliberately does not: nothing says such a path is being *read*,
    Codex's only native writer is `apply_patch`, and denying a write under
    "PRIVACY HUD blocked a read" is the false block the spec weighs as worse
    than a miss.

    This costs no coverage on Codex, which has no native file-read tool (see
    `codex.SHELL_TOOL`). If that changes, this test is the one that must be
    argued with -- not quietly deleted."""
    from privacy_hud import origin, settings

    settings.Settings(tmp_path).set_deny_read(True)
    _hook(state, "SessionStart")

    tool_input = {"file_path": ".env"}
    assert origin.extract_origin("SomePluginTool", tool_input) is not None, \
        "fixture no longer reproduces the case this test is about"

    reply = _hook(state, "PreToolUse", tool_name="SomePluginTool",
                  tool_input=tool_input)
    assert reply == {}, "allowed, unexamined -- no deny, no notice"
    assert state.ledger.conn.execute(
        "SELECT count(*) FROM events").fetchone()[0] == 0
