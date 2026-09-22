# tests/test_mcp.py
"""Tests for the pure MCP tool functions in privacy_hud.mcp_tools.

These functions are the last hop before user-facing surfaces (the UI, the
skill's printed audit). The risk that matters most here is I1: no raw
sensitive value may ever leave one of these functions — only IDs, counts,
types, destinations, timestamps, and the pre-masked `masked_example` the
ledger already stores. `test_no_raw_value_survives_json_round_trip` is the
gate for that, run against every function's return value at once.

The second risk that matters is design.md §8's consent rule: `allow_once`
must refuse to mint a token for an exposure the user has not reviewed
(`reviewed=False` -> PermissionError). Consent without information is not
consent.
"""
from __future__ import annotations

import json

import pytest

from privacy_hud import hud_snapshot as hs
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.mcp_tools import (
    allow_once,
    apply_policy,
    get_exposure_detail,
    get_session_summary,
    hud_set_hidden,
    hud_status,
    read_guard_set,
    read_guard_status,
    list_exposures,
)

M = load_matrix()

# A raw value that must NEVER appear, in any form, in any function's return.
RAW_LOCAL_PART = "jordan"
RAW_SECRET = "sk-live-abcdef0123456789"


@pytest.fixture
def led(tmp_path):
    ledger = Ledger(tmp_path / "l.db", M)
    ledger.start_session("s1", cwd="/r", model="gpt-5")
    ledger.record("s1", turn_id="t1", kind="exposed", data_type="email",
                   source="support.log", destination="model_context",
                   value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
                   tool_name="Read", protection=None)
    ledger.record("s1", turn_id="t2", kind="prevented", data_type="credential",
                   source="tool input", destination="mcp_tool",
                   value_hash=b"\x02" * 16, masked_example=None,
                   tool_name="mcp__github__x", protection="blocked")
    ledger.record("s1", turn_id="t3", kind="local_access", data_type="path",
                   source="terminal output", destination="local",
                   value_hash=b"\x03" * 16, masked_example="/Users/.../app.log",
                   tool_name="Read", protection=None)
    return ledger


# --------------------------------------------------------------------- #
# get_session_summary
# --------------------------------------------------------------------- #

def test_summary_returns_the_legacy_variant(led):
    s = get_session_summary(led, "s1")
    assert list(s.as_dict()) == [
        "accounting_version", "legacy_score", "legacy_cap", "legacy_percent",
        "legacy_permitted_crossing_rows", "legacy_boundary_kinds",
        "legacy_prevented_rows", "score_label", "accounting_note"]
    assert s.legacy_permitted_crossing_rows == 1
    assert s.legacy_prevented_rows == 1


# --------------------------------------------------------------------- #
# list_exposures
# --------------------------------------------------------------------- #

def test_list_exposures_returns_no_raw_values(led):
    rows = list_exposures(led, "s1", "Exposed")
    # `.as_dict()` is the explicit serialization step at the JSON boundary
    # (ledger.py's `_EXPOSURE_JSON_FIELDS`); this is what a client receives.
    blob = json.dumps([r.as_dict() for r in rows])
    assert "@acme.com" in blob          # the masked exemplar is fine
    assert RAW_LOCAL_PART not in blob   # the raw local part is not
    assert len(rows) == 1
    assert rows[0].data_type == "email"


def test_list_exposures_prevented_tab(led):
    rows = list_exposures(led, "s1", "Prevented")
    assert len(rows) == 1
    assert rows[0].data_type == "credential"
    assert rows[0].protection == "blocked"


def test_list_exposures_all_events_includes_every_kind(led):
    rows = list_exposures(led, "s1", "All events")
    kinds = {r.kind for r in rows}
    assert kinds == {"exposed", "prevented", "local_access"}
    assert len(rows) == 3


def test_list_exposures_rejects_an_unknown_tab(led):
    with pytest.raises(ValueError):
        list_exposures(led, "s1", "Nonexistent")


def test_list_exposures_rows_carry_no_value_hash_bytes(led):
    # bytes are not JSON-serializable at all -- if this key ever leaked
    # through, json.dumps above would already have raised. This test names
    # the invariant explicitly rather than relying on that side effect.
    #
    # It is now structural, not a maintained exclusion list: `ExposureRow` has
    # no `value_hash` field at all (only `EventRow`, which never crosses this
    # boundary, does), and `as_dict()` emits only `_EXPOSURE_JSON_FIELDS`.
    rows = list_exposures(led, "s1", "All events")
    assert all(not hasattr(r, "value_hash") for r in rows)
    assert all("value_hash" not in r.as_dict() for r in rows)


# --------------------------------------------------------------------- #
# get_exposure_detail
# --------------------------------------------------------------------- #

def test_get_exposure_detail_by_row_id(led):
    rows = list_exposures(led, "s1", "Exposed")
    event_id = rows[0].id
    detail = get_exposure_detail(led, "s1", event_id)
    assert detail.data_type == "email"
    assert detail.masked_example == "jo•••@acme.com"
    blob = json.dumps(detail.as_dict())
    assert RAW_LOCAL_PART not in blob


def test_get_exposure_detail_includes_budget_cap(led):
    rows = list_exposures(led, "s1", "Exposed")
    detail = get_exposure_detail(led, "s1", rows[0].id)
    assert detail.budget_cap == M.budget_cap


def test_get_exposure_detail_unknown_id_raises(led):
    with pytest.raises(LookupError):
        get_exposure_detail(led, "s1", 999999)


def test_get_exposure_detail_scoped_to_session(led):
    # A row id from a DIFFERENT session must not resolve, even if the
    # integer id happens to exist in the events table.
    rows = list_exposures(led, "s1", "Exposed")
    event_id = rows[0].id
    with pytest.raises(LookupError):
        get_exposure_detail(led, "s2-does-not-exist", event_id)


# --------------------------------------------------------------------- #
# allow_once
# --------------------------------------------------------------------- #

def test_allow_once_requires_a_reviewed_exposure(led):
    with pytest.raises(PermissionError):
        allow_once(led, "s1", tool_name="Bash", tool_input={"command": "x"},
                   reviewed=False)


def test_allow_once_mints_a_token_when_reviewed(led):
    allow_once(led, "s1", tool_name="Bash", tool_input={"command": "x"},
               reviewed=True)
    rows = [dict(r) for r in led.conn.execute(
        "SELECT * FROM policy_tokens WHERE session_id='s1'")]
    assert len(rows) == 1
    assert rows[0]["mode"] == "allow_once"
    assert rows[0]["tool_name"] == "Bash"


def test_allow_once_does_not_mint_when_not_reviewed(led):
    with pytest.raises(PermissionError):
        allow_once(led, "s1", tool_name="Bash", tool_input={"command": "x"},
                   reviewed=False)
    rows = led.conn.execute("SELECT count(*) FROM policy_tokens").fetchone()[0]
    assert rows == 0


# --------------------------------------------------------------------- #
# apply_policy
# --------------------------------------------------------------------- #

@pytest.mark.parametrize("selector", ["support.log", "tool input", "Bash"])
def test_block_source_is_refused_for_any_selector(led, selector):
    # #38: block_source names a label, not a source, so no selector -- not
    # even one shaped like a real origin -- makes a rule written that way
    # able to match one. Refused unconditionally, not contingent on whether
    # the ledger happens to record an origin for this particular value.
    with pytest.raises(ValueError, match="#38"):
        apply_policy(led, "s1", rule_type="block_source", selector=selector)
    assert led.conn.execute("SELECT count(*) FROM policy").fetchone()[0] == 0


def test_mask_rule_is_saved(led):
    apply_policy(led, "s1", rule_type="mask", selector="email")
    assert led.conn.execute(
        "SELECT count(*) FROM policy WHERE rule_type='mask'").fetchone()[0] == 1


def test_apply_policy_scopes_the_rule_to_the_session(led):
    apply_policy(led, "s1", rule_type="mask", selector="email")
    row = led.conn.execute("SELECT scope FROM policy").fetchone()
    assert "s1" in row["scope"]


def test_apply_policy_rejects_an_unknown_rule_type(led):
    with pytest.raises(ValueError):
        apply_policy(led, "s1", rule_type="not_a_real_rule", selector="x")
    assert led.conn.execute("SELECT count(*) FROM policy").fetchone()[0] == 0


@pytest.mark.parametrize("rule_type,selector", [
    ("block_path", ".env"),
    ("block_command", "git log"),
])
def test_an_origin_rule_is_written(led, rule_type, selector):
    apply_policy(led, "s1", rule_type=rule_type, selector=selector)
    assert led.policy_selectors("s1", rule_type) == {selector}


def test_block_source_is_still_refused(led):
    # #38: the old rule type named a label, not a source. It stays refused.
    with pytest.raises(ValueError, match="#38"):
        apply_policy(led, "s1", rule_type="block_source", selector=".env")


def test_allow_dest_is_refused_like_block_source(led):
    """`allow_dest` was accepted, written, and reported applied — and the
    engine never read it. `Engine.observe` compares `rule_type` against
    exactly `mask`, `block_path` and `block_command`, so an `allow_dest`
    row decided nothing while `{"applied": True}` said otherwise. That is
    #38's defect wearing a different name, and `apply_policy`'s own
    docstring calls it worse than an error."""
    with pytest.raises(ValueError, match="allow_dest"):
        apply_policy(led, "s1", rule_type="allow_dest",
                     selector="external_net")
    assert led.policy_selectors("s1", "allow_dest") == set()


# --------------------------------------------------------------------- #
# Cross-cutting: no raw sensitive value leaves ANY function, ever.
# --------------------------------------------------------------------- #

def test_no_raw_value_survives_json_round_trip(led):
    outputs = [
        get_session_summary(led, "s1").as_dict(),
        [r.as_dict() for r in list_exposures(led, "s1", "Exposed")],
        [r.as_dict() for r in list_exposures(led, "s1", "Prevented")],
        [r.as_dict() for r in list_exposures(led, "s1", "All events")],
    ]
    rows = list_exposures(led, "s1", "Exposed")
    outputs.append(get_exposure_detail(led, "s1", rows[0].id).as_dict())

    blob = json.dumps(outputs)
    for raw in (RAW_LOCAL_PART, RAW_SECRET):
        assert raw not in blob


# --------------------------------------------------------------------- #
# resolve_audit_session — which session is the audit ABOUT?
#
# The bug this replaces: `$privacy` resolved the session with `sessions
# ORDER BY started_at DESC LIMIT 1`, so a user with two Codex windows open
# who ran it in the first one was shown the second one's audit, silently.
# `MAX(events.ts)` is not the fix — a session that has disclosed nothing
# owns no event row, so a brand-new clean session would be skipped and an
# older session's numbers served in its place.
#
# The daemon is the only process that knows (it sees every hook, including
# the ones that write no ledger row). These tests stub the socket call and
# assert the POLICY: who is chosen, and what the output is allowed to claim.
# `tests/test_daemon.py` covers the same resolution against a real daemon
# over a real socket.
# --------------------------------------------------------------------- #

import privacy_hud.mcp_tools as mcp_tools  # noqa: E402
from privacy_hud.mcp_tools import CONCURRENT_WITHIN, resolve_audit_session  # noqa: E402


@pytest.fixture
def two_sessions(tmp_path):
    """A ledger where "most recently started" and "most recently active" are
    different sessions — the shape of the real report."""
    led = Ledger(tmp_path / "two.db", M)
    led.start_session("older", cwd="/r", model="gpt-5")
    led.conn.execute(
        "UPDATE sessions SET started_at = started_at - 600 "
        "WHERE session_id = 'older'")
    led.start_session("newer", cwd="/r", model="gpt-5")
    return led


def _daemon_says(monkeypatch, sessions):
    monkeypatch.setattr(mcp_tools, "_ask_daemon", lambda data_dir: sessions)


def test_explicit_id_wins_and_is_never_second_guessed(two_sessions, monkeypatch):
    """`$privacy <id>` is a deep link: it must keep working unchanged and
    take precedence over anything the daemon says."""
    _daemon_says(monkeypatch, [{"session_id": "newer", "age": 0.0}])
    r = resolve_audit_session(two_sessions, "/nowhere", explicit="older")
    assert (r.session_id, r.basis) == ("older", "explicit")
    assert r.certain and r.note == ""


def test_explicit_id_works_with_no_daemon(two_sessions, monkeypatch):
    _daemon_says(monkeypatch, None)
    r = resolve_audit_session(two_sessions, "/nowhere", explicit="whatever")
    assert (r.session_id, r.basis, r.note) == ("whatever", "explicit", "")


def test_the_bug_the_active_session_beats_the_last_started_one(
        two_sessions, monkeypatch):
    _daemon_says(monkeypatch, [{"session_id": "older", "age": 0.02}])
    old_answer = two_sessions.conn.execute(
        "SELECT session_id FROM sessions ORDER BY started_at DESC LIMIT 1"
    ).fetchone()["session_id"]
    r = resolve_audit_session(two_sessions, "/nowhere")
    assert old_answer == "newer", "fixture no longer reproduces the bug"
    assert r.session_id == "older"
    assert r.basis == "active"
    assert r.certain and r.note == ""


def test_a_session_with_no_events_is_still_resolvable(tmp_path, monkeypatch):
    """The `MAX(events.ts)` trap, stated as a test: the cleanest possible
    session has nothing in `events` and must still be the answer."""
    led = Ledger(tmp_path / "clean.db", M)
    led.start_session("spotless", cwd="/r", model="gpt-5")
    _daemon_says(monkeypatch, [{"session_id": "spotless", "age": 0.01}])
    assert led.conn.execute("SELECT COUNT(*) AS n FROM events"
                            ).fetchone()["n"] == 0
    assert resolve_audit_session(led, "/nowhere").session_id == "spotless"


def test_two_concurrent_sessions_are_named_not_silently_picked(
        two_sessions, monkeypatch):
    """Ambiguity is a real state in this design and the audit says so."""
    _daemon_says(monkeypatch, [{"session_id": "newer", "age": 0.1},
                               {"session_id": "older", "age": 0.4}])
    r = resolve_audit_session(two_sessions, "/nowhere")
    assert r.session_id == "newer"
    assert r.also_active == ("older",)
    assert not r.certain
    assert "older" in r.note
    assert "$privacy <session id>" in r.note


def test_an_idle_second_session_earns_no_caveat(two_sessions, monkeypatch):
    """The ordinary two-windows case: the other window's user is reading, not
    running tools, so it cannot be the caller and needs no hedge."""
    _daemon_says(monkeypatch, [
        {"session_id": "newer", "age": 0.1},
        {"session_id": "older", "age": CONCURRENT_WITHIN + 30},
    ])
    r = resolve_audit_session(two_sessions, "/nowhere")
    assert r.session_id == "newer"
    assert r.also_active == ()
    assert r.certain and r.note == ""


def test_no_daemon_falls_back_to_the_ledger_and_says_so(two_sessions,
                                                        monkeypatch):
    """A daemon that cannot be reached must not stop `$privacy` working — and
    must not let it claim to be showing the caller's own session either."""
    _daemon_says(monkeypatch, None)
    r = resolve_audit_session(two_sessions, "/nowhere")
    assert r.session_id == "newer"          # the old query's answer
    assert r.basis == "started_at"
    assert r.daemon_answered is False
    assert not r.certain
    assert "did not answer" in r.note
    assert "not necessarily the one you are in" in r.note
    # Being unmonitored is the other half of a missing daemon (README known
    # limit 1), and the note says so rather than pointing at the coverage
    # banner — a session observed earlier by a daemon that has since exited
    # still reads `verified`, so that banner would not be there to see.
    assert "Nothing is being recorded" in r.note


def test_a_daemon_with_no_live_session_is_a_different_answer(two_sessions,
                                                            monkeypatch):
    """Distinct from "could not ask": the daemon is up and started after
    this session did, which `Ledger.coverage` records as `attached`."""
    _daemon_says(monkeypatch, [])
    r = resolve_audit_session(two_sessions, "/nowhere")
    assert (r.session_id, r.basis) == ("newer", "started_at")
    assert r.daemon_answered is True
    assert "no live session on record" in r.note


def test_an_empty_ledger_resolves_to_nothing(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "empty.db", M)
    _daemon_says(monkeypatch, None)
    r = resolve_audit_session(led, "/nowhere")
    assert (r.session_id, r.basis) == (None, "none")
    assert not r.certain


def test_a_broken_daemon_socket_is_not_an_exception(two_sessions, tmp_path):
    """The real `_ask_daemon`, against a data dir with no socket in it. The
    fallback has to be reachable, so this cannot raise."""
    r = resolve_audit_session(two_sessions, tmp_path / "no-such-dir")
    assert (r.session_id, r.basis) == ("newer", "started_at")
    assert r.daemon_answered is False


def test_every_note_obeys_the_copy_rules(two_sessions, tmp_path, monkeypatch):
    """design.md §9 / I5: no note may imply the disclosure can be taken back,
    and none may editorialize about severity."""
    forbidden = ("undo", "revoke", "remove from context", "protected",
                 "100% secure", "critical", "severe", "dangerous")
    notes = []
    for sessions in (None, [],
                     [{"session_id": "newer", "age": 0.1},
                      {"session_id": "older", "age": 0.2}]):
        _daemon_says(monkeypatch, sessions)
        notes.append(resolve_audit_session(two_sessions, "/nowhere").note)
    # ... and the fourth basis, "none": an empty ledger with no daemon.
    _daemon_says(monkeypatch, None)
    notes.append(resolve_audit_session(
        Ledger(tmp_path / "nothing.db", M), "/nowhere").note)
    assert len(set(notes)) == 4, "a basis is sharing another's copy"
    for note in notes:
        assert note
        low = note.lower()
        for word in forbidden:
            assert word not in low, f"{word!r} in {note!r}"


# --------------------------------------------------------------------- #
# hud_status and hud_set_hidden
# --------------------------------------------------------------------- #

def test_hud_status_absent_then_shown_then_hidden(tmp_path):
    assert hud_status(tmp_path, "s1") == {
        "session_id": "s1", "present": False, "hidden": None, "state": "absent"}
    hs.HudPublisher(tmp_path).publish("s1", percent=3, blocked=0, unverified=False)
    assert hud_status(tmp_path, "s1") == {
        "session_id": "s1", "present": True, "hidden": False, "state": "shown"}
    hs.HudPublisher(tmp_path).set_hidden("s1", True)
    assert hud_status(tmp_path, "s1") == {
        "session_id": "s1", "present": True, "hidden": True, "state": "hidden"}


def test_hud_status_stale_snapshot(tmp_path):
    """A stale snapshot (older than STALE_AFTER) is not drawn -- `present:
    False` -- but it is a different diagnosis from having no file at all:
    the daemon that writes it is gone or wedged, so the session is not being
    recorded either. `state` is what carries that distinction."""
    hs.HudPublisher(tmp_path).publish("s1", percent=3, blocked=0, unverified=False)
    # Rewrite the file's updated_at to 60 s in the past
    snap = hs.read_snapshot(tmp_path, "s1", ignore_staleness=True)
    stale_doc = {"v": hs.SNAPSHOT_VERSION, "percent": snap.percent,
                 "blocked": snap.blocked, "unverified": snap.unverified,
                 "hidden": snap.hidden, "updated_at": snap.updated_at - 60.0}
    path = hs.snapshot_path(tmp_path, "s1")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        import json
        json.dump(stale_doc, fh, separators=(",", ":"))
    # Not drawn, and the reason is nameable.
    assert hud_status(tmp_path, "s1") == {
        "session_id": "s1", "present": False, "hidden": None, "state": "stale"}


def test_hud_set_hidden_round_trip(tmp_path):
    hs.HudPublisher(tmp_path).publish("s1", percent=3, blocked=0, unverified=False)
    off = hud_set_hidden(tmp_path, "s1", True)
    assert off["hidden"] is True and off["state"] == "hidden"
    assert hs.read_snapshot(tmp_path, "s1").hidden is True
    on = hud_set_hidden(tmp_path, "s1", False)
    assert on["hidden"] is False and on["state"] == "shown"
    assert hs.read_snapshot(tmp_path, "s1").percent == 3   # numbers untouched


def test_hud_toggle_output_carries_no_content(tmp_path):
    out = hud_set_hidden(tmp_path, "s1", True)
    assert set(out) == {"session_id", "present", "hidden", "state"}
    assert out["state"] in {"absent", "stale", "hidden", "shown"}


# --------------------------------------------------------------------- #
# read_guard_status / read_guard_set
# --------------------------------------------------------------------- #

def test_read_guard_round_trip(tmp_path):
    assert read_guard_status(tmp_path) == {"deny_read": False}
    assert read_guard_set(tmp_path, True) == {"deny_read": True}
    assert read_guard_set(tmp_path, False) == {"deny_read": False}


def test_read_guard_set_says_so_when_the_setting_cannot_be_written(tmp_path):
    """`$privacy read on` against an unwritable `PLUGIN_DATA` used to let
    `PermissionError` escape, so the skill printed a traceback. The user
    has to learn that the setting did not stick -- and what it still says,
    since the guard goes on reading the old file."""
    data = tmp_path / "data"
    data.mkdir(mode=0o500)
    try:
        out = read_guard_set(data, True)
    finally:
        data.chmod(0o700)
    assert out["deny_read"] is False
    assert "unchanged" in out["error"]
