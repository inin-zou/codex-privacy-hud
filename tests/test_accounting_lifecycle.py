"""#54 Phase 3: version-2 session lifecycle in the ledger.

Unavailability is permanent and never subtracts. Ending a session sets its
end time, then nulls the identity hashes in both identity tables, in one
transaction; opaque IDs, labels, resolution, history and charges survive.
This proves ledger erasure only. It does not prove destruction of a
production accounting key, which Phase 3 does not implement.
"""
from __future__ import annotations

import sqlite3

import pytest
from accounting_fakes import (
    crossed, event, prepared_ledger, recipient, snapshot, start_v2,
    unresolved_recipient, unresolved_subject, value_subject,
)

from privacy_hud import ledger as ledger_mod
from privacy_hud.ledger import UnsupportedAccounting

EMAIL_B3 = 6.0 * 1.5
INVALID_RECORD = r"invalid accounting (observation|event)"


@pytest.fixture
def led(tmp_path):
    ledger = prepared_ledger(tmp_path / "ledger.db")
    yield ledger
    try:
        ledger.conn.close()
    except sqlite3.ProgrammingError:
        pass


def _hashes(led, sid):
    return [tuple(r) for r in led.conn.execute(
        "SELECT identity_hash FROM subjects WHERE session_id=?"
        " UNION ALL SELECT identity_hash FROM recipients WHERE session_id=?",
        (sid, sid))]


def _identities(led, sid):
    return ([tuple(r) for r in led.conn.execute(
        "SELECT subject_id, subject_kind, resolution, label,"
        " unresolved_observation_id FROM subjects WHERE session_id=?"
        " ORDER BY subject_id", (sid,))],
        [tuple(r) for r in led.conn.execute(
            "SELECT recipient_id, destination_kind, resolution, label,"
            " unresolved_observation_id FROM recipients WHERE session_id=?"
            " ORDER BY recipient_id", (sid,))])


def _history(led, sid):
    return {table: [tuple(r) for r in led.conn.execute(
        f"SELECT * FROM {table} WHERE session_id=? ORDER BY rowid", (sid,))]
        for table in ("observations", "events", "disclosures", "scan_gaps")}


def _session(led, sid):
    return led.conn.execute("SELECT * FROM sessions WHERE session_id=?",
                            (sid,)).fetchone()


def test_unavailable_accounting_never_recharges(led):
    sid = start_v2(led)
    led.record_observation(crossed(sid), [event()])
    led.mark_accounting_unavailable(sid)
    led.mark_accounting_unavailable(sid)  # idempotent
    row = _session(led, sid)
    assert row["accounting_status"] == "unavailable"
    assert row["budget_score"] == pytest.approx(EMAIL_B3)
    assert row["profile_id"] and row["budget_cap"] == 120.0
    assert all(h[0] is not None for h in _hashes(led, sid))  # still open

    before = snapshot(led.conn)
    with pytest.raises(ValueError, match=INVALID_RECORD):
        led.record_observation(crossed(sid), [event(
            value_subject("new@example.com"))])
    assert snapshot(led.conn) == before
    late = led.record_observation(crossed(sid), [
        event(unresolved_subject(), unresolved_recipient())])
    assert late.budget_delta == 0.0 and late.disclosure_ids == ()
    assert _session(led, sid)["budget_score"] == pytest.approx(EMAIL_B3)

    with pytest.raises(sqlite3.DatabaseError):
        led.conn.execute("UPDATE sessions SET accounting_status='available'"
                         " WHERE session_id=?", (sid,))
    assert led.summary(sid).accounting_status == "unavailable"

    for not_v2 in ("legacy-boundary", "absent"):
        with pytest.raises(UnsupportedAccounting):
            led.mark_accounting_unavailable(not_v2)


def test_end_erases_hashes_but_preserves_joins_and_summary(led):
    sid = start_v2(led)
    led.record_observation(crossed(sid), [
        event(), event(value_subject("b@example.com"),
                       recipient("mcp_tool", "server-b"))])
    identities, history = _identities(led, sid), _history(led, sid)
    summary = led.summary(sid)
    profile = led.profile_for_session(sid)
    led.end_session(sid)
    assert _hashes(led, sid) and all(h[0] is None for h in _hashes(led, sid))
    assert _identities(led, sid) == identities
    assert _history(led, sid) == history
    row = _session(led, sid)
    assert row["ended_at"] is not None
    assert row["budget_score"] == pytest.approx(summary.confirmed_points)
    assert led.profile_for_session(sid) == profile
    assert led.summary(sid) == summary


@pytest.mark.parametrize("table", ["subjects", "recipients"])
def test_end_is_atomic_and_idempotent(led, table, monkeypatch):
    sid = start_v2(led)
    led.record_observation(crossed(sid), [event()])
    before = snapshot(led.conn)

    def deny(action, arg1, arg2, database, trigger):
        if action == sqlite3.SQLITE_UPDATE and arg1 == table:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    led.conn.set_authorizer(deny)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            led.end_session(sid)
    finally:
        led.conn.set_authorizer(None)
    assert snapshot(led.conn) == before
    assert _session(led, sid)["ended_at"] is None
    assert not led.conn.in_transaction and led._write_depth == 0

    monkeypatch.setattr(ledger_mod.time, "time", lambda: 1_800_000_000.0)
    led.end_session(sid)
    ended = _session(led, sid)["ended_at"]
    assert ended == 1_800_000_000
    monkeypatch.setattr(ledger_mod.time, "time", lambda: 1_900_000_000.0)
    led.end_session(sid)
    assert _session(led, sid)["ended_at"] == ended
    assert all(h[0] is None for h in _hashes(led, sid))


def test_ended_session_rejects_resolved_identity_insertion(led):
    sid = start_v2(led)
    led.record_observation(crossed(sid), [event()])
    led.end_session(sid)
    assert all(h[0] is None for h in _hashes(led, sid))
    before = snapshot(led.conn)
    for record in (event(), event(value_subject("new@example.com")),
                   event(unresolved_subject()),
                   event(to=recipient("mcp_tool", "server-z"))):
        with pytest.raises(ValueError, match=INVALID_RECORD):
            led.record_observation(crossed(sid), [record])
        assert snapshot(led.conn) == before


def test_delivery_retry_after_end_returns_original_result(led):
    sid = start_v2(led)
    obs = crossed(sid)
    first = led.record_observation(obs, [event()])
    led.end_session(sid)
    before = snapshot(led.conn)
    again = led.record_observation(obs, [event()])
    assert again.duplicate_delivery is True
    assert (again.observation_id, again.event_ids, again.disclosure_ids,
            again.budget_delta) == (first.observation_id, first.event_ids,
                                    first.disclosure_ids, first.budget_delta)
    assert snapshot(led.conn) == before
    assert all(h[0] is None for h in _hashes(led, sid))


def test_late_unresolved_observation_after_end_is_zero_charge(led):
    sid = start_v2(led)
    led.record_observation(crossed(sid), [event()])
    led.end_session(sid)
    score = _session(led, sid)["budget_score"]
    late = led.record_observation(crossed(sid), [
        event(unresolved_subject(), unresolved_recipient())])
    assert late.budget_delta == 0.0 and late.disclosure_ids == ()
    assert len(late.event_ids) == 1
    assert _session(led, sid)["budget_score"] == score
    assert all(h[0] is None for h in _hashes(led, sid))
    summary = led.summary(sid)
    assert summary.event_rows == 2
    assert summary.unresolved_subject_events == 1
