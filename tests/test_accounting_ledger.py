"""#54 Phase 3: profile persistence and atomic version-2 observation writes.

Every version-2 session here is synthetic, created through the private
constructor on a prepared (5401) ledger. No production path creates one.
An observation and everything it implies — identities, events, first
disclosures, the cached score and its scan gap — commit together or not at
all, and a retried delivery changes nothing.
"""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import threading
import time
from pathlib import Path

import pytest
from accounting_fakes import (
    KEY, M, PROFILE, count, event, hex_id, observation, prepared_ledger,
    profile_with, recipient, replace, score, snapshot, start_v2,
    unresolved_recipient, unresolved_subject, value_subject,
)

from privacy_hud import ledger_schema
from privacy_hud.accounting import Evidence, ScoringProfile
from privacy_hud.budget import group_score
from privacy_hud.ledger import Ledger, UnsupportedAccounting
from runtime_helpers import close_writer, writer_ledger

E = Evidence
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


def _trace(led: Ledger) -> list[str]:
    statements: list[str] = []
    led.conn.set_trace_callback(statements.append)
    return statements


def _deny(led: Ledger, *, insert: str | None = None,
          update: str | None = None, commit: bool = False) -> None:
    def authorizer(action, arg1, arg2, database, trigger):
        if insert and action == sqlite3.SQLITE_INSERT and arg1 == insert:
            return sqlite3.SQLITE_DENY
        if update and action == sqlite3.SQLITE_UPDATE and arg1 == update:
            return sqlite3.SQLITE_DENY
        if commit and action == sqlite3.SQLITE_TRANSACTION and arg1 == "COMMIT":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    led.conn.set_authorizer(authorizer)


def _raw_profile(led: Ledger, profile_id: str, *, document: str,
                 matrix_version: str = "1", cap: float = 120.0) -> None:
    led.conn.execute(
        "INSERT INTO scoring_profiles(profile_id,format_version,"
        "matrix_version,created_at,budget_cap,parameters_json)"
        " VALUES(?,1,?,1,?,?)", (profile_id, matrix_version, cap, document))


def _raw_v2_session(led: Ledger, session_id: str, profile_id: str,
                    cap: float) -> None:
    led.conn.execute(
        "INSERT INTO sessions(session_id,started_at,budget_cap,"
        "accounting_version,accounting_status,profile_id)"
        " VALUES(?,1,?,2,'available',?)", (session_id, cap, profile_id))


# -- profiles ----------------------------------------------------------------

def test_existing_profile_is_never_replaced(led, tmp_path):
    pid = led.ensure_profile(PROFILE)
    assert pid == PROFILE.profile_id
    row = led.conn.execute("SELECT * FROM scoring_profiles").fetchone()
    assert row["profile_id"] == pid
    assert row["parameters_json"] == PROFILE.as_canonical_json()
    assert row["format_version"] == 1
    assert row["matrix_version"] == PROFILE.matrix_version
    assert row["budget_cap"] == PROFILE.budget_cap
    assert isinstance(row["created_at"], int)
    before = snapshot(led.conn)

    statements = _trace(led)
    assert led.ensure_profile(ScoringProfile.from_matrix(M)) == pid
    led.conn.set_trace_callback(None)
    assert snapshot(led.conn) == before
    for statement in statements:
        upper = " ".join(statement.upper().split())
        assert not upper.startswith("UPDATE"), statement
        assert "REPLACE" not in upper, statement
        assert not upper.startswith("INSERT"), statement

    # Stored content under an ID that does not describe it is corruption.
    other = profile_with(budget_cap=150.0)
    _raw_profile(led, other.profile_id, document=PROFILE.as_canonical_json(),
                 cap=150.0)
    corrupt = snapshot(led.conn)
    with pytest.raises(UnsupportedAccounting):
        led.ensure_profile(other)
    assert snapshot(led.conn) == corrupt

    legacy = writer_ledger(tmp_path / "legacy.db", M)
    try:
        with pytest.raises(UnsupportedAccounting):
            legacy.ensure_profile(PROFILE)
    finally:
        close_writer(legacy)


def test_profile_read_validates_digest_and_columns(led):
    sid = start_v2(led)
    assert led.profile_for_session(sid) == PROFILE
    assert led.profile_for_session(sid).profile_id == PROFILE.profile_id

    corruptions = []

    bad_digest = "0" * 64
    _raw_profile(led, bad_digest, document=PROFILE.as_canonical_json())
    corruptions.append((bad_digest, 120.0))

    wrong_version = profile_with(budget_cap=130.0)
    _raw_profile(led, wrong_version.profile_id, matrix_version="2",
                 document=wrong_version.as_canonical_json(), cap=130.0)
    corruptions.append((wrong_version.profile_id, 130.0))

    wrong_cap = profile_with(budget_cap=140.0)
    _raw_profile(led, wrong_cap.profile_id,
                 document=wrong_cap.as_canonical_json(), cap=141.0)
    corruptions.append((wrong_cap.profile_id, 141.0))

    spaced = json.dumps(json.loads(profile_with(
        budget_cap=160.0).as_canonical_json()), indent=1)
    spaced_id = hashlib.sha256(spaced.encode()).hexdigest()
    _raw_profile(led, spaced_id, document=spaced, cap=160.0)
    corruptions.append((spaced_id, 160.0))

    empty_id = hashlib.sha256(b"{}").hexdigest()
    _raw_profile(led, empty_id, document="{}", cap=170.0)
    corruptions.append((empty_id, 170.0))

    for i, (pid, cap) in enumerate(corruptions):
        corrupt_sid = f"corrupt-{i}"
        _raw_v2_session(led, corrupt_sid, pid, cap)
        before = snapshot(led.conn)
        with pytest.raises(UnsupportedAccounting):
            led.profile_for_session(corrupt_sid)
        with pytest.raises(UnsupportedAccounting):
            led.record_observation(observation(corrupt_sid), [event()])
        assert snapshot(led.conn) == before

    for not_v2 in ("legacy-boundary", "absent"):
        with pytest.raises(UnsupportedAccounting):
            led.profile_for_session(not_v2)


# -- the private constructor -------------------------------------------------

def test_v2_constructor_requires_prepared_owned_absent_session(led, tmp_path):
    sid = start_v2(led)
    ended = start_v2(led)
    led.end_session(ended)
    before = snapshot(led.conn)

    with pytest.raises(RuntimeError):
        led._start_v2_session("no-owner", cwd="", model="", profile=PROFILE)
    for bad in ("", sid, ended, "legacy-boundary", None):
        with pytest.raises(ValueError, match="invalid version-2 session"):
            with led._write_transaction():
                led._start_v2_session(bad, cwd="", model="",  # type: ignore[arg-type]
                                      profile=PROFILE)
    assert snapshot(led.conn) == before

    led.conn.execute(f"PRAGMA user_version = {ledger_schema.ACTIVATED_VERSION}")
    try:
        with pytest.raises(UnsupportedAccounting):
            with led._write_transaction():
                led._start_v2_session("activated", cwd="", model="",
                                      profile=PROFILE)
    finally:
        led.conn.execute(
            f"PRAGMA user_version = {ledger_schema.PREPARED_VERSION}")
    assert snapshot(led.conn) == before

    legacy = writer_ledger(tmp_path / "legacy.db", M)
    try:
        legacy.start_session("old", cwd="", model="")
        legacy_before = snapshot(legacy.conn)
        with pytest.raises(UnsupportedAccounting):
            with legacy._write_transaction():
                legacy._start_v2_session("new", cwd="", model="",
                                         profile=PROFILE)
        assert snapshot(legacy.conn) == legacy_before
        assert legacy.conn.execute("PRAGMA user_version").fetchone()[0] == 0
    finally:
        close_writer(legacy)


def test_v2_constructor_stores_no_cwd_or_model(led):
    statements = _trace(led)
    with led._write_transaction():
        led._start_v2_session("planted-session", cwd="/home/alice/planted-repo",
                              model="planted-model-7", profile=PROFILE)
    led.conn.set_trace_callback(None)
    assert statements
    for statement in statements:
        assert "planted-repo" not in statement
        assert "planted-model" not in statement
    row = led.conn.execute(
        "SELECT * FROM sessions WHERE session_id='planted-session'").fetchone()
    assert row["cwd"] is None and row["model"] is None


def test_v2_constructor_does_not_activate_schema(led):
    sid = start_v2(led)
    assert led.conn.execute("PRAGMA user_version").fetchone()[0] == 5401
    assert ledger_schema.validate_schema(led.conn) == 5401
    row = led.conn.execute("SELECT * FROM sessions WHERE session_id=?",
                           (sid,)).fetchone()
    assert row["accounting_version"] == 2
    assert row["accounting_status"] == "available"
    assert row["profile_id"] == PROFILE.profile_id
    assert row["budget_score"] == 0
    assert row["budget_cap"] == PROFILE.budget_cap
    assert row["ended_at"] is None
    assert isinstance(row["started_at"], int)
    coverage = led.conn.execute(
        "SELECT observer, reason FROM coverage WHERE session_id=?",
        (sid,)).fetchall()
    assert [tuple(c) for c in coverage] == [(led.observer, "session_start")]
    assert count(led.conn, "observations", sid) == 0
    # A new host session is still created under legacy accounting.
    led.start_session("host", cwd="", model="")
    assert led.conn.execute(
        "SELECT accounting_version FROM sessions WHERE session_id='host'"
    ).fetchone()[0] == 1


# -- deliveries --------------------------------------------------------------

def test_delivery_retry_changes_nothing(led):
    sid = start_v2(led)
    obs = observation(sid)
    events = [event(value_subject("a@example.com")),
              event(value_subject("b@example.com"))]
    first = led.record_observation(obs, events)
    assert first.duplicate_delivery is False
    assert len(first.event_ids) == 2 and len(first.disclosure_ids) == 2
    assert first.budget_delta == pytest.approx(
        group_score(PROFILE, "email", "mcp_tool", 2), rel=1e-12)
    assert score(led.conn, sid) == pytest.approx(first.budget_delta, rel=1e-12)
    before = snapshot(led.conn)

    again = led.record_observation(obs, events)
    assert again.duplicate_delivery is True
    assert again.observation_id == first.observation_id
    assert again.event_ids == first.event_ids
    assert again.disclosure_ids == first.disclosure_ids
    assert again.budget_delta == first.budget_delta
    assert snapshot(led.conn) == before


def test_delivery_retry_uses_the_first_committed_record(led):
    sid = start_v2(led)
    obs = observation(sid)
    first = led.record_observation(obs, [event()])
    before = snapshot(led.conn)

    changed = replace(obs, action_id=hex_id(), ts=obs.ts + 5,
                      hook_event="PostToolUse", phase="post",
                      decision="none",
                      evidence=E.EXECUTION_OBSERVED | E.CROSSING_CONFIRMED)
    again = led.record_observation(changed, [
        event(value_subject("someone-else@example.com")),
        event(value_subject("third@example.com"), data_type="person")])
    assert again.duplicate_delivery is True
    assert (again.observation_id, again.event_ids, again.disclosure_ids,
            again.budget_delta) == (first.observation_id, first.event_ids,
                                    first.disclosure_ids, first.budget_delta)
    assert snapshot(led.conn) == before


def test_pre_and_post_have_distinct_delivery_identity(led):
    sid = start_v2(led)
    action = hex_id()
    pre = observation(sid, action_id=action,
                      evidence=E.PERMISSION_ISSUED | E.HOOK_OBSERVED)
    post = observation(sid, action_id=action, hook_event="PostToolUse",
                       phase="post", decision="none",
                       evidence=E.EXECUTION_OBSERVED | E.CROSSING_CONFIRMED)
    a = led.record_observation(pre, [event(kind="permitted",
                                           evidence=E.PERMISSION_ISSUED)])
    b = led.record_observation(post, [event()])
    assert a.observation_id != b.observation_id
    rows = led.conn.execute(
        "SELECT action_id, phase FROM observations WHERE session_id=?"
        " ORDER BY phase", (sid,)).fetchall()
    assert [tuple(r) for r in rows] == [(action, "post"), (action, "pre")]
    assert a.disclosure_ids == () and len(b.disclosure_ids) == 1
    assert score(led.conn, sid) == pytest.approx(EMAIL_B3)


def test_zero_finding_scan_gap_is_atomic(led):
    sid = start_v2(led)
    obs = observation(sid, scan_gap="timeout", ts=1_700_000_123)
    result = led.record_observation(obs, [])
    assert result.event_ids == () and result.disclosure_ids == ()
    assert result.budget_delta == 0.0
    assert count(led.conn, "observations", sid) == 1
    gaps = led.conn.execute(
        "SELECT ts, boundary, reason FROM scan_gaps WHERE session_id=?",
        (sid,)).fetchall()
    assert [tuple(g) for g in gaps] == [(1_700_000_123, "B3", "timeout")]
    assert led.scan_gaps(sid) == 1
    stored = led.conn.execute(
        "SELECT scan_gap FROM observations WHERE session_id=?",
        (sid,)).fetchone()[0]
    assert stored == "timeout"
    before = snapshot(led.conn)
    assert led.record_observation(obs, []).duplicate_delivery is True
    assert snapshot(led.conn) == before


# -- validation --------------------------------------------------------------

_OBSERVATION_DEFECTS = {
    "delivery_key_not_hex": {"delivery_key": "delivery-1"},
    "delivery_key_upper": {"delivery_key": "A" * 32},
    "action_id_empty": {"action_id": ""},
    "turn_id_host_text": {"turn_id": "turn-1"},
    "ts_bool": {"ts": True},
    "ts_float": {"ts": 1.5},
    "ts_negative": {"ts": -1},
    "hook_event_unknown": {"hook_event": "Notification"},
    "phase_mismatch": {"phase": "post"},
    "lifecycle_phase_on_tool": {"phase": "lifecycle"},
    "action_kind_unknown": {"action_kind": "exec"},
    "boundary_unknown": {"boundary": "B9"},
    "decision_unknown": {"decision": "block"},
    "evidence_out_of_range": {"evidence": 4096},
    "evidence_negative": {"evidence": -1},
    "evidence_plain_int": {"evidence": 64 | 1 | 256},
    "potential_crossing_int": {"potential_crossing": 1},
    "scan_gap_unknown": {"scan_gap": "slow"},
    "scan_gap_on_lifecycle": {"hook_event": "SessionStart",
                              "phase": "lifecycle", "action_kind": "lifecycle",
                              "scan_gap": "timeout"},
    "resolution_scope_unknown": {"resolution_scope": "all"},
    "resolution_scope_without_outcome": {
        "resolution_scope": "pairs",
        "evidence": E.PERMISSION_ISSUED | E.LOCAL_DETECTION},
    "deny_issued_without_deny": {
        "evidence": E.DENY_ISSUED | E.CROSSING_CONFIRMED | E.LOCAL_DETECTION},
    "rewrite_issued_without_rewrite": {
        "evidence": E.REWRITE_ISSUED | E.CROSSING_CONFIRMED},
    "permission_with_deny": {"decision": "deny"},
}

_EVENT_DEFECTS = {
    "occurrences_zero": {"occurrences": 0},
    "occurrences_bool": {"occurrences": True},
    "occurrences_float": {"occurrences": 1.0},
    "rule_id_not_committed": {"rule_id": "secret.aws_key"},
    "source_label_free_text": {"source_label": "support.log"},
    "source_label_file_label": {"source_label": "file " + "0" * 32},
    "exemplar_raw_value": {"masked_example": "alice@example.com"},
    "exemplar_on_credential": {"data_type": "credential",
                               "masked_example": "••••"},
    "exemplar_on_path": {"data_type": "path", "masked_example": "/h•••x"},
    "exemplar_with_control": {"masked_example": "a\x1b•••m"},
    "data_type_unknown": {"data_type": "zipcode"},
    "kind_unknown": {"kind": "leaked"},
    "detected_without_local_detection": {"kind": "detected"},
    "permitted_without_permission": {"kind": "permitted"},
    "prevented_without_intervention": {"kind": "prevented"},
    "retention_without_persistence": {"kind": "retention"},
    "local_access_off_b0": {"kind": "local_access",
                            "evidence": E.CROSSING_CONFIRMED},
    "evidence_plain_int": {"evidence": 64},
    "evidence_zero_exposed": {"evidence": E(0)},
    "subject_not_descriptor": {"subject": b"\x00" * 32},
    "recipient_not_descriptor": {"recipient": "server-a"},
}


@pytest.mark.parametrize(
    "case", [f"observation:{c}" for c in _OBSERVATION_DEFECTS]
    + [f"event:{c}" for c in _EVENT_DEFECTS])
def test_observation_rejects_invalid_metadata_atomically(led, case):
    sid = start_v2(led)
    good = event(value_subject("first@example.com"))
    assert led.record_observation(observation(sid), [good]).event_ids
    before = snapshot(led.conn)

    where, name = case.split(":")
    obs = observation(sid, scan_gap="busy")
    events = [event(value_subject("second@example.com")),
              event(value_subject("third@example.com"), to=recipient(
                  "mcp_tool", "server-b"))]
    if where == "observation":
        obs = replace(obs, **_OBSERVATION_DEFECTS[name])
    else:
        events.append(replace(event(value_subject("fourth@example.com")),
                              **_EVENT_DEFECTS[name]))
    with pytest.raises(ValueError, match=INVALID_RECORD):
        led.record_observation(obs, events)
    assert snapshot(led.conn) == before
    assert not led.conn.in_transaction


def test_valid_metadata_variants_are_accepted(led):
    """The counterpart of the rejection table: each nonnull form it
    rejects has a valid neighbour that is stored as given."""
    sid = start_v2(led)
    result = led.record_observation(observation(sid, turn_id=hex_id()), [
        event(value_subject("x@example.com"), rule_id=None,
              masked_example="x@•••m"),
        event(value_subject("abcd"), data_type="account",
              masked_example="••••", source_label="tool result"),
        event(value_subject("/home/a/.env"), data_type="path",
              rule_id="path.env", masked_example=None,
              source_label="local file"),
    ])
    assert len(result.event_ids) == 3
    rows = led.conn.execute(
        "SELECT rule_id, source_label, source_kind, masked_example"
        " FROM events WHERE session_id=? ORDER BY id", (sid,)).fetchall()
    assert [tuple(r) for r in rows] == [
        (None, "tool input", None, "x@•••m"),
        (None, "tool result", None, "••••"),
        ("path.env", "local file", None, None)]


def test_event_evidence_and_boundary_match_observation(led):
    sid = start_v2(led)
    before = snapshot(led.conn)
    obs = observation(sid)
    for bad in (event(value_subject("c@example.com"),
                      evidence=E.CROSSING_CONFIRMED | E.DENY_ENFORCED),
                event(value_subject("c@example.com"), boundary="B4",
                      to=recipient("external_net", "api.example.com"))):
        with pytest.raises(ValueError, match=INVALID_RECORD):
            led.record_observation(obs, [event(), bad])
        assert snapshot(led.conn) == before


def test_event_boundary_matches_frozen_profile(led):
    sid = start_v2(led)
    before = snapshot(led.conn)
    # Both names are valid; the frozen profile maps model_context to B1.
    with pytest.raises(ValueError, match=INVALID_RECORD):
        led.record_observation(observation(sid), [
            event(), event(to=recipient("model_context", "model context"))])
    assert snapshot(led.conn) == before

    # A session frozen under a different mapping is held to that mapping,
    # not to the live matrix.
    moved = profile_with(destination_boundary={"mcp_tool": "B4"})
    other = start_v2(led, profile=moved)
    with pytest.raises(ValueError, match=INVALID_RECORD):
        led.record_observation(observation(other), [event()])
    result = led.record_observation(observation(other, boundary="B4"),
                                    [event(boundary="B4")])
    assert result.budget_delta == pytest.approx(6.0 * 2.0)
    assert led.profile_for_session(other) == moved


# -- identity ----------------------------------------------------------------

def test_same_hash_in_two_sessions_never_shares_rows(led):
    one, two = start_v2(led), start_v2(led)
    a = led.record_observation(observation(one), [event()])
    b = led.record_observation(observation(two), [event()])
    assert a.budget_delta == b.budget_delta == pytest.approx(EMAIL_B3)
    subjects = led.conn.execute(
        "SELECT session_id, subject_id FROM subjects ORDER BY session_id"
    ).fetchall()
    recipients = led.conn.execute(
        "SELECT session_id, recipient_id FROM recipients ORDER BY session_id"
    ).fetchall()
    assert len(subjects) == len(recipients) == 2
    assert subjects[0]["subject_id"] != subjects[1]["subject_id"]
    assert recipients[0]["recipient_id"] != recipients[1]["recipient_id"]
    assert count(led.conn, "disclosures", one) == 1
    assert count(led.conn, "disclosures", two) == 1
    assert score(led.conn, one) == score(led.conn, two) == pytest.approx(
        EMAIL_B3)
    labels = [r[0] for r in led.conn.execute(
        "SELECT label FROM subjects ORDER BY rowid")]
    ids = [r[0] for r in led.conn.execute(
        "SELECT subject_id FROM subjects ORDER BY rowid")]
    assert labels == [f"value {i}" for i in ids]
    rlabels = [tuple(r) for r in led.conn.execute(
        "SELECT label, recipient_id FROM recipients ORDER BY rowid")]
    assert all(label == f"MCP recipient {rid}" for label, rid in rlabels)


def test_unresolved_descriptors_do_not_merge_by_null_hash(led):
    sid = start_v2(led)
    result = led.record_observation(observation(sid), [
        event(unresolved_subject()), event(unresolved_subject())])
    assert len(result.event_ids) == 2
    assert result.disclosure_ids == () and result.budget_delta == 0.0
    rows = led.conn.execute(
        "SELECT subject_id, resolution, identity_hash,"
        " unresolved_observation_id, label FROM subjects").fetchall()
    assert len(rows) == 2
    for row in rows:
        assert row["resolution"] == "unresolved"
        assert row["identity_hash"] is None
        assert row["unresolved_observation_id"] == result.observation_id
        assert row["label"] == f"unresolved value {row['subject_id']}"

    both = led.record_observation(observation(sid), [
        event(to=unresolved_recipient()), event(to=unresolved_recipient())])
    assert len(both.event_ids) == 2 and both.disclosure_ids == ()
    rrows = led.conn.execute(
        "SELECT recipient_id, label FROM recipients"
        " WHERE resolution='unresolved'").fetchall()
    assert len(rrows) == 2
    assert all(r["label"] == f"unresolved recipient {r['recipient_id']}"
               for r in rrows)

    # A deliberately reused token names one entity within an observation.
    token = hex_id()
    reused = led.record_observation(observation(sid), [
        event(unresolved_subject(token)),
        event(unresolved_subject(token), kind="detected",
              evidence=E.LOCAL_DETECTION)])
    subject_ids = {r[0] for r in led.conn.execute(
        "SELECT subject_id FROM events WHERE observation_id=?",
        (reused.observation_id,))}
    assert len(subject_ids) == 1
    assert score(led.conn, sid) == 0.0


def test_unresolved_identity_is_never_reused_across_observations(led):
    sid = start_v2(led)
    token = hex_id()
    first = led.record_observation(observation(sid),
                                   [event(unresolved_subject(token))])
    second = led.record_observation(observation(sid),
                                    [event(unresolved_subject(token))])
    rows = led.conn.execute(
        "SELECT subject_id, unresolved_observation_id FROM subjects"
        " ORDER BY rowid").fetchall()
    assert len(rows) == 2
    assert rows[0]["subject_id"] != rows[1]["subject_id"]
    assert [r["unresolved_observation_id"] for r in rows] == [
        first.observation_id, second.observation_id]
    # The token itself is never stored anywhere.
    for table, rows_ in snapshot(led.conn).items():
        for row in rows_:
            assert token not in repr(row), table


def test_duplicate_event_key_is_rejected_atomically(led):
    sid = start_v2(led)
    before = snapshot(led.conn)
    token = hex_id()
    for pair in ([event(), event(data_type="person", masked_example=None)],
                 [event(unresolved_subject(token)),
                  event(unresolved_subject(token), data_type="phone")]):
        with pytest.raises(ValueError, match=INVALID_RECORD):
            led.record_observation(observation(sid), pair)
        assert snapshot(led.conn) == before


# -- charging ----------------------------------------------------------------

def test_only_new_chargeable_pairs_change_score(led):
    sid = start_v2(led)
    subject = value_subject("carol@example.com")
    to = recipient()
    no_charge = [
        (observation(sid, evidence=E.PERMISSION_ISSUED),
         event(subject, to, kind="permitted", evidence=E.PERMISSION_ISSUED)),
        (observation(sid, decision="deny",
                     evidence=E.DENY_ISSUED | E.DENY_ENFORCED),
         event(subject, to, kind="prevented",
               evidence=E.DENY_ISSUED | E.DENY_ENFORCED)),
        (observation(sid, evidence=E.LOCAL_DETECTION),
         event(subject, to, kind="detected", evidence=E.LOCAL_DETECTION)),
        (observation(sid, boundary="B0", hook_event="PostToolUse",
                     phase="post", action_kind="read", decision="none",
                     evidence=E.EXECUTION_OBSERVED),
         event(subject, recipient("local", "local"), kind="local_access",
               evidence=E.EXECUTION_OBSERVED, boundary="B0")),
        (observation(sid, boundary="B1", hook_event="PreCompact",
                     phase="lifecycle", action_kind="lifecycle",
                     decision="none", evidence=E.PERSISTENCE_OBSERVED),
         event(subject, recipient("model_context", "model context"),
               kind="retention", evidence=E.PERSISTENCE_OBSERVED,
               boundary="B1", source_label="lifecycle")),
        (observation(sid), event(unresolved_subject(), to)),
        (observation(sid), event(subject, unresolved_recipient())),
    ]
    for obs, ev in no_charge:
        result = led.record_observation(obs, [ev])
        assert result.disclosure_ids == () and result.budget_delta == 0.0
    assert count(led.conn, "disclosures", sid) == 0
    assert score(led.conn, sid) == 0.0

    charged = led.record_observation(observation(sid), [event(subject, to)])
    assert len(charged.disclosure_ids) == 1
    assert charged.budget_delta == pytest.approx(EMAIL_B3)
    repeat = led.record_observation(observation(sid), [event(subject, to)])
    assert repeat.disclosure_ids == () and repeat.budget_delta == 0.0
    assert len(repeat.event_ids) == 1
    assert score(led.conn, sid) == pytest.approx(EMAIL_B3)

    # Unavailable and ended sessions take unresolved evidence only, and
    # never charge.
    unavailable = start_v2(led)
    led.conn.execute("UPDATE sessions SET accounting_status='unavailable'"
                     " WHERE session_id=?", (unavailable,))
    ended = start_v2(led)
    led.end_session(ended)
    for sid_ in (unavailable, ended):
        before = snapshot(led.conn)
        with pytest.raises(ValueError, match=INVALID_RECORD):
            led.record_observation(observation(sid_), [event()])
        assert snapshot(led.conn) == before
        late = led.record_observation(observation(sid_), [
            event(unresolved_subject(), unresolved_recipient())])
        assert late.disclosure_ids == () and late.budget_delta == 0.0
        assert score(led.conn, sid_) == 0.0


def test_first_crossing_type_is_frozen(led):
    sid = start_v2(led)
    subject = value_subject("sk-live-abcdef")
    first = led.record_observation(observation(sid), [
        event(subject, data_type="email")])
    later = led.record_observation(observation(sid), [
        event(subject, data_type="credential", masked_example=None)])
    assert later.disclosure_ids == () and later.budget_delta == 0.0
    assert len(later.event_ids) == 1
    rows = led.conn.execute(
        "SELECT disclosure_id, charged_data_type, budget_delta, group_n"
        " FROM disclosures WHERE session_id=?", (sid,)).fetchall()
    assert [tuple(r) for r in rows] == [
        (first.disclosure_ids[0], "email", pytest.approx(EMAIL_B3), 1)]
    assert score(led.conn, sid) == pytest.approx(EMAIL_B3)


# -- concurrency -------------------------------------------------------------

def _contend(path: Path, records) -> list:
    """Each record from its own connection, released together. A contender
    whose lock wait outlasts the busy timeout retries the whole transaction
    with the same delivery key."""
    barrier = threading.Barrier(len(records))
    results: list = [None] * len(records)

    def run(i, obs, events):
        led = writer_ledger(path, M, initialize=False)
        try:
            barrier.wait()
            deadline = time.monotonic() + 30
            while True:
                try:
                    results[i] = led.record_observation(obs, events)
                    return
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc) or time.monotonic() > deadline:
                        results[i] = exc
                        return
        except BaseException as exc:
            results[i] = exc
        finally:
            close_writer(led)

    threads = [threading.Thread(target=run, args=(i, *r))
               for i, r in enumerate(records)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    return results


def test_two_connections_cannot_double_charge(led, tmp_path):
    sid = start_v2(led)
    results = _contend(tmp_path / "ledger.db", [
        (observation(sid), [event()]), (observation(sid), [event()])])
    assert not [r for r in results if isinstance(r, BaseException)], results
    assert count(led.conn, "observations", sid) == 2
    assert count(led.conn, "events", sid) == 2
    assert count(led.conn, "disclosures", sid) == 1
    assert sorted(r.budget_delta for r in results) == [
        0.0, pytest.approx(EMAIL_B3)]
    assert score(led.conn, sid) == pytest.approx(EMAIL_B3)


def test_two_connections_allocate_distinct_group_positions(led, tmp_path):
    sid = start_v2(led)
    results = _contend(tmp_path / "ledger.db", [
        (observation(sid), [event(value_subject("p@example.com"))]),
        (observation(sid), [event(value_subject("q@example.com"))])])
    assert not [r for r in results if isinstance(r, BaseException)], results
    positions = sorted(r[0] for r in led.conn.execute(
        "SELECT group_n FROM disclosures WHERE session_id=?", (sid,)))
    assert positions == [1, 2]
    expected = group_score(PROFILE, "email", "mcp_tool", 2)
    assert score(led.conn, sid) == pytest.approx(expected, rel=1e-12)
    assert sum(r.budget_delta for r in results) == pytest.approx(
        expected, rel=1e-12)
    assert expected == pytest.approx(EMAIL_B3 * (1 + math.log(2)))


# -- atomicity ---------------------------------------------------------------

@pytest.mark.parametrize("stage", [
    ("insert", "observations"), ("insert", "subjects"),
    ("insert", "recipients"), ("insert", "events"),
    ("insert", "disclosures"), ("update", "sessions"),
    ("insert", "scan_gaps")])
def test_failure_at_each_write_stage_rolls_back_all_effects(led, stage):
    sid = start_v2(led)
    before = snapshot(led.conn)
    obs = observation(sid, scan_gap="oversize")
    _deny(led, **{stage[0]: stage[1]})
    try:
        with pytest.raises(sqlite3.DatabaseError):
            led.record_observation(obs, [event()])
    finally:
        led.conn.set_authorizer(None)
    assert not led.conn.in_transaction
    assert led._write_depth == 0
    assert snapshot(led.conn) == before
    # The same delivery then records normally: nothing partial remains.
    assert led.record_observation(obs, [event()]).duplicate_delivery is False


def test_caught_observation_failure_does_not_commit_partial_rows(led):
    sid = start_v2(led)
    before = snapshot(led.conn)
    with led._write_transaction():
        led.conn.execute(
            "INSERT INTO policy(scope,rule_type,selector,created_at)"
            " VALUES('session:unrelated','mask','email',1)")
        _deny(led, insert="disclosures")
        try:
            with pytest.raises(sqlite3.DatabaseError):
                led.record_observation(observation(sid, scan_gap="busy"),
                                       [event()])
        finally:
            led.conn.set_authorizer(None)
    after = snapshot(led.conn)
    assert len(after["policy"]) == len(before["policy"]) + 1
    after.pop("policy"), before.pop("policy")
    assert after == before
    assert led._write_depth == 0


def test_v2_writer_refuses_an_open_read_transaction(led):
    sid = start_v2(led)
    before = snapshot(led.conn)
    statements = _trace(led)
    with led._read_transaction():
        with pytest.raises(RuntimeError):
            led.record_observation(observation(sid), [event()])
        assert led._write_depth == 0
    led.conn.set_trace_callback(None)
    upper = [" ".join(s.upper().split()) for s in statements]
    assert not any(s.startswith(("BEGIN IMMEDIATE", "INSERT", "UPDATE",
                                 "SAVEPOINT")) for s in upper), upper
    assert snapshot(led.conn) == before


def test_v2_commit_failure_rolls_back_and_releases_ownership(led):
    sid = start_v2(led)
    before = snapshot(led.conn)
    obs = observation(sid, scan_gap="unavailable")
    _deny(led, commit=True)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            led.record_observation(obs, [event()])
    finally:
        led.conn.set_authorizer(None)
    assert not led.conn.in_transaction
    assert led._write_depth == 0
    assert snapshot(led.conn) == before
    result = led.record_observation(obs, [event()])
    assert result.duplicate_delivery is False
    assert score(led.conn, sid) == pytest.approx(EMAIL_B3)


def test_fakes_are_test_only():
    src = Path(__file__).resolve().parents[1] / "src"
    for module in src.rglob("*.py"):
        assert "accounting_fakes" not in module.read_text(encoding="utf-8"), module
    assert KEY  # the shared synthetic key is a test constant


def test_reused_action_id_keeps_its_action_kind(led):
    sid = start_v2(led)
    action = hex_id()
    led.record_observation(observation(sid, action_id=action,
                                       action_kind="read"), [])
    before = snapshot(led.conn)
    with pytest.raises(ValueError, match=INVALID_RECORD):
        led.record_observation(observation(sid, action_id=action,
                                           action_kind="tool"), [])
    assert snapshot(led.conn) == before
    assert led.record_observation(observation(
        sid, action_id=action, action_kind="read"), []).event_ids == ()
