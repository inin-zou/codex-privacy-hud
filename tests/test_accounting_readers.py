"""#54 Phase 3: typed version-2 readers.

A version-2 session is summarized, listed and detailed from its own tables
under one read snapshot, with its frozen profile validated first. A legacy
session keeps its exact legacy shapes; an unknown session stays unrecorded.
"""
from __future__ import annotations

import json
import logging
import math
import sqlite3
from pathlib import Path

import pytest
from accounting_fakes import (
    E, KEY, M, PROFILE, crossed, denied, detected, event, file_subject,
    hex_id, observation, pre, prepared_ledger, prevented, recipient, start_v2,
    unresolved_recipient, unresolved_subject, value_subject,
)

from privacy_hud import render
from privacy_hud.accounting import (
    ACCOUNTING_NOTE, ACCOUNTING_SCORE_LABEL, AccountingEventRow,
    AccountingExposureRow, AccountingSummary,
)
from privacy_hud.budget import group_score
from privacy_hud.identity import recipient_identity, value_identity
from privacy_hud.ledger import LegacyExposureRow, UnsupportedAccounting
from runtime_helpers import close_writer, writer_ledger

EMAIL_B3 = 6.0 * 1.5

SUMMARY_KEYS = [
    "accounting_version", "accounting_status", "profile_id",
    "confirmed_points", "budget_cap", "percent", "observations",
    "event_rows", "finding_occurrences", "distinct_subjects",
    "exposure_events", "intervention_events", "distinct_disclosures",
    "concrete_recipients", "permission_actions", "denials_issued",
    "denials_enforced", "reads_stopped", "rewrite_actions_issued",
    "rewrite_actions_enforced", "unresolved_actions",
    "unresolved_subject_events", "unresolved_recipient_events",
    "percentage_unavailable_reasons", "score_label", "accounting_note",
]

ROW_KEYS = [
    "accounting_version", "id", "observation_id", "action_id", "turn_id",
    "ts", "hook_event", "phase", "action_kind", "kind", "evidence",
    "data_type", "rule_id", "occurrences", "subject_id", "subject_kind",
    "subject_resolution", "subject_label", "recipient_id",
    "recipient_resolution", "destination_kind", "recipient_label",
    "source_label", "source_kind", "boundary", "masked_example",
    "budget_delta", "scan_gap", "budget_cap", "guard_target",
]


@pytest.fixture
def led(tmp_path):
    ledger = prepared_ledger(tmp_path / "ledger.db")
    yield ledger
    try:
        ledger.conn.close()
    except sqlite3.ProgrammingError:
        pass


def test_summary_reports_each_named_quantity(led):
    sid = start_v2(led)
    a, b, c = (value_subject(f"{n}@example.com") for n in "abc")
    r = recipient()
    led.record_observation(crossed(sid), [event(a, r), event(b, r)])
    led.record_observation(denied(sid), [prevented(c, r), prevented(a, r)])
    led.record_observation(pre(sid), [detected(unresolved_subject(), r)])
    led.record_observation(crossed(sid), [event(a, unresolved_recipient())])
    led.record_observation(
        observation(sid, evidence=E.LOCAL_DETECTION,
                    potential_crossing=False),
        [detected(a, r, occurrences=3)])

    summary = led.summary(sid)
    assert isinstance(summary, AccountingSummary)
    payload = summary.as_dict()
    assert list(payload) == SUMMARY_KEYS
    assert payload == {
        "accounting_version": 2,
        "accounting_status": "available",
        "profile_id": PROFILE.profile_id,
        "confirmed_points": pytest.approx(
            group_score(PROFILE, "email", "mcp_tool", 2)),
        "budget_cap": 120.0,
        "percent": None,
        "observations": 5,
        "event_rows": 7,
        "finding_occurrences": 9,
        "distinct_subjects": 3,
        "exposure_events": 3,
        "intervention_events": 2,
        "distinct_disclosures": 2,
        "concrete_recipients": 1,
        "permission_actions": 1,
        "denials_issued": 1,
        "denials_enforced": 1,
        "reads_stopped": 0,
        "rewrite_actions_issued": 0,
        "rewrite_actions_enforced": 0,
        "unresolved_actions": 1,
        "unresolved_subject_events": 1,
        "unresolved_recipient_events": 1,
        "percentage_unavailable_reasons": [
            "unresolved_actions", "unresolved_subjects",
            "unresolved_recipients"],
        "score_label": ACCOUNTING_SCORE_LABEL,
        "accounting_note": ACCOUNTING_NOTE,
    }
    assert summary.score_label == "confirmed disclosure points"
    json.dumps(payload, allow_nan=False)


def test_percentage_reasons_have_fixed_order(led):
    sid = start_v2(led)
    led.record_observation(pre(sid), [detected(unresolved_subject())])
    led.record_observation(crossed(sid), [event(to=unresolved_recipient())])
    led.record_observation(observation(sid, scan_gap="timeout"), [])
    led.mark_accounting_unavailable(sid)
    summary = led.summary(sid)
    assert summary.accounting_status == "unavailable"
    assert summary.percentage_unavailable_reasons == (
        "accounting_unavailable", "unresolved_actions",
        "unresolved_subjects", "unresolved_recipients",
        "coverage_incomplete")
    assert summary.percent is None


def test_verified_complete_synthetic_session_can_have_numeric_percent(led):
    empty = start_v2(led)
    summary = led.summary(empty)
    assert summary.percentage_unavailable_reasons == ()
    assert summary.percent == 0
    assert summary.confirmed_points == 0.0

    sid = start_v2(led)
    to = recipient("model_context", "model context")
    led.record_observation(crossed(sid, boundary="B1"), [
        event(value_subject(f"u{i}@example.com"), to, boundary="B1")
        for i in range(12)])
    summary = led.summary(sid)
    assert summary.percentage_unavailable_reasons == ()
    assert summary.confirmed_points == pytest.approx(20.909439898728, abs=1e-9)
    assert summary.percent == 17


def test_erased_resolved_identity_is_not_unresolved(led):
    sid = start_v2(led)
    led.record_observation(crossed(sid), [event()])
    before = led.summary(sid)
    led.end_session(sid)
    assert led.conn.execute(
        "SELECT COUNT(*) FROM subjects WHERE session_id=?"
        " AND identity_hash IS NOT NULL", (sid,)).fetchone()[0] == 0
    after = led.summary(sid)
    assert after.unresolved_subject_events == 0
    assert after.unresolved_recipient_events == 0
    assert after.distinct_subjects == 1
    assert after == before


def test_v2_public_projection_has_exact_keys_and_symbolic_evidence(led):
    sid = start_v2(led)
    delivery = hex_id()
    led.record_observation(crossed(sid, delivery_key=delivery), [event()])
    led.record_observation(denied(sid), [prevented(
        value_subject("p@example.com"),
        evidence=E.DENY_ISSUED | E.DENY_ENFORCED)])
    (row,) = led.list_events(sid, "exposed")
    assert isinstance(row, AccountingEventRow)
    public = row.to_exposure()
    assert type(public) is AccountingExposureRow
    assert not isinstance(public, LegacyExposureRow)
    assert public.accounting_version == 2
    payload = public.as_dict()
    assert list(payload) == ROW_KEYS
    assert payload["evidence"] == ["crossing_confirmed"]
    assert payload["source_kind"] is None
    assert payload["budget_cap"] == 120.0
    text = json.dumps(payload)
    for secret in (sid, delivery, value_identity(KEY, "alice@example.com").hex(),
                   recipient_identity(KEY, "mcp_tool", "server-a").hex(),
                   "server-a"):
        assert secret not in text
    (denial,) = led.list_events(sid, "prevented")
    assert denial.to_exposure().as_dict()["evidence"] == [
        "deny_issued", "deny_enforced"]


def test_only_first_disclosure_event_has_budget_delta(led):
    sid = start_v2(led)
    for _ in range(2):
        led.record_observation(crossed(sid), [event()])
    rows = led.list_events(sid, "exposed")
    assert [r.budget_delta for r in rows] == [pytest.approx(EMAIL_B3), 0.0]
    detail = led.get_event(sid, rows[1].id)
    assert detail.budget_delta == 0.0


def test_v2_detail_is_scoped_to_session_and_table(led):
    led.record("legacy-boundary", turn_id="t", kind="exposed",
               data_type="email", source="a.log",
               destination="model_context", value_hash=b"\x01" * 16,
               masked_example=None, tool_name="Read", protection=None)
    legacy_id = led.conn.execute(
        "SELECT id FROM events_legacy_v1").fetchone()[0]
    one = start_v2(led)
    first = led.record_observation(crossed(one), [event()]).event_ids[0]
    two = start_v2(led)
    second = led.record_observation(crossed(two), [event()]).event_ids[0]
    assert first == legacy_id  # the two tables number independently

    v2 = led.get_event(one, first)
    assert isinstance(v2, AccountingExposureRow)
    assert v2.budget_cap == 120.0
    legacy = led.get_event("legacy-boundary", legacy_id)
    assert isinstance(legacy, LegacyExposureRow)
    with pytest.raises(LookupError):
        led.get_event(one, second)
    with pytest.raises(LookupError):
        led.get_event("legacy-boundary", second)
    with pytest.raises(LookupError):
        led.get_event(two, 10_000)


def test_v2_reads_use_one_snapshot(led, tmp_path):
    sid = start_v2(led)
    led.record_observation(crossed(sid), [event()])
    before = led.summary(sid)

    writer = writer_ledger(tmp_path / "ledger.db", M,
                           initialize=False)
    fired: list[object] = []

    def interleave(statement: str) -> None:
        if fired or "FROM observations" not in statement:
            return
        try:
            fired.append(writer.record_observation(
                crossed(sid), [event(value_subject("late@example.com"))]))
        except BaseException as exc:  # reported below
            fired.append(exc)

    led.conn.set_trace_callback(interleave)
    try:
        during = led.summary(sid)
    finally:
        led.conn.set_trace_callback(None)
        close_writer(writer)
    assert fired and not isinstance(fired[0], BaseException), fired
    assert during == before
    after = led.summary(sid)
    assert after.distinct_disclosures == 2
    assert after.observations == 2


def test_malformed_v2_profile_is_not_rendered_as_zero(led):
    valid = start_v2(led)
    assert isinstance(led.summary(valid), AccountingSummary)
    assert led.list_events(valid, "exposed") == []
    bad = "0" * 64
    led.conn.execute(
        "INSERT INTO scoring_profiles(profile_id,format_version,"
        "matrix_version,created_at,budget_cap,parameters_json)"
        " VALUES(?,1,'1',1,120.0,?)", (bad, PROFILE.as_canonical_json()))
    led.conn.execute(
        "INSERT INTO sessions(session_id,started_at,budget_cap,"
        "accounting_version,accounting_status,profile_id)"
        " VALUES('corrupt',1,120.0,2,'available',?)", (bad,))
    with pytest.raises(UnsupportedAccounting):
        led.summary("corrupt")
    with pytest.raises(UnsupportedAccounting):
        led.list_events("corrupt", "exposed")
    with pytest.raises(UnsupportedAccounting):
        led.get_event("corrupt", 1)


def test_new_metadata_has_no_planted_sensitive_bytes(led, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    planted_email = "planted.person@secret-corp.example"
    planted_path = "/home/planted-user/secret-dir/prod.pem"
    planted_host = "https://planted-host.example/api?token=planted-token"
    statements: list[str] = []
    led.conn.set_trace_callback(statements.append)
    with led._write_transaction():
        led._start_v2_session("s-marked", cwd="/home/planted-user/repo",
                              model="planted-model", profile=PROFILE)
    sid = "s-marked"
    net = recipient("external_net", planted_host)
    led.record_observation(
        crossed(sid, boundary="B4"),
        [event(value_subject(planted_email), net, boundary="B4",
               masked_example="pl•••e")])
    led.record_observation(
        denied(sid, action_kind="read", boundary="B1"),
        [prevented(file_subject(planted_path),
                   recipient("model_context", "model context"),
                   boundary="B1", data_type="credential",
                   masked_example=None, source_label="local file")])
    summary = led.summary(sid)
    rows = [r.to_exposure() for kind in ("exposed", "prevented")
            for r in led.list_events(sid, kind)]
    details = [led.get_event(sid, r.id) for r in rows]
    # #54 Phase 4: the surfaces render version 2 now, and what they render
    # carries no planted byte either.
    refusals = [render.receipt(sid, summary, rows, None),
                *(render.detail(r) for r in rows),
                render.audit(summary, rows, "All events", session_id=sid)]
    led.conn.set_trace_callback(None)
    led.end_session(sid)

    outputs = [json.dumps(summary.as_dict()),
               *(json.dumps(r.as_dict()) for r in rows),
               *(json.dumps(d.as_dict()) for d in details),
               *refusals, *statements, caplog.text]
    stored = b"".join(p.read_bytes() for p in Path(tmp_path).glob("ledger.db*"))
    planted = ("planted", "secret-corp", "secret-dir", "prod.pem",
               "planted-host", "planted-token")
    for text in outputs:
        for needle in planted:
            assert needle not in text, needle
    for needle in planted:
        assert needle.encode() not in stored, needle
    assert KEY not in stored
    assert KEY.hex() not in "".join(outputs)
    assert all(math.isfinite(v) for v in (summary.confirmed_points,))
