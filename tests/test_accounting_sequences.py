"""#54 Phase 3: outcome sequences through the version-2 writer and summary.

Synthetic receipts only. A later retry that actually executes is a new
action ID; reusing one action ID with incompatible terminal receipts is a
conflict, not a retry. The summary separates what was issued from what was
enforced, events from disclosures, and resolved from unresolved actions.
"""
from __future__ import annotations

import sqlite3

import pytest
from accounting_fakes import (
    E, crossed, denied, detected, event, file_subject, hex_id, model_context,
    observation, pre, prepared_ledger, prevented, recipient, start_v2,
    value_subject,
)

from privacy_hud.budget import group_score, percent

EMAIL_B3 = 6.0 * 1.5


@pytest.fixture
def led(tmp_path):
    ledger = prepared_ledger(tmp_path / "ledger.db")
    yield ledger
    try:
        ledger.conn.close()
    except sqlite3.ProgrammingError:
        pass


def _post(sid, action, **changes):
    values = {"action_id": action, "hook_event": "PostToolUse",
              "phase": "post", "decision": "none",
              "potential_crossing": False}
    values.update(changes)
    return observation(sid, **values)


# -- the seven sequences -----------------------------------------------------

def test_prevented_then_exposed(led):
    sid = start_v2(led)
    s, r = value_subject("dana@example.com"), recipient()
    first = led.record_observation(denied(sid), [prevented(s, r)])
    second = led.record_observation(crossed(sid), [event(s, r)])
    assert first.budget_delta == 0.0
    assert second.budget_delta == pytest.approx(EMAIL_B3)
    summary = led.summary(sid)
    assert summary.event_rows == 2
    assert summary.intervention_events == 1
    assert summary.exposure_events == 1
    assert summary.distinct_disclosures == 1
    assert summary.confirmed_points == pytest.approx(EMAIL_B3)
    assert summary.denials_issued == summary.denials_enforced == 1
    assert summary.unresolved_actions == 0
    assert summary.percent == percent(EMAIL_B3, 120.0)


def test_exposed_then_prevented(led):
    sid = start_v2(led)
    s, r = value_subject("dana@example.com"), recipient()
    led.record_observation(crossed(sid), [event(s, r)])
    later = led.record_observation(denied(sid), [prevented(s, r)])
    assert later.budget_delta == 0.0
    summary = led.summary(sid)
    assert summary.event_rows == 2
    assert summary.exposure_events == 1 and summary.intervention_events == 1
    assert summary.distinct_disclosures == 1
    assert summary.confirmed_points == pytest.approx(EMAIL_B3)
    assert summary.denials_enforced == 1
    assert summary.unresolved_actions == 0
    kinds = [row.kind for row in led.list_events(sid, "exposed")
             + led.list_events(sid, "prevented")]
    assert kinds == ["exposed", "prevented"]


def test_two_pem_files_denied(led):
    sid = start_v2(led)
    for path in ("/home/zq-user/zq-vault/alpha-secret.pem",
                 "/home/zq-user/zq-vault/beta-secret.pem"):
        led.record_observation(
            denied(sid, action_kind="read", boundary="B1"),
            [prevented(file_subject(path), model_context(), boundary="B1",
                       data_type="credential", masked_example=None,
                       source_label="local file")])
    summary = led.summary(sid)
    assert summary.confirmed_points == 0.0
    assert summary.distinct_disclosures == 0
    assert summary.denials_issued == summary.denials_enforced == 2
    assert summary.reads_stopped == 2
    assert summary.distinct_subjects == 2
    assert summary.intervention_events == 2
    rows = led.list_events(sid, "prevented")
    assert [r.subject_kind for r in rows] == ["file", "file"]
    assert [r.subject_label for r in rows] == [
        f"file {r.subject_id} (.pem)" for r in rows]
    assert len({r.subject_id for r in rows}) == 2
    for row in rows:
        public = repr(row.to_exposure().as_dict())
        for part in ("zq-user", "zq-vault", "alpha-secret", "beta-secret",
                     "/home"):
            assert part not in public
        assert row.masked_example is None


def test_twelve_findings_in_one_denied_call(led):
    sid = start_v2(led)
    findings = [prevented(value_subject(f"user{i}@example.com"))
                for i in range(12)]
    led.record_observation(denied(sid), findings)
    summary = led.summary(sid)
    assert summary.observations == 1
    assert summary.denials_issued == summary.denials_enforced == 1
    assert summary.event_rows == summary.intervention_events == 12
    assert summary.distinct_disclosures == 0
    assert summary.confirmed_points == 0.0
    assert summary.unresolved_actions == 0


def test_repeated_value_one_recipient(led):
    sid = start_v2(led)
    s, r = value_subject("erin@example.com"), recipient()
    for _ in range(3):
        led.record_observation(crossed(sid), [event(s, r)])
    summary = led.summary(sid)
    assert summary.exposure_events == summary.event_rows == 3
    assert summary.distinct_disclosures == 1
    assert summary.confirmed_points == pytest.approx(EMAIL_B3)
    assert [row.budget_delta for row in led.list_events(sid, "exposed")] == [
        pytest.approx(EMAIL_B3), 0.0, 0.0]


def test_same_value_two_mcp_recipients(led):
    sid = start_v2(led)
    s = value_subject("frank@example.com")
    led.record_observation(crossed(sid), [
        event(s, recipient("mcp_tool", "server-a")),
        event(s, recipient("mcp_tool", "server-b"))])
    summary = led.summary(sid)
    assert summary.distinct_disclosures == 2
    assert summary.concrete_recipients == 2
    assert summary.distinct_subjects == 1
    expected = 2 * group_score(led.profile_for_session(sid), "email",
                               "mcp_tool", 1)
    assert summary.confirmed_points == pytest.approx(expected)
    groups = led.conn.execute(
        "SELECT recipient_id, group_n FROM disclosures WHERE session_id=?",
        (sid,)).fetchall()
    assert len({g[0] for g in groups}) == 2
    assert [g[1] for g in groups] == [1, 1]


def test_permission_then_downstream_rejection(led):
    sid = start_v2(led)
    action = hex_id()
    s, r = value_subject("gina@example.com"), recipient()
    led.record_observation(pre(sid, action_id=action), [
        event(s, r, kind="permitted", evidence=E.PERMISSION_ISSUED)])
    led.record_observation(
        _post(sid, action, evidence=E.REJECTED_BEFORE_CROSSING,
              resolution_scope="pairs"),
        [prevented(s, r, evidence=E.REJECTED_BEFORE_CROSSING)])
    summary = led.summary(sid)
    assert summary.permission_actions == 1
    assert summary.event_rows == 2
    assert summary.unresolved_actions == 0
    assert summary.distinct_disclosures == 0
    assert summary.confirmed_points == 0.0
    assert [row.kind for row in led.list_events(sid, "permitted")] == [
        "permitted"]


# -- reducer rules -----------------------------------------------------------

def test_zero_finding_denial_is_counted(led):
    sid = start_v2(led)
    led.record_observation(observation(
        sid, decision="deny", evidence=E.DENY_ISSUED,
        potential_crossing=False), [])
    summary = led.summary(sid)
    assert summary.observations == 1
    assert summary.event_rows == 0
    assert summary.denials_issued == 1
    assert summary.denials_enforced == 0


def test_zero_finding_boundary_rejection_resolves_attempt(led):
    sid = start_v2(led)
    action = hex_id()
    led.record_observation(pre(sid, action_id=action), [])
    assert led.summary(sid).unresolved_actions == 1
    led.record_observation(_post(sid, action,
                                 evidence=E.REJECTED_BEFORE_CROSSING,
                                 resolution_scope="boundary"), [])
    summary = led.summary(sid)
    assert summary.unresolved_actions == 0
    assert summary.observations == 2 and summary.event_rows == 0


def test_partial_receipt_resolves_only_its_pair(led):
    sid = start_v2(led)
    action = hex_id()
    a, b, r = value_subject("a@x.example"), value_subject("b@x.example"), recipient()
    led.record_observation(pre(sid, action_id=action),
                           [detected(a, r), detected(b, r)])
    led.record_observation(crossed(sid, action_id=action), [event(a, r)])
    assert led.summary(sid).unresolved_actions == 1
    led.record_observation(crossed(sid, action_id=action), [event(b, r)])
    assert led.summary(sid).unresolved_actions == 0


def test_rejection_at_b3_does_not_resolve_b1(led):
    sid = start_v2(led)
    action = hex_id()
    a = value_subject("h@x.example")
    led.record_observation(pre(sid, action_id=action, boundary="B1"),
                           [detected(a, model_context(), boundary="B1")])
    led.record_observation(pre(sid, action_id=action),
                           [detected(a, recipient())])
    led.record_observation(_post(sid, action,
                                 evidence=E.REJECTED_BEFORE_CROSSING,
                                 resolution_scope="boundary"), [])
    assert led.summary(sid).unresolved_actions == 1
    led.record_observation(
        crossed(sid, action_id=action, boundary="B1"),
        [event(a, model_context(), boundary="B1")])
    assert led.summary(sid).unresolved_actions == 0


def test_resolution_scope_none_is_not_terminal(led):
    sid = start_v2(led)
    action = hex_id()
    a, r = value_subject("i@x.example"), recipient()
    led.record_observation(pre(sid, action_id=action), [detected(a, r)])
    led.record_observation(
        _post(sid, action,
              evidence=E.REJECTED_BEFORE_CROSSING | E.DENY_ENFORCED),
        [prevented(a, r, evidence=E.REJECTED_BEFORE_CROSSING)])
    summary = led.summary(sid)
    assert summary.unresolved_actions == 1
    assert summary.percent is None
    assert "unresolved_actions" in summary.percentage_unavailable_reasons


def test_execution_is_not_crossing(led):
    sid = start_v2(led)
    action = hex_id()
    led.record_observation(pre(sid, action_id=action),
                           [detected(value_subject("j@x.example"))])
    led.record_observation(_post(sid, action,
                                 evidence=E.EXECUTION_OBSERVED), [])
    summary = led.summary(sid)
    assert summary.distinct_disclosures == 0
    assert summary.confirmed_points == 0.0
    assert summary.unresolved_actions == 1
    assert summary.percent is None


def test_rewrite_issued_is_not_rewrite_enforced(led):
    sid = start_v2(led)
    a = value_subject("k@x.example")
    led.record_observation(
        pre(sid, decision="rewrite",
            evidence=E.REWRITE_ISSUED | E.LOCAL_DETECTION),
        [detected(a, evidence=E.LOCAL_DETECTION | E.REWRITE_ISSUED)])
    summary = led.summary(sid)
    assert summary.rewrite_actions_issued == 1
    assert summary.rewrite_actions_enforced == 0
    assert summary.intervention_events == 1
    assert summary.unresolved_actions == 1


def test_rewrite_receipt_resolves_only_removed_subjects(led):
    sid = start_v2(led)
    action = hex_id()
    a, b, r = value_subject("l@x.example"), value_subject("m@x.example"), recipient()
    led.record_observation(
        pre(sid, action_id=action, decision="rewrite",
            evidence=E.REWRITE_ISSUED | E.LOCAL_DETECTION),
        [detected(a, r, evidence=E.LOCAL_DETECTION | E.REWRITE_ISSUED),
         detected(b, r)])
    led.record_observation(
        _post(sid, action, evidence=E.REWRITE_ENFORCED | E.EXECUTION_OBSERVED,
              resolution_scope="pairs"),
        [prevented(a, r, evidence=E.REWRITE_ENFORCED)])
    summary = led.summary(sid)
    assert summary.rewrite_actions_enforced == 1
    assert summary.unresolved_actions == 1
    led.record_observation(crossed(sid, action_id=action), [event(b, r)])
    summary = led.summary(sid)
    assert summary.unresolved_actions == 0
    assert summary.confirmed_points == pytest.approx(EMAIL_B3)


def test_conflicting_evidence_keeps_charge_and_withholds_percent(led):
    sid = start_v2(led)
    action = hex_id()
    a, r = value_subject("n@x.example"), recipient()
    led.record_observation(pre(sid, action_id=action), [detected(a, r)])
    led.record_observation(crossed(sid, action_id=action), [event(a, r)])
    assert led.summary(sid).unresolved_actions == 0
    led.record_observation(_post(sid, action,
                                 evidence=E.REJECTED_BEFORE_CROSSING,
                                 resolution_scope="boundary"), [])
    summary = led.summary(sid)
    assert summary.unresolved_actions == 1
    assert summary.percent is None
    assert summary.distinct_disclosures == 1
    assert summary.confirmed_points == pytest.approx(EMAIL_B3)


def test_issued_denial_followed_by_execution_is_not_a_stopped_read(led):
    sid = start_v2(led)
    action = hex_id()
    led.record_observation(
        pre(sid, action_id=action, action_kind="read", boundary="B1",
            decision="deny", evidence=E.DENY_ISSUED | E.LOCAL_DETECTION),
        [detected(value_subject("o@x.example"), model_context(),
                  boundary="B1")])
    led.record_observation(
        _post(sid, action, action_kind="read", boundary="B1",
              evidence=E.EXECUTION_OBSERVED), [])
    summary = led.summary(sid)
    assert summary.denials_issued == 1
    assert summary.denials_enforced == 0
    assert summary.reads_stopped == 0
    assert summary.unresolved_actions == 1


def test_occurrences_are_fixed_and_not_disclosure_volume(led):
    sid = start_v2(led)
    led.record_observation(crossed(sid), [event(occurrences=12)])
    summary = led.summary(sid)
    assert summary.finding_occurrences == 12
    assert summary.event_rows == 1
    assert summary.distinct_disclosures == 1
    assert summary.confirmed_points == pytest.approx(EMAIL_B3)
    (row,) = led.list_events(sid, "exposed")
    assert row.occurrences == 12
    assert row.budget_delta == pytest.approx(EMAIL_B3)
