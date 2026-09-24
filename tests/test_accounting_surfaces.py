"""#54 Phase 4 P4-C7: every consumer presents version-2 accounting.

The terminal audit, event detail and session receipt, the HUD snapshot,
the local browser endpoints and the MCP tools render version-2 sessions
with the exact §C copy, keep a null percentage null, and keep malformed or
unsupported accounting an explicit failure. Legacy and unrecorded
contracts stay byte-for-byte what they were.

Version-2 sessions here are synthetic, built through the ledger's private
constructor on a prepared ledger under a temporary directory.
"""
from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request

import pytest
from accounting_fakes import (
    PROFILE, E, crossed, event, observation, pre, prepared_ledger,
    recipient, start_v2, value_subject,
)
from legacy_fakes import legacy_summary

import server  # `mcp/` is on sys.path via conftest

from privacy_hud import hud_snapshot as hs
from privacy_hud import local_ui_server, mcp_tools, render
from privacy_hud.accounting import (
    ACCOUNTING_NOTE, AccountingExposureRow, AccountingSummary,
)
from privacy_hud.ledger import Ledger, SessionCoverage, UnsupportedAccounting
from runtime_helpers import close_writer

ERROR = ("Privacy HUD accounting could not be read. No percentage or counts "
         "are available.")
ZERO_LINE = "0 confirmed points does not mean no disclosure occurred."
UNAVAILABLE_LINE = "Disclosure percentage: unavailable."
KEY_LINE = ("Accounting is unavailable for the rest of this session because "
            "its identity key is unavailable.")


def unresolved_denial(sid, **changes):
    values = {"decision": "deny",
              "evidence": E.DENY_ISSUED | E.LOCAL_DETECTION | E.HOOK_OBSERVED,
              "potential_crossing": True}
    values.update(changes)
    return observation(sid, **values)


def seed_baseline_a(led) -> str:
    """Baseline A: two issued denials and one permitted pending crossing,
    nothing confirmed. Three unresolved actions, zero points."""
    sid = start_v2(led)
    for value in ("a@example.com", "b@example.com"):
        led.record_observation(unresolved_denial(sid), [event(
            value_subject(value), kind="prevented",
            evidence=E.DENY_ISSUED | E.LOCAL_DETECTION)])
    led.record_observation(pre(sid), [event(
        value_subject("c@example.com"), kind="permitted",
        evidence=E.PERMISSION_ISSUED | E.LOCAL_DETECTION)])
    return sid


@pytest.fixture
def led(tmp_path):
    ledger = prepared_ledger(tmp_path / "ledger.db")
    yield ledger
    try:
        ledger.conn.close()
    except sqlite3.Error:
        pass


def verified() -> SessionCoverage:
    return SessionCoverage(recorded=True, observers=1, attached=False,
                           unobserved_hooks=False, shallow_scans=0)


def _coverage(led, sid):
    return led.coverage(sid)


# --------------------------------------------------------------------- #
# terminal renderers
# --------------------------------------------------------------------- #

def test_accounting_helpers_use_the_exact_copy(led):
    sid = seed_baseline_a(led)
    s = led.summary(sid)
    assert s.percent is None and s.unresolved_actions == 3
    assert render.accounting_percentage_line(s) == UNAVAILABLE_LINE
    assert render.accounting_reason_lines(s) == (
        "3 unresolved actions. Percentage unavailable until the required "
        "evidence is available.",)
    one = start_v2(led)
    led.record_observation(pre(one), [event(
        value_subject("d@example.com"), kind="permitted",
        evidence=E.PERMISSION_ISSUED | E.LOCAL_DETECTION)])
    led.mark_accounting_unavailable(one)
    assert render.accounting_reason_lines(led.summary(one)) == (
        KEY_LINE,
        "1 unresolved action. Percentage unavailable until the required "
        "evidence is available.")
    numeric = start_v2(led)
    led.record_observation(crossed(numeric), [event()])
    n = led.summary(numeric)
    assert n.percent is not None
    assert render.accounting_percentage_line(n) == (
        f"Disclosure percentage: {n.percent}% of the session's frozen "
        "disclosure budget.")
    assert render.accounting_reason_lines(n) == ()


def test_v2_empty_renderers_are_real_renderers(led):
    sid = start_v2(led)
    s = led.summary(sid)
    text = render.audit(s, [], "Exposed", coverage=verified(), session_id=sid)
    lines = text.splitlines()
    assert lines[:7] == ["Privacy Audit", f"Session {sid}", "",
                         "0  confirmed points", "0  distinct disclosures",
                         "0  confirmed recipients", "0  denials issued"]
    assert "Disclosure percentage: 0% of the session's frozen disclosure " \
        "budget." in text
    assert ACCOUNTING_NOTE in text
    assert "Confirmed crossings 0" in text
    assert "Interventions 0" in text
    assert "All finding events 0" in text
    assert "No confirmed crossing events recorded for this session." in text
    assert "legacy" not in text.lower()
    for tab, line in (
            ("Prevented", "No intervention finding events recorded for this "
                          "session. Actions without findings are included in "
                          "the summary."),
            ("All events", "No finding events recorded for this session. "
                           "Delivered actions may still be recorded in the "
                           "observation count.")):
        assert render.empty_message(tab, verified(), summary=s) == line
    receipt = render.receipt(sid, s, [], None)
    assert receipt.splitlines()[0] == f"PRIVACY RECEIPT · {sid}"
    assert "confirmed points: 0" in receipt


def test_unresolved_zero_reaches_every_surface(led, tmp_path, monkeypatch):
    sid = seed_baseline_a(led)
    s = led.summary(sid)
    cov = _coverage(led, sid)
    rows = mcp_tools.list_exposures(led, sid, "Prevented")
    audit = render.audit(s, rows, "Prevented", coverage=cov, session_id=sid)
    assert audit.splitlines()[:13] == [
        "Privacy Audit", f"Session {sid}", "",
        "0  confirmed points", "0  distinct disclosures",
        "0  confirmed recipients", "2  denials issued", "",
        UNAVAILABLE_LINE,
        "3 unresolved actions. Percentage unavailable until the required "
        "evidence is available.",
        ZERO_LINE, "", ACCOUNTING_NOTE]
    receipt = render.receipt(sid, s, [], 5, coverage=cov)
    assert receipt == "\n".join([
        f"PRIVACY RECEIPT · {sid} · 5 min", "",
        "confirmed points: 0",
        "distinct disclosures: 0",
        "confirmed recipients: 0",
        "denials issued: 2",
        "denials enforced: 0",
        "reads stopped: 0",
        "rewrites issued: 0",
        "rewrites applied: 0",
        "unresolved actions: 3", "",
        UNAVAILABLE_LINE,
        "3 unresolved actions. Percentage unavailable until the required "
        "evidence is available.",
        ZERO_LINE, "",
        "This score is a versioned policy index over evidenced disclosures, "
        "not a measurement of harm.",
        "Current hooks do not confirm transmission or host application of a "
        "denial or rewrite.",
        "Transcript retention is outside this ledger's account.",
        "This ledger stores metadata, not file contents, prompts, or raw "
        "values."])
    wire = mcp_tools.get_session_summary(led, sid).as_dict()
    assert wire["percent"] is None and wire["unresolved_actions"] == 3
    publisher = hs.HudPublisher(tmp_path / "hud-root")
    publisher.publish(sid, summary=s, unverified=not cov.verified)
    reading = hs.read_snapshot(tmp_path / "hud-root", sid)
    assert reading is not None and reading.percent is None
    assert render.hud_line(reading, 80) == \
        "Privacy —% · 3 unresolved · 2 denials issued"


def test_snapshot_publish_v2_preserves_null(led, tmp_path):
    sid = seed_baseline_a(led)
    s = led.summary(sid)
    publisher = hs.HudPublisher(tmp_path)
    publisher.publish(sid, summary=s, unverified=False)
    doc = json.loads(hs.snapshot_path(tmp_path, sid).read_text())
    assert set(doc) == {"v", "accounting_version", "percent",
                        "confirmed_points", "denials_issued",
                        "legacy_prevented_rows", "unresolved_actions",
                        "unverified", "hidden", "updated_at"}
    assert (doc["v"], doc["accounting_version"], doc["percent"],
            doc["confirmed_points"], doc["denials_issued"],
            doc["legacy_prevented_rows"], doc["unresolved_actions"],
            doc["unverified"], doc["hidden"]) == \
        (2, 2, None, 0.0, 2, None, 3, False, False)
    publisher.heartbeat([sid])
    publisher.set_hidden(sid, True)
    publisher.set_hidden(sid, False)
    after = json.loads(hs.snapshot_path(tmp_path, sid).read_text())
    assert after["percent"] is None and after["unresolved_actions"] == 3
    numeric = start_v2(led)
    led.record_observation(crossed(numeric), [event()])
    n = led.summary(numeric)
    publisher.publish(numeric, summary=n, unverified=True)
    doc = json.loads(hs.snapshot_path(tmp_path, numeric).read_text())
    assert doc["percent"] == n.percent and doc["unverified"] is True
    assert doc["confirmed_points"] == n.confirmed_points


def test_key_loss_is_not_coverage_unverified(led, tmp_path):
    sid = start_v2(led)
    led.mark_accounting_unavailable(sid)
    s = led.summary(sid)
    cov = _coverage(led, sid)
    assert cov.verified
    assert s.percent is None
    publisher = hs.HudPublisher(tmp_path)
    publisher.publish(sid, summary=s, unverified=not cov.verified)
    reading = hs.read_snapshot(tmp_path, sid)
    assert reading.unverified is False
    assert render.hud_line(reading, 80) == \
        "Privacy —% · 0 unresolved · 0 denials issued"
    audit = render.audit(s, [], "Exposed", coverage=cov, session_id=sid)
    assert KEY_LINE in audit
    assert "Session record incomplete" not in audit


def test_intervention_tab_includes_issued_rewrites_once(led):
    sid = start_v2(led)
    led.record_observation(
        observation(sid, decision="rewrite",
                    evidence=E.PERMISSION_ISSUED | E.REWRITE_ISSUED
                    | E.LOCAL_DETECTION | E.HOOK_OBSERVED,
                    potential_crossing=True),
        [event(value_subject("r@example.com"), kind="permitted",
               evidence=E.PERMISSION_ISSUED | E.REWRITE_ISSUED
               | E.LOCAL_DETECTION)])
    led.record_observation(unresolved_denial(sid), [event(
        value_subject("d@example.com"), kind="prevented",
        evidence=E.DENY_ISSUED | E.LOCAL_DETECTION)])
    rows = mcp_tools.list_exposures(led, sid, "Prevented")
    s = led.summary(sid)
    assert len(rows) == s.intervention_events == 2
    assert len({r.id for r in rows}) == 2
    assert [r.id for r in rows] == sorted(r.id for r in rows)
    assert [r.kind for r in rows] == ["permitted", "prevented"]


def test_event_chips_use_only_event_evidence(led):
    sid = start_v2(led)
    led.record_observation(
        observation(sid, decision="rewrite",
                    evidence=E.PERMISSION_ISSUED | E.REWRITE_ISSUED
                    | E.LOCAL_DETECTION | E.CROSSING_CONFIRMED
                    | E.HOOK_OBSERVED, resolution_scope="pairs",
                    potential_crossing=True),
        [event(value_subject("a@example.com"), kind="exposed",
               evidence=E.PERMISSION_ISSUED | E.REWRITE_ISSUED
               | E.CROSSING_CONFIRMED),
         event(value_subject("b@example.com"), kind="permitted",
               evidence=E.PERMISSION_ISSUED | E.LOCAL_DETECTION)])
    rows = {r.subject_id: r for r in mcp_tools.list_exposures(
        led, sid, "All events")}
    chips = sorted(render.accounting_event_chips(r) for r in rows.values())
    assert chips == [("PERMITTED", "DETECTED"),
                     ("REWRITE ISSUED", "EXPOSED", "PERMITTED")]
    for row in rows.values():
        assert "REWRITE APPLIED" not in render.accounting_event_chips(row)
    table = render.audit(led.summary(sid), list(rows.values()), "All events",
                         session_id=sid)
    assert "[REWRITE ISSUED] [EXPOSED] [PERMITTED]" in table


def test_v2_detail_uses_the_exact_labels_and_notes(led):
    sid = start_v2(led)
    led.record_observation(crossed(sid), [event(masked_example=None)])
    row = mcp_tools.list_exposures(led, sid, "Exposed")[0]
    text = render.detail(row)
    for label in ("Subject", "Recipient", "Source", "Boundary",
                  "Observation", "Action", "Evidence",
                  "Occurrences in this observation",
                  "Confirmed contribution", "Masked example"):
        assert any(line.startswith(label + " ") for line in
                   text.splitlines()), label
    assert "Not stored." in text
    assert ("This row records evidence at one observation point. It does "
            "not establish a causal multi-hop flow.") in text
    assert "A source rule cannot be saved from this opaque label." in text
    assert ("Policy rules can be saved in the local audit browser opened by "
            "$privacy.") in text
    assert text.endswith(
        "Already disclosed data cannot be recalled from this session.")
    assert row.subject_label in text and row.recipient_label in text


def test_receipt_retains_unresolved_state_after_end(led):
    sid = seed_baseline_a(led)
    led.end_session(sid)
    s = led.summary(sid)
    assert s.percent is None
    text = render.receipt(sid, s, [], None)
    assert UNAVAILABLE_LINE in text
    assert "unresolved actions: 3" in text
    assert "denials enforced: 0" in text
    assert "enforced by the host" not in text


def test_accounting_copy_is_the_static_catalog():
    copy = render.accounting_copy()
    assert isinstance(copy, dict) and all(
        isinstance(v, str) for v in copy.values())
    values = set(copy.values())
    for text in ("confirmed disclosure points", ACCOUNTING_NOTE,
                 "confirmed points", "distinct disclosures",
                 "confirmed recipients", "denials issued",
                 "Confirmed crossings", "Interventions",
                 "All finding events", "Disclosure percentage: unavailable.",
                 KEY_LINE, ZERO_LINE, ERROR, "Not stored.",
                 "A source rule cannot be saved from this opaque label."):
        assert text in values, text


# --------------------------------------------------------------------- #
# the local browser endpoints
# --------------------------------------------------------------------- #

def _get(base, path, **query):
    url = f"{base}{path}?{urllib.parse.urlencode(query)}"
    try:
        with urllib.request.urlopen(url) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as err:
        return err.code, json.load(err)


@pytest.fixture
def ui(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    led = prepared_ledger(tmp_path / "ledger.db")
    sid = seed_baseline_a(led)
    close_writer(led)
    server_ = local_ui_server.serve(sid, print_url=False)
    host, port = server_.socket.getsockname()[:2]
    try:
        yield f"http://{host}:{port}", sid
    finally:
        server_.shutdown()
        server_.server_close()


def test_browser_endpoints_serve_v2_from_one_reading(ui):
    base, sid = ui
    status, summary = _get(base, "/api/summary", session_id=sid)
    assert status == 200
    assert summary["accounting_version"] == 2
    assert summary["percent"] is None
    assert "coverage" in summary
    status, tab = _get(base, "/api/exposures", session_id=sid,
                       tab="Prevented")
    assert status == 200
    assert len(tab["rows"]) == 2
    assert tab["summary"]["intervention_events"] == 2
    assert tab["summary"]["unresolved_actions"] == 3
    assert "coverage" in tab["summary"]
    assert tab["empty_message"]
    status, detail = _get(base, "/api/detail", session_id=sid,
                          id=tab["rows"][0]["id"])
    assert status == 200 and detail["row"]["accounting_version"] == 2
    assert "Not stored." in detail["text"] or detail["row"]["masked_example"]
    status, copy = _get(base, "/api/copy")
    assert status == 200 and "acronyms" in copy
    assert copy["accounting"] == render.accounting_copy()
    status, missing = _get(base, "/api/detail", session_id=sid, id=999999)
    assert status == 404 and missing["error"] != ERROR


def test_browser_corrupt_accounting_is_the_fixed_error(tmp_path,
                                                       monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    led = prepared_ledger(tmp_path / "ledger.db")
    bad = "0" * 64
    led.conn.execute(
        "INSERT INTO scoring_profiles(profile_id,format_version,"
        "matrix_version,created_at,budget_cap,parameters_json)"
        " VALUES(?,1,'1',1,120.0,?)", (bad, PROFILE.as_canonical_json()))
    led.conn.execute(
        "INSERT INTO sessions(session_id,started_at,budget_cap,"
        "accounting_version,accounting_status,profile_id)"
        " VALUES('corrupt',1,120.0,2,'available',?)", (bad,))
    close_writer(led)
    server_ = local_ui_server.serve("corrupt", print_url=False)
    host, port = server_.socket.getsockname()[:2]
    base = f"http://{host}:{port}"
    try:
        for path, query in (("/api/summary", {}),
                            ("/api/exposures", {"tab": "Exposed"}),
                            ("/api/detail", {"id": 1})):
            assert _get(base, path, session_id="corrupt", **query) == \
                (409, {"error": ERROR}), path
    finally:
        server_.shutdown()
        server_.server_close()


# --------------------------------------------------------------------- #
# MCP
# --------------------------------------------------------------------- #

V2_DESCRIPTIONS = {
    "privacy.get_session_summary": """Read the selected session's accounting summary.

accounting_version=2 returns confirmed disclosure points, the frozen budget
cap, observation and finding counts, distinct disclosures and recipients,
issued and enforced intervention counts, unresolved counts, and
percentage_unavailable_reasons. percent is null when accounting, identities,
action outcomes, or recorded coverage are incomplete. Zero confirmed points
with unresolved actions does not mean no disclosure occurred.

accounting_version=1 returns the explicitly prefixed legacy fields and the
legacy accounting note. Historical permitted-crossing scores are not
confirmed-disclosure percentages.

accounting_version=0 returns percent=null and no numeric score, cap, or
counts.

Report score_label, accounting_note, and unavailable reasons. Never replace
null with zero. This is a policy index, not a probability or measurement of
harm. The tool does not establish unobserved transmission, host enforcement,
subagent inheritance, or downstream forwarding.""",
    "privacy.list_exposures": """Read public finding-event rows for the selected session. Accepted tab values
are "Exposed", "Prevented", and "All events".

For accounting_version=2, "Exposed" selects confirmed crossing events;
"Prevented" selects prevention evidence and issued rewrites; "All events"
includes detection, local access, permission, exposure, prevention, and
retention. Evidence names distinguish issued interventions from confirmed
application. occurrences counts matches inside one observation, not calls
or distinct disclosures. Actions with no findings appear in summary counts,
not in this list.

For accounting_version=1, tabs retain legacy meanings: permitted-crossing
rows, legacy prevented rows, and all legacy rows. Legacy outcomes may have
collapsed.

An unrecorded session returns an empty list. An empty list does not establish
that no events occurred. Raw values and identity hashes are not returned.""",
    "privacy.get_exposure_detail": """Read one public finding-event row scoped to both session_id and event_id.

accounting_version=2 returns the observation and action identifiers,
subject and recipient labels, outcome evidence, occurrences, scan-gap
metadata, and the contribution charged at this event. A repeated confirmed
crossing can have zero contribution because the disclosure was charged
earlier. An intended recipient label is not proof of delivery.

accounting_version=1 retains legacy classifications, repetition counts,
intervention labels, and contributions. These do not establish confirmed
delivery or host enforcement.

Neither variant reconstructs a causal multi-hop flow. An unknown event or an
event outside the selected session is an error. This tool reads metadata;
it does not save a policy rule.""",
}


def _norm(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.parametrize("name", sorted(V2_DESCRIPTIONS))
def test_mcp_v2_descriptions_match_verbatim(monkeypatch, tmp_path, name):
    from test_legacy_mcp import _tools

    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    led = prepared_ledger(tmp_path / "ledger.db")
    close_writer(led)
    tools = _tools(server.build_app())
    assert len(tools) == 5
    assert _norm(tools[name].description) == _norm(V2_DESCRIPTIONS[name])


def test_mcp_v2_contract_through_worker_and_stdio(tmp_path, monkeypatch):
    """Regression gate for Phase 3's exact public JSON, on a baseline-A
    fixture: keys, types, null percent, and no hashes or delivery keys."""
    from test_mcp_calls import _call, _payload

    led = prepared_ledger(tmp_path / "ledger.db")
    sid = seed_baseline_a(led)
    delivery_keys = [r[0] for r in led.conn.execute(
        "SELECT delivery_key FROM observations")]
    close_writer(led)
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    app = server.build_app()
    summary = _payload(_call(app, "privacy.get_session_summary",
                             {"session_id": sid}))
    assert summary["percent"] is None
    assert summary["accounting_version"] == 2
    rows = _payload(_call(app, "privacy.list_exposures",
                          {"session_id": sid, "tab": "All events"}))
    assert len(rows) == 3
    for row in rows:
        assert set(row) == {"accounting_version", *(
            f.name for f in __import__("dataclasses").fields(
                AccountingExposureRow))}
        text = json.dumps(row)
        for key in delivery_keys:
            assert key not in text
        assert "identity_hash" not in text and "session_id" not in row


def test_doctor_accepts_v2_and_rejects_invalid_numbers(led):
    from privacy_hud import doctor

    sid = seed_baseline_a(led)
    good = led.summary(sid).as_dict()
    assert doctor._is_summary(good)
    for key, bad in (("confirmed_points", True), ("confirmed_points",
                                                   float("nan")),
                     ("confirmed_points", float("inf")),
                     ("observations", 1.5), ("observations", True),
                     ("percent", 5), ("unresolved_actions", -1)):
        assert not doctor._is_summary({**good, key: bad}), (key, bad)


# --------------------------------------------------------------------- #
# legacy, runtime failure and reader parity
# --------------------------------------------------------------------- #

def test_legacy_contracts_are_byte_unchanged(tmp_path):
    """Regression gate: V0/V1 renderers and JSON are exactly as before."""
    legacy = legacy_summary(28, 2)
    assert legacy.as_dict()["score_label"] == \
        "legacy permitted-crossing score"
    audit = render.audit(legacy, [], "Exposed", session_id="s")
    assert "legacy permitted-crossing score" in audit
    assert "Legacy permitted crossings 0" in audit
    publisher = hs.HudPublisher(tmp_path)
    publisher.publish("s", summary=legacy, unverified=False)
    doc = json.loads(hs.snapshot_path(tmp_path, "s").read_text())
    assert (doc["accounting_version"], doc["percent"],
            doc["legacy_prevented_rows"], doc["confirmed_points"]) == \
        (1, 28, 2, None)


def test_runtime_failure_is_not_unrecorded_or_v2_key_loss():
    from privacy_hud import runtime_messages
    from privacy_hud.hud_snapshot import Snapshot

    key_loss = Snapshot(accounting_version=2, percent=None,
                        confirmed_points=0.0, denials_issued=0,
                        legacy_prevented_rows=None, unresolved_actions=0,
                        unverified=False, hidden=False, updated_at=1.0)
    unrecorded = Snapshot(accounting_version=0, percent=None,
                          confirmed_points=None, denials_issued=None,
                          legacy_prevented_rows=None,
                          unresolved_actions=None, unverified=True,
                          hidden=False, updated_at=1.0)
    lines = {render.hud_line(key_loss, 80), render.hud_line(unrecorded, 80),
             runtime_messages.AMBIENT_RUNTIME_MISMATCH}
    assert len(lines) == 3


def test_v2_rust_python_reading_parity():
    """The shared snapshot golden's version-2 cases render identically in
    Python; the patched reader is pinned to the same file."""
    from pathlib import Path

    golden = json.loads((Path(__file__).resolve().parent / "matrix"
                         / "hud_reading_golden.json").read_text())
    now, width = golden["now"], golden["width"]
    seen = 0
    for name, case in golden["cases"].items():
        snap = case.get("snapshot")
        if not isinstance(snap, dict) or snap.get("accounting_version") != 2:
            continue
        reading = hs._parse(snap)
        if reading is None:
            continue
        seen += 1
        assert render.hud_line(reading, width) == case["expected"], name
    assert seen >= 3 and now


def test_v2_production_surfaces_after_a_real_start(state, tmp_path):
    """A genuine production start is version-2 accounted, and every
    presentation of it succeeds."""
    from privacy_hud import dispatch as dispatch_mod

    dispatch_mod.dispatch(state, {"hook_event_name": "SessionStart",
                                  "session_id": "prod", "cwd": "/r"})
    dispatch_mod.dispatch(state, {"hook_event_name": "UserPromptSubmit",
                                  "session_id": "prod", "prompt": "hi"})
    s = state.ledger.summary("prod")
    assert isinstance(s, AccountingSummary)
    reading = hs.read_snapshot(tmp_path, "prod")
    assert reading is not None and reading.accounting_version == 2
    out = dispatch_mod.dispatch(state, {"hook_event_name": "SessionEnd",
                                        "session_id": "prod"})
    assert out["systemMessage"].startswith("PRIVACY RECEIPT · prod")
    assert "unresolved actions: 1" in out["systemMessage"]


def test_renderers_refuse_an_unknown_accounting_type():
    class Strange:
        accounting_version = 3

    with pytest.raises((UnsupportedAccounting, ValueError, TypeError,
                        AttributeError)):
        render.audit(Strange(), [], "Exposed")  # type: ignore[arg-type]
    assert Ledger  # the reader type stays importable
    assert recipient  # fixtures stay importable
