"""#54 phase 1: the terminal renderers under legacy and unrecorded summaries.

Legacy numbers keep their values and gain their labels. An unrecorded
session renders no number, band, bar, row or policy action. Intervention
copy says what Privacy HUD returned, never that the host applied it.
"""
from __future__ import annotations

import pytest

from privacy_hud import mcp_tools, render
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix

M = load_matrix()

LEGACY_NOTE = ("Historical accounting includes permitted crossings and may "
               "collapse different outcomes. It does not establish confirmed "
               "disclosure.")
UNRECORDED_NOTE = ("No session record is available in this ledger. The "
                   "percentage and counts are unavailable.")
UNRECORDED_EMPTY = ("No events can be shown for an unrecorded session. This "
                    "is not evidence that none occurred.")


@pytest.fixture
def led(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db", M)
    ledger.start_session("s1", cwd="/repo", model="gpt-5")
    yield ledger
    ledger.conn.close()


def _rec(led, **kw):
    base = dict(turn_id="t1", kind="exposed", data_type="email",
                source="support.log", destination="model_context",
                value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
                tool_name="Read", protection=None)
    base.update(kw)
    return led.record("s1", **base)


def _rows(led, tab):
    return mcp_tools.list_exposures(led, "s1", tab)


# -- audit ------------------------------------------------------------------

def test_legacy_tiles_carry_the_legacy_labels_and_note(led):
    _rec(led)
    text = render.audit(led.summary("s1"), _rows(led, "Exposed"), "Exposed",
                        session_id="s1")
    for label in ("legacy permitted-crossing score",
                  "legacy permitted-crossing rows",
                  "legacy boundary kinds",
                  "legacy prevented rows"):
        assert label in text
    assert LEGACY_NOTE in text
    assert "of budget" not in text


def test_unrecorded_audit_shows_no_number(led):
    summary = led.summary("missing")
    text = render.audit(summary, [], "Exposed", session_id="missing")
    for value, label in (("—%", "percentage unavailable"),
                         ("—", "permitted-crossing rows unavailable"),
                         ("—", "boundary kinds unavailable"),
                         ("—", "prevented rows unavailable")):
        assert value in text and label in text
    assert "No session on record" in text
    assert UNRECORDED_NOTE in text
    assert UNRECORDED_EMPTY in text
    assert "0%" not in text


def test_tab_labels_are_legacy_and_all_events_is_exact(led):
    _rec(led)
    _rec(led, value_hash=b"\x02" * 16, kind="local_access",
         destination="model_context")
    text = render.audit(led.summary("s1"), _rows(led, "Exposed"), "Exposed",
                        session_id="s1", all_events_count=2)
    assert "Legacy permitted crossings 1" in text
    assert "Legacy prevented rows 0" in text
    assert "All legacy events 2" in text


def test_all_events_count_is_unavailable_when_not_supplied(led):
    _rec(led)
    text = render.audit(led.summary("s1"), _rows(led, "Exposed"), "Exposed",
                        session_id="s1")
    assert "All legacy events —" in text


@pytest.mark.parametrize("kind,protection,chip", [
    ("exposed", None, "LEGACY PERMITTED"),
    ("exposed", "masked", "LEGACY PERMITTED"),
    ("prevented", "blocked", "LEGACY PREVENTED ROW"),
    ("local_access", None, "LEGACY LOCAL ACCESS"),
    ("detected", None, "LEGACY DETECTED"),
    ("retention", None, "LEGACY RETENTION"),
    ("mystery", None, "LEGACY UNKNOWN"),
])
def test_legacy_row_chips_map_only_by_kind(led, kind, protection, chip):
    _rec(led, kind=kind, protection=protection)
    [row] = _rows(led, "All events") if kind != "mystery" else [
        r.to_exposure() for r in led.list_events("s1", "mystery")]
    assert render._status_chip(row) == f"[{chip}]"


# -- detail -----------------------------------------------------------------

@pytest.mark.parametrize("protection,shown", [
    ("blocked", "denial recorded; host enforcement unconfirmed"),
    ("masked", "rewrite recorded; host application unconfirmed"),
    ("minimized", "rewrite recorded; host application unconfirmed"),
    (None, "no intervention recorded"),
    ("none", "no intervention recorded"),
    ("other", "legacy intervention not recognized"),
])
def test_detail_labels_legacy_interventions(led, protection, shown):
    _rec(led, protection=protection)
    [row] = led.list_events("s1", "exposed")
    text = render.detail(led.get_event("s1", row.id))
    assert "Recorded association" in text
    assert "Legacy intervention" in text and shown in text
    assert "Legacy score contribution" in text
    assert ("This legacy source-to-destination association does not "
            "establish delivery or a multi-hop flow.") in text
    assert LEGACY_NOTE in text
    assert "Protection" not in text


def test_detail_prints_no_pretend_buttons(led):
    _rec(led, source="/w/.env", source_kind="path")
    [row] = led.list_events("s1", "exposed")
    text = render.detail(led.get_event("s1", row.id))
    assert "[ " not in text
    assert ("Policy rules can be saved in the local audit browser opened by "
            "$privacy.") in text
    assert "Already disclosed data cannot be recalled from this session." \
        in text


def test_detail_contribution_is_labelled_legacy(led):
    _rec(led)
    [row] = led.list_events("s1", "exposed")
    detail = led.get_event("s1", row.id)
    text = render.detail(detail)
    assert f"+{detail.budget_delta:g} legacy pts of {detail.budget_cap:g}" \
        in text


# -- receipt ----------------------------------------------------------------

def test_unrecorded_receipt_is_exactly_the_approved_text(led):
    text = render.receipt("missing", led.summary("missing"), [], None)
    assert text == (
        "PRIVACY RECEIPT · missing\n"
        "\n"
        "No session on record\n"
        "Percentage unavailable.\n"
        f"{UNRECORDED_NOTE}\n"
        "No event rows can be listed for this session.\n"
        "\n"
        "This ledger stores metadata, not file contents, prompts, or raw "
        "values.")


def test_legacy_receipt_lines(led):
    _rec(led, protection="masked")
    summary = led.summary("s1")
    text = render.receipt("s1", summary, _rows(led, "Exposed"), 3)
    assert (f"legacy permitted-crossing score: {summary.legacy_percent}% "
            f"({summary.legacy_score:g} pts of {summary.legacy_cap:g})") in text
    assert "legacy permitted-crossing rows: 1" in text
    assert "legacy boundary kinds: 1" in text
    assert "legacy prevented rows: 0" in text
    assert "Transcript retention is outside this ledger's account." in text
    assert LEGACY_NOTE in text
    assert "(masked)" not in text
    assert text.endswith("This ledger stores metadata, not file contents, "
                         "prompts, or raw values.")


def test_legacy_receipt_without_a_start_time_omits_duration(led):
    text = render.receipt("s1", led.summary("s1"), [], None)
    assert text.splitlines()[0] == "PRIVACY RECEIPT · s1"
    assert "0 min" not in text


# -- intervention copy ------------------------------------------------------

def test_intervention_templates_do_not_claim_host_application():
    from privacy_hud import engine
    assert "Host enforcement is not confirmed." in engine.READ_BLOCK_TEMPLATE
    assert "This one did not run" not in engine.READ_BLOCK_TEMPLATE
    assert "Host enforcement is not confirmed." in engine.BLOCK_TEMPLATE
    assert "Host enforcement is not confirmed." in \
        engine.ORIGIN_BLOCK_TEMPLATE
    assert "Application by the host is not confirmed." in \
        engine.REWRITE_TEMPLATE
    assert "Host enforcement is not confirmed." in \
        engine.READ_NOTICE_TEMPLATE


def test_rule_notes_end_with_the_host_caveat():
    for rule_type, selector in (("mask", "email"), ("mask", "path"),
                                ("block_path", "/w/.env")):
        note = mcp_tools.rule_enforcement_note(rule_type, selector)
        assert note.endswith(" Host application of a denial or rewritten "
                             "input is not confirmed by these hooks.")
