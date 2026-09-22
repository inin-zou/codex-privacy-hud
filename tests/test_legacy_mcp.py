"""#54 phase 1: the MCP surface and the doctor probe under the new summary
variants.

The tool descriptions are what the model reads to decide what a number
means, so they are pinned verbatim (whitespace-normalized: the SDK may
reflow a docstring).
"""
from __future__ import annotations

import json
import math

import pytest

import server  # `mcp/` is on sys.path via conftest

from privacy_hud import doctor

DESCRIPTIONS = {
    'privacy.get_session_summary': (
        "Read the selected session's accounting summary.\n"
        '\n'
        'accounting_version=1 returns legacy_score, legacy_cap, legacy_percent, legacy_permitted_crossing_rows, legacy_boundary_kinds, legacy_prevented_rows, score_label, and accounting_note. legacy_percent is the existing score divided by its stored cap, rounded and capped at 100. It is not a probability or a fraction of data disclosed. Row counts are not call counts, and boundary kinds are not concrete recipients. Historical accounting includes permitted crossings and may collapse different outcomes. It does not establish confirmed disclosure.\n'
        '\n'
        'accounting_version=0 returns percent=null, score_label="No session on record", and accounting_note. No numeric score, cap, or counts are available for that session.\n'
        '\n'
        'Report score_label and accounting_note with the result. Do not replace null with zero. The old percent, exposed_items, destinations, and prevented fields are not returned for legacy summaries.\n'
    ),
    'privacy.list_exposures': (
        'Read public legacy event rows for the selected session. Accepted tab values are "Exposed", "Prevented", and "All events"; they select stored legacy classifications.\n'
        '\n'
        'Each returned row has accounting_version=1. "Exposed" selects legacy permitted-crossing rows, not confirmed deliveries. "Prevented" selects legacy prevented rows, not confirmed host-enforced interventions. count is the stored legacy repetition count, not a distinct-value or call count. Different outcomes may have collapsed into one row.\n'
        '\n'
        'An unrecorded session returns an empty list. That is not evidence that no events occurred. Raw values and identity hashes are not returned.\n'
    ),
    'privacy.get_exposure_detail': (
        'Read one public legacy event row by session_id and event_id. The lookup is scoped to both identifiers and returns accounting_version=1.\n'
        '\n'
        'The stored classification, intervention label, repetition count, and budget contribution retain legacy meanings. They do not establish delivery, host enforcement, or a multi-hop flow. first_seen and budget_cap are included when available.\n'
        '\n'
        'An unknown event or an event outside the selected session is an error. An unrecorded session has no event detail. This tool reads metadata; it does not save a policy rule.\n'
    ),
    'privacy.update_policy': (
        'Save a policy rule for the selected session: mask selects a data type; block_path and block_command select a recorded origin.\n'
        '\n'
        'Success returns saved=true and enforcement="conditional". Report the returned conditions to the user. Saving a rule does not establish that a later call will match it or that the host will apply a denial or rewritten input.\n'
        '\n'
        'Mask rules can cause Privacy HUD to return rewritten input for matching findings on later outbound calls this plugin checks. A deny takes precedence. Types other than path and credential require an accepted deep-scan result.\n'
        '\n'
        'Origin rules require detection on ingress and again on egress. They match the whole value normalized using value.strip().lower(); summaries and partial quotations may not match. Scan gaps and detector misses can prevent matching, and hosted tools bypass these hooks.\n'
        '\n'
        'block_source and allow_dest are refused. A mask rule selecting a hard-blocked data type is also refused. Data already disclosed stays disclosed.\n'
    ),
    'privacy.read_guard_status': (
        "Read whether the known-sensitive-path read guard is enabled in Privacy HUD's settings.json. deny_read=true means the plugin is configured to issue denials for recognized matching reads. It does not confirm host enforcement. This tool does not change the setting.\n"
    ),
}


def _norm(text: str) -> str:
    return " ".join(text.split())


def _tools(app):
    for get in (lambda: app.list_tools(),
                lambda: app._tool_manager.list_tools()):
        try:
            tools = get()
        except (AttributeError, TypeError):
            continue
        if hasattr(tools, "__await__"):
            import asyncio
            tools = asyncio.run(tools)
        return {t.name: t for t in tools}
    raise AssertionError("no accessor for the registered tools on this SDK")


@pytest.mark.parametrize("name", sorted(DESCRIPTIONS))
def test_tool_descriptions_are_the_approved_text(monkeypatch, tmp_path, name):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    (tmp_path / "ledger.db").touch()
    from privacy_hud.ledger import Ledger
    from privacy_hud.matrix.loader import load_matrix
    Ledger(tmp_path / "ledger.db", load_matrix()).conn.close()
    tool = _tools(server.build_app())[name]
    assert _norm(tool.description) == _norm(DESCRIPTIONS[name])


def _reply(payload) -> dict:
    return {"jsonrpc": "2.0", "id": 2, "result": {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "isError": False}}


LEGACY = {
    "accounting_version": 1, "legacy_score": 33.6, "legacy_cap": 120.0,
    "legacy_percent": 28, "legacy_permitted_crossing_rows": 4,
    "legacy_boundary_kinds": 2, "legacy_prevented_rows": 2,
    "score_label": "legacy permitted-crossing score",
    "accounting_note": ("Historical accounting includes permitted crossings "
                        "and may collapse different outcomes. It does not "
                        "establish confirmed disclosure."),
}
UNRECORDED = {
    "accounting_version": 0, "percent": None,
    "score_label": "No session on record",
    "accounting_note": ("No session record is available in this ledger. The "
                        "percentage and counts are unavailable."),
}


def test_doctor_accepts_both_summary_variants():
    assert doctor._is_summary_reply(_reply(LEGACY))
    assert doctor._is_summary_reply(_reply(UNRECORDED))


@pytest.mark.parametrize("bad", [
    {"percent": 0, "exposed_items": 0, "destinations": 0, "prevented": 0},
    {**UNRECORDED, "percent": 0},
    {**UNRECORDED, "accounting_version": False},
    {**LEGACY, "accounting_version": True},
    {**LEGACY, "legacy_percent": 101},
    {**LEGACY, "legacy_cap": 0},
    {**LEGACY, "legacy_score": -1},
    {**LEGACY, "legacy_prevented_rows": 1.5},
    {**LEGACY, "legacy_boundary_kinds": True},
    {**LEGACY, "score_label": "score"},
    {**LEGACY, "accounting_note": ""},
    {k: v for k, v in LEGACY.items() if k != "legacy_cap"},
    {**LEGACY, "extra": 1},
])
def test_doctor_rejects_malformed_or_ambiguous_summaries(bad):
    assert not doctor._is_summary_reply(_reply(bad))


def test_doctor_rejects_a_nonfinite_score():
    text = json.dumps({**LEGACY, "legacy_score": math.inf})
    assert "Infinity" in text
    reply = {"jsonrpc": "2.0", "id": 2, "result": {
        "content": [{"type": "text", "text": text}], "isError": False}}
    assert not doctor._is_summary_reply(reply)
