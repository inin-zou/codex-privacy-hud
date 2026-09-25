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
from runtime_helpers import writer_ledger

DESCRIPTIONS = {
    # #54 Phase 4 replaced the three read-tool descriptions; they are pinned
    # verbatim in tests/test_accounting_surfaces.py.
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
    from privacy_hud.matrix.loader import load_matrix
    writer_ledger(tmp_path / "ledger.db", load_matrix()).conn.close()
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
    {**LEGACY, "legacy_score": 10**400},
    {**LEGACY, "legacy_score": -(10**400)},
    {**LEGACY, "legacy_cap": 10**400},
    {**LEGACY, "legacy_cap": -(10**400)},
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


def test_server_starts_before_the_ledger_exists(monkeypatch, tmp_path):
    """A reader's open cannot create the ledger, and Codex can start the
    server before the daemon has. The server must still start; a call made
    before the ledger exists fails with the fixed ledger error rather than
    reporting a session, and the next call after the daemon creates it
    succeeds."""
    import asyncio

    from privacy_hud.matrix.loader import load_matrix

    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    app = server.build_app()
    assert not (tmp_path / "ledger.db").exists()
    with pytest.raises(Exception) as caught:
        asyncio.run(app.call_tool("privacy.get_session_summary",
                                  {"session_id": "s1"}))
    assert server.LEDGER_ERROR in str(caught.value)
    assert not (tmp_path / "ledger.db").exists()

    writer_ledger(tmp_path / "ledger.db", load_matrix()).conn.close()
    result = asyncio.run(app.call_tool("privacy.get_session_summary",
                                       {"session_id": "s1"}))
    text = json.dumps(result, default=lambda o: getattr(o, "__dict__", str(o)))
    assert "No session on record" in text
