# tests/test_contract_characterization.py
"""Characterization tests for the ledger -> mcp_tools -> render / HTTP chain.

These pin the *observable* output of the whole chain, not the internal shape
that carries it. That distinction is the entire point of this file: the three
modules below used to hand each other bare `dict`s whose contract existed only
as string literals, and the project has already been bitten by that class of
bug once (`detect/model.py`'s `LABEL_MAP` used `EMAIL` where the model emits
`private_email`, so tier 3 silently returned nothing). Before replacing that
implicit contract with dataclasses, we need something that fails loudly if the
replacement changes a single rendered byte.

So every test here:

* builds its input by driving the REAL chain (`Ledger` -> `mcp_tools` ->
  `render`), never by hand-writing a literal row dict. A literal would pin the
  old carrier type instead of the behaviour, and would have to be rewritten by
  the very refactor it is supposed to police;
* asserts on a byte-exact golden string (the rendered ASCII *is* the product
  surface -- design.md P6: "every view must have a legible ASCII rendering")
  or on a byte-exact JSON payload (the `privacy.*` MCP tools and the local
  UI's endpoints are a public contract).

`_json()` below is the one concession to the refactor: it is the explicit
serialization step at the JSON boundary, and it is a no-op passthrough for a
plain dict. Nothing else in this file knows or cares what type the chain
passes around internally.

If a test in this file has to be edited to make a refactor pass, the refactor
changed behaviour. That is a bug, not a rebaseline.
"""
from __future__ import annotations

import time

import json
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

import pytest

from privacy_hud import local_ui_server, mcp_tools, render
from privacy_hud.dispatch import dispatch
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix

from legacy_fakes import legacy_line
from runtime_helpers import writer_ledger
from runtime_helpers import writer_state_with_detectors

M = load_matrix()

SESSION = "sess-golden"
EMPTY_SESSION = "sess-empty"

#: A frozen wall clock. `Ledger.record` stamps `int(time.time())`, which would
#: make every golden below a different string on every run; each row's `ts` is
#: rewritten to a fixed value straight after insert instead of monkeypatching
#: the clock globally, so nothing outside these rows is affected.
TS = 1_757_000_000

#: One row per rendered case the audit table can produce: an [EXPOSED] chip
#: with a source long enough to exercise middle-truncation and a masked
#: exemplar, a [MASKED] chip, a [PREVENTED] chip with no exemplar at all
#: (credentials never get one -- mask.py), and a [LOCAL] chip.
_ROWS = (
    dict(turn_id="t1", kind="exposed", data_type="email",
         source="support/logs/production/app.log", destination="model_context",
         value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
         tool_name="Read", protection=None),
    dict(turn_id="t2", kind="exposed", data_type="path",
         source="terminal output", destination="subagent",
         value_hash=b"\x02" * 16, masked_example="/Users/•••/app.log",
         tool_name="Task", protection="masked"),
    dict(turn_id="t3", kind="prevented", data_type="credential",
         source=".env", source_kind="path", destination="external_net",
         value_hash=b"\x03" * 16, masked_example=None,
         tool_name="Bash", protection="blocked"),
    dict(turn_id="t4", kind="local_access", data_type="hostname",
         source="shell", destination="local",
         value_hash=b"\x04" * 16, masked_example="db•••.internal",
         tool_name="Read", protection=None),
)


def _fill(ledger: Ledger) -> None:
    """Drive the ledger's real `record()` path, then freeze each row's `ts`."""
    ledger.start_session(SESSION, cwd="/repo", model="gpt-5")
    ledger.start_session(EMPTY_SESSION, cwd="/repo", model="gpt-5")
    for i, spec in enumerate(_ROWS):
        ledger.record(SESSION, **spec)
        ledger.conn.execute(
            "UPDATE events SET ts=? WHERE session_id=? AND turn_id=?",
            (TS + i * 60, SESSION, spec["turn_id"]))


def _json(obj):
    """Serialize a chain return value the way a JSON consumer must.

    A plain dict passes straight through; anything carrying an explicit
    `as_dict()` serialization step is asked for it. This is deliberately the
    ONLY place in this file that adapts to the carrier type -- every assertion
    below is on the resulting JSON, which is the part the MCP clients and the
    browser UI actually see and which must not move.
    """
    if isinstance(obj, (list, tuple)):
        return [_json(o) for o in obj]
    as_dict = getattr(obj, "as_dict", None)
    return as_dict() if callable(as_dict) else dict(obj)


def _hhmmss(ts: int) -> str:
    """`render._fmt_time`'s format, recomputed rather than hardcoded: the
    goldens must not depend on the machine's timezone. Every other byte of
    the detail view IS hardcoded."""
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


@pytest.fixture
def led(tmp_path):
    ledger = writer_ledger(tmp_path / "l.db", M)
    _fill(ledger)
    return ledger


def _audit(ledger, session_id, tab):
    return render.audit(mcp_tools.get_session_summary(ledger, session_id),
                        mcp_tools.list_exposures(ledger, session_id, tab),
                        tab)


# --------------------------------------------------------------------- #
# render.audit -- the L2 session audit (design.md §5)
#
# Rebaselined on purpose by #54 phase 1, which changed what these views
# say, not how the chain carries it: every number is now labelled legacy,
# an unrecorded session has none, and intervention labels say what Privacy
# HUD returned rather than what the host applied. The numbers themselves
# did not move.
# --------------------------------------------------------------------- #

AUDIT_EXPOSED = (
    'Privacy Audit\n'
    'Session ID unknown\n'
    '\n'
    '┌─────────────────────────────────┐ ┌────────────────────────────────┐\n'
    '│                6%               │ │               2                │\n'
    '│ legacy permitted-crossing score │ │ legacy permitted-crossing rows │\n'
    '└─────────────────────────────────┘ └────────────────────────────────┘\n'
    '┌───────────────────────┐ ┌───────────────────────┐\n'
    '│           2           │ │           1           │\n'
    '│ legacy boundary kinds │ │ legacy prevented rows │\n'
    '└───────────────────────┘ └───────────────────────┘\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    '\n'
    ' Legacy permitted crossings 2      Legacy prevented rows 1      All legacy events —\n'
    ' ────────────────────────────                                                      \n'
    '\n'
    'SENSITIVE DATA  SOURCE                    DESTINATION    STATUS            \n'
    'Email ×1        support/log...on/app.log  model_context  [LEGACY PERMITTED]\n'
    'Path ×1         terminal output           subagent       [LEGACY PERMITTED]'
)

AUDIT_PREVENTED = (
    'Privacy Audit\n'
    'Session ID unknown\n'
    '\n'
    '┌─────────────────────────────────┐ ┌────────────────────────────────┐\n'
    '│                6%               │ │               2                │\n'
    '│ legacy permitted-crossing score │ │ legacy permitted-crossing rows │\n'
    '└─────────────────────────────────┘ └────────────────────────────────┘\n'
    '┌───────────────────────┐ ┌───────────────────────┐\n'
    '│           2           │ │           1           │\n'
    '│ legacy boundary kinds │ │ legacy prevented rows │\n'
    '└───────────────────────┘ └───────────────────────┘\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    '\n'
    ' Legacy permitted crossings 2      Legacy prevented rows 1      All legacy events —\n'
    '                                   ───────────────────────                         \n'
    '\n'
    'SENSITIVE DATA  SOURCE  DESTINATION   STATUS                \n'
    'Credential ×1   .env    external_net  [LEGACY PREVENTED ROW]'
)

AUDIT_ALL = (
    'Privacy Audit\n'
    'Session ID unknown\n'
    '\n'
    '┌─────────────────────────────────┐ ┌────────────────────────────────┐\n'
    '│                6%               │ │               2                │\n'
    '│ legacy permitted-crossing score │ │ legacy permitted-crossing rows │\n'
    '└─────────────────────────────────┘ └────────────────────────────────┘\n'
    '┌───────────────────────┐ ┌───────────────────────┐\n'
    '│           2           │ │           1           │\n'
    '│ legacy boundary kinds │ │ legacy prevented rows │\n'
    '└───────────────────────┘ └───────────────────────┘\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    '\n'
    ' Legacy permitted crossings 2      Legacy prevented rows 1      All legacy events 4\n'
    '                                                                ───────────────────\n'
    '\n'
    'SENSITIVE DATA  SOURCE                    DESTINATION    STATUS                \n'
    'Email ×1        support/log...on/app.log  model_context  [LEGACY PERMITTED]    \n'
    'Path ×1         terminal output           subagent       [LEGACY PERMITTED]    \n'
    'Credential ×1   .env                      external_net   [LEGACY PREVENTED ROW]\n'
    'Hostname ×1     shell                     local          [LEGACY LOCAL ACCESS] '
)

_AUDIT_EMPTY_EXPOSED = (
    'Privacy Audit\n'
    'Session ID unknown\n'
    '\n'
    '┌─────────────────────────────────┐ ┌────────────────────────────────┐\n'
    '│                0%               │ │               0                │\n'
    '│ legacy permitted-crossing score │ │ legacy permitted-crossing rows │\n'
    '└─────────────────────────────────┘ └────────────────────────────────┘\n'
    '┌───────────────────────┐ ┌───────────────────────┐\n'
    '│           0           │ │           0           │\n'
    '│ legacy boundary kinds │ │ legacy prevented rows │\n'
    '└───────────────────────┘ └───────────────────────┘\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    '\n'
    ' Legacy permitted crossings 0      Legacy prevented rows 0      All legacy events —\n'
    ' ────────────────────────────                                                      \n'
    '\n'
    'No exposure recorded this session.'
)

_AUDIT_EMPTY_PREVENTED = (
    'Privacy Audit\n'
    'Session ID unknown\n'
    '\n'
    '┌─────────────────────────────────┐ ┌────────────────────────────────┐\n'
    '│                0%               │ │               0                │\n'
    '│ legacy permitted-crossing score │ │ legacy permitted-crossing rows │\n'
    '└─────────────────────────────────┘ └────────────────────────────────┘\n'
    '┌───────────────────────┐ ┌───────────────────────┐\n'
    '│           0           │ │           0           │\n'
    '│ legacy boundary kinds │ │ legacy prevented rows │\n'
    '└───────────────────────┘ └───────────────────────┘\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    '\n'
    ' Legacy permitted crossings 0      Legacy prevented rows 0      All legacy events —\n'
    '                                   ───────────────────────                         \n'
    '\n'
    'Nothing recorded as blocked or minimized yet.'
)

_AUDIT_EMPTY_ALL = (
    'Privacy Audit\n'
    'Session ID unknown\n'
    '\n'
    '┌─────────────────────────────────┐ ┌────────────────────────────────┐\n'
    '│                0%               │ │               0                │\n'
    '│ legacy permitted-crossing score │ │ legacy permitted-crossing rows │\n'
    '└─────────────────────────────────┘ └────────────────────────────────┘\n'
    '┌───────────────────────┐ ┌───────────────────────┐\n'
    '│           0           │ │           0           │\n'
    '│ legacy boundary kinds │ │ legacy prevented rows │\n'
    '└───────────────────────┘ └───────────────────────┘\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    '\n'
    ' Legacy permitted crossings 0      Legacy prevented rows 0      All legacy events 0\n'
    '                                                                ───────────────────\n'
    '\n'
    'No privacy events recorded for this session.'
)

AUDIT_EMPTY = {
    "Exposed": _AUDIT_EMPTY_EXPOSED,
    "Prevented": _AUDIT_EMPTY_PREVENTED,
    "All events": _AUDIT_EMPTY_ALL,
}


def test_audit_exposed_tab_is_byte_identical(led):
    assert _audit(led, SESSION, "Exposed") == AUDIT_EXPOSED


def test_audit_prevented_tab_is_byte_identical(led):
    assert _audit(led, SESSION, "Prevented") == AUDIT_PREVENTED


def test_audit_all_events_tab_is_byte_identical(led):
    assert _audit(led, SESSION, "All events") == AUDIT_ALL


@pytest.mark.parametrize("tab", ["Exposed", "Prevented", "All events"])
def test_audit_empty_session_is_byte_identical(led, tab):
    assert _audit(led, EMPTY_SESSION, tab) == AUDIT_EMPTY[tab]


#: The same empty audit, for a session the ledger did NOT watch from the start.
#:
#: Read the two goldens side by side. `AUDIT_EMPTY["All events"]` ends with a
#: statement about the ledger — "No privacy events recorded for this session."
#: This one replaces it wholesale, because for this session observation began
#: late and even that statement would invite being read as an account.
#:
#: Until #49 the difference was sharper and in the wrong direction: the
#: verified golden said "No privacy events recorded. The engine is running.",
#: design.md §5's answer to "an empty audit is otherwise indistinguishable
#: from a broken plugin". Right question, wrong evidence — a ledger is history
#: and cannot vouch for a live process, and `SessionCoverage` says in its own
#: docstring that `verified` is "deliberately weaker than complete". The
#: distinction these two goldens draw is still the fix; it is now drawn
#: between two things the record can actually support.
AUDIT_UNVERIFIED = (
    'Privacy Audit\n'
    'Session ID unknown\n'
    '\n'
    '┌─────────────────────────────────┐ ┌────────────────────────────────┐\n'
    '│                0%               │ │               0                │\n'
    '│ legacy permitted-crossing score │ │ legacy permitted-crossing rows │\n'
    '└─────────────────────────────────┘ └────────────────────────────────┘\n'
    '┌───────────────────────┐ ┌───────────────────────┐\n'
    '│           0           │ │           0           │\n'
    '│ legacy boundary kinds │ │ legacy prevented rows │\n'
    '└───────────────────────┘ └───────────────────────┘\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    '\n'
    ' Legacy permitted crossings 0      Legacy prevented rows 0      All legacy events 0\n'
    '                                                                ───────────────────\n'
    '\n'
    '⚠ Session record incomplete — observation began after this session was already under way.\n'
    '  Figures below are not a full account of this session.\n'
    '\n'
    "No events recorded for this tab. With this session's record incomplete, that is not evidence that none occurred."
)


def test_audit_for_an_unwatched_session_is_byte_identical(led):
    led.start_session("sess-attached", cwd="/repo", model="gpt-5",
                       observed_start=False)
    out = render.audit(
        mcp_tools.get_session_summary(led, "sess-attached"),
        mcp_tools.list_exposures(led, "sess-attached", "All events"),
        "All events",
        coverage=mcp_tools.get_session_coverage(led, "sess-attached"))
    assert out == AUDIT_UNVERIFIED


def test_audit_for_a_watched_session_did_not_move(led):
    """Passing a *verified* coverage reading must render exactly what passing
    none renders. Otherwise every existing golden in this file would have had to
    be rebaselined, and the change would be a rendering rewrite rather than a
    new state."""
    for tab in ("Exposed", "Prevented", "All events"):
        with_coverage = render.audit(
            mcp_tools.get_session_summary(led, SESSION),
            mcp_tools.list_exposures(led, SESSION, tab), tab,
            coverage=mcp_tools.get_session_coverage(led, SESSION))
        assert with_coverage == _audit(led, SESSION, tab)


# --------------------------------------------------------------------- #
# render.detail -- the L3 exposure detail (design.md §6)
# --------------------------------------------------------------------- #

DETAIL_EMAIL = (
    'Email ×1\n'
    'Recorded association       support/logs/production/app.log → model_context\n'
    'This legacy source-to-destination association does not establish delivery or a multi-hop flow.\n'
    '\n'
    'First seen                 {t}\n'
    'Legacy intervention        no intervention recorded\n'
    'Example                    jo•••@acme.com\n'
    'Legacy score contribution  +6 legacy pts of 120\n'
    '\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    '\n'
    'Policy rules can be saved in the local audit browser opened by $privacy.\n'
    '\n'
    'Already disclosed data cannot be recalled from this session.'
)

DETAIL_MASKED_PATH = (
    'Path ×1\n'
    'Recorded association       terminal output → subagent\n'
    'This legacy source-to-destination association does not establish delivery or a multi-hop flow.\n'
    '\n'
    'First seen                 {t}\n'
    'Legacy intervention        rewrite recorded; host application unconfirmed\n'
    'Example                    /Users/•••/app.log\n'
    'Legacy score contribution  +0.6 legacy pts of 120\n'
    '\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    '\n'
    'Policy rules can be saved in the local audit browser opened by $privacy.\n'
    '\n'
    'Already disclosed data cannot be recalled from this session.'
)

#: A credential carries no exemplar at all, so the Example line is absent --
#: the view must never print "Example None". This is the golden that pins it.
#:
#: This row's `source_kind` is "path" (Task 2/3: ingress dispatch now records
#: where a value actually came from), so it also pins the L3 origin action
#: (#40): a row naming a real origin gets a second action line, after the
#: mask action, offering to block that exact origin.
DETAIL_CREDENTIAL = (
    'Credential ×1\n'
    'Recorded association       .env → external_net\n'
    'This legacy source-to-destination association does not establish delivery or a multi-hop flow.\n'
    '\n'
    'First seen                 {t}\n'
    'Legacy intervention        denial recorded; host enforcement unconfirmed\n'
    'Legacy score contribution  +0 legacy pts of 120\n'
    '\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    '\n'
    'Policy rules can be saved in the local audit browser opened by $privacy.\n'
    '\n'
    'Already disclosed data cannot be recalled from this session.'
)


@pytest.mark.parametrize("index,golden", [
    (0, DETAIL_EMAIL),
    (1, DETAIL_MASKED_PATH),
    (2, DETAIL_CREDENTIAL),
])
def test_detail_is_byte_identical(led, index, golden):
    ids = [r["id"] for r in _json(mcp_tools.list_exposures(led, SESSION, "All events"))]
    row = mcp_tools.get_exposure_detail(led, SESSION, ids[index])
    assert render.detail(row) == golden.format(t=_hhmmss(TS + index * 60))


# --------------------------------------------------------------------- #
# render.receipt -- the end-of-session receipt (design.md §10)
# --------------------------------------------------------------------- #

RECEIPT = (
    'PRIVACY RECEIPT · sess-golden · 41 min\n'
    '\n'
    'legacy permitted-crossing score: 6% (6.6 pts of 120)\n'
    'legacy permitted-crossing rows: 2\n'
    'legacy boundary kinds: 2\n'
    'legacy prevented rows: 1\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    "Transcript retention is outside this ledger's account.\n"
    '\n'
    '  Email ×1              support/l.../app.log→ model_context\n'
    '  Path ×1               terminal output   → subagent\n'
    '\n'
    'This ledger stores metadata, not file contents, prompts, or raw values.'
)

RECEIPT_EMPTY = (
    'PRIVACY RECEIPT · sess-empty · 0 min\n'
    '\n'
    'legacy permitted-crossing score: 0% (0 pts of 120)\n'
    'legacy permitted-crossing rows: 0\n'
    'legacy boundary kinds: 0\n'
    'legacy prevented rows: 0\n'
    'Historical accounting includes permitted crossings and may collapse different outcomes.\n'
    'It does not establish confirmed disclosure.\n'
    "Transcript retention is outside this ledger's account.\n"
    '\n'
    '\n'
    'This ledger stores metadata, not file contents, prompts, or raw values.'
)


def test_receipt_is_byte_identical(led):
    out = render.receipt(SESSION,
                         mcp_tools.get_session_summary(led, SESSION),
                         mcp_tools.list_exposures(led, SESSION, "Exposed"), 41)
    assert out == RECEIPT


def test_receipt_for_a_clean_session_is_byte_identical(led):
    out = render.receipt(EMPTY_SESSION,
                         mcp_tools.get_session_summary(led, EMPTY_SESSION),
                         mcp_tools.list_exposures(led, EMPTY_SESSION, "Exposed"), 0)
    assert out == RECEIPT_EMPTY


def test_receipt_over_raw_ledger_rows_is_byte_identical(led):
    """`dispatch._handle_session_end` feeds `Ledger.list_events` output
    straight into `render.receipt`, bypassing `mcp_tools` entirely. That is a
    second, independent row shape reaching the same renderer, so it gets its
    own golden -- the two paths must not drift apart."""
    out = render.receipt(SESSION, led.summary(SESSION),
                         led.list_events(SESSION, "exposed"), 41)
    assert out == RECEIPT


# --------------------------------------------------------------------- #
# render.hud_line -- the L1 width ladder (design.md §4)
#
# Rebaselined by #54 phase 1. The line now takes a snapshot reading and
# draws a labelled legacy percentage with no bar: the first whole candidate
# that fits, and nothing when none does. The old ladder (bar, `›`, band dot,
# right-truncation) is gone with the numeric-only reading it drew.
# --------------------------------------------------------------------- #

HUD_LADDER = {
    80: 'Privacy legacy 28%',
    52: 'Privacy legacy 28%',
    51: 'Privacy legacy 28%',
    40: 'Privacy legacy 28%',
    39: 'Privacy legacy 28%',
    28: 'Privacy legacy 28%',
    27: 'Privacy legacy 28%',
    18: 'Privacy legacy 28%',
    12: 'legacy 28%',
    10: 'legacy 28%',
    6: 'legacy',
    4: '',
    1: '',
}

HUD_ROWS = {
    80: 'Privacy legacy 63% · 17 prevented rows',
    52: 'Privacy legacy 63% · 17 prevented rows',
    51: 'Privacy legacy 63% · 17 prevented rows',
    40: 'Privacy legacy 63% · 17 prevented rows',
    39: 'Privacy legacy 63% · 17 prevented rows',
    28: 'Privacy legacy 63%',
    27: 'Privacy legacy 63%',
    18: 'Privacy legacy 63%',
    12: 'legacy 63%',
    10: 'legacy 63%',
    6: 'legacy',
    4: '',
    1: '',
}

HUD_UNVERIFIED = {
    80: 'Privacy legacy 28% ⚠unverified',
    52: 'Privacy legacy 28% ⚠unverified',
    51: 'Privacy legacy 28% ⚠unverified',
    40: 'Privacy legacy 28% ⚠unverified',
    39: 'Privacy legacy 28% ⚠unverified',
    28: 'legacy 28% ⚠unverified',
    27: 'legacy 28% ⚠unverified',
    18: '⚠ legacy 28%',
    12: '⚠ legacy 28%',
    10: '⚠ legacy',
    6: '',
    4: '',
    1: '',
}


@pytest.mark.parametrize("width,golden", sorted(HUD_LADDER.items()))
def test_hud_line_ladder_is_byte_identical(width, golden):
    assert legacy_line(28, width) == golden


@pytest.mark.parametrize("width,golden", sorted(HUD_ROWS.items()))
def test_hud_line_prevented_rows_are_byte_identical(width, golden):
    assert legacy_line(63, width, 17) == golden


@pytest.mark.parametrize("width,golden", sorted(HUD_UNVERIFIED.items()))
def test_hud_line_unverified_ladder_is_byte_identical(width, golden):
    assert legacy_line(28, width, unverified=True) == golden


# --------------------------------------------------------------------- #
# The MCP / JSON contract -- the `privacy.*` tools are public.
# --------------------------------------------------------------------- #

#: A recorded session's summary is the legacy variant (#54 phase 1): the
#: stored numbers under legacy names, with the label and note that travel
#: with them. The old four keys are gone rather than aliased.
JSON_SUMMARY = {
    "accounting_version": 1, "legacy_score": 6.6, "legacy_cap": 120.0,
    "legacy_percent": 6, "legacy_permitted_crossing_rows": 2,
    "legacy_boundary_kinds": 2, "legacy_prevented_rows": 1,
    "score_label": "legacy permitted-crossing score",
    "accounting_note": ("Historical accounting includes permitted crossings "
                        "and may collapse different outcomes. It does not "
                        "establish confirmed disclosure."),
}

#: `/api/summary` = the summary PLUS the coverage reading, appended after it.
#:
#: This golden MOVED, on purpose, and the reason is the point of the change: the
#: four tiles alone serialize a session that was never observed and a genuinely
#: clean session to the same four numbers, so a JSON client had no way to tell
#: "nothing was disclosed" from "nothing was recorded". `coverage` is that
#: channel. `mcp_tools.get_session_summary`'s own payload is unchanged (see
#: `JSON_SUMMARY` above and its test) — the extra key lives at the HTTP boundary
#: only, because that is where the browser reads it.
#:
#: `verified` is True here because `_fill` opens both sessions through
#: `Ledger.start_session`, which records a `session_start` coverage row. That is
#: the ordinary path, and it is what keeps every other golden in this file where
#: it was.
#: `shallow_scans` joined this payload in #47 item 1/6: it counts scan gaps —
#: an applicable deep scan supplied no accepted result. Each observed scan
#: gap is recorded per observation and counted per session, including
#: observations with no event row. It is the fourth
#: thing that can make `verified` false. Additive — a client that does not
#: know the key still reads `verified` and `reason`, which is why it was safe
#: to change this golden rather than version the endpoint.
JSON_UI_SUMMARY = dict(JSON_SUMMARY, coverage={
    "verified": True, "reason": "", "recorded": True, "observers": 1,
    "attached": False, "unobserved_hooks": False, "shallow_scans": 0,
})

JSON_ROWS = [
    {"accounting_version": 1, "id": 1, "turn_id": "t1", "ts": TS, "kind": "exposed",
     "data_type": "email", "source": "support/logs/production/app.log",
     "source_kind": None,
     "destination": "model_context", "boundary": "B1", "count": 1,
     "masked_example": "jo•••@acme.com", "budget_delta": 6.0,
     "protection": None, "tool_name": "Read"},
    {"accounting_version": 1, "id": 2, "turn_id": "t2", "ts": TS + 60, "kind": "exposed",
     "data_type": "path", "source": "terminal output",
     "source_kind": None,
     "destination": "subagent", "boundary": "B2", "count": 1,
     "masked_example": "/Users/•••/app.log", "budget_delta": 0.6,
     "protection": "masked", "tool_name": "Task"},
    {"accounting_version": 1, "id": 3, "turn_id": "t3", "ts": TS + 120, "kind": "prevented",
     "data_type": "credential", "source": ".env",
     "source_kind": "path",
     "destination": "external_net", "boundary": "B4", "count": 1,
     "masked_example": None, "budget_delta": 0.0,
     "protection": "blocked", "tool_name": "Bash"},
    {"accounting_version": 1, "id": 4, "turn_id": "t4", "ts": TS + 180, "kind": "local_access",
     "data_type": "hostname", "source": "shell",
     "source_kind": None, "destination": "local",
     "boundary": "B0", "count": 1, "masked_example": "db•••.internal",
     "budget_delta": 0.0, "protection": None, "tool_name": "Read"},
]

JSON_DETAIL = dict(JSON_ROWS[0], first_seen=TS, budget_cap=120.0)


def test_get_session_summary_json_is_byte_identical(led):
    assert _json(mcp_tools.get_session_summary(led, SESSION)) == JSON_SUMMARY


@pytest.mark.parametrize("tab,expected", [
    ("Exposed", [0, 1]),
    ("Prevented", [2]),
    ("All events", [0, 1, 2, 3]),
])
def test_list_exposures_json_is_byte_identical(led, tab, expected):
    assert _json(mcp_tools.list_exposures(led, SESSION, tab)) == \
        [JSON_ROWS[i] for i in expected]


def test_list_exposures_json_key_order_is_stable(led):
    """Key ORDER, not just key set: `ui/app.js` and any MCP client reading a
    serialized payload see this ordering, and a silent reshuffle is exactly
    the kind of drift a dict-only contract cannot catch."""
    for row in _json(mcp_tools.list_exposures(led, SESSION, "All events")):
        assert list(row) == list(JSON_ROWS[0])


def test_get_exposure_detail_json_is_byte_identical(led):
    assert _json(mcp_tools.get_exposure_detail(led, SESSION, 1)) == JSON_DETAIL


def test_get_exposure_detail_needs_a_session_row(led, tmp_path):
    """Historical orphaned evidence must not produce session event detail."""
    assert not led.conn.in_transaction
    assert led.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    # Deliberately construct historical corruption on a fixture-only
    # connection. Production ledger connections keep FK enforcement.
    raw = sqlite3.connect(tmp_path / "l.db", isolation_level=None)
    try:
        raw.execute("PRAGMA foreign_keys=OFF")
        assert raw.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        raw.execute("DELETE FROM sessions WHERE session_id=?", (SESSION,))
    finally:
        raw.close()

    assert led.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert led.conn.execute(
        "SELECT 1 FROM events WHERE session_id=? AND id=1",
        (SESSION,)).fetchone() is not None
    with pytest.raises(LookupError):
        mcp_tools.get_exposure_detail(led, SESSION, 1)


def test_every_mcp_payload_survives_a_real_json_dumps(led):
    """The whole point of the serialization step: what these functions hand a
    JSON consumer must actually be encodable, with no bytes and no raw value."""
    blob = json.dumps([
        _json(mcp_tools.get_session_summary(led, SESSION)),
        _json(mcp_tools.list_exposures(led, SESSION, "All events")),
        _json(mcp_tools.get_exposure_detail(led, SESSION, 1)),
    ])
    assert "value_hash" not in blob
    assert "session_id" not in blob


# --------------------------------------------------------------------- #
# The local UI's HTTP endpoints -- the browser's contract.
# --------------------------------------------------------------------- #

@pytest.fixture
def ui(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    ledger = writer_ledger(Path(tmp_path) / "ledger.db", M)
    _fill(ledger)
    ledger.conn.close()

    server = local_ui_server.serve(SESSION, print_url=False)
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def test_ui_offers_no_clean_session_endpoint(ui, tmp_path):
    """#23: the endpoint minted a session id Codex never sends, so the audit
    it switched to stayed at 0% while disclosures kept landing on the real id.
    A clean context is a new Codex conversation, which nothing here can start;
    the endpoint must not come back."""
    def sessions() -> int:
        conn = sqlite3.connect(Path(tmp_path) / "ledger.db")
        try:
            return conn.execute("SELECT count(*) FROM sessions").fetchone()[0]
        finally:
            conn.close()

    before = sessions()
    req = urllib.request.Request(
        ui + "/api/clean_session", method="POST",
        data=json.dumps({"session_id": SESSION}).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(req, timeout=10)
    assert err.value.code == 404
    assert sessions() == before


def test_ui_summary_endpoint_json_is_byte_identical(ui):
    payload = _get(ui, f"/api/summary?session_id={SESSION}")
    assert payload == JSON_UI_SUMMARY
    # Key ORDER: the summary variant's keys first, with `coverage` appended.
    assert list(payload) == list(JSON_SUMMARY) + ["coverage"]


def test_ui_exposures_endpoint_json_is_byte_identical(ui):
    payload = _get(ui, f"/api/exposures?session_id={SESSION}&tab=All%20events")
    assert list(payload) == ["rows", "text", "empty_message", "coverage_banner"]
    assert payload["rows"] == JSON_ROWS
    # The browser's ASCII view names the session it was asked about (#49
    # item 1b); everything below the subtitle is the shared golden.
    assert payload["text"] == AUDIT_ALL.replace(
        "Session ID unknown\n", f"Session {SESSION}\n", 1)
    # Two fields the browser needs and the ASCII block cannot give it: that
    # block is rendered into a region `ui/index.html` hides by default, so a
    # caveat delivered only inside `text` reaches the terminal and not the
    # page. Spelled out as a literal, not recomputed from `render` — a golden
    # that calls the code it is pinning pins nothing. `SESSION` was watched
    # from the start, so it is verified: no banner, and the empty line says
    # what a verified record does and does not amount to.
    assert payload["empty_message"] == (
        "No privacy events recorded for this session. Coverage found no gaps "
        "in this session's record, which is not proof that every event was "
        "seen."
    )
    assert payload["coverage_banner"] is None


def test_ui_detail_endpoint_json_is_byte_identical(ui):
    payload = _get(ui, f"/api/detail?session_id={SESSION}&id=1")
    assert list(payload) == ["row", "text"]
    assert payload["row"] == JSON_DETAIL
    assert payload["text"] == DETAIL_EMAIL.format(t=_hhmmss(TS))


def test_ui_copy_endpoint_carries_no_empty_messages(ui):
    """`empty_messages` was here, and its removal is the fix, not a loss.

    This endpoint is session-independent and fetched once per page load, so a
    browser indexing it by tab could only ever pick a line for a session whose
    coverage it had not consulted — which is exactly what happened: the
    reassuring line was shown on sessions the ledger knew it could not vouch
    for. The line is now chosen per session by `render.empty_message` and
    delivered by `/api/exposures`, and there is deliberately no second source
    left for a client to fall back to."""
    from privacy_hud.render import accounting_copy
    copy = _get(ui, "/api/copy")
    # #54 Phase 4 adds the static version-2 catalog, which carries no
    # empty-state line either: those stay per session.
    assert copy == {
        "acronyms": {"ssn": "SSN", "ip": "IP", "url": "URL"},
        "accounting": accounting_copy(),
    }
    assert not any(key.startswith("empty_") and key != "empty_unresolved"
                   for key in copy["accounting"])


# --------------------------------------------------------------------- #
# dispatch._handle_session_end -- summary + rows -> receipt, over the wire.
# --------------------------------------------------------------------- #

DISPATCH_RECEIPT = RECEIPT.replace("· 41 min", "· 0 min")


def test_session_end_hook_output_receipt_is_byte_identical(tmp_path):
    state = writer_state_with_detectors(tmp_path, detectors=[])
    # A legacy-accounted session, as 0.8.x recorded one: this pins the
    # legacy receipt. A genuine SessionStart is version-2 accounted since
    # #54 Phase 4, and its receipt is pinned in test_accounting_surfaces.
    state.ledger.start_session(SESSION, cwd="/repo", model="gpt-5")
    state.started_at[SESSION] = time.time()
    table = state.ledger._legacy_events_table()
    for i, spec in enumerate(_ROWS):
        state.ledger.record(SESSION, **spec)
        state.ledger.conn.execute(
            f"UPDATE {table} SET ts=? WHERE session_id=? AND turn_id=?",
            (TS + i * 60, SESSION, spec["turn_id"]))

    out = dispatch(state, {"hook_event_name": "SessionEnd",
                           "session_id": SESSION, "reason": "exit"})
    assert list(out) == ["systemMessage"]
    assert out["systemMessage"] == DISPATCH_RECEIPT
