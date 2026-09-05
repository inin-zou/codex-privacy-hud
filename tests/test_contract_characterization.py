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
  or on a byte-exact JSON payload (the six `privacy.*` MCP tools and the local
  UI's endpoints are a public contract).

`_json()` below is the one concession to the refactor: it is the explicit
serialization step at the JSON boundary, and it is a no-op passthrough for a
plain dict. Nothing else in this file knows or cares what type the chain
passes around internally.

If a test in this file has to be edited to make a refactor pass, the refactor
changed behaviour. That is a bug, not a rebaseline.
"""
from __future__ import annotations

import json
import urllib.request
from datetime import datetime
from pathlib import Path

import pytest

from privacy_hud import local_ui_server, mcp_tools, render
from privacy_hud.dispatch import dispatch, new_state
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix

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
         source=".env", destination="external_net",
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
    ledger = Ledger(tmp_path / "l.db", M)
    _fill(ledger)
    return ledger


def _audit(ledger, session_id, tab):
    return render.audit(mcp_tools.get_session_summary(ledger, session_id),
                        mcp_tools.list_exposures(ledger, session_id, tab),
                        tab)


# --------------------------------------------------------------------- #
# render.audit -- the L2 session audit (design.md §5)
# --------------------------------------------------------------------- #

AUDIT_EXPOSED = (
    "Privacy Audit\n"
    "Current session\n"
    "\n"
    "┌────────────┐ ┌───────────────┐ ┌──────────────┐ ┌───────────┐\n"
    "│     6%     │ │       2       │ │      2       │ │     1     │\n"
    "│ disclosure │ │ exposed items │ │ destinations │ │ prevented │\n"
    "└────────────┘ └───────────────┘ └──────────────┘ └───────────┘\n"
    "\n"
    " Exposed 2      Prevented 1      All events 3\n"
    " ─────────                                   \n"
    "\n"
    "SENSITIVE DATA  SOURCE                    DESTINATION    STATUS   \n"
    "Email ×1        support/log...on/app.log  model_context  [EXPOSED]\n"
    "Path ×1         terminal output           subagent       [MASKED] "
)

AUDIT_PREVENTED = (
    "Privacy Audit\n"
    "Current session\n"
    "\n"
    "┌────────────┐ ┌───────────────┐ ┌──────────────┐ ┌───────────┐\n"
    "│     6%     │ │       2       │ │      2       │ │     1     │\n"
    "│ disclosure │ │ exposed items │ │ destinations │ │ prevented │\n"
    "└────────────┘ └───────────────┘ └──────────────┘ └───────────┘\n"
    "\n"
    " Exposed 2      Prevented 1      All events 3\n"
    "                ───────────                  \n"
    "\n"
    "SENSITIVE DATA  SOURCE  DESTINATION   STATUS     \n"
    "Credential ×1   .env    external_net  [PREVENTED]"
)

AUDIT_ALL = (
    "Privacy Audit\n"
    "Current session\n"
    "\n"
    "┌────────────┐ ┌───────────────┐ ┌──────────────┐ ┌───────────┐\n"
    "│     6%     │ │       2       │ │      2       │ │     1     │\n"
    "│ disclosure │ │ exposed items │ │ destinations │ │ prevented │\n"
    "└────────────┘ └───────────────┘ └──────────────┘ └───────────┘\n"
    "\n"
    " Exposed 2      Prevented 1      All events 4\n"
    "                                 ────────────\n"
    "\n"
    "SENSITIVE DATA  SOURCE                    DESTINATION    STATUS     \n"
    "Email ×1        support/log...on/app.log  model_context  [EXPOSED]  \n"
    "Path ×1         terminal output           subagent       [MASKED]   \n"
    "Credential ×1   .env                      external_net   [PREVENTED]\n"
    "Hostname ×1     shell                     local          [LOCAL]    "
)

_EMPTY_TILES = (
    "Privacy Audit\n"
    "Current session\n"
    "\n"
    "┌────────────┐ ┌───────────────┐ ┌──────────────┐ ┌───────────┐\n"
    "│     0%     │ │       0       │ │      0       │ │     0     │\n"
    "│ disclosure │ │ exposed items │ │ destinations │ │ prevented │\n"
    "└────────────┘ └───────────────┘ └──────────────┘ └───────────┘\n"
    "\n"
    " Exposed 0      Prevented 0      All events 0\n"
)

AUDIT_EMPTY = {
    "Exposed": _EMPTY_TILES + " ─────────                                   \n"
               "\nNo sensitive data has crossed a trust boundary this session.",
    "Prevented": _EMPTY_TILES + "                ───────────                  \n"
                 "\nNothing has been blocked or minimized yet.",
    "All events": _EMPTY_TILES + "                                 ────────────\n"
                  "\nNo privacy events recorded. The engine is running.",
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


# --------------------------------------------------------------------- #
# render.detail -- the L3 exposure detail (design.md §6)
# --------------------------------------------------------------------- #

DETAIL_EMAIL = (
    "Email ×1\n"
    "support/logs/production/app.log → model_context\n"
    "\n"
    "First seen   {t}\n"
    "Protection   none\n"
    "Example      jo•••@acme.com\n"
    "Budget       +6 pts of 120\n"
    "\n"
    "[ Protect future occurrences ]\n"
    "[ Block this source ]\n"
    "\n"
    "Already disclosed data cannot be recalled from this session."
)

DETAIL_MASKED_PATH = (
    "Path ×1\n"
    "terminal output → subagent\n"
    "\n"
    "First seen   {t}\n"
    "Protection   masked\n"
    "Example      /Users/•••/app.log\n"
    "Budget       +0.6 pts of 120\n"
    "\n"
    "[ Protect future occurrences ]\n"
    "[ Block this source ]\n"
    "\n"
    "Already disclosed data cannot be recalled from this session."
)

#: A credential carries no exemplar at all, so the Example line is absent --
#: the view must never print "Example None". This is the golden that pins it.
DETAIL_CREDENTIAL = (
    "Credential ×1\n"
    ".env → external_net\n"
    "\n"
    "First seen   {t}\n"
    "Protection   blocked\n"
    "Budget       +0 pts of 120\n"
    "\n"
    "[ Protect future occurrences ]\n"
    "[ Block this source ]\n"
    "\n"
    "Already disclosed data cannot be recalled from this session."
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
    "PRIVACY RECEIPT · sess-golden · 41 min\n"
    "\n"
    "Disclosure       6% of budget\n"
    "Exposed          2 flows across 2 destinations\n"
    "Prevented        1 events\n"
    "Retained         session transcript, persisted by Codex outside this ledger.\n"
    "\n"
    "  Email ×1              support/l.../app.log→ model_context\n"
    "  Path ×1               terminal output   → subagent  (masked)\n"
    "\n"
    "No file contents, prompts, or raw values were stored."
)

RECEIPT_EMPTY = (
    "PRIVACY RECEIPT · sess-empty · 0 min\n"
    "\n"
    "Disclosure       0% of budget\n"
    "Exposed          0 flows across 0 destinations\n"
    "Prevented        0 events\n"
    "Retained         session transcript, persisted by Codex outside this ledger.\n"
    "\n"
    "\n"
    "No file contents, prompts, or raw values were stored."
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
# --------------------------------------------------------------------- #

HUD_LADDER = {
    80: "PRIVACY  Disclosure ███░░░░░░░ 28%  ›",
    52: "PRIVACY  Disclosure ███░░░░░░░ 28%  ›",
    51: "PRIVACY ███░░░░░░░ 28% ›",
    40: "PRIVACY ███░░░░░░░ 28% ›",
    39: "PRIV ███░░ 28% ›",
    28: "PRIV ███░░ 28% ›",
    27: "⬤ 28%",
    12: "⬤ 28%",
    4: "⬤ 28",
    1: "⬤",
}

HUD_BLOCKED = {
    80: "PRIVACY  ⚠ 17 blocked · Disclosure ██████░░░░ 63%  ›",
    45: "PRIVACY ⚠ 17 blocked · ██████░░░░ 63% ›",
    30: "PRIV ⚠17 █████ 63% ›",
    15: "⬤ 63%",
}


@pytest.mark.parametrize("width,golden", sorted(HUD_LADDER.items()))
def test_hud_line_ladder_is_byte_identical(width, golden):
    assert render.hud_line(28, width) == golden


@pytest.mark.parametrize("width,golden", sorted(HUD_BLOCKED.items()))
def test_hud_line_blocked_prefix_is_byte_identical(width, golden):
    assert render.hud_line(63, width, blocked=17) == golden


# --------------------------------------------------------------------- #
# The MCP / JSON contract -- the six `privacy.*` tools are public.
# --------------------------------------------------------------------- #

JSON_SUMMARY = {"percent": 6, "exposed_items": 2, "destinations": 2,
                "prevented": 1}

JSON_ROWS = [
    {"id": 1, "turn_id": "t1", "ts": TS, "kind": "exposed",
     "data_type": "email", "source": "support/logs/production/app.log",
     "destination": "model_context", "boundary": "B1", "count": 1,
     "masked_example": "jo•••@acme.com", "budget_delta": 6.0,
     "protection": None, "tool_name": "Read"},
    {"id": 2, "turn_id": "t2", "ts": TS + 60, "kind": "exposed",
     "data_type": "path", "source": "terminal output",
     "destination": "subagent", "boundary": "B2", "count": 1,
     "masked_example": "/Users/•••/app.log", "budget_delta": 0.6,
     "protection": "masked", "tool_name": "Task"},
    {"id": 3, "turn_id": "t3", "ts": TS + 120, "kind": "prevented",
     "data_type": "credential", "source": ".env",
     "destination": "external_net", "boundary": "B4", "count": 1,
     "masked_example": None, "budget_delta": 0.0,
     "protection": "blocked", "tool_name": "Bash"},
    {"id": 4, "turn_id": "t4", "ts": TS + 180, "kind": "local_access",
     "data_type": "hostname", "source": "shell", "destination": "local",
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


def test_get_exposure_detail_omits_budget_cap_with_no_session_row(led):
    """`budget_cap` is *absent*, not None, when the session row is missing --
    `render.detail()` keys the optional "of {cap}" tail off exactly that."""
    led.conn.execute("DELETE FROM sessions WHERE session_id=?", (SESSION,))
    payload = _json(mcp_tools.get_exposure_detail(led, SESSION, 1))
    assert "budget_cap" not in payload
    assert payload == dict(JSON_ROWS[0], first_seen=TS)


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
    ledger = Ledger(Path(tmp_path) / "ledger.db", M)
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


def test_ui_summary_endpoint_json_is_byte_identical(ui):
    assert _get(ui, f"/api/summary?session_id={SESSION}") == JSON_SUMMARY


def test_ui_exposures_endpoint_json_is_byte_identical(ui):
    payload = _get(ui, f"/api/exposures?session_id={SESSION}&tab=All%20events")
    assert list(payload) == ["rows", "text"]
    assert payload["rows"] == JSON_ROWS
    assert payload["text"] == AUDIT_ALL


def test_ui_detail_endpoint_json_is_byte_identical(ui):
    payload = _get(ui, f"/api/detail?session_id={SESSION}&id=1")
    assert list(payload) == ["row", "text"]
    assert payload["row"] == JSON_DETAIL
    assert payload["text"] == DETAIL_EMAIL.format(t=_hhmmss(TS))


def test_ui_copy_endpoint_json_is_byte_identical(ui):
    assert _get(ui, "/api/copy") == {
        "empty_messages": {
            "Exposed": "No sensitive data has crossed a trust boundary this session.",
            "Prevented": "Nothing has been blocked or minimized yet.",
            "All events": "No privacy events recorded. The engine is running.",
        },
        "acronyms": {"ssn": "SSN", "ip": "IP", "url": "URL"},
    }


# --------------------------------------------------------------------- #
# dispatch._handle_session_end -- summary + rows -> receipt, over the wire.
# --------------------------------------------------------------------- #

DISPATCH_RECEIPT = RECEIPT.replace("· 41 min", "· 0 min")


def test_session_end_hook_output_receipt_is_byte_identical(tmp_path):
    state = new_state(tmp_path)
    dispatch(state, {"hook_event_name": "SessionStart", "session_id": SESSION,
                     "cwd": "/repo", "model": "gpt-5"})
    for i, spec in enumerate(_ROWS):
        state.ledger.record(SESSION, **spec)
        state.ledger.conn.execute(
            "UPDATE events SET ts=? WHERE session_id=? AND turn_id=?",
            (TS + i * 60, SESSION, spec["turn_id"]))

    out = dispatch(state, {"hook_event_name": "SessionEnd",
                           "session_id": SESSION, "reason": "exit"})
    assert list(out) == ["systemMessage"]
    assert out["systemMessage"] == DISPATCH_RECEIPT
