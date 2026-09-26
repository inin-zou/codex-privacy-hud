"""#54 phase 1: typed legacy readers and the unrecorded state.

Every session recorded so far is accounted by the legacy writer. Its
number is a "legacy permitted-crossing score", not a confirmed-disclosure
percentage, and every reader has to say so. A session the ledger has no
row for is not a clean session: it has no percentage and no counts, and
no reader may turn that into zero.

These tests stay on synthetic ledgers. The rebuilt-schema cases create
`events_legacy_v1` by hand, the way phase 2's migration will, so the
readers are known to follow the rename before the migration exists.
"""
from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request

import pytest

from privacy_hud import local_ui_server, mcp_tools
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from runtime_helpers import writer_ledger

M = load_matrix()

LEGACY_NOTE = ("Historical accounting includes permitted crossings and may "
               "collapse different outcomes. It does not establish confirmed "
               "disclosure.")
UNRECORDED_NOTE = ("No session record is available in this ledger. The "
                   "percentage and counts are unavailable.")

LEGACY_KEYS = [
    "accounting_version", "legacy_score", "legacy_cap", "legacy_percent",
    "legacy_permitted_crossing_rows", "legacy_boundary_kinds",
    "legacy_prevented_rows", "score_label", "accounting_note",
]
UNRECORDED_KEYS = ["accounting_version", "percent", "score_label",
                   "accounting_note"]
EXPOSURE_KEYS = [
    "accounting_version", "id", "turn_id", "ts", "kind", "data_type",
    "source", "source_kind", "destination", "boundary", "count",
    "masked_example", "budget_delta", "protection", "tool_name",
]


@pytest.fixture
def state(deterministic_state):
    """These contracts exercise dispatch and projections, not model inference."""
    return deterministic_state


@pytest.fixture
def led(tmp_path):
    ledger = writer_ledger(tmp_path / "ledger.db", M)
    ledger.start_session("s1", cwd="/repo", model="gpt-5")
    yield ledger
    ledger.conn.close()


def _rec(led, session="s1", **kw):
    base = dict(turn_id="t1", kind="exposed", data_type="email",
                source="support.log", destination="model_context",
                value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
                tool_name="Read", protection=None)
    base.update(kw)
    return led.record(session, **base)


def _rename_to_legacy(path) -> None:
    """What phase 2's rebuild does to the legacy table, and no more."""
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("ALTER TABLE events RENAME TO events_legacy_v1")
    conn.close()


# -- summary variants -------------------------------------------------------

def test_legacy_summary_is_separately_typed_and_labelled(led):
    _rec(led)
    _rec(led, value_hash=b"\x02" * 16, destination="mcp_tool")
    _rec(led, value_hash=b"\x03" * 16, kind="prevented",
         data_type="credential", destination="external_net",
         protection="blocked")
    summary = led.summary("s1")
    assert type(summary).__name__ == "LegacySessionSummary"
    payload = summary.as_dict()
    assert list(payload) == LEGACY_KEYS
    stored = led.conn.execute(
        "SELECT budget_score, budget_cap FROM sessions WHERE session_id='s1'"
    ).fetchone()
    assert payload["accounting_version"] == 1
    assert payload["legacy_score"] == stored["budget_score"]
    assert payload["legacy_cap"] == stored["budget_cap"]
    assert payload["legacy_permitted_crossing_rows"] == 2
    assert payload["legacy_boundary_kinds"] == 2
    assert payload["legacy_prevented_rows"] == 1
    assert payload["score_label"] == "legacy permitted-crossing score"
    assert payload["accounting_note"] == LEGACY_NOTE
    for old in ("percent", "exposed_items", "destinations", "prevented"):
        assert old not in payload


def test_legacy_percent_keeps_the_existing_arithmetic(led):
    from privacy_hud.budget import percent
    _rec(led)
    summary = led.summary("s1")
    assert summary.legacy_percent == percent(summary.legacy_score,
                                             summary.legacy_cap)


def test_a_recorded_empty_session_is_a_legacy_zero(led):
    payload = led.summary("s1").as_dict()
    assert payload["accounting_version"] == 1
    assert payload["legacy_percent"] == 0
    assert payload["legacy_prevented_rows"] == 0


def test_unknown_session_has_no_percentage(led):
    summary = led.summary("missing")
    assert type(summary).__name__ == "UnrecordedSessionSummary"
    payload = summary.as_dict()
    assert payload == {"accounting_version": 0, "percent": None,
                       "score_label": "No session on record",
                       "accounting_note": UNRECORDED_NOTE}
    assert list(payload) == UNRECORDED_KEYS
    for name in ("legacy_score", "legacy_cap", "legacy_percent",
                 "legacy_prevented_rows"):
        assert not hasattr(summary, name)


# -- rows -------------------------------------------------------------------

def test_public_legacy_rows_carry_the_accounting_version_and_no_hash(led):
    _rec(led)
    [row] = mcp_tools.list_exposures(led, "s1", "Exposed")
    assert type(row).__name__ == "LegacyExposureRow"
    payload = row.as_dict()
    assert list(payload) == EXPOSURE_KEYS
    assert payload["accounting_version"] == 1
    for hidden in ("session_id", "value_hash", "degraded"):
        assert hidden not in payload


def test_unknown_session_lists_nothing_and_has_no_detail(led):
    assert mcp_tools.list_exposures(led, "missing", "All events") == []
    with pytest.raises(LookupError):
        mcp_tools.get_exposure_detail(led, "missing", 1)


def test_legacy_detail_is_scoped_to_its_session(led):
    led.start_session("s2", cwd="/repo", model="gpt-5")
    _rec(led)
    _rec(led, session="s2", value_hash=b"\x09" * 16)
    [mine] = led.list_events("s1", "exposed")
    [theirs] = led.list_events("s2", "exposed")
    detail = led.get_event("s1", mine.id)
    assert type(detail).__name__ == "LegacyExposureRow"
    assert detail.first_seen == mine.ts
    assert detail.budget_cap == led.summary("s1").legacy_cap
    with pytest.raises(LookupError):
        led.get_event("s1", theirs.id)


def test_detail_no_longer_queries_the_events_table_directly():
    import inspect
    source = inspect.getsource(mcp_tools.get_exposure_detail)
    assert "FROM events" not in source


# -- schema routing ---------------------------------------------------------

def test_legacy_detail_routes_by_session_and_schema(tmp_path):
    path = tmp_path / "ledger.db"
    led = writer_ledger(path, M)
    led.start_session("s1", cwd="/repo", model="gpt-5")
    _rec(led)
    [row] = led.list_events("s1", "exposed")
    before = led.summary("s1").as_dict()
    led.conn.close()

    _rename_to_legacy(path)

    reader = Ledger(path, M, initialize=False)
    try:
        assert reader.summary("s1").as_dict() == before
        [again] = reader.list_events("s1", "exposed")
        assert again.id == row.id and again.budget_delta == row.budget_delta
        assert reader.get_event("s1", row.id).id == row.id
        with pytest.raises(LookupError):
            reader.get_event("other", row.id)
    finally:
        reader.conn.close()


def test_schema_choice_is_read_per_transaction(tmp_path):
    """A long-lived reader spans the rebuild: the table it reads from is
    decided inside each read, never cached."""
    path = tmp_path / "ledger.db"
    writer = writer_ledger(path, M)
    writer.start_session("s1", cwd="/repo", model="gpt-5")
    _rec(writer)
    writer.conn.close()

    reader = Ledger(path, M, initialize=False)
    try:
        assert reader._legacy_events_table() == "events"
        _rename_to_legacy(path)
        assert reader._legacy_events_table() == "events_legacy_v1"
        assert reader.summary("s1").legacy_permitted_crossing_rows == 1
    finally:
        reader.conn.close()


def test_a_read_transaction_is_stable_across_a_concurrent_rename(tmp_path):
    path = tmp_path / "ledger.db"
    writer = writer_ledger(path, M)
    writer.start_session("s1", cwd="/repo", model="gpt-5")
    _rec(writer)
    writer.conn.close()

    reader = Ledger(path, M, initialize=False)
    try:
        with reader._read_transaction():
            assert reader._legacy_events_table() == "events"
            other = sqlite3.connect(path, isolation_level=None, timeout=0.1)
            # WAL lets the rename commit while the reader holds its
            # snapshot; the reader keeps seeing the schema it started with.
            try:
                other.execute("ALTER TABLE events RENAME TO events_legacy_v1")
            finally:
                other.close()
            assert reader._legacy_events_table() == "events"
        assert reader._legacy_events_table() == "events_legacy_v1"
    finally:
        reader.conn.close()


def test_a_historical_table_without_source_kind_reads_as_null(tmp_path):
    path = tmp_path / "ledger.db"
    conn = sqlite3.connect(path, isolation_level=None)
    conn.executescript("""
        CREATE TABLE sessions (session_id TEXT PRIMARY KEY,
          started_at INTEGER NOT NULL, ended_at INTEGER, cwd TEXT,
          model TEXT, budget_score REAL NOT NULL DEFAULT 0,
          budget_cap REAL NOT NULL DEFAULT 120);
        CREATE TABLE events (id INTEGER PRIMARY KEY,
          session_id TEXT NOT NULL, turn_id TEXT, ts INTEGER NOT NULL,
          kind TEXT NOT NULL, data_type TEXT NOT NULL, source TEXT NOT NULL,
          destination TEXT NOT NULL, boundary TEXT NOT NULL,
          count INTEGER NOT NULL DEFAULT 1, value_hash BLOB,
          masked_example TEXT, budget_delta REAL NOT NULL DEFAULT 0,
          protection TEXT, tool_name TEXT);
        INSERT INTO sessions VALUES ('s1', 1000, NULL, '/r', 'm', 6.0, 120);
        INSERT INTO events VALUES (1, 's1', 't', 1001, 'exposed', 'email',
          'a.log', 'model_context', 'B1', 1, NULL, NULL, 6.0, NULL, 'Read');
    """)
    conn.close()
    reader = Ledger(path, M, initialize=False)
    try:
        [row] = reader.list_events("s1", "exposed")
        assert row.source_kind is None
        cols = {r[1] for r in reader.conn.execute("PRAGMA table_info(events)")}
        assert "source_kind" not in cols, "a reader must not migrate"
    finally:
        reader.conn.close()


def test_a_noninitializing_open_does_not_create_a_database(tmp_path):
    missing = tmp_path / "absent.db"
    with pytest.raises(sqlite3.OperationalError):
        Ledger(missing, M, initialize=False)
    assert not missing.exists()


def test_initializing_open_refuses_a_partial_rebuild(tmp_path):
    """A renamed legacy table with no schema marker is an incomplete rebuild
    (#54 Phase 2): the daemon refuses it rather than recreating `events`."""
    path = tmp_path / "ledger.db"
    led = writer_ledger(path, M)
    led.start_session("s1", cwd="/repo", model="gpt-5")
    led.conn.close()
    _rename_to_legacy(path)
    with pytest.raises(Exception) as caught:
        writer_ledger(path, M)
    assert type(caught.value).__name__ == "UnsupportedAccounting"
    raw = sqlite3.connect(path)
    try:
        tables = {r[0] for r in raw.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "events" not in tables
    finally:
        raw.close()


def test_a_version_two_session_is_not_read_as_legacy(tmp_path):
    path = tmp_path / "ledger.db"
    led = writer_ledger(path, M)
    led.start_session("s2", cwd="/repo", model="gpt-5")
    led.conn.close()
    _rename_to_legacy(path)
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("ALTER TABLE sessions ADD COLUMN accounting_version "
                 "INTEGER NOT NULL DEFAULT 1")
    conn.execute("UPDATE sessions SET accounting_version=2")
    conn.close()
    reader = Ledger(path, M, initialize=False)
    try:
        with pytest.raises(Exception) as caught:
            reader.summary("s2")
        assert type(caught.value).__name__ == "UnsupportedAccounting"
    finally:
        reader.conn.close()


# -- the browser endpoints --------------------------------------------------

@pytest.fixture
def ui(state):
    # A legacy-accounted session, as 0.8.x recorded one. A genuine
    # SessionStart is version-2 accounted since #54 Phase 4.
    state.ledger.start_session("s1", cwd="/w", model="gpt-5")
    server = local_ui_server.serve("s1", print_url=False)
    host, port = server.socket.getsockname()[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _get(base, path, **query):
    url = f"{base}{path}?{urllib.parse.urlencode(query)}"
    try:
        with urllib.request.urlopen(url) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as err:
        return err.code, json.load(err)


def test_ui_summary_for_an_unknown_session_is_unrecorded(ui):
    status, payload = _get(ui, "/api/summary", session_id="missing")
    assert status == 200
    assert payload["accounting_version"] == 0
    assert payload["percent"] is None
    assert "coverage" in payload


def test_ui_lists_nothing_for_an_unknown_session(ui):
    status, payload = _get(ui, "/api/exposures", session_id="missing",
                           tab="Exposed")
    assert status == 200
    assert payload["rows"] == []
    assert payload["empty_message"] == (
        "No events can be shown for an unrecorded session. This is not "
        "evidence that none occurred.")
    status, _ = _get(ui, "/api/detail", session_id="missing", id=1)
    assert status == 404


def test_ui_summary_for_a_recorded_session_is_legacy(ui):
    status, payload = _get(ui, "/api/summary", session_id="s1")
    assert status == 200
    assert payload["accounting_version"] == 1
    assert payload["score_label"] == "legacy permitted-crossing score"
    assert "percent" not in payload
