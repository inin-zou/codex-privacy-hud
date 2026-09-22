"""#54 Phase 2: the one permitted rebuild, at a new-session boundary.

`events` becomes `events_legacy_v1`, byte-exact, and the new accounting
tables are created, in the same transaction that creates the session whose
genuine `SessionStart` triggered it. Every session stays on legacy
accounting. A crash at any point leaves the complete old schema or the
complete new one. Readers never migrate.

All ledgers here are synthetic.
"""
from __future__ import annotations

import os
import sqlite3
import struct
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from privacy_hud import dispatch as dispatch_mod
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from runtime_helpers import writer_ledger
from runtime_helpers import writer_state

M = load_matrix()
REPO = Path(__file__).resolve().parents[1]
NEW_TABLES = {"scoring_profiles", "observations", "subjects", "recipients",
              "events", "disclosures", "events_legacy_v1"}


# -- fixtures ---------------------------------------------------------------

def _legacy_ledger(path: Path) -> None:
    """A pre-#54 ledger with rows in every table, written the old way."""
    led = writer_ledger(path, M)
    led.start_session("old1", cwd="/r", model="m")
    led.start_session("old2", cwd="/r", model="m", observed_start=False)
    for i, (kind, dest, prot) in enumerate([
            ("exposed", "model_context", None),
            ("exposed", "mcp_tool", "masked"),
            ("prevented", "external_net", "blocked"),
            ("local_access", "local", None)]):
        led.record("old1", turn_id=f"t{i}", kind=kind, data_type="email",
                   source="a.log", destination=dest,
                   value_hash=bytes([i + 1]) * 16,
                   masked_example="jo•••@acme.com", tool_name="Read",
                   protection=prot, source_kind="path" if i else None)
    led.record("old1", turn_id="t9", kind="exposed", data_type="email",
               source="a.log", destination="model_context",
               value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
               tool_name="Read", protection=None)  # a count increment
    led.record_scan_gap("old1", boundary="B3", reason="timeout", ts=1000)
    led.note_unobserved_hooks(1001)
    led.add_policy("old1", rule_type="mask", selector="email")
    led.conn.execute(
        "INSERT INTO policy_tokens VALUES('tok','old1','Bash',x'00ff',"
        "'allow_once',9999999999)")
    led.conn.execute(
        "INSERT INTO flows(session_id,value_hash,hop_index,node)"
        " VALUES('old1',x'0101',0,'a')")
    led.end_session("old2")
    led.conn.close()


def _cells(conn: sqlite3.Connection, table: str) -> list[tuple]:
    """Every cell of `table` with its storage class; REAL as packed IEEE."""
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    out = []
    select = ", ".join(f"typeof({c}), {c}" for c in cols)
    for row in conn.execute(f"SELECT {select} FROM {table} ORDER BY rowid"):
        cells = []
        for i in range(0, len(row), 2):
            kind, value = row[i], row[i + 1]
            if kind == "real":
                value = struct.pack(">d", value)
            cells.append((kind, value))
        out.append(tuple(cells))
    return out


def _raw(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)
    return conn


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _version(conn) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def _boundary(path: Path, sid: str = "new1") -> None:
    """A genuine SessionStart for an absent session, through the daemon."""
    state = writer_state(path.parent)
    try:
        dispatch_mod.dispatch(state, {
            "hook_event_name": "SessionStart", "session_id": sid,
            "cwd": "/w", "model": "gpt-5", "turn_id": "t1"})
    finally:
        state.ledger.conn.close()


@pytest.fixture
def legacy(tmp_path) -> Path:
    path = tmp_path / "ledger.db"
    _legacy_ledger(path)
    return path


# -- preservation -----------------------------------------------------------

def test_migration_preserves_every_legacy_cell(legacy):
    raw = _raw(legacy)
    before_events = _cells(raw, "events")
    before_sessions = _cells(raw, "sessions")
    raw.close()

    _boundary(legacy)

    raw = _raw(legacy)
    try:
        assert _version(raw) == 5401
        assert NEW_TABLES <= _tables(raw)
        assert _cells(raw, "events_legacy_v1") == before_events
        sessions = _cells(raw, "sessions")
        width = len(before_sessions[0])
        assert [s[:width] for s in sessions[:len(before_sessions)]] == \
            before_sessions
        new = raw.execute(
            "SELECT accounting_version, accounting_status, profile_id"
            " FROM sessions WHERE session_id='new1'").fetchone()
        assert new == (1, "legacy", None)
    finally:
        raw.close()


def test_migration_preserves_auxiliary_tables(legacy):
    raw = _raw(legacy)
    before = {t: _cells(raw, t) for t in
              ("coverage", "scan_gaps", "policy", "policy_tokens", "flows")}
    indexes = sorted(raw.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='index'"
        " AND sql IS NOT NULL").fetchall())
    raw.close()

    _boundary(legacy)

    raw = _raw(legacy)
    try:
        for table, cells in before.items():
            after = _cells(raw, table)
            if table == "coverage":
                after = after[:len(cells)]  # the new session's own row follows
            assert after == cells, table
        after_indexes = dict(raw.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='index'"
            " AND sql IS NOT NULL").fetchall())
        for name, sql in indexes:
            assert after_indexes[name] == sql
    finally:
        raw.close()


def test_migration_preserves_missing_source_kind(tmp_path):
    path = tmp_path / "ledger.db"
    raw = _raw(path)
    raw.executescript("""
        CREATE TABLE sessions (session_id TEXT PRIMARY KEY,
          started_at INTEGER NOT NULL, ended_at INTEGER, cwd TEXT,
          model TEXT, budget_score REAL NOT NULL DEFAULT 0,
          budget_cap REAL NOT NULL DEFAULT 120);
        CREATE TABLE events (id INTEGER PRIMARY KEY,
          session_id TEXT NOT NULL REFERENCES sessions, turn_id TEXT,
          ts INTEGER NOT NULL, kind TEXT NOT NULL, data_type TEXT NOT NULL,
          source TEXT NOT NULL, destination TEXT NOT NULL,
          boundary TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 1,
          value_hash BLOB, masked_example TEXT,
          budget_delta REAL NOT NULL DEFAULT 0, protection TEXT,
          tool_name TEXT, UNIQUE(session_id, value_hash, destination));
        INSERT INTO sessions VALUES ('s1', 1000, NULL, '/r', 'm', 6.0, 120);
        INSERT INTO events VALUES (1, 's1', 't', 1001, 'exposed', 'email',
          'a.log', 'model_context', 'B1', 1, x'01', NULL, 6.0, NULL, 'Read');
    """)
    raw.close()

    led = writer_ledger(path, M)
    cols = {r[1] for r in led.conn.execute("PRAGMA table_info(events)")}
    assert "source_kind" not in cols, "initializing open must not migrate"
    with led._write_transaction():
        led.prepare_session_boundary("new1")
        led.start_session("new1", cwd="/w", model="m")
    cols = {r[1] for r in
            led.conn.execute("PRAGMA table_info(events_legacy_v1)")}
    assert "source_kind" not in cols
    [row] = led.list_events("s1", "exposed")
    assert row.source_kind is None
    led.record("s1", turn_id="t2", kind="exposed", data_type="email",
               source="b.log", destination="mcp_tool", value_hash=b"\x02",
               masked_example=None, tool_name="Read", protection=None,
               source_kind="path")
    assert len(led.list_events("s1", "exposed")) == 2
    led.conn.close()


# -- the boundary transaction -----------------------------------------------

def test_boundary_creation_and_rebuild_commit_together(legacy):
    led = writer_ledger(legacy, M)
    calls = []

    def failpoint(statement):
        calls.append(statement)
        if len(calls) == 5:
            raise RuntimeError("injected")

    led._migration_failpoint = failpoint
    with pytest.raises(RuntimeError):
        with led._write_transaction():
            led.prepare_session_boundary("new1")
            led.start_session("new1", cwd="/w", model="m")
    led.conn.close()
    raw = _raw(legacy)
    try:
        assert _version(raw) == 0
        assert "events_legacy_v1" not in _tables(raw)
        assert raw.execute("SELECT 1 FROM sessions WHERE session_id='new1'"
                           ).fetchone() is None
    finally:
        raw.close()


def test_lazy_attachment_never_migrates(legacy):
    state = writer_state(legacy.parent)
    try:
        dispatch_mod.dispatch(state, {
            "hook_event_name": "UserPromptSubmit", "session_id": "lazy",
            "prompt": "hello", "turn_id": "t1"})
    finally:
        state.ledger.conn.close()
    raw = _raw(legacy)
    try:
        assert _version(raw) == 0
        assert "events_legacy_v1" not in _tables(raw)
    finally:
        raw.close()


def test_a_replayed_start_does_not_migrate(legacy):
    _boundary(legacy, "old1")
    raw = _raw(legacy)
    try:
        assert _version(raw) == 0
    finally:
        raw.close()


def test_migration_rerun_has_no_writes(legacy):
    _boundary(legacy, "new1")
    led = writer_ledger(legacy, M)
    statements = []
    led.conn.set_trace_callback(statements.append)
    with led._write_transaction():
        led.prepare_session_boundary("new2")
        led.start_session("new2", cwd="/w", model="m")
    led.conn.set_trace_callback(None)
    ddl = [s for s in statements
           if s.lstrip().upper().startswith(("CREATE", "ALTER", "DROP",
                                              "PRAGMA USER_VERSION ="))]
    assert ddl == []
    assert not any("scoring_profiles" in s for s in statements)
    led.conn.close()


# -- legacy writes after the rebuild ----------------------------------------

def test_running_legacy_writer_uses_renamed_table(legacy):
    _boundary(legacy)
    led = writer_ledger(legacy, M)
    before = led.summary("old1")
    delta = led.record("old1", turn_id="t10", kind="exposed",
                       data_type="phone", source="b.log",
                       destination="model_context", value_hash=b"\x77" * 16,
                       masked_example=None, tool_name="Read",
                       protection=None)
    assert delta > 0
    again = led.record("old1", turn_id="t11", kind="exposed",
                       data_type="phone", source="b.log",
                       destination="model_context", value_hash=b"\x77" * 16,
                       masked_example=None, tool_name="Read",
                       protection=None)
    assert again == 0.0
    after = led.summary("old1")
    assert after.legacy_score == pytest.approx(before.legacy_score + delta)
    rows = led.conn.execute(
        "SELECT count FROM events_legacy_v1 WHERE value_hash=?",
        (b"\x77" * 16,)).fetchall()
    assert [r[0] for r in rows] == [2]
    assert led.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    led.conn.close()


def test_legacy_end_uses_renamed_table(legacy):
    _boundary(legacy)
    led = writer_ledger(legacy, M)
    led.start_session("old3", cwd="/r", model="m")
    led.record("old3", turn_id="t", kind="exposed", data_type="email",
               source="a", destination="model_context",
               value_hash=b"\x33" * 16, masked_example=None,
               tool_name="Read", protection=None)
    led.end_session("old3")
    hashes = dict(led.conn.execute(
        "SELECT session_id, COUNT(value_hash) FROM events_legacy_v1"
        " GROUP BY session_id").fetchall())
    assert hashes["old3"] == 0
    assert hashes["old1"] > 0
    led.conn.close()


def test_legacy_record_is_one_write_transaction(legacy):
    led = writer_ledger(legacy, M)
    statements = []
    led.conn.set_trace_callback(statements.append)
    led.record("old1", turn_id="t", kind="exposed", data_type="phone",
               source="a", destination="model_context",
               value_hash=b"\x44" * 16, masked_example=None,
               tool_name="Read", protection=None)
    led.conn.set_trace_callback(None)
    upper = [s.strip().upper() for s in statements]
    assert upper[0] == "BEGIN IMMEDIATE"
    assert upper[-1] == "COMMIT"
    assert any(s.startswith("INSERT INTO") for s in upper)
    assert any(s.startswith("UPDATE SESSIONS") for s in upper)
    led.conn.close()


def test_commit_failure_rolls_back_and_releases_write_ownership(legacy):
    led = writer_ledger(legacy, M)

    def authorizer(action, arg1, arg2, database, trigger):
        if action == sqlite3.SQLITE_TRANSACTION and arg1 == "COMMIT":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    try:
        led.conn.set_authorizer(authorizer)
        with pytest.raises(sqlite3.DatabaseError):
            with led._write_transaction():
                led.prepare_session_boundary("commit-failed")
                led.start_session("commit-failed", cwd="", model="")
        led.conn.set_authorizer(None)

        assert not led.conn.in_transaction
        assert led._write_depth == 0
        assert _version(led.conn) == 0
        assert not led.session_exists("commit-failed")
        assert "events_legacy_v1" not in _tables(led.conn)

        with led._write_transaction():
            led.prepare_session_boundary("retry")
            led.start_session("retry", cwd="", model="")
        assert _version(led.conn) == 5401
    finally:
        led.conn.close()


def test_failed_boundary_does_not_install_session_state(legacy):
    state = writer_state(legacy.parent)

    def failpoint(statement):
        raise RuntimeError("injected")

    state.ledger._migration_failpoint = failpoint
    try:
        with pytest.raises(RuntimeError):
            dispatch_mod.dispatch(state, {
                "hook_event_name": "SessionStart",
                "session_id": "failed-start",
            })
        assert "failed-start" not in state.salts
        assert "failed-start" not in state.engines
        assert "failed-start" not in state.started_at
        assert not state.ledger.session_exists("failed-start")
        assert _version(state.ledger.conn) == 0
    finally:
        state.ledger.conn.close()


# -- crashes ----------------------------------------------------------------

_CHILD = textwrap.dedent("""
    import os, sys
    sys.path.insert(0, {src!r})
    from privacy_hud.ledger import Ledger
    from privacy_hud.matrix.loader import load_matrix
    from privacy_hud.runtime_owner import acquire_writer, unselected_activation
    stop = int(sys.argv[2])
    # A real lease, in this crash's own data root: the parent process holds
    # one on the shared temporary directory for the whole test, and #66's
    # exclusion is between processes, not a convention this child could
    # opt out of.
    lease = acquire_writer(sys.argv[1] + ".owner",
                           activation=unselected_activation())
    led = Ledger(sys.argv[1], load_matrix(), writer_lease=lease)
    n = [0]
    def failpoint(statement):
        n[0] += 1
        if n[0] == stop:
            os._exit(3)
    led._migration_failpoint = failpoint
    with led._write_transaction():
        led.prepare_session_boundary("new1")
        led.start_session("new1", cwd="/w", model="m")
        if stop == 0:
            os._exit(4)
    os._exit(5)
""")


def _statement_count() -> int:
    from privacy_hud import ledger_schema
    return len(ledger_schema.migration_statements())


def test_migration_crash_after_each_statement(tmp_path):
    template = tmp_path / "template.db"
    _legacy_ledger(template)
    raw = _raw(template)
    original = _cells(raw, "events")
    raw.close()
    child = tmp_path / "child.py"
    child.write_text(_CHILD.format(src=str(REPO / "src")), encoding="utf-8")
    total = _statement_count()
    assert total >= 10
    for stop in list(range(1, total + 1)) + [0]:
        path = tmp_path / f"crash{stop}.db"
        src = sqlite3.connect(template)
        dst = sqlite3.connect(path)
        src.backup(dst)
        src.close()
        dst.close()
        proc = subprocess.run([sys.executable, str(child), str(path),
                               str(stop)], capture_output=True, timeout=60)
        assert proc.returncode in (3, 4), proc.stderr
        raw = _raw(path)
        try:
            assert _version(raw) == 0, stop
            assert "events_legacy_v1" not in _tables(raw), stop
            assert _cells(raw, "events") == original, stop
            assert raw.execute("SELECT 1 FROM sessions WHERE"
                               " session_id='new1'").fetchone() is None
        finally:
            raw.close()
        # And the next genuine start completes the migration.
        writer_ledger(path, M).conn.close()
        led = writer_ledger(path, M)
        with led._write_transaction():
            led.prepare_session_boundary("new1")
            led.start_session("new1", cwd="/w", model="m")
        assert _version(led.conn) == 5401
        led.conn.close()


# -- schema versions --------------------------------------------------------

def test_malformed_or_future_schema_is_rejected(legacy, tmp_path):
    raw = _raw(legacy)
    raw.execute("PRAGMA user_version=9999")
    raw.close()
    with pytest.raises(Exception) as caught:
        writer_ledger(legacy, M)
    assert type(caught.value).__name__ == "UnsupportedAccounting"

    half = tmp_path / "half.db"
    _legacy_ledger(half)
    raw = _raw(half)
    raw.execute("ALTER TABLE events RENAME TO events_legacy_v1")
    raw.execute("PRAGMA user_version=5401")
    raw.close()
    with pytest.raises(Exception) as caught:
        writer_ledger(half, M)
    assert type(caught.value).__name__ == "UnsupportedAccounting"
    raw = _raw(half)
    assert "observations" not in _tables(raw), "no repair"
    raw.close()


def test_phase2_rejects_activated_writer_downgrade(legacy):
    _boundary(legacy)
    raw = _raw(legacy)
    raw.execute("PRAGMA user_version=5402")
    raw.close()
    with pytest.raises(Exception) as caught:
        writer_ledger(legacy, M)
    assert type(caught.value).__name__ == "UnsupportedAccounting"


def test_reader_open_never_rebuilds_or_changes_pragmas(legacy):
    raw = _raw(legacy)
    raw.execute("PRAGMA journal_mode=DELETE")
    raw.close()
    mode = os.stat(legacy).st_mode
    reader = Ledger(legacy, M, initialize=False)
    reader.summary("old1")
    reader.conn.close()
    raw = _raw(legacy)
    try:
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert _version(raw) == 0
        assert "events_legacy_v1" not in _tables(raw)
    finally:
        raw.close()
    assert os.stat(legacy).st_mode == mode


def test_existing_reader_refreshes_legacy_route(legacy):
    reader = Ledger(legacy, M, initialize=False)
    assert reader._legacy_events_table() == "events"
    _boundary(legacy)
    assert reader._legacy_events_table() == "events_legacy_v1"
    assert reader.summary("old1").legacy_permitted_crossing_rows == 2
    reader.conn.close()


@pytest.mark.parametrize("prepared", [False, True])
def test_a_late_legacy_record_is_kept_without_a_charge(legacy, prepared):
    """After SessionEnd a late finding is still written, with a NULL hash
    and zero contribution; the ended session's score and history stay as
    they were, on both schema generations."""
    if prepared:
        _boundary(legacy)
    led = writer_ledger(legacy, M)
    led.start_session("late", cwd="/r", model="m")
    first = led.record("late", turn_id="t", kind="exposed", data_type="email",
                       source="a", destination="model_context",
                       value_hash=b"\x55" * 16, masked_example=None,
                       tool_name="Read", protection=None)
    assert first > 0
    table = led._legacy_events_table()
    history = led.conn.execute(
        f"SELECT id, count, budget_delta FROM {table} WHERE session_id='late'"
    ).fetchall()
    led.end_session("late")
    ended = tuple(led.conn.execute(
        "SELECT * FROM sessions WHERE session_id='late'").fetchone())
    for _ in range(2):
        assert led.record("late", turn_id="t", kind="exposed",
                          data_type="email", source="a",
                          destination="model_context",
                          value_hash=b"\x55" * 16, masked_example=None,
                          tool_name="Read", protection=None) == 0.0
    rows = led.conn.execute(
        f"SELECT id, count, budget_delta, value_hash FROM {table}"
        " WHERE session_id='late' ORDER BY id").fetchall()
    assert [(r[0], r[1], r[2]) for r in rows[:len(history)]] == \
        [tuple(h) for h in history]
    late = rows[len(history):]
    assert len(late) == 2
    assert all(r[3] is None and r[2] == 0.0 for r in late)
    assert tuple(led.conn.execute(
        "SELECT * FROM sessions WHERE session_id='late'").fetchone()) == ended
    led.conn.close()
