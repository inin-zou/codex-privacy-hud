"""#54 Phase 2: the prepared schema's own guards.

After the rebuild the new tables are empty and unused by production, but
their constraints are live: composite foreign keys keep every reference
inside its session, history is append-only, scoring profiles are
immutable, and an identity hash can only be erased, only after its session
ended. These tests write to the new tables directly because no production
writer does yet.
"""
from __future__ import annotations

import sqlite3

import pytest

from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix

M = load_matrix()
PROFILE = "a" * 64


@pytest.fixture
def conn(tmp_path):
    path = tmp_path / "ledger.db"
    led = Ledger(path, M)
    with led._write_transaction():
        led.prepare_session_boundary("s1")
        led.start_session("s1", cwd="/w", model="m")
    c = led.conn
    c.execute("INSERT INTO scoring_profiles VALUES(?,1,'m',1,120.0,'{}')",
              (PROFILE,))
    for sid in ("v2a", "v2b"):
        c.execute(
            "INSERT INTO sessions(session_id,started_at,budget_cap,"
            "accounting_version,accounting_status,profile_id)"
            " VALUES(?,1,120.0,2,'available',?)", (sid, PROFILE))
        c.execute(
            "INSERT INTO observations VALUES(?,?,?,?,NULL,1,'PreToolUse',"
            "'pre','tool','B3','allow',1,'none',1,NULL)",
            (f"o-{sid}", sid, f"d-{sid}", f"a-{sid}"))
    yield c
    c.close()


def _subject(c, sid, sub_id, obs=None, identity=b"\x01" * 32):
    if obs is None:
        c.execute("INSERT INTO subjects VALUES(?,?,'value','resolved',?,"
                  "'email',NULL)", (sub_id, sid, identity))
    else:
        c.execute("INSERT INTO subjects VALUES(?,?,'value','unresolved',"
                  "NULL,'email',?)", (sub_id, sid, obs))


def test_new_schema_rejects_cross_session_references(conn):
    with pytest.raises(sqlite3.IntegrityError):
        _subject(conn, "v2a", "u1", obs="o-v2b")
    _subject(conn, "v2a", "u2")
    conn.execute("INSERT INTO recipients VALUES('r1','v2a','mcp_tool',"
                 "'resolved',?,'mcp',NULL)", (b"\x02" * 32,))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO events(session_id,observation_id,subject_id,"
            "recipient_id,kind,evidence,data_type,source_label,boundary)"
            " VALUES('v2b','o-v2b','u2','r1','permitted',1,'email','x','B3')")


def test_observations_require_a_version_two_session(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO observations VALUES('o-s1','s1','d','a',NULL,1,"
            "'PreToolUse','pre','tool','B3','allow',1,'none',1,NULL)")


def test_new_history_and_profiles_are_immutable(conn):
    for sql in ("UPDATE scoring_profiles SET budget_cap=1",
                "DELETE FROM scoring_profiles",
                "UPDATE observations SET ts=2",
                "DELETE FROM observations",
                "UPDATE coverage SET ts=2",
                "DELETE FROM scan_gaps"):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(sql)


def test_session_accounting_is_frozen(conn):
    for sql in ("UPDATE sessions SET accounting_version=2"
                " WHERE session_id='s1'",
                "UPDATE sessions SET budget_cap=1 WHERE session_id='v2a'",
                "UPDATE sessions SET profile_id=NULL WHERE session_id='v2a'",
                "UPDATE sessions SET accounting_status='available'"
                " WHERE session_id='s1'"):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(sql)


def test_identity_hash_can_only_be_erased_after_end(conn):
    _subject(conn, "v2a", "u1")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE subjects SET identity_hash=NULL"
                     " WHERE subject_id='u1'")
    conn.execute("UPDATE sessions SET ended_at=5 WHERE session_id='v2a'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE subjects SET identity_hash=?"
                     " WHERE subject_id='u1'", (b"\x09" * 32,))
    conn.execute("UPDATE subjects SET identity_hash=NULL"
                 " WHERE subject_id='u1'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE subjects SET label='x' WHERE subject_id='u1'")


def test_the_schema_validates_after_migration(conn):
    from privacy_hud import ledger_schema
    assert ledger_schema.validate_schema(conn) == 5401
