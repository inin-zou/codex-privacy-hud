#!/usr/bin/env python3
"""Rehearse #54's ledger migration on a private copy of a real ledger.

Developer-only. The source ledger is opened read-only and copied with
SQLite's backup API (committed WAL contents included) into a work directory
that only the current user can read; every check runs against copies. All
comparison material stays in memory. Nothing read from a ledger is printed:
the output is one fixed line, and a failure exits nonzero with a fixed
check name, never an exception value, SQL parameter, row or traceback.

    python scripts/check-issue54-ledger.py --source PATH --work-dir PATH --phase 2

Phase 2 checks: byte-exact preservation of the legacy table and every
auxiliary table; the prepared schema and marker; unchanged pre-existing
foreign-key violations and clean new tables; legacy summaries, lists and
details before and after; a reader opened before the migration, across it;
a continuing legacy session's arithmetic; an idempotent reopen and rerun;
and process termination after every migration statement and immediately
before and after commit, each on a fresh baseline copy, leaving either the
complete old state or the complete prepared state with its triggering
legacy session and coverage row.

Deleting the work directory afterwards is logical deletion, not secure
erasure.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import stat
import struct
import subprocess
import sys
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from privacy_hud import ledger_schema  # noqa: E402
from privacy_hud.budget import contribution  # noqa: E402
from privacy_hud.ledger import Ledger  # noqa: E402
from privacy_hud.matrix.loader import load_matrix  # noqa: E402

PASS = "Phase {phase} private-ledger checks: PASS. No ledger values were printed."
FAIL = "Private-ledger check failed. No ledger values were printed."

_CHILD = """
import os, sys
sys.path.insert(0, sys.argv[3])
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
stop = int(sys.argv[2])
led = Ledger(sys.argv[1], load_matrix())
n = [0]
def failpoint(statement):
    n[0] += 1
    if n[0] == stop:
        os._exit(3)
led._migration_failpoint = failpoint
with led._write_transaction():
    led.prepare_session_boundary(sys.argv[4])
    led.start_session(sys.argv[4], cwd="", model="")
    if stop == 0:
        os._exit(4)
os._exit(5)
"""


class CheckFailed(Exception):
    """A named check failed. The name is a fixed string from this file."""


def _check(condition: bool, name: str) -> None:
    if not condition:
        raise CheckFailed(name)


def _private_dir(path: Path) -> None:
    info = path.lstat()
    _check(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
           "work-dir-not-a-directory")
    _check(info.st_mode & 0o077 == 0, "work-dir-not-private")
    _check(not any(path.iterdir()), "work-dir-not-empty")


def _copy(source: Path, dest: Path) -> None:
    _check(not dest.exists() and not dest.is_symlink(), "output-exists")
    src = sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)
    try:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    os.chmod(dest, 0o600)


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _layout(conn: sqlite3.Connection, table: str) -> list[tuple]:
    return list(conn.execute(f"PRAGMA table_info({_quote(table)})"))


def _schema(conn: sqlite3.Connection) -> dict:
    return {
        (kind, name): (table, sql)
        for kind, name, table, sql in conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master")
    }


def _cells(conn: sqlite3.Connection, table: str) -> list[tuple]:
    cols = [_quote(r[1]) for r in _layout(conn, table)]
    select = ", ".join(
        f"typeof({c}), CASE WHEN typeof({c})='text' "
        f"THEN CAST({c} AS BLOB) ELSE {c} END"
        for c in cols)
    rows = []
    for row in conn.execute(
            f"SELECT {select} FROM {_quote(table)} ORDER BY rowid"):
        cells = []
        for i in range(0, len(row), 2):
            kind, value = row[i], row[i + 1]
            if kind == "real":
                value = struct.pack(">d", value)
            cells.append((kind, value))
        rows.append(tuple(cells))
    return rows


def _raw(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)
    return conn


def _tables(conn) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
        " AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def _fk_violations(conn) -> set[tuple]:
    return {tuple(r) for r in conn.execute("PRAGMA foreign_key_check")}


def _readings(led: Ledger) -> dict:
    out = {}
    ids = [r[0] for r in led.conn.execute(
        "SELECT session_id FROM sessions ORDER BY session_id")]
    for sid in ids:
        rows = [r.as_dict() for kind in
                ("exposed", "prevented", "local_access", "detected",
                 "retention")
                for r in (x.to_exposure() for x in led.list_events(sid, kind))]
        details = [led.get_event(sid, r["id"]).as_dict() for r in rows]
        out[sid] = (led.summary(sid).as_dict(), rows, details)
    return out


def _boundary(path: Path, session_id: str) -> None:
    led = Ledger(path, load_matrix())
    try:
        with led._write_transaction():
            led.prepare_session_boundary(session_id)
            led.start_session(session_id, cwd="", model="")
    finally:
        led.conn.close()


def phase2(source: Path, work: Path) -> None:
    matrix = load_matrix()
    copy = work / "copy.db"
    _copy(source, copy)
    # The daemon's own startup step, committed before any boundary: a
    # legacy ledger from an older release gains the legacy tables it lacks
    # (for example `scan_gaps`). The rebuild is checked against that state,
    # which is also what every crash copy returns to.
    Ledger(copy, matrix).conn.close()
    baseline = work / "baseline.db"
    _copy(copy, baseline)

    raw = _raw(copy)
    try:
        _check(ledger_schema.validate_schema(raw) == 0, "source-not-legacy")
        tables = _tables(raw)
        _check("events" in tables and "sessions" in tables,
               "source-not-a-ledger")
        before = {t: _cells(raw, t) for t in tables}
        layouts = {t: _layout(raw, t) for t in tables}
        original_schema = _schema(raw)
        violations = _fk_violations(raw)

        reference = sqlite3.connect(":memory:", isolation_level=None)
        try:
            raw.backup(reference)
            reference.execute(
                "ALTER TABLE events RENAME TO events_legacy_v1")
            renamed_schema = _schema(reference)
        finally:
            reference.close()
    finally:
        raw.close()

    # A continuing legacy session, on the copy only, started before the
    # rebuild and written after it.
    continuing = f"privacy-hud-dry-run-{uuid.uuid4().hex}"
    led = Ledger(copy, matrix)
    led.start_session(continuing, cwd="", model="")
    led.conn.close()

    reader = Ledger(copy, matrix, initialize=False)
    readings = _readings(reader)

    trigger = f"privacy-hud-dry-run-{uuid.uuid4().hex}"
    _boundary(copy, trigger)

    raw = _raw(copy)
    try:
        _check(ledger_schema.validate_schema(raw) == 5401, "marker")
        _check(_cells(raw, "events_legacy_v1") == before["events"],
               "legacy-cells")
        for table, cells in before.items():
            if table == "events":
                continue
            after = _cells(raw, table)
            if table in ("sessions", "coverage"):
                width = len(cells[0]) if cells else 0
                after = [row[:width] for row in after[:len(cells)]]
            _check(after == cells, "auxiliary-cells")
        for table, layout in layouts.items():
            target = "events_legacy_v1" if table == "events" else table
            actual_layout = _layout(raw, target)
            if table == "sessions":
                actual_layout = actual_layout[:len(layout)]
            _check(actual_layout == layout, "preserved-layout")

        actual_schema = _schema(raw)
        for key, definition in renamed_schema.items():
            if key != ("table", "sessions"):
                _check(actual_schema.get(key) == definition,
                       "preserved-schema")
        old_sessions = ledger_schema._norm(
            original_schema[("table", "sessions")][1])
        new_sessions = ledger_schema._norm(
            actual_schema[("table", "sessions")][1])
        _check(new_sessions.startswith(old_sessions[:-1].rstrip()),
               "preserved-session-definition")
        after_violations = _fk_violations(raw)
        renamed = {(("events_legacy_v1",) + v[1:]) if v[0] == "events" else v
                   for v in violations}
        _check(after_violations == renamed, "foreign-keys")
        new_tables = {"scoring_profiles", "observations", "subjects",
                      "recipients", "events", "disclosures"}
        _check(not any(v[0] in new_tables for v in after_violations),
               "new-foreign-keys")
    finally:
        raw.close()

    after = _readings(reader)
    for sid, reading in readings.items():
        _check(after.get(sid) == reading, "legacy-readings")
    reader.conn.close()

    led = Ledger(copy, matrix)
    try:
        before_score = led.summary(continuing).legacy_score
        delta = led.record(continuing, turn_id=None, kind="exposed",
                           data_type="email", source="dry-run",
                           destination="model_context",
                           value_hash=os.urandom(16), masked_example=None,
                           tool_name=None, protection=None)
        expected = contribution(matrix, "email", 1, "model_context")
        _check(delta == expected, "continuing-arithmetic")
        _check(led.summary(continuing).legacy_score == before_score + delta,
               "continuing-score")
        _check(led.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
               == 0, "new-events-empty")
    finally:
        led.conn.close()

    statements: list[str] = []
    led = Ledger(copy, matrix)
    try:
        led.conn.set_trace_callback(statements.append)
        with led._write_transaction():
            again = f"privacy-hud-dry-run-{uuid.uuid4().hex}"
            led.prepare_session_boundary(again)
            led.start_session(again, cwd="", model="")
        led.conn.set_trace_callback(None)
    finally:
        led.conn.close()
    ddl = [s for s in statements if s.lstrip().upper().startswith(
        ("CREATE", "ALTER", "DROP", "PRAGMA USER_VERSION ="))]
    _check(ddl == [], "rerun-writes")

    total = len(ledger_schema.migration_statements())
    child = work / "child.py"
    child.write_text(_CHILD, encoding="utf-8")
    os.chmod(child, 0o600)
    for stop in list(range(1, total + 1)) + [0, -1]:
        path = work / f"crash-{stop}.db"
        _copy(baseline, path)
        proc = subprocess.run(
            [sys.executable, str(child), str(path), str(stop),
             str(REPO / "src"), trigger],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=300)
        expected_exit = 5 if stop == -1 else 4 if stop == 0 else 3
        _check(proc.returncode == expected_exit, "crash-child")
        raw = _raw(path)
        try:
            prepared = stop == -1
            _check(
                ledger_schema.validate_schema(raw)
                == (5401 if prepared else 0),
                "crash-marker")

            if prepared:
                _check(
                    set(_tables(raw))
                    == set(tables) | new_tables | {"events_legacy_v1"},
                    "crash-tables")
                actual_schema = _schema(raw)
                for key, definition in renamed_schema.items():
                    if key != ("table", "sessions"):
                        _check(actual_schema.get(key) == definition,
                               "crash-schema")
                old_sessions = ledger_schema._norm(
                    original_schema[("table", "sessions")][1])
                new_sessions = ledger_schema._norm(
                    actual_schema[("table", "sessions")][1])
                _check(
                    new_sessions.startswith(old_sessions[:-1].rstrip()),
                    "crash-session-definition")
                _check(_fk_violations(raw) == renamed, "crash-foreign-keys")
                _check(raw.execute(
                    "SELECT accounting_version, accounting_status, "
                    "profile_id FROM sessions WHERE session_id=?",
                    (trigger,)).fetchone() == (1, "legacy", None),
                    "crash-trigger-session")
                _check(raw.execute(
                    "SELECT COUNT(*) FROM coverage "
                    "WHERE session_id=? AND reason='session_start'",
                    (trigger,)).fetchone()[0] == 1,
                    "crash-trigger-coverage")
            else:
                _check(_schema(raw) == original_schema, "crash-schema")
                _check(_fk_violations(raw) == violations,
                       "crash-foreign-keys")

            for table, cells in before.items():
                target = (
                    "events_legacy_v1"
                    if prepared and table == "events" else table)
                actual_layout = _layout(raw, target)
                after_cells = _cells(raw, target)
                if prepared and table == "sessions":
                    actual_layout = actual_layout[:len(layouts[table])]
                    # _cells yields one (storage class, value) pair per
                    # column, so the original columns are the first
                    # len(layout) entries of each row.
                    after_cells = [
                        row[:len(layouts[table])]
                        for row in after_cells
                    ]
                _check(actual_layout == layouts[table], "crash-layout")
                extra = int(prepared and table in ("sessions", "coverage"))
                _check(len(after_cells) == len(cells) + extra,
                       "crash-row-count")
                _check(after_cells[:len(cells)] == cells, "crash-cells")
        finally:
            raw.close()
        for suffix in ("", "-wal", "-shm"):
            target = Path(str(path) + suffix)
            if target.exists():
                target.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--phase", required=True, type=int, choices=(2,))
    args = parser.parse_args(argv)
    try:
        source, work = args.source, args.work_dir
        _check(source.is_file() and not source.is_symlink(), "source")
        _private_dir(work)
        _check(source.resolve().parent != work.resolve(), "source-in-work-dir")
        phase2(source, work)
    except CheckFailed as failed:
        print(FAIL)
        print(f"check: {failed.args[0]}", file=sys.stderr)
        return 1
    except Exception:
        print(FAIL)
        print("check: unexpected-error", file=sys.stderr)
        return 2
    print(PASS.format(phase=args.phase))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
