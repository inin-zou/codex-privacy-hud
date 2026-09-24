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

Phase 3 checks (`--phase 3`) accept a legacy (0) or prepared (5401) source
with no version-2 sessions and refuse anything else. A legacy source gets
the complete Phase 2 rehearsal first; a prepared one gets the same
preservation checks without a rebuild. A separate synthetic copy then
exercises the inactive version-2 core through `record_observation`: the
seven outcome sequences, adversarial checks, a real production start that
stays legacy, a reopened reader, unavailability, end-of-session erasure and
a retried delivery. Finally an observation write and a version-2 end are
terminated after every mutating statement and around the outer commit, each
on a fresh clone. Output is the same closed set of fixed lines and check
names.

Deleting the work directory afterwards is logical deletion, not secure
erasure.
"""
from __future__ import annotations

import argparse
import contextlib
import io
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

from privacy_hud import codex, dispatch, ledger_schema  # noqa: E402
from privacy_hud.accounting import (  # noqa: E402
    EventRecord, Evidence, ObservationRecord, RecipientInput, ScoringProfile,
    SubjectInput,
)
from privacy_hud.budget import contribution, group_score  # noqa: E402
from privacy_hud.identity import (  # noqa: E402
    file_identity, recipient_identity, value_identity,
)
from privacy_hud.ledger import Ledger  # noqa: E402
from privacy_hud.matrix.loader import load_matrix  # noqa: E402
from privacy_hud.runtime_owner import (  # noqa: E402
    acquire_writer,
    unselected_activation,
)

PASS = "Phase {phase} private-ledger checks: PASS. No ledger values were printed."
FAIL = "Private-ledger check failed. No ledger values were printed."

_CHILD = """
import os, sys
sys.path.insert(0, sys.argv[3])
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.runtime_owner import acquire_writer, unselected_activation
stop = int(sys.argv[2])
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
    led.prepare_session_boundary(sys.argv[4])
    led.start_session(sys.argv[4], cwd="", model="")
    if stop == 0:
        os._exit(4)
os._exit(5)
"""


#: Writer leases taken for the private copies, kept alive for the run.
#: Each copy owns its own lock directory beside it, inside the private work
#: directory, so a rehearsal never contends with — or waits for — the real
#: installation's ledger owner (#66).
_LEASES: list = []


def _lease(path: Path):
    """A real writer lease for one private copy. Not a bypass: the same
    `acquire_writer` the daemon uses, on a lock this rehearsal owns."""
    lease = acquire_writer(Path(str(path) + ".owner"),
                           activation=unselected_activation())
    _LEASES.append(lease)
    return lease


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
    led = Ledger(path, load_matrix(), writer_lease=_lease(path))
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
    Ledger(copy, matrix, writer_lease=_lease(copy)).conn.close()
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
    led = Ledger(copy, matrix, writer_lease=_lease(copy))
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

    led = Ledger(copy, matrix, writer_lease=_lease(copy))
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
    led = Ledger(copy, matrix, writer_lease=_lease(copy))
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


# -- Phase 3 ------------------------------------------------------------------

_CHILD3 = """
import os, sys
sys.path.insert(0, sys.argv[4])
from privacy_hud.accounting import (
    Evidence as E, EventRecord, ObservationRecord, RecipientInput,
    SubjectInput)
from privacy_hud.identity import recipient_identity, value_identity
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.runtime_owner import acquire_writer, unselected_activation
op, stop, path, sid = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[5]
key, delivery = bytes.fromhex(sys.argv[6]), sys.argv[7]


class Proxy:
    # Delegates to the real connection and ends the process after the Nth
    # successful mutating statement, or around the outer COMMIT. Prints no
    # SQL.
    def __init__(self, conn):
        self._conn = conn
        self.mutations = 0

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def execute(self, sql, params=()):
        head = sql.lstrip().upper()
        if stop == 0 and head.startswith("COMMIT"):
            os._exit(4)
        cursor = self._conn.execute(sql, params)
        if head.startswith(("INSERT", "UPDATE", "DELETE")):
            self.mutations += 1
            if self.mutations == stop:
                os._exit(3)
        if stop == -1 and head.startswith("COMMIT"):
            os._exit(5)
        return cursor


led = Ledger(path, load_matrix(), writer_lease=acquire_writer(
    path + ".owner", activation=unselected_activation()))

# Only this rehearsal child uses repeatable generated metadata, so the
# complete committed rows can be compared across fresh baseline clones.
import uuid
import privacy_hud.ledger as ledger_module
sequence = 0
def repeatable_uuid():
    global sequence
    sequence += 1
    return uuid.uuid5(uuid.NAMESPACE_OID, f"{delivery}:{sequence}")
fixed_time = led.conn.execute(
    "SELECT started_at FROM sessions WHERE session_id=?", (sid,)
).fetchone()[0] + 1
ledger_module.uuid.uuid4 = repeatable_uuid
ledger_module.time.time = lambda: fixed_time

proxy = Proxy(led.conn)
led.conn = proxy
if op == "observe":
    led.record_observation(
        ObservationRecord(
            session_id=sid, delivery_key=delivery, action_id=delivery,
            turn_id=None, ts=1, hook_event="PostToolUse", phase="post",
            action_kind="tool", boundary="B3", decision="none",
            evidence=E.EXECUTION_OBSERVED | E.CROSSING_CONFIRMED,
            resolution_scope="pairs", potential_crossing=False,
            scan_gap="timeout"),
        [EventRecord(
            subject=SubjectInput(
                subject_kind="value",
                identity_hash=value_identity(key, "crash-subject")),
            recipient=RecipientInput(
                destination_kind="mcp_tool",
                identity_hash=recipient_identity(
                    key, "mcp_tool", "crash-recipient")),
            kind="exposed", evidence=E.CROSSING_CONFIRMED,
            data_type="email", rule_id=None, occurrences=1,
            source_label="tool result", boundary="B3",
            masked_example=None)])
else:
    led.end_session(sid)
if stop == -2:
    sys.stdout.write(str(proxy.mutations))
    sys.stdout.flush()
    os._exit(6)
os._exit(7)
"""

#: Fixed session-ID prefixes for rows the rehearsal adds to its copies.
_V2_PREFIX = "privacy-hud-dry-run-v2-"
_PRODUCTION_PREFIX = "privacy-hud-dry-run-production-"
_V2_TABLES = ("scoring_profiles", "observations", "subjects", "recipients",
              "events", "disclosures")
_E = Evidence


@contextlib.contextmanager
def _silenced():
    """Discard everything written to stdout and stderr, at both the Python
    and the file-descriptor level, while real daemon code runs: a model
    loader's progress output is not the rehearsal's to print."""
    sys.stdout.flush()
    sys.stderr.flush()
    saved = [os.dup(1), os.dup(2)]
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            yield
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        for fd in (*saved, devnull):
            os.close(fd)


def _mkdir(path: Path) -> None:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def _generation(path: Path) -> int:
    raw = _raw(path)
    try:
        return ledger_schema.validate_schema(raw)
    except ledger_schema.UnsupportedAccounting:
        raise CheckFailed("phase3-source-version") from None
    finally:
        raw.close()


def phase3(source: Path, work: Path) -> None:
    """Phase 3: preserve the source's legacy state on copies, then exercise
    version-2 accounting on a separate synthetic copy only."""
    inspect = work / "inspect"
    _mkdir(inspect)
    backup = inspect / "backup.db"
    # SQLite may create WAL/SHM bookkeeping during a read-only backup.
    # Their prior absence does not give us ownership: another connection
    # may already be using them. Leave source-side cleanup to SQLite.
    _copy(source, backup)
    version = _generation(backup)
    _check(version in (0, ledger_schema.PREPARED_VERSION),
           "phase3-source-version")
    if version == ledger_schema.PREPARED_VERSION:
        raw = _raw(backup)
        try:
            original_v2 = raw.execute(
                "SELECT COUNT(*) FROM sessions"
                " WHERE accounting_version <> 1").fetchone()[0]
        finally:
            raw.close()
        _check(original_v2 == 0, "phase3-source-has-v2")
        prepared = _check_prepared_copy(backup, work / "prepared")
    else:
        rehearsal = work / "phase2"
        _mkdir(rehearsal)
        phase2(backup, rehearsal)
        prepared = rehearsal / "copy.db"

    synthetic_dir = work / "synthetic"
    _mkdir(synthetic_dir)
    synthetic = codex.ledger_path(synthetic_dir)
    _copy(prepared, synthetic)
    _check_synthetic_v2(synthetic)
    _check_v2_crash_atomicity(prepared, work / "crash")


def _check_prepared_copy(
    source: Path, work: Path,
) -> Path:
    """A generation-5401 source: its prepared state survives the daemon's
    open, a reader across a boundary, a further genuine boundary, continuing
    legacy arithmetic and a reopen. Returns the verified copy."""
    matrix = load_matrix()
    _mkdir(work)
    copy = work / "copy.db"
    _copy(source, copy)
    raw = _raw(copy)
    try:
        tables = _tables(raw)
        before = {t: _cells(raw, t) for t in tables}
        layouts = {t: _layout(raw, t) for t in tables}
        schema = _schema(raw)
        violations = _fk_violations(raw)
    finally:
        raw.close()

    def unchanged(appended: bool) -> None:
        raw = _raw(copy)
        try:
            _check(ledger_schema.validate_schema(raw)
                   == ledger_schema.PREPARED_VERSION, "phase3-preservation")
            _check(_schema(raw) == schema, "phase3-preservation")
            for table, cells in before.items():
                _check(_layout(raw, table) == layouts[table],
                       "phase3-preservation")
                after = _cells(raw, table)
                if appended:
                    after = after[:len(cells)]
                _check(after == cells, "phase3-preservation")
            _check(_fk_violations(raw) == violations, "phase3-foreign-keys")
        finally:
            raw.close()

    Ledger(copy, matrix, writer_lease=_lease(copy)).conn.close()
    unchanged(appended=False)

    reader = Ledger(copy, matrix, initialize=False)
    try:
        readings = _readings(reader)
        statements: list[str] = []
        led = Ledger(copy, matrix, writer_lease=_lease(copy))
        try:
            led.conn.set_trace_callback(statements.append)
            with led._write_transaction():
                boundary = f"privacy-hud-dry-run-{uuid.uuid4().hex}"
                led.prepare_session_boundary(boundary)
                led.start_session(boundary, cwd="", model="")
            led.conn.set_trace_callback(None)
        finally:
            led.conn.close()
        ddl = [s for s in statements if s.lstrip().upper().startswith(
            ("CREATE", "ALTER", "DROP", "PRAGMA USER_VERSION ="))]
        _check(ddl == [], "phase3-preservation")
        after = _readings(reader)
        for sid, reading in readings.items():
            _check(after.get(sid) == reading, "phase3-preservation")
    finally:
        reader.conn.close()

    continuing = f"privacy-hud-dry-run-{uuid.uuid4().hex}"
    led = Ledger(copy, matrix, writer_lease=_lease(copy))
    try:
        led.start_session(continuing, cwd="", model="")
        delta = led.record(continuing, turn_id=None, kind="exposed",
                           data_type="email", source="dry-run",
                           destination="model_context",
                           value_hash=os.urandom(16), masked_example=None,
                           tool_name=None, protection=None)
        _check(delta == contribution(matrix, "email", 1, "model_context"),
               "phase3-preservation")
        _check(led.summary(continuing).legacy_score == delta,
               "phase3-preservation")
    finally:
        led.conn.close()

    Ledger(copy, matrix, writer_lease=_lease(copy)).conn.close()
    unchanged(appended=True)
    return copy


class _Records:
    """Synthetic version-2 records under a key that exists only in this
    process. Built through the public record types; nothing is inserted by
    hand."""

    def __init__(self, led: Ledger, profile: ScoringProfile) -> None:
        self.led, self.profile, self.key = led, profile, os.urandom(32)

    def session(self) -> str:
        sid = _V2_PREFIX + uuid.uuid4().hex
        with self.led._write_transaction():
            self.led._start_v2_session(sid, cwd="", model="",
                                       profile=self.profile)
        return sid

    def value(self, text: str) -> SubjectInput:
        return SubjectInput(subject_kind="value",
                            identity_hash=value_identity(self.key, text))

    def file(self, path: str) -> SubjectInput:
        return SubjectInput(subject_kind="file",
                            identity_hash=file_identity(self.key, path, "/"),
                            safe_suffix=".pem")

    def to(self, kind: str = "mcp_tool", name: str = "server-a"
           ) -> RecipientInput:
        return RecipientInput(
            destination_kind=kind,  # type: ignore[arg-type]
            identity_hash=recipient_identity(self.key, kind, name))  # type: ignore[arg-type]

    @staticmethod
    def observation(sid: str, **changes) -> ObservationRecord:
        values = dict(
            session_id=sid, delivery_key=uuid.uuid4().hex,
            action_id=uuid.uuid4().hex, turn_id=None, ts=1,
            hook_event="PreToolUse", phase="pre", action_kind="tool",
            boundary="B3", decision="allow",
            evidence=_E.PERMISSION_ISSUED | _E.LOCAL_DETECTION,
            resolution_scope="none", potential_crossing=True, scan_gap=None)
        values.update(changes)
        return ObservationRecord(**values)  # type: ignore[arg-type]

    def crossed(self, sid: str, **changes) -> ObservationRecord:
        values = dict(hook_event="PostToolUse", phase="post",
                      decision="none",
                      evidence=_E.EXECUTION_OBSERVED | _E.CROSSING_CONFIRMED,
                      resolution_scope="pairs", potential_crossing=False)
        values.update(changes)
        return self.observation(sid, **values)

    def denied(self, sid: str, **changes) -> ObservationRecord:
        values = dict(decision="deny",
                      evidence=_E.DENY_ISSUED | _E.DENY_ENFORCED,
                      resolution_scope="boundary", potential_crossing=True)
        values.update(changes)
        return self.observation(sid, **values)

    @staticmethod
    def event(subject: SubjectInput, to: RecipientInput, **changes
              ) -> EventRecord:
        values = dict(subject=subject, recipient=to, kind="exposed",
                      evidence=_E.CROSSING_CONFIRMED, data_type="email",
                      rule_id=None, occurrences=1, source_label="tool input",
                      boundary="B3", masked_example=None)
        values.update(changes)
        return EventRecord(**values)  # type: ignore[arg-type]

    def prevented(self, subject: SubjectInput, to: RecipientInput,
                  **changes) -> EventRecord:
        values = dict(kind="prevented", evidence=_E.DENY_ENFORCED)
        values.update(changes)
        return self.event(subject, to, **values)


def _close(a: float, b: float) -> bool:
    return abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b))


def _v2_readings(led: Ledger, sids: list[str]) -> dict:
    out = {}
    for sid in sids:
        rows = [r.to_exposure().as_dict() for kind in
                ("detected", "local_access", "permitted", "exposed",
                 "prevented", "retention")
                for r in led.list_events(sid, kind)]
        details = [led.get_event(sid, r["id"]).as_dict() for r in rows]
        out[sid] = (led.summary(sid).as_dict(), rows, details)
    return out


def _check_synthetic_v2(path: Path) -> None:
    """The version-2 core on a synthetic copy: the seven sequences and
    adversarial checks through `record_observation`, a real production
    start that stays legacy, untouched original sessions, a reopened
    reader, unavailability, end-of-session erasure and a retried
    delivery."""
    matrix = load_matrix()
    profile = ScoringProfile.from_matrix(matrix)
    email_b3 = group_score(profile, "email", "mcp_tool", 1)

    led = Ledger(path, matrix, writer_lease=_lease(path))
    try:
        originals = {row[0]: tuple(row) for row in led.conn.execute(
            "SELECT * FROM sessions ORDER BY session_id")}
        legacy_rows = _cells(led.conn, "events_legacy_v1")
        b = _Records(led, profile)
        record = led.record_observation
        sids: list[str] = []

        def summary(sid: str):
            s = led.summary(sid)
            _check(s.accounting_version == 2, "phase3-synthetic-sequences")
            return s

        # 1. prevented, then exposed.
        s1 = b.session(); sids.append(s1)
        subject, to = b.value("seq-one"), b.to()
        record(b.denied(s1), [b.prevented(subject, to)])
        record(b.crossed(s1), [b.event(subject, to)])
        r = summary(s1)
        _check(r.event_rows == 2 and r.distinct_disclosures == 1
               and r.unresolved_actions == 0, "phase3-synthetic-sequences")
        _check(_close(r.confirmed_points, email_b3),
               "phase3-synthetic-scoring")

        # 2. exposed, then prevented.
        s2 = b.session(); sids.append(s2)
        record(b.crossed(s2), [b.event(subject, to)])
        record(b.denied(s2), [b.prevented(subject, to)])
        r = summary(s2)
        _check(r.event_rows == 2 and r.distinct_disclosures == 1
               and r.denials_enforced == 1, "phase3-synthetic-sequences")
        _check(_close(r.confirmed_points, email_b3),
               "phase3-synthetic-scoring")

        # 3. two key-container files, each read denied.
        s3 = b.session(); sids.append(s3)
        for name in ("one", "two"):
            record(b.denied(s3, action_kind="read", boundary="B1"),
                   [b.prevented(b.file(f"/privacy-hud-dry-run/{name}.pem"),
                                b.to("model_context", "model context"),
                                boundary="B1", data_type="credential",
                                source_label="local file")])
        r = summary(s3)
        _check(r.confirmed_points == 0.0 and r.reads_stopped == 2
               and r.distinct_subjects == 2, "phase3-synthetic-sequences")

        # 4. twelve findings in one denied call.
        s4 = b.session(); sids.append(s4)
        record(b.denied(s4), [b.prevented(b.value(f"seq-four-{i}"), to)
                              for i in range(12)])
        r = summary(s4)
        _check(r.denials_issued == 1 and r.intervention_events == 12
               and r.distinct_disclosures == 0,
               "phase3-synthetic-sequences")

        # 5. one value repeated to one recipient.
        s5 = b.session(); sids.append(s5)
        retry_obs = b.crossed(s5)
        retry_events = [b.event(subject, to)]
        retry_first = record(retry_obs, retry_events)
        for _ in range(2):
            record(b.crossed(s5), [b.event(subject, to)])
        r = summary(s5)
        _check(r.exposure_events == 3 and r.distinct_disclosures == 1,
               "phase3-synthetic-sequences")
        _check(_close(r.confirmed_points, email_b3),
               "phase3-synthetic-scoring")

        # 6. one value to two MCP recipients.
        s6 = b.session(); sids.append(s6)
        record(b.crossed(s6), [b.event(subject, b.to(name="server-a")),
                               b.event(subject, b.to(name="server-b"))])
        r = summary(s6)
        _check(r.distinct_disclosures == 2 and r.concrete_recipients == 2,
               "phase3-synthetic-sequences")
        _check(_close(r.confirmed_points, 2 * email_b3),
               "phase3-synthetic-scoring")

        # 7. permission, then a downstream rejection.
        s7 = b.session(); sids.append(s7)
        action = uuid.uuid4().hex
        record(b.observation(s7, action_id=action),
               [b.event(subject, to, kind="permitted",
                        evidence=_E.PERMISSION_ISSUED)])
        record(b.observation(s7, action_id=action, hook_event="PostToolUse",
                             phase="post", decision="none",
                             evidence=_E.REJECTED_BEFORE_CROSSING,
                             resolution_scope="pairs",
                             potential_crossing=False),
               [b.prevented(subject, to,
                            evidence=_E.REJECTED_BEFORE_CROSSING)])
        r = summary(s7)
        _check(r.permission_actions == 1 and r.distinct_disclosures == 0,
               "phase3-synthetic-sequences")
        _check(r.unresolved_actions == 0, "phase3-synthetic-resolution")

        # Adversarial: a partial receipt, a conflict, unresolved tokens,
        # the grouped percentage, and an invalid record.
        s8 = b.session(); sids.append(s8)
        action = uuid.uuid4().hex
        other = b.value("adv-other")
        record(b.observation(s8, action_id=action),
               [b.event(subject, to, kind="detected",
                        evidence=_E.LOCAL_DETECTION),
                b.event(other, to, kind="detected",
                        evidence=_E.LOCAL_DETECTION)])
        record(b.crossed(s8, action_id=action), [b.event(subject, to)])
        _check(summary(s8).unresolved_actions == 1,
               "phase3-synthetic-resolution")
        record(b.observation(s8, action_id=action, hook_event="PostToolUse",
                             phase="post", decision="none",
                             evidence=_E.REJECTED_BEFORE_CROSSING,
                             resolution_scope="boundary",
                             potential_crossing=False), [])
        r = summary(s8)
        _check(r.unresolved_actions == 1 and r.percent is None
               and _close(r.confirmed_points, email_b3),
               "phase3-synthetic-resolution")
        unresolved = record(b.crossed(s8), [
            b.event(SubjectInput(subject_kind="value", identity_hash=None),
                    to),
            b.event(SubjectInput(subject_kind="value", identity_hash=None),
                    to)])
        subjects = {row[0] for row in led.conn.execute(
            "SELECT subject_id FROM events WHERE observation_id=?",
            (unresolved.observation_id,))}
        _check(len(subjects) == 2 and unresolved.budget_delta == 0.0,
               "phase3-synthetic-resolution")

        s9 = b.session(); sids.append(s9)
        model = b.to("model_context", "model context")
        record(b.crossed(s9, boundary="B1"),
               [b.event(b.value(f"grouped-{i}"), model, boundary="B1")
                for i in range(12)])
        r = summary(s9)
        _check(r.percent == 17 and _close(
            r.confirmed_points, group_score(profile, "email",
                                            "model_context", 12)),
            "phase3-synthetic-scoring")

        counts = {t: led.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in _V2_TABLES}
        try:
            record(b.crossed(s9, delivery_key="not-a-delivery-key"),
                   [b.event(b.value("rejected"), to)])
            rejected = False
        except ValueError:
            rejected = True
        _check(rejected, "phase3-synthetic-sequences")
        _check(counts == {
            t: led.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in _V2_TABLES}, "phase3-synthetic-sequences")
    finally:
        led.conn.close()

    # A frozen Phase 3 compatibility scenario, not a claim about current
    # production. Phase 3 production created a legacy session through the
    # legacy session boundary; that path is replayed here, explicitly, and
    # must still yield a legacy session on a prepared copy. Since #54 Phase
    # 4 a genuine production SessionStart activates version-2 accounting,
    # which only the Phase 4 rehearsal exercises. The check keeps its fixed
    # name so historical output stays comparable.
    production = _PRODUCTION_PREFIX + uuid.uuid4().hex
    with _silenced():
        state = dispatch.new_state(path.parent,
                                   writer_lease=_lease(path))
    try:
        with state.ledger._write_transaction():
            if not state.ledger.session_exists(production):
                state.ledger.prepare_session_boundary(production)
            state.ledger.start_session(production, cwd="", model="")
        version = state.ledger.conn.execute(
            "SELECT accounting_version FROM sessions WHERE session_id=?",
            (production,)).fetchone()
        _check(version is not None and version[0] == 1,
               "phase3-production-legacy")
        _check(state.ledger.summary(production).accounting_version == 1,
               "phase3-production-legacy")
    finally:
        state.ledger.conn.close()

    led = Ledger(path, matrix, writer_lease=_lease(path))
    try:
        for sid, row in originals.items():
            current = led.conn.execute(
                "SELECT * FROM sessions WHERE session_id=?",
                (sid,)).fetchone()
            _check(current is not None and tuple(current) == row,
                   "phase3-preservation")
        _check(_cells(led.conn, "events_legacy_v1")[:len(legacy_rows)]
               == legacy_rows, "phase3-preservation")
        _check(ledger_schema.validate_schema(led.conn)
               == ledger_schema.PREPARED_VERSION, "phase3-preservation")
        _check(not any(v[0] in _V2_TABLES
                       for v in _fk_violations(led.conn)),
               "phase3-foreign-keys")
        readings = _v2_readings(led, sids)
    finally:
        led.conn.close()

    reader = Ledger(path, matrix, initialize=False)
    try:
        _check(_v2_readings(reader, sids) == readings,
               "phase3-synthetic-sequences")
    finally:
        reader.conn.close()

    led = Ledger(path, matrix, writer_lease=_lease(path))
    try:
        b = _Records(led, profile)
        score = led.summary(s1).confirmed_points
        led.mark_accounting_unavailable(s1)
        late = led.record_observation(b.crossed(s1), [b.event(
            SubjectInput(subject_kind="value", identity_hash=None),
            RecipientInput(destination_kind="mcp_tool", identity_hash=None))])
        try:
            led.record_observation(b.crossed(s1), [b.event(
                b.value("after-unavailable"), b.to())])
            refused = False
        except ValueError:
            refused = True
        r = led.summary(s1)
        _check(refused and late.budget_delta == 0.0
               and r.accounting_status == "unavailable"
               and r.confirmed_points == score, "phase3-synthetic-scoring")

        def history(sid: str) -> dict:
            return {t: [tuple(x) for x in led.conn.execute(
                f"SELECT * FROM {t} WHERE session_id=? ORDER BY rowid",
                (sid,))] for t in ("observations", "events", "disclosures")}

        def identities(sid: str) -> list:
            return [tuple(x) for x in led.conn.execute(
                "SELECT subject_id, resolution, label FROM subjects"
                " WHERE session_id=? UNION ALL"
                " SELECT recipient_id, resolution, label FROM recipients"
                " WHERE session_id=? ORDER BY 1", (sid, sid))]

        kept, ids = history(s5), identities(s5)
        score = led.summary(s5).confirmed_points
        led.end_session(s5)
        hashes = led.conn.execute(
            "SELECT (SELECT COUNT(*) FROM subjects WHERE session_id=?"
            " AND identity_hash IS NOT NULL)"
            " + (SELECT COUNT(*) FROM recipients WHERE session_id=?"
            " AND identity_hash IS NOT NULL)", (s5, s5)).fetchone()[0]
        _check(hashes == 0 and history(s5) == kept
               and identities(s5) == ids
               and led.summary(s5).confirmed_points == score
               and led.conn.execute(
                   "SELECT ended_at FROM sessions WHERE session_id=?",
                   (s5,)).fetchone()[0] is not None,
               "phase3-synthetic-erasure")

        again = led.record_observation(retry_obs, retry_events)
        _check(again.duplicate_delivery
               and again.observation_id == retry_first.observation_id
               and again.event_ids == retry_first.event_ids
               and again.disclosure_ids == retry_first.disclosure_ids
               and again.budget_delta == retry_first.budget_delta
               and history(s5) == kept, "phase3-synthetic-retry")
    finally:
        led.conn.close()


def _run_child(args: list[str]) -> subprocess.CompletedProcess[str]:
    """One crash child. Its output is kept in memory and never printed."""
    return subprocess.run([sys.executable, *args], capture_output=True,
                          text=True, timeout=300)


def _signature(raw: sqlite3.Connection, sid: str) -> tuple:
    """Complete typed rows, including original sessions and legacy data."""
    return tuple((table, tuple(_cells(raw, table)))
                 for table in _tables(raw))


def _check_v2_crash_atomicity(
    baseline: Path, work: Path,
) -> None:
    """Terminate an observation write and a version-2 end after every
    mutating statement and around the outer COMMIT, each on a fresh clone:
    before commit the clone is exactly the baseline, after it the complete
    operation."""
    matrix = load_matrix()
    _mkdir(work)
    base = work / "base.db"
    _copy(baseline, base)
    led = Ledger(base, matrix, writer_lease=_lease(base))
    try:
        records = _Records(led, ScoringProfile.from_matrix(matrix))
        sid = records.session()
        led.record_observation(records.crossed(sid), [records.event(
            records.value("crash-before"), records.to())])
        key = records.key.hex()
    finally:
        led.conn.close()
    raw = _raw(base)
    try:
        tables = _tables(raw)
        cells = {t: _cells(raw, t) for t in tables}
        layouts = {t: _layout(raw, t) for t in tables}
        schema = _schema(raw)
        violations = _fk_violations(raw)
    finally:
        raw.close()

    child = work / "child.py"
    child.write_text(_CHILD3, encoding="utf-8")
    os.chmod(child, 0o600)
    delivery = uuid.uuid4().hex

    def clone(name: str) -> Path:
        path = work / name
        _copy(base, path)
        return path

    def remove(path: Path) -> None:
        for suffix in ("", "-wal", "-shm"):
            target = Path(str(path) + suffix)
            if target.exists():
                target.unlink()

    def run(path: Path, op: str, stop: int):
        return _run_child([str(child), op, str(stop), str(path),
                           str(REPO / "src"), sid, key, delivery])

    for op in ("observe", "end"):
        path = clone(f"{op}-dry.db")
        proc = run(path, op, -2)
        _check(proc.returncode == 6 and proc.stdout.isdigit(),
               "phase3-crash-child")
        mutations = int(proc.stdout)
        _check(mutations >= 1, "phase3-crash-child")
        raw = _raw(path)
        try:
            expected = _signature(raw, sid)
        finally:
            raw.close()
        remove(path)

        for stop in list(range(1, mutations + 1)) + [0, -1]:
            path = clone(f"{op}-{stop}.db")
            proc = run(path, op, stop)
            code = 5 if stop == -1 else 4 if stop == 0 else 3
            _check(proc.returncode == code, "phase3-crash-child")
            raw = _raw(path)
            try:
                _check(ledger_schema.validate_schema(raw)
                       == ledger_schema.PREPARED_VERSION, "phase3-crash-state")
                _check(_schema(raw) == schema, "phase3-crash-state")
                for table in tables:
                    _check(_layout(raw, table) == layouts[table],
                           "phase3-crash-state")
                if stop == -1:
                    _check(_signature(raw, sid) == expected,
                           "phase3-crash-state")
                else:
                    for table in tables:
                        _check(_cells(raw, table) == cells[table],
                               "phase3-crash-state")
                charged = raw.execute(
                    "SELECT COALESCE(SUM(budget_delta), 0) FROM disclosures"
                    " WHERE session_id=?", (sid,)).fetchone()[0]
                score = raw.execute(
                    "SELECT budget_score FROM sessions WHERE session_id=?",
                    (sid,)).fetchone()[0]
                _check(_close(score, charged), "phase3-crash-state")
                _check(_fk_violations(raw) == violations,
                       "phase3-foreign-keys")
            finally:
                raw.close()
            remove(path)
    remove(base)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument(
        "--phase", required=True, type=int, choices=(2, 3),
    )
    args = parser.parse_args(argv)
    try:
        source, work = args.source, args.work_dir
        _check(source.is_file() and not source.is_symlink(), "source")
        _private_dir(work)
        _check(source.resolve().parent != work.resolve(), "source-in-work-dir")
        if args.phase == 2:
            phase2(source, work)
        else:
            phase3(source, work)
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
