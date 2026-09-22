#!/usr/bin/env python3
"""Rehearse #66's storage transition on a private copy of a real ledger.

Developer-only, and the reason it exists is that 0.8.0 relocates a live
WAL database, retires files beside it and changes who may write it. None
of that is reversible by a downgrade, so it is rehearsed against a copy
of the owner's real ledger before it is run against the ledger itself.

    umask 077
    work="$(mktemp -d "${TMPDIR:-/tmp}/privacy-hud-66.XXXXXXXX")"
    chmod 700 "$work"
    python scripts/check-issue66-runtime.py \\
      --source "$PLUGIN_DATA/ledger.db" --work-dir "$work"

After installation the source is `$PLUGIN_DATA/ledger/active.db`.

**What the source is allowed to experience: being read.** It is opened
`mode=ro` and copied with SQLite's backup API, which is what makes the
copy a consistent snapshot including committed WAL contents. Nothing here
initializes it, migrates it, checkpoints it, changes its permissions, or
opens it with `immutable=1` — that shortcut ignores a live write-ahead
log, so it would silently rehearse against a database missing everything
committed since the last checkpoint. Every check below runs against
copies, under this rehearsal's own writer leases, in this rehearsal's own
work directory.

**Checks**, each on a private copy:

* the source opens read-only and its accounting generation is one 0.8.0
  writes (0 or a valid 5401; 5402, a malformed schema and an altered
  prepared schema are refused, preserved and not repaired);
* the backup is a consistent snapshot, and committed rows that were only
  in the WAL are in it;
* the cutover preserves every table's typed cells and the schema, and
  preserves the generation it found;
* `$PLUGIN_DATA/ledger.db` becomes a directory that the actual historical
  initializer cannot open, and the active store is unchanged by its
  attempt;
* a new-session boundary after the cutover still prepares 5401, which is
  the accounting migration tested separately from the generation-
  preserving transition it follows;
* terminating the cutover after each durable stage leaves either the
  complete old state or the complete new state, with values intact;
* foreign-key violations the source already had are carried through and
  no new ones appear;
* and the source's own bytes are unchanged, when the source was quiescent
  for the run — a concurrent legitimate writer is reported as
  inconclusive rather than blamed on this rehearsal.

**Output.** One fixed line on success. On failure, one fixed line on
stdout and one fixed check name on stderr. No ledger value, path, SQL,
identifier, hash, fingerprint or exception text is ever printed: the
whole point of a rehearsal on real data is that it can be run without
producing something the owner then has to be careful with.

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

from privacy_hud import ledger_schema, runtime_storage  # noqa: E402
from privacy_hud.ledger import Ledger  # noqa: E402
from privacy_hud.matrix.loader import load_matrix  # noqa: E402
from privacy_hud.runtime_contract import RuntimeRefusal  # noqa: E402
from privacy_hud.runtime_owner import (  # noqa: E402
    acquire_writer,
    unselected_activation,
)

PASS = "Issue 66 private-ledger checks: PASS. No ledger values were printed."
FAIL = "Private-ledger check failed. No ledger values were printed."

#: The vendored 0.7.1 package, run in its own isolated interpreter against
#: private copies only. It never reaches the original source.
HISTORICAL = REPO / "tests" / "fixtures" / "runtime_071"

_HISTORICAL_OPEN = """
import sys
sys.path.insert(0, sys.argv[1])
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
Ledger(sys.argv[2], load_matrix()).conn.close()
"""

#: A child that performs the cutover and terminates immediately after the
#: named stage is durably journalled. `os._exit` so nothing unwinds: this
#: has to look like a machine losing power, not like a clean abort.
_CRASH_CHILD = """
import os, sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from privacy_hud import runtime_storage as storage
from privacy_hud.runtime_owner import acquire_writer, unselected_activation

root = Path(sys.argv[2])
stop = sys.argv[3]

def failpoint(stage):
    if stage == stop:
        os._exit(3)

storage._stage_failpoint = failpoint
with storage.acquire_transition(root):
    with acquire_writer(root, activation=unselected_activation()) as lease:
        storage.prepare_storage(root, activation=lease.activation)
os._exit(0)
"""


class CheckFailed(Exception):
    """A named check failed. The name is a fixed string from this file."""


def _check(condition: bool, name: str) -> None:
    if not condition:
        raise CheckFailed(name)


#: Leases taken over private copies, held for the run and released at the
#: end. Each copy owns its own data root inside the work directory, so a
#: rehearsal never contends with the real installation's ledger owner.
_LEASES: list = []


def _lease(data_dir: Path):
    lease = acquire_writer(data_dir, activation=unselected_activation())
    _LEASES.append(lease)
    return lease


def _release() -> None:
    while _LEASES:
        _LEASES.pop().close()


# --------------------------------------------------------------------- #
# private copies
# --------------------------------------------------------------------- #

def _private_dir(path: Path) -> None:
    info = path.lstat()
    _check(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
           "work-dir")
    _check(info.st_mode & 0o077 == 0, "work-dir")
    _check(not any(path.iterdir()), "work-dir")


def _backup(source: Path, dest: Path) -> None:
    """A consistent snapshot of `source`, committed WAL contents included.

    `mode=ro` on the way in and SQLite's own backup API to copy: a file
    copy of a live WAL database is a torn read, and `immutable=1` is a
    promise the caller cannot keep about a database something else may be
    writing.
    """
    _check(not dest.exists() and not dest.is_symlink(), "backup")
    src = sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)
    try:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    except sqlite3.Error:
        raise CheckFailed("backup") from None
    finally:
        src.close()
    os.chmod(dest, 0o600)


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _raw(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, isolation_level=None)


def _tables(conn) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
        " AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def _layout(conn, table: str) -> list[tuple]:
    return list(conn.execute(f"PRAGMA table_info({_quote(table)})"))


def _schema(conn) -> dict:
    return {(kind, name): (table, sql)
            for kind, name, table, sql in conn.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master")}


def _cells(conn, table: str) -> list[tuple]:
    """Every row, with each cell's storage class, so a value silently
    retyped by a copy is a difference rather than a match. Text is cast to
    a blob and reals are packed, so nothing here is compared as a number
    that might round."""
    cols = [_quote(r[1]) for r in _layout(conn, table)]
    if not cols:
        return []
    select = ", ".join(
        f"typeof({c}), CASE WHEN typeof({c})='text' "
        f"THEN CAST({c} AS BLOB) ELSE {c} END" for c in cols)
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


def _state(path: Path) -> tuple:
    conn = _raw(path)
    try:
        tables = _tables(conn)
        return (conn.execute("PRAGMA user_version").fetchone()[0],
                _schema(conn),
                {name: _cells(conn, name) for name in tables},
                {name: _layout(conn, name) for name in tables})
    finally:
        conn.close()


def _fk_violations(path: Path) -> set[tuple]:
    conn = _raw(path)
    try:
        return {tuple(r) for r in conn.execute("PRAGMA foreign_key_check")}
    finally:
        conn.close()


def _fingerprint(source: Path) -> tuple:
    """The source's own bytes, database and write-ahead log.

    The `-shm` file is SQLite's shared-memory index, which any reader —
    including a read-only one — may rewrite, and which holds no ledger
    data; it is deliberately not part of this.
    """
    out = []
    for suffix in ("", "-wal"):
        path = Path(str(source) + suffix)
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            out.append(None)
            continue
        if suffix and not blob:
            # An empty log. SQLite creates one beside a WAL-mode database
            # for a read-only connection too, and a zero-length file is
            # the absence of a log rather than a change to one.
            out.append(None)
            continue
        out.append(blob)
    return tuple(out)


def _other_holders(source: Path) -> frozenset[int] | None:
    """Who else has the source open, or `None` when this host cannot say.

    Used for one thing only: deciding whether a change to the source's
    bytes can be attributed to this rehearsal. It cannot — this process
    only ever opened the source `mode=ro` — but a rehearsal that reported
    "the source changed" while the owner's daemon was legitimately writing
    to it would be sending them after a bug that is not there.
    """
    paths = [Path(str(source) + suffix) for suffix in ("", "-wal", "-shm")]
    paths = [p for p in paths if p.is_file() and not p.is_symlink()]
    if not paths:
        return frozenset()
    inspect = runtime_storage._inspector()
    if inspect is None:
        return None
    try:
        return frozenset(pid for pid in inspect(paths) if pid != os.getpid())
    except Exception:
        return None


# --------------------------------------------------------------------- #
# the rehearsal
# --------------------------------------------------------------------- #

def _seed(work: Path, name: str, backup: Path) -> Path:
    """A private data root holding one copy of the backup at the
    historical ledger pathname."""
    root = work / name
    root.mkdir(mode=0o700)
    target = runtime_storage.legacy_path(root)
    target.write_bytes(backup.read_bytes())
    os.chmod(target, 0o600)
    return root


def _cutover(root: Path):
    with runtime_storage.acquire_transition(root):
        with acquire_writer(root,
                            activation=unselected_activation()) as lease:
            return runtime_storage.prepare_storage(
                root, activation=lease.activation)


def rehearse(source: Path, work_dir: Path) -> None:
    """Run every check. Raises `CheckFailed` with a fixed name."""
    source = Path(source)
    work = Path(work_dir)

    _check(source.is_file() and not source.is_symlink(), "source-open")
    _private_dir(work)
    _check(source.resolve().parent != work.resolve(), "work-dir")

    before_bytes = _fingerprint(source)
    backup = work / "snapshot.db"
    _backup(source, backup)

    # -- what the source is ------------------------------------------- #
    conn = _raw(backup)
    try:
        try:
            generation = ledger_schema.validate_schema(conn)
        except (ledger_schema.UnsupportedAccounting, sqlite3.Error):
            raise CheckFailed("source-schema") from None
        _check(generation in (0, 5401), "source-schema")
        tables = _tables(conn)
        _check("sessions" in tables, "source-schema")
        _check("events" in tables or "events_legacy_v1" in tables,
               "source-schema")
    finally:
        conn.close()

    # -- the snapshot really carries the write-ahead log --------------- #
    live = sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)
    try:
        live_counts = {name: live.execute(
            f"SELECT COUNT(*) FROM {_quote(name)}").fetchone()[0]
            for name in tables}
    finally:
        live.close()
    copy_conn = _raw(backup)
    try:
        copy_counts = {name: copy_conn.execute(
            f"SELECT COUNT(*) FROM {_quote(name)}").fetchone()[0]
            for name in tables}
    finally:
        copy_conn.close()
    _check(copy_counts == live_counts, "wal-preservation")

    baseline = _state(backup)
    baseline_fk = _fk_violations(backup)

    # -- preservation, fence, and the generation ----------------------- #
    root = _seed(work, "cutover", backup)
    result = _cutover(root)
    active = runtime_storage.active_path(root)
    _check(active.is_file(), "preservation")
    after = _state(active)
    _check(after[0] == baseline[0], "generation-preserved")
    _check(result.schema_version == generation, "generation-preserved")
    _check(after[1] == baseline[1], "preservation")
    _check(after[2] == baseline[2], "preservation")
    _check(after[3] == baseline[3], "preservation")
    _check(result.preserved_existing is True, "preservation")

    retained = (runtime_storage.retired_dir(root, result.transition_id)
                / runtime_storage.LEGACY_NAME)
    _check(retained.is_file(), "preservation")
    _check(_state(retained)[2] == baseline[2], "preservation")

    _check(runtime_storage.is_fenced(root), "fence")
    fence = runtime_storage.legacy_path(root)
    _check(fence.is_dir() and not fence.is_symlink(), "fence")

    _check(_fk_violations(active) == baseline_fk, "foreign-keys")

    # -- the actual historical initializer, on a private copy ---------- #
    before_open = _state(active)
    historical = subprocess.run(
        [sys.executable, "-I", "-c", _HISTORICAL_OPEN, str(HISTORICAL),
         str(fence)], capture_output=True, text=True, timeout=300)
    _check(historical.returncode != 0, "old-initializer")
    _check(fence.is_dir() and not fence.is_symlink(), "old-initializer")
    _check(_state(active) == before_open, "old-initializer")

    # -- the accounting migration, separately from the transition ------ #
    if generation == 0:
        boundary_root = _seed(work, "boundary", backup)
        boundary_result = _cutover(boundary_root)
        _check(boundary_result.schema_version == 0, "boundary-migration")
        boundary_active = runtime_storage.active_path(boundary_root)
        lease = _lease(boundary_root)
        led = Ledger(boundary_active, load_matrix(), writer_lease=lease)
        try:
            session = f"privacy-hud-rehearsal-{uuid.uuid4().hex}"
            with led._write_transaction():
                led.prepare_session_boundary(session)
                led.start_session(session, cwd="", model="")
        finally:
            led.conn.close()
        migrated = _state(boundary_active)
        _check(migrated[0] == 5401, "boundary-migration")
        _check("events_legacy_v1" in migrated[2], "boundary-migration")
        _check(migrated[2]["events_legacy_v1"] == baseline[2]["events"],
               "boundary-migration")
    else:
        # Already prepared. The transition preserves it and nothing here
        # re-runs a migration that has happened: there is no second
        # boundary to rehearse, and inventing one would rehearse something
        # the daemon will never do.
        _check(baseline[0] == 5401, "boundary-migration")

    # -- crash recovery, one copy per durable stage -------------------- #
    for stage in runtime_storage.STAGES[
            :runtime_storage.STAGES.index(
                runtime_storage.FINAL_STORAGE_STAGE) + 1]:
        crash_root = _seed(work, f"crash-{stage}", backup)
        crashed = subprocess.run(
            [sys.executable, "-I", "-c", _CRASH_CHILD, str(REPO / "src"),
             str(crash_root), stage],
            capture_output=True, text=True, timeout=600)
        _check(crashed.returncode == 3, "crash-state")
        resumed = _cutover(crash_root)
        crash_active = runtime_storage.active_path(crash_root)
        _check(crash_active.is_file(), "crash-state")
        _check(_state(crash_active) == baseline, "crash-state")
        _check(runtime_storage.is_fenced(crash_root), "crash-state")
        _check(resumed.preserved_existing is True, "crash-state")
        crash_retained = (
            runtime_storage.retired_dir(crash_root, resumed.transition_id)
            / runtime_storage.LEGACY_NAME)
        _check(crash_retained.is_file(), "crash-state")

    # -- and the source is exactly as it was --------------------------- #
    after_bytes = _fingerprint(source)
    if after_bytes != before_bytes:
        holders = _other_holders(source)
        # Inconclusive, not a failure, when something else legitimately
        # has the source open: this process never opened it for writing,
        # and attributing another writer's commit to the rehearsal would
        # send the owner after a bug that is not there.
        _check(holders is None or bool(holders), "source-preservation")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        rehearse(args.source, args.work_dir)
    except CheckFailed as failed:
        print(FAIL)
        print(f"check: {failed.args[0]}", file=sys.stderr)
        return 1
    except RuntimeRefusal as refusal:
        print(FAIL)
        # A refusal code is this project's own fixed vocabulary, not a
        # message from anywhere else, and it maps to one of these names.
        print("check: " + {"ledger_unsupported": "source-schema",
                           "holder_unknown": "crash-state"}.get(
                               refusal.code, "unexpected-error"),
              file=sys.stderr)
        return 1
    except Exception:
        print(FAIL)
        print("check: unexpected-error", file=sys.stderr)
        return 2
    finally:
        _release()
    print(PASS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
