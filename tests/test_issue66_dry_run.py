# tests/test_issue66_dry_run.py
"""#66's private-copy rehearsal script.

`scripts/check-issue66-runtime.py` is what is run against a copy of the
owner's real ledger before 0.8.0 is run against the ledger itself, so the
three things it must never do are the three things tested here: it must
not change the source, it must not accept a work directory anyone else
can read, and it must not print anything it read.

The synthetic source is shaped like a real one — a session, a recorded
row, a scan gap and a policy rule — with its rows still in the
write-ahead log, because a rehearsal that quietly missed committed WAL
contents would rehearse against a smaller database than the owner has.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from privacy_hud import runtime_storage as storage
from privacy_hud.matrix.loader import load_matrix
from runtime_helpers import writer_ledger

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check-issue66-runtime.py"
PLANTED = "planted-66a31f-value"
PASS_LINE = ("Issue 66 private-ledger checks: PASS. No ledger values were "
             "printed.\n")
FAIL_LINE = "Private-ledger check failed. No ledger values were printed.\n"


def _source(tmp_path: Path):
    """A private ledger with an open connection, so its committed rows are
    still in the WAL. Returns `(path, ledger)`; the caller closes it."""
    path = tmp_path / "src" / "ledger.db"
    path.parent.mkdir()
    led = writer_ledger(path, load_matrix())
    led.start_session(f"sess-{PLANTED}", cwd=f"/{PLANTED}", model="m")
    led.record(f"sess-{PLANTED}", turn_id="t", kind="exposed",
               data_type="email", source=f"{PLANTED}.log",
               destination="model_context", value_hash=b"\x01" * 16,
               masked_example=f"{PLANTED}@x", tool_name="Read",
               protection=None, source_kind="path")
    led.record_scan_gap(f"sess-{PLANTED}", boundary="B3", reason="timeout")
    led.add_policy(f"sess-{PLANTED}", rule_type="block_path",
                   selector=f"/{PLANTED}")
    return path, led


def _work(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    os.chmod(work, 0o700)
    return work


def _run(source: Path, work: Path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--source", str(source),
         "--work-dir", str(work)],
        capture_output=True, text=True, timeout=1800)


def _bytes(path: Path) -> dict[str, bytes]:
    """The database and its write-ahead log.

    `-shm` is SQLite's shared-memory index, which any reader may rewrite
    and which holds no ledger data. A zero-length `-wal` is dropped for
    the same reason: SQLite creates one beside a WAL-mode database even
    for a read-only connection, and an empty log is the absence of a log
    rather than a change to one.
    """
    out = {}
    for name in (path.name, path.name + "-wal"):
        candidate = path.parent / name
        if not candidate.exists():
            continue
        blob = candidate.read_bytes()
        if name.endswith("-wal") and not blob:
            continue
        out[name] = blob
    return out


def test_private_rehearsal_preserves_source(tmp_path):
    """The source is read and nothing else: same bytes, same permissions,
    and the transition it rehearsed happened entirely inside the work
    directory."""
    source, led = _source(tmp_path)
    try:
        assert Path(str(source) + "-wal").stat().st_size > 0
        before = _bytes(source)
        mode = source.stat().st_mode
        work = _work(tmp_path)

        proc = _run(source, work)

        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == PASS_LINE
        assert _bytes(source) == before
        assert source.stat().st_mode == mode
        assert not storage.is_fenced(source.parent)
        assert not (source.parent / "legacy-retired").exists()
        assert not (source.parent / storage.JOURNAL_NAME).exists()

        # The committed rows that lived only in the WAL reached the copy.
        copy = sqlite3.connect(work / "snapshot.db")
        try:
            assert copy.execute(
                "SELECT COUNT(*) FROM events WHERE source=?",
                (f"{PLANTED}.log",)).fetchone()[0] == 1
        finally:
            copy.close()
        assert storage.is_fenced(work / "cutover")
        assert storage.active_path(work / "cutover").is_file()
    finally:
        led.conn.close()


def test_private_rehearsal_never_prints_values_or_exception_text(tmp_path):
    """Both outcomes, and neither says anything about what it read.

    A rehearsal that printed a row, a path, an id or a traceback would be
    a command the owner could not paste into a bug report — which is the
    one thing it exists to be. The failing half is driven by a source that
    is not a ledger at all, so the refusal comes out of an exception
    rather than a planned branch: that is the path a traceback would
    escape through.
    """
    source, led = _source(tmp_path)
    try:
        good = _run(source, _work(tmp_path))
        assert good.returncode == 0, good.stderr
        assert good.stdout == PASS_LINE
        assert good.stderr == ""
        assert PLANTED not in good.stdout + good.stderr
    finally:
        led.conn.close()

    broken = tmp_path / "broken" / "ledger.db"
    broken.parent.mkdir()
    broken.write_bytes(b"SQLite format 3\x00" + PLANTED.encode() * 8)
    work = tmp_path / "work-broken"
    work.mkdir(mode=0o700)
    os.chmod(work, 0o700)

    bad = _run(broken, work)

    assert bad.returncode != 0
    assert bad.stdout == FAIL_LINE
    assert bad.stderr.startswith("check: ")
    assert len(bad.stderr.splitlines()) == 1
    assert PLANTED not in bad.stdout + bad.stderr
    for banned in ("Traceback", "sqlite3.", "Error", str(broken),
                   "SELECT", "PRAGMA"):
        assert banned not in bad.stdout + bad.stderr


@pytest.mark.parametrize("generation", [5402, 4])
def test_private_rehearsal_refuses_an_unsupported_generation(tmp_path,
                                                             generation):
    source, led = _source(tmp_path)
    led.conn.close()
    raw = sqlite3.connect(source)
    raw.execute(f"PRAGMA user_version={generation}")
    raw.close()
    before = _bytes(source)

    proc = _run(source, _work(tmp_path))

    assert proc.returncode != 0
    assert proc.stdout == FAIL_LINE
    assert proc.stderr.strip() == "check: source-schema"
    assert PLANTED not in proc.stdout + proc.stderr
    assert _bytes(source) == before


def test_private_rehearsal_refuses_an_altered_prepared_source(tmp_path):
    """A prepared ledger with a column nobody's schema declares is
    preserved and refused, never repaired."""
    source, led = _source(tmp_path)
    with led._write_transaction():
        led.prepare_session_boundary("s2")
        led.start_session("s2", cwd="", model="")
    led.conn.close()
    raw = sqlite3.connect(source)
    raw.execute("ALTER TABLE events ADD COLUMN unexpected_column TEXT")
    raw.commit()
    raw.close()
    before = _bytes(source)

    proc = _run(source, _work(tmp_path))

    assert proc.returncode != 0
    assert proc.stdout == FAIL_LINE
    assert proc.stderr.startswith("check: ")
    assert PLANTED not in proc.stdout + proc.stderr
    assert _bytes(source) == before


@pytest.mark.parametrize("problem", ["not-empty", "group-readable",
                                     "source-inside", "not-a-directory"])
def test_private_rehearsal_requires_empty_owner_only_workdir(tmp_path,
                                                             problem):
    """Four ways a work directory is the wrong place to copy a ledger
    into, each refused before anything is copied."""
    source, led = _source(tmp_path)
    try:
        work = _work(tmp_path)
        if problem == "not-empty":
            (work / "x").write_text("x")
        elif problem == "group-readable":
            os.chmod(work, 0o750)
        elif problem == "not-a-directory":
            work = tmp_path / "file"
            work.write_text("not a directory")
        else:
            work = source.parent
            os.chmod(work, 0o700)
        before = _bytes(source)

        proc = _run(source, work)

        assert proc.returncode != 0
        assert proc.stdout == FAIL_LINE
        assert proc.stderr.strip() == "check: work-dir"
        assert PLANTED not in proc.stdout + proc.stderr
        assert _bytes(source) == before
    finally:
        led.conn.close()


def test_private_rehearsal_accepts_a_prepared_source(tmp_path):
    """Generation 5401 is preserved by the transition, not migrated by
    it: the accounting rebuild already happened and this release does not
    repeat it."""
    source, led = _source(tmp_path)
    with led._write_transaction():
        led.prepare_session_boundary("s2")
        led.start_session("s2", cwd="", model="")
    try:
        before = _bytes(source)
        work = _work(tmp_path)

        proc = _run(source, work)

        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == PASS_LINE
        assert _bytes(source) == before
        active = storage.active_path(work / "cutover")
        conn = sqlite3.connect(active)
        try:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 5401
        finally:
            conn.close()
    finally:
        led.conn.close()
