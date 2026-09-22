"""#54 Phase 2: the private-copy rehearsal script.

Runs `scripts/check-issue54-ledger.py` against a synthetic ledger shaped
like a real one, with committed rows still in its WAL. The source must be
unchanged, the work files private, and no planted value may reach stdout
or stderr.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check-issue54-ledger.py"
PLANTED = "planted-7c1e9a-value"


def _source(tmp_path: Path):
    path = tmp_path / "src" / "ledger.db"
    path.parent.mkdir()
    led = Ledger(path, load_matrix())
    led.start_session(f"sess-{PLANTED}", cwd=f"/{PLANTED}", model="m")
    led.record(f"sess-{PLANTED}", turn_id="t", kind="exposed",
               data_type="email", source=f"{PLANTED}.log",
               destination="model_context", value_hash=b"\x01" * 16,
               masked_example=f"{PLANTED}@x", tool_name="Read",
               protection=None, source_kind="path")
    led.record_scan_gap(f"sess-{PLANTED}", boundary="B3", reason="timeout")
    led.add_policy(f"sess-{PLANTED}", rule_type="block_path",
                   selector=f"/{PLANTED}")
    return path, led  # the open connection keeps rows in the WAL


def _work(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    os.chmod(work, 0o700)
    return work


def _run(source: Path, work: Path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--source", str(source),
         "--work-dir", str(work), "--phase", "2"],
        capture_output=True, text=True, timeout=600)


def _bytes(path: Path) -> dict[str, bytes]:
    """The database and its WAL. The `-shm` file is SQLite's shared-memory
    index, which any reader, even a read-only one, may rewrite; it holds no
    ledger data."""
    return {p.name: p.read_bytes() for p in path.parent.iterdir()
            if p.name in (path.name, path.name + "-wal")}


def test_rehearsal_passes_and_leaves_the_source_unchanged(tmp_path):
    source, led = _source(tmp_path)
    try:
        assert Path(str(source) + "-wal").stat().st_size > 0
        before = _bytes(source)
        work = _work(tmp_path)
        proc = _run(source, work)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == ("Phase 2 private-ledger checks: PASS. No "
                               "ledger values were printed.\n")
        assert PLANTED not in proc.stdout + proc.stderr
        assert _bytes(source) == before
        for path in work.iterdir():
            if path.suffix == ".db":
                assert path.stat().st_mode & 0o077 == 0, path.name
        copy = sqlite3.connect(work / "copy.db")
        try:
            assert copy.execute("PRAGMA user_version").fetchone()[0] == 5401
            # The committed rows that were only in the WAL were copied.
            assert copy.execute(
                "SELECT COUNT(*) FROM events_legacy_v1 WHERE source=?",
                (f"{PLANTED}.log",)).fetchone()[0] == 1
        finally:
            copy.close()
    finally:
        led.conn.close()


@pytest.mark.parametrize("problem", ["not-empty", "group-readable",
                                     "source-inside"])
def test_rehearsal_refuses_an_unsafe_work_dir(tmp_path, problem):
    source, led = _source(tmp_path)
    try:
        work = _work(tmp_path)
        if problem == "not-empty":
            (work / "x").write_text("x")
        elif problem == "group-readable":
            os.chmod(work, 0o750)
        else:
            work = source.parent
            os.chmod(work, 0o700)
        proc = _run(source, work)
        assert proc.returncode != 0
        assert proc.stdout == ("Private-ledger check failed. No ledger values "
                               "were printed.\n")
        assert PLANTED not in proc.stdout + proc.stderr
    finally:
        led.conn.close()


def test_rehearsal_refuses_an_already_prepared_source(tmp_path):
    source, led = _source(tmp_path)
    with led._write_transaction():
        led.prepare_session_boundary("new")
        led.start_session("new", cwd="", model="")
    led.conn.close()
    proc = _run(source, _work(tmp_path))
    assert proc.returncode != 0
    assert PLANTED not in proc.stdout + proc.stderr


def test_rehearsal_handles_a_ledger_without_newer_legacy_tables(tmp_path):
    """A real ledger from before `scan_gaps` existed: the daemon's startup
    adds the table before any boundary, and the rehearsal checks against
    that state."""
    source, led = _source(tmp_path)
    led.conn.close()
    raw = sqlite3.connect(source)
    raw.execute("DROP TABLE scan_gaps")
    raw.close()
    proc = _run(source, _work(tmp_path))
    assert proc.returncode == 0, proc.stderr
    assert PLANTED not in proc.stdout + proc.stderr
