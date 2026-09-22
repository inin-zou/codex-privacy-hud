"""#54 Phases 2 and 3: the private-copy rehearsal script.

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

from privacy_hud.matrix.loader import load_matrix
from runtime_helpers import writer_ledger

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check-issue54-ledger.py"
PLANTED = "planted-7c1e9a-value"


def _source(tmp_path: Path):
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
    return path, led  # the open connection keeps rows in the WAL


def _work(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    os.chmod(work, 0o700)
    return work


def _run(
    source: Path, work: Path, phase: int = 2,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--source", str(source),
         "--work-dir", str(work), "--phase", str(phase)],
        capture_output=True, text=True, timeout=900)


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


@pytest.mark.parametrize("phase", [2, 3])
@pytest.mark.parametrize("problem", ["not-empty", "group-readable",
                                     "source-inside"])
def test_rehearsal_refuses_an_unsafe_work_dir(tmp_path, problem, phase):
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
        proc = _run(source, work, phase)
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


# --------------------------------------------------------------------- #
# #54 Phase 3: `--phase 3`
# --------------------------------------------------------------------- #

PASS3 = ("Phase 3 private-ledger checks: PASS. No ledger values were "
         "printed.\n")
FAIL = "Private-ledger check failed. No ledger values were printed.\n"
FIXED_CHECKS = {
    "phase3-source-version", "phase3-source-has-v2", "phase3-preservation",
    "phase3-production-legacy", "phase3-synthetic-sequences",
    "phase3-synthetic-scoring", "phase3-synthetic-resolution",
    "phase3-synthetic-erasure", "phase3-synthetic-retry",
    "phase3-crash-child", "phase3-crash-state", "phase3-foreign-keys",
    "unexpected-error",
}


def _prepared_source(tmp_path: Path) -> Path:
    source, led = _source(tmp_path)
    with led._write_transaction():
        led.prepare_session_boundary(f"prepared-{PLANTED}")
        led.start_session(f"prepared-{PLANTED}", cwd="", model="")
    led.conn.close()
    return source


def _schema_of(path: Path) -> list[tuple]:
    raw = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        return sorted(raw.execute(
            "SELECT type, name, sql FROM sqlite_master"))
    finally:
        raw.close()


def _module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_issue54_ledger",
                                                  SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _in_process(module, source: Path, work: Path, capsys):
    code = module.main(["--source", str(source), "--work-dir", str(work),
                        "--phase", "3"])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_phase3_rehearsal_passes_from_legacy_source(tmp_path):
    source, led = _source(tmp_path)
    try:
        assert Path(str(source) + "-wal").stat().st_size > 0
        before = _bytes(source)
        proc = _run(source, _work(tmp_path), 3)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == PASS3
        assert proc.stderr == ""
        assert PLANTED not in proc.stdout + proc.stderr
        assert _bytes(source) == before
    finally:
        led.conn.close()


def test_phase3_rehearsal_passes_from_prepared_source(tmp_path):
    source = _prepared_source(tmp_path)
    # Read the schema first: a read-only open of a WAL database may create
    # an empty WAL file, which is the reader's doing, not the rehearsal's.
    schema = _schema_of(source)
    before = _bytes(source)
    proc = _run(source, _work(tmp_path), 3)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == PASS3
    assert PLANTED not in proc.stdout + proc.stderr
    assert _bytes(source) == before
    assert _schema_of(source) == schema
    raw = sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)
    try:
        assert raw.execute("PRAGMA user_version").fetchone()[0] == 5401
    finally:
        raw.close()


def test_phase3_rehearsal_handles_missing_scan_gaps(tmp_path):
    source, led = _source(tmp_path)
    led.conn.close()
    raw = sqlite3.connect(source)
    raw.execute("DROP TABLE scan_gaps")
    raw.close()
    before = _bytes(source)
    work = _work(tmp_path)
    proc = _run(source, work, 3)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == PASS3
    assert PLANTED not in proc.stdout + proc.stderr
    assert _bytes(source) == before
    assert "scan_gaps" not in {name for _t, name, _s in _schema_of(source)}
    synthetic = sqlite3.connect(work / "synthetic" / "ledger.db")
    try:
        assert synthetic.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='scan_gaps'"
        ).fetchone()[0] == 1
    finally:
        synthetic.close()


def test_phase3_rehearsal_keeps_production_starts_legacy(tmp_path):
    source = _prepared_source(tmp_path)
    work = _work(tmp_path)
    proc = _run(source, work, 3)
    assert proc.returncode == 0, proc.stderr
    synthetic = sqlite3.connect(work / "synthetic" / "ledger.db")
    try:
        production = synthetic.execute(
            "SELECT accounting_version FROM sessions"
            " WHERE session_id LIKE 'privacy-hud-dry-run-production-%'"
        ).fetchall()
        assert production == [(1,)]
        assert synthetic.execute(
            "SELECT COUNT(*) FROM sessions WHERE accounting_version=2"
            " AND session_id NOT LIKE 'privacy-hud-dry-run-v2-%'"
        ).fetchone()[0] == 0
        assert synthetic.execute(
            "SELECT COUNT(*) FROM sessions WHERE accounting_version=2"
        ).fetchone()[0] >= 7
    finally:
        synthetic.close()
    for path in work.rglob("*.db"):
        if path.parent.name == "synthetic":
            continue
        raw = sqlite3.connect(path)
        try:
            tables = {r[0] for r in raw.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if "scoring_profiles" in tables:
                assert raw.execute(
                    "SELECT COUNT(*) FROM sessions WHERE accounting_version=2"
                ).fetchone()[0] == 0, path.name
        finally:
            raw.close()


def test_phase3_rehearsal_runs_v2_accounting_checks(tmp_path):
    source = _prepared_source(tmp_path)
    work = _work(tmp_path)
    assert _run(source, work, 3).returncode == 0
    raw = sqlite3.connect(work / "synthetic" / "ledger.db")
    try:
        assert raw.execute("SELECT COUNT(*) FROM observations").fetchone()[0] > 0
        assert raw.execute("SELECT COUNT(*) FROM disclosures").fetchone()[0] > 0
        for sid, score in raw.execute(
                "SELECT session_id, budget_score FROM sessions"
                " WHERE accounting_version=2"):
            charged = raw.execute(
                "SELECT COALESCE(SUM(budget_delta), 0) FROM disclosures"
                " WHERE session_id=?", (sid,)).fetchone()[0]
            assert score == pytest.approx(charged, rel=1e-12, abs=1e-12)
        assert raw.execute(
            "SELECT COUNT(*) FROM sessions WHERE accounting_version=2"
            " AND accounting_status='unavailable'").fetchone()[0] >= 1
        ended = [r[0] for r in raw.execute(
            "SELECT session_id FROM sessions WHERE accounting_version=2"
            " AND ended_at IS NOT NULL")]
        assert ended
        for sid in ended:
            for table in ("subjects", "recipients"):
                assert raw.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE session_id=?"
                    " AND identity_hash IS NOT NULL", (sid,)).fetchone()[0] == 0
        assert raw.execute(
            "SELECT COUNT(*) FROM disclosures d JOIN sessions s"
            " USING (session_id) WHERE s.ended_at IS NOT NULL"
        ).fetchone()[0] >= 1
        assert raw.execute("PRAGMA user_version").fetchone()[0] == 5401
    finally:
        raw.close()
    reader = Ledger(work / "synthetic" / "ledger.db", load_matrix(),
                    initialize=False)
    try:
        summaries = [reader.summary(r[0]) for r in reader.conn.execute(
            "SELECT session_id FROM sessions WHERE accounting_version=2")]
        assert any(s.percent is None for s in summaries)
        assert any(s.percent is not None for s in summaries)
    finally:
        reader.conn.close()


def test_phase3_rehearsal_checks_v2_crash_atomicity(tmp_path, monkeypatch,
                                                    capsys):
    module = _module()
    seen: list[tuple[str, int]] = []
    real = module._run_child

    def spy(args):
        seen.append((args[1], int(args[2])))
        return real(args)

    monkeypatch.setattr(module, "_run_child", spy)
    code, out, err = _in_process(module, _prepared_source(tmp_path),
                                 _work(tmp_path), capsys)
    assert code == 0, err
    assert out == PASS3
    for op in ("observe", "end"):
        stops = [stop for name, stop in seen if name == op]
        dry = [s for s in stops if s == -2]
        assert dry == [-2]
        crashes = [s for s in stops if s != -2]
        mutations = max(crashes)
        assert mutations >= 1
        assert crashes == list(range(1, mutations + 1)) + [0, -1]


def test_phase3_rehearsal_refuses_activated_or_original_v2_sources(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    activated = _prepared_source(tmp_path / "a")
    raw = sqlite3.connect(activated)
    raw.execute("PRAGMA user_version = 5402")
    raw.close()
    proc = _run(activated, _work(tmp_path / "a"), 3)
    assert proc.returncode == 1
    assert proc.stdout == FAIL
    assert proc.stderr == "check: phase3-source-version\n"

    from privacy_hud.accounting import ScoringProfile
    source = _prepared_source(tmp_path / "b")
    led = Ledger(source, load_matrix())
    with led._write_transaction():
        led._start_v2_session(f"v2-{PLANTED}", cwd="", model="",
                              profile=ScoringProfile.from_matrix(led.matrix))
    led.conn.close()
    proc = _run(source, _work(tmp_path / "b"), 3)
    assert proc.returncode == 1
    assert proc.stdout == FAIL
    assert proc.stderr == "check: phase3-source-has-v2\n"
    assert PLANTED not in proc.stdout + proc.stderr


@pytest.mark.parametrize("failure", ["child", "comparison", "unexpected"])
def test_phase3_rehearsal_never_prints_planted_values_on_failure(
        tmp_path, monkeypatch, capsys, failure):
    module = _module()
    if failure == "child":
        monkeypatch.setattr(module, "_run_child", lambda args: subprocess.
                            CompletedProcess(args, 99, PLANTED, PLANTED))
        expected = "phase3-crash-child"
    elif failure == "comparison":
        real = module._fk_violations
        calls = [0]

        def drifting(conn):
            calls[0] += 1
            found = real(conn)
            return found | {(PLANTED,)} if calls[0] > 1 else found

        monkeypatch.setattr(module, "_fk_violations", drifting)
        expected = None
    else:
        def explode(path):
            raise RuntimeError(PLANTED)
        monkeypatch.setattr(module, "_check_synthetic_v2", explode)
        expected = "unexpected-error"
    code, out, err = _in_process(module, _prepared_source(tmp_path),
                                 _work(tmp_path), capsys)
    assert code != 0
    assert out == FAIL
    assert PLANTED not in out + err
    assert err.startswith("check: ") and err.endswith("\n")
    name = err[len("check: "):-1]
    assert name in FIXED_CHECKS
    if expected is not None:
        assert name == expected
