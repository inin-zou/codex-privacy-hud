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

from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from runtime_helpers import close_writer, writer_ledger

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
    # An absent WAL and an empty WAL contain the same committed data.
    # Never delete SQLite's source-side bookkeeping to satisfy this check.
    out = {}
    for p in path.parent.iterdir():
        if p.name in (path.name, path.name + "-wal"):
            data = p.read_bytes()
            if p.name == path.name or data:
                out[p.name] = data
    return out


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
    led = writer_ledger(source, load_matrix())
    with led._write_transaction():
        led._start_v2_session(f"v2-{PLANTED}", cwd="", model="",
                              profile=ScoringProfile.from_matrix(led.matrix))
    close_writer(led)
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


def test_phase3_does_not_unlink_sidecars_held_by_another_connection(
        tmp_path, monkeypatch):
    module = _module()
    source = _prepared_source(tmp_path)
    wal = Path(str(source) + "-wal")
    shm = Path(str(source) + "-shm")
    assert not wal.exists() and not shm.exists()
    real_copy = module._copy
    holders = []

    def copy_then_open_writer(src, dest):
        real_copy(src, dest)
        holder = sqlite3.connect(src)
        holders.append(holder)
        holder.execute("BEGIN IMMEDIATE")
        assert wal.exists() and wal.stat().st_size == 0
        assert shm.exists()

    def stop_after_backup(path):
        raise module.CheckFailed("phase3-source-version")

    monkeypatch.setattr(module, "_copy", copy_then_open_writer)
    monkeypatch.setattr(module, "_generation", stop_after_backup)
    try:
        with pytest.raises(module.CheckFailed, match="phase3-source-version"):
            module.phase3(source, _work(tmp_path))
        assert wal.exists()
        assert shm.exists()
    finally:
        for holder in holders:
            holder.rollback()
            holder.close()


@pytest.mark.parametrize("column", ["source", "masked_example"])
def test_phase3_crash_signature_detects_changed_original_cells(
        tmp_path, column):
    module = _module()
    source = _prepared_source(tmp_path)
    raw = sqlite3.connect(source)
    try:
        before = module._signature(raw, f"sess-{PLANTED}")
        raw.execute(
            f"UPDATE events_legacy_v1 SET {column}=?", ("changed-cell",))
        assert module._signature(raw, f"sess-{PLANTED}") != before
    finally:
        raw.close()


# --------------------------------------------------------------------- #
# #54 Phase 4: `--phase 4`, from the fenced active store
# --------------------------------------------------------------------- #

PASS4 = ("Phase 4 private-ledger checks: PASS. No ledger values were "
         "printed.\n")
PHASE4_CHECKS = {
    "phase4-source-version", "phase4-preservation", "phase4-activation",
    "phase4-direct-upgrade", "phase4-existing-session",
    "phase4-lazy-attachment", "phase4-empty-probe",
    "phase4-dispatch-sequences", "phase4-current-evidence",
    "phase4-recipients", "phase4-evaluated-paths", "phase4-key-loss",
    "phase4-end-erasure", "phase4-late-observation", "phase4-consumers",
    "phase4-crash-child", "phase4-crash-state", "phase4-foreign-keys",
    "phase4-fenced-layout", "phase4-writer-ownership",
    "phase4-runtime-selection", "phase4-repair-preservation",
}


def _fenced_root(tmp_path: Path, *, generation: int = 5401) -> Path:
    """A synthetic `$PLUGIN_DATA` after #66's transition: `ledger.db` is the
    directory fence and the ledger is `ledger/active.db`, at the requested
    generation, with committed rows still in its WAL."""
    from privacy_hud import runtime_storage
    root = tmp_path / "plugin-data"
    root.mkdir()
    runtime_storage.legacy_path(root).mkdir()
    active = runtime_storage.active_path(root)
    active.parent.mkdir()
    led = writer_ledger(active, load_matrix(), data_dir=root)
    led.start_session(f"sess-{PLANTED}", cwd=f"/{PLANTED}", model="m")
    led.record(f"sess-{PLANTED}", turn_id="t", kind="exposed",
               data_type="email", source=f"{PLANTED}.log",
               destination="model_context", value_hash=b"\x01" * 16,
               masked_example=f"{PLANTED}@x", tool_name="Read",
               protection=None, source_kind="path")
    led.record_scan_gap(f"sess-{PLANTED}", boundary="B3", reason="timeout")
    led.add_policy(f"sess-{PLANTED}", rule_type="block_path",
                   selector=f"/{PLANTED}")
    if generation >= 5401:
        with led._write_transaction():
            led.prepare_session_boundary(f"prepared-{PLANTED}")
            led.start_session(f"prepared-{PLANTED}", cwd="", model="")
    if generation == 5402:
        from privacy_hud.accounting import ScoringProfile
        profile = ScoringProfile.from_matrix(load_matrix())
        with led._write_transaction():
            led._start_v2_session(f"v2-{PLANTED}", cwd="", model="",
                                  profile=profile)
        led.conn.execute("PRAGMA user_version = 5402")
    close_writer(led)
    return root


def _active(root: Path) -> Path:
    from privacy_hud import runtime_storage
    return runtime_storage.active_path(root)


def _run4(module, source: Path, work: Path, capsys):
    try:
        code = module.main(["--source", str(source), "--work-dir", str(work),
                            "--phase", "4"])
    except SystemExit as exit_:
        code = exit_.code
    out = capsys.readouterr()
    return code, out.out, out.err


def _assert_pass4(proc) -> None:
    assert proc.stdout == PASS4, proc.stderr[-400:]
    assert proc.returncode == 0
    assert proc.stderr == ""
    assert PLANTED not in proc.stdout + proc.stderr


def test_phase4_rehearsal_from_fenced_5401_active_store(tmp_path):
    root = _fenced_root(tmp_path)
    source = _active(root)
    fence = root / "ledger.db"
    schema = _schema_of(source)
    before = _bytes(source)
    proc = _run(source, _work(tmp_path), 4)
    _assert_pass4(proc)
    assert _bytes(source) == before
    assert _schema_of(source) == schema
    assert fence.is_dir() and list(fence.iterdir()) == []
    raw = sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)
    try:
        assert raw.execute("PRAGMA user_version").fetchone()[0] == 5401
    finally:
        raw.close()


def test_phase4_rehearsal_from_legacy_source(tmp_path):
    root = _fenced_root(tmp_path, generation=0)
    before = _bytes(_active(root))
    proc = _run(_active(root), _work(tmp_path), 4)
    _assert_pass4(proc)
    assert _bytes(_active(root)) == before


def test_phase4_rehearsal_from_prepared_source(tmp_path):
    source, led = _source(tmp_path)
    with led._write_transaction():
        led.prepare_session_boundary(f"prepared-{PLANTED}")
        led.start_session(f"prepared-{PLANTED}", cwd="", model="")
    led.conn.close()
    before = _bytes(source)
    proc = _run(source, _work(tmp_path), 4)
    _assert_pass4(proc)
    assert _bytes(source) == before


def test_phase4_rehearsal_from_activated_source(tmp_path):
    root = _fenced_root(tmp_path, generation=5402)
    before = _bytes(_active(root))
    proc = _run(_active(root), _work(tmp_path), 4)
    _assert_pass4(proc)
    assert _bytes(_active(root)) == before


def _spies(module, monkeypatch) -> dict:
    """Count what the rehearsal actually exercises, in process."""
    import privacy_hud.dispatch as dispatch_mod
    import privacy_hud.engine as engine_mod
    import privacy_hud.hud_snapshot as hs
    import privacy_hud.render as render_mod
    import privacy_hud.runtime_owner as owner_mod
    seen: dict = {"dispatch": [], "observe": 0, "receipt": 0, "publish": 0,
                  "new_state": [], "acquire": [], "children": []}

    real_dispatch = dispatch_mod.dispatch

    def dispatch(state, payload, **kw):
        seen["dispatch"].append(payload.get("hook_event_name"))
        return real_dispatch(state, payload, **kw)

    real_observe = engine_mod.Engine.observe

    def observe(self, obs, **kw):
        seen["observe"] += 1
        return real_observe(self, obs, **kw)

    real_receipt = render_mod.receipt

    def receipt(*a, **k):
        seen["receipt"] += 1
        return real_receipt(*a, **k)

    real_publish = hs.HudPublisher.publish

    def publish(self, *a, **k):
        seen["publish"] += 1
        return real_publish(self, *a, **k)

    real_new_state = dispatch_mod.new_state

    def new_state(data_dir, *, writer_lease):
        from privacy_hud import runtime_storage
        seen["new_state"].append((
            Path(data_dir).resolve(), writer_lease.data_dir.resolve(),
            runtime_storage.is_fenced(data_dir),
            runtime_storage.resolved_ledger_path(data_dir).resolve()))
        return real_new_state(data_dir, writer_lease=writer_lease)

    real_acquire = owner_mod.acquire_writer

    def acquire(data_dir, *, activation):
        seen["acquire"].append((Path(data_dir).resolve(),
                                owner_mod.owns_writer(data_dir)))
        return real_acquire(data_dir, activation=activation)

    real_child = module._run_child

    def run_child(args):
        seen["children"].append(list(args))
        return real_child(args)

    monkeypatch.setattr(dispatch_mod, "dispatch", dispatch)
    monkeypatch.setattr(engine_mod.Engine, "observe", observe)
    monkeypatch.setattr(render_mod, "receipt", receipt)
    monkeypatch.setattr(dispatch_mod, "render_receipt", receipt)
    monkeypatch.setattr(hs.HudPublisher, "publish", publish)
    monkeypatch.setattr(dispatch_mod, "new_state", new_state)
    monkeypatch.setattr(module, "acquire_writer", acquire)
    monkeypatch.setattr(owner_mod, "acquire_writer", acquire)
    monkeypatch.setattr(module, "_run_child", run_child)
    return seen


def test_phase4_rehearsal_runs_real_dispatch_and_consumers(
        tmp_path, monkeypatch, capsys):
    module = _module()
    root = _fenced_root(tmp_path)
    seen = _spies(module, monkeypatch)
    code, out, err = _run4(module, _active(root), _work(tmp_path), capsys)
    assert (code, out, err) == (0, PASS4, "")
    events = set(seen["dispatch"])
    assert {"SessionStart", "SessionEnd", "PreToolUse", "PostToolUse",
            "UserPromptSubmit", "SubagentStart", "PreCompact"} <= events
    assert seen["observe"] >= 10
    assert seen["receipt"] >= 1 and seen["publish"] >= 1


def test_phase4_rehearsal_checks_lazy_replay_and_restart(
        tmp_path, monkeypatch, capsys):
    module = _module()
    root = _fenced_root(tmp_path)
    seen = _spies(module, monkeypatch)
    code, out, _err = _run4(module, _active(root), _work(tmp_path), capsys)
    assert (code, out) == (0, PASS4)
    roots = [entry[0] for entry in seen["new_state"]]
    assert any(roots.count(r) >= 2 for r in roots), \
        "no daemon restart on the same clone root"
    assert seen["dispatch"].count("SessionStart") >= 3


def test_phase4_clones_use_matching_root_writer_leases(
        tmp_path, monkeypatch, capsys):
    module = _module()
    root = _fenced_root(tmp_path)
    seen = _spies(module, monkeypatch)
    work = _work(tmp_path)
    code, out, _err = _run4(module, _active(root), work, capsys)
    assert (code, out) == (0, PASS4)
    assert seen["new_state"]
    for data_dir, lease_dir, fenced, ledger in seen["new_state"]:
        assert lease_dir == data_dir
        assert fenced
        assert ledger == (data_dir / "ledger" / "active.db").resolve()
        assert str(data_dir).startswith(str(work.resolve()))
    assert root.resolve() not in [entry[0] for entry in seen["acquire"]]


def test_phase4_child_releases_parent_ownership_before_restart(
        tmp_path, monkeypatch, capsys):
    module = _module()
    root = _fenced_root(tmp_path)
    seen = _spies(module, monkeypatch)
    code, out, _err = _run4(module, _active(root), _work(tmp_path), capsys)
    assert (code, out) == (0, PASS4)
    assert seen["acquire"]
    for _data_dir, already_owned in seen["acquire"]:
        assert not already_owned, "ownership was inherited, not acquired"
    assert seen["children"]


def test_phase4_rehearsal_checks_all_crash_boundaries(
        tmp_path, monkeypatch, capsys):
    module = _module()
    root = _fenced_root(tmp_path)
    seen = _spies(module, monkeypatch)
    code, out, _err = _run4(module, _active(root), _work(tmp_path), capsys)
    assert (code, out) == (0, PASS4)
    stops: dict[str, list[int]] = {}
    for args in seen["children"]:
        if len(args) >= 3 and args[1] in ("activate", "observe", "end"):
            stops.setdefault(args[1], []).append(int(args[2]))
    assert set(stops) == {"activate", "observe", "end"}
    for op, found in stops.items():
        dry = [s for s in found if s == -2]
        rest = sorted(s for s in found if s != -2)
        assert dry == [-2], op
        n = max(rest)
        assert n >= 1
        assert rest == [-1, 0] + list(range(1, n + 1)), op


@pytest.mark.parametrize("failure", ["child", "unexpected"])
def test_phase4_rehearsal_never_prints_private_values(
        tmp_path, monkeypatch, capsys, failure):
    module = _module()
    if failure == "child":
        monkeypatch.setattr(module, "_run_child", lambda args: subprocess.
                            CompletedProcess(args, 99, PLANTED, PLANTED))
    else:
        def explode(path):
            raise RuntimeError(PLANTED)
        monkeypatch.setattr(module, "_check_phase4_consumers", explode,
                            raising=False)
    root = _fenced_root(tmp_path)
    code, out, err = _run4(module, _active(root), _work(tmp_path), capsys)
    assert code != 0
    assert out == FAIL
    assert PLANTED not in out + err and str(root) not in err
    assert err.startswith("check: ") and err.endswith("\n")
    name = err[len("check: "):-1]
    assert name in PHASE4_CHECKS | {"unexpected-error"}
    if failure == "child":
        assert name == "phase4-crash-child"
    else:
        assert name == "unexpected-error"


@pytest.mark.parametrize("problem", ["not-empty", "group-readable",
                                     "source-inside"])
def test_phase4_rehearsal_rejects_unsafe_work_dirs(tmp_path, problem):
    root = _fenced_root(tmp_path)
    source = _active(root)
    work = _work(tmp_path)
    if problem == "not-empty":
        (work / "x").write_text("x")
    elif problem == "group-readable":
        os.chmod(work, 0o750)
    else:
        work = source.parent
        os.chmod(work, 0o700)
    before = _bytes(source)
    proc = _run(source, work, 4)
    assert proc.returncode != 0
    assert proc.stdout == FAIL
    assert PLANTED not in proc.stdout + proc.stderr
    assert _bytes(source) == before


def test_phase4_rehearsal_wrong_source_directory_is_sanitized(tmp_path):
    root = _fenced_root(tmp_path)
    fence = root / "ledger.db"
    proc = _run(fence, _work(tmp_path), 4)
    assert proc.returncode != 0
    assert proc.stdout == FAIL
    assert proc.stderr == "check: source\n"
    assert str(root) not in proc.stdout + proc.stderr
    # And it is the phase-4 path that refused, not the parser.
    (tmp_path / "again").mkdir()
    good = _run(_active(root), _work(tmp_path / "again"), 4)
    assert good.stdout == PASS4


def test_phase4_preserves_phase2_and_phase3_contracts(tmp_path):
    """Regression gate: Phase 2 stays legacy-only, and Phase 3 still
    refuses an activated source."""
    source, led = _source(tmp_path)
    led.conn.close()
    proc = _run(source, _work(tmp_path), 2)
    assert proc.stdout == ("Phase 2 private-ledger checks: PASS. No ledger "
                           "values were printed.\n")
    (tmp_path / "act").mkdir()
    root = _fenced_root(tmp_path / "act", generation=5402)
    proc = _run(_active(root), _work(tmp_path / "act"), 3)
    assert proc.returncode == 1
    assert proc.stderr == "check: phase3-source-version\n"
