# tests/test_runtime_storage.py
"""#66 Pair 4: the crash-recoverable transition to a fenced active store.

Nothing here is simulated. The historical initializer is the actual 0.7.1
`Ledger.__init__`, vendored from `ad835b8` under `tests/fixtures/runtime_071`
and run in a subprocess whose only first-party path is that directory. The
crash tests terminate real processes with `os._exit`, between real durable
steps, rather than raising an exception that would politely run cleanup.
Every database is a private copy under the test's own temporary directory.
"""
from __future__ import annotations

import hashlib
import socket
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from privacy_hud import ledger_schema, runtime_storage as storage
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.runtime_contract import RuntimeRefusal
from privacy_hud.runtime_owner import acquire_writer, unselected_activation
from privacy_hud.runtime_storage import acquire_transition, prepare_storage
from runtime_helpers import REPO

M = load_matrix()
HISTORICAL = REPO / "tests" / "fixtures" / "runtime_071"


# --------------------------------------------------------------------- #
# the vendored historical runtime
# --------------------------------------------------------------------- #

def test_the_historical_fixture_matches_its_recorded_checksums():
    """The 0.7.1 bytes under test are the ones `PROVENANCE.md` names.

    A fixture edited by accident would otherwise keep every test below
    green while testing something that is not 0.7.1 — the one failure mode
    a vendored copy has that a `git show` does not.
    """
    recorded = {}
    for line in (HISTORICAL / "SHA256SUMS").read_text().splitlines():
        digest, rel = line.split("  ", 1)
        recorded[rel] = digest
    actual = {
        p.relative_to(HISTORICAL).as_posix():
            hashlib.sha256(p.read_bytes()).hexdigest()
        for p in HISTORICAL.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS" and p.suffix != ".md"
        and "__pycache__" not in p.parts
    }
    assert actual == recorded


_HISTORICAL_OPEN = textwrap.dedent("""
    import sys
    sys.path.insert(0, sys.argv[1])
    from privacy_hud.ledger import Ledger
    from privacy_hud.matrix.loader import load_matrix
    Ledger(sys.argv[2], load_matrix()).conn.close()
""")


def _historical_open(db_path) -> subprocess.CompletedProcess:
    """Run the actual 0.7.1 `Ledger.__init__` against `db_path`.

    `-I` and an explicit `sys.path` entry: the child must load the vendored
    0.7.1 package and never this checkout's.
    """
    return subprocess.run(
        [sys.executable, "-I", "-c", _HISTORICAL_OPEN, str(HISTORICAL),
         str(db_path)], capture_output=True, text=True, timeout=120)


# --------------------------------------------------------------------- #
# private ledgers
# --------------------------------------------------------------------- #

def _write(data_dir: Path, *, prepared: bool) -> Path:
    """A private ledger at the historical path with one recorded session
    and one exposed row; prepared to 5401 when asked."""
    data_dir.mkdir(parents=True, exist_ok=True)
    path = storage.legacy_path(data_dir)
    lease = acquire_writer(data_dir / "seed-owner",
                           activation=unselected_activation())
    led = Ledger(path, M, writer_lease=lease)
    led.start_session("s1", cwd="/w", model="m")
    led.record("s1", turn_id="t1", kind="exposed", data_type="email",
               source="support.log", destination="model_context",
               value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
               tool_name="Read", protection=None)
    if prepared:
        with led._write_transaction():
            led.prepare_session_boundary("s2")
            led.start_session("s2", cwd="/w", model="m")
    led.conn.close()
    lease.close()
    return path


def _raw(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro",
                           uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _schema(conn) -> list[tuple]:
    return sorted((r[0], r[1], r[2]) for r in conn.execute(
        "SELECT type, name, sql FROM sqlite_master"))


def _cells(conn) -> dict[str, list[tuple]]:
    """Every row of every table, with each cell's SQLite type, so a value
    silently retyped by a copy is a difference rather than a match."""
    out = {}
    for name in [r[1] for r in conn.execute(
            "SELECT type, name FROM sqlite_master WHERE type='table'")]:
        rows = []
        for row in conn.execute(f'SELECT * FROM "{name}"'):
            rows.append(tuple((type(v).__name__, v) for v in tuple(row)))
        out[name] = sorted(rows, key=repr)
    return out


def _state(path: Path) -> tuple:
    assert Path(path).is_file(), f"there is no database at {path}"
    conn = _raw(path)
    try:
        return (conn.execute("PRAGMA user_version").fetchone()[0],
                _schema(conn), _cells(conn))
    finally:
        conn.close()


def _cutover(data_dir: Path):
    """`prepare_storage` under the ownership it requires."""
    with acquire_transition(data_dir) as transition:
        assert transition.held
        with acquire_writer(data_dir,
                            activation=unselected_activation()) as lease:
            assert lease.held
            return prepare_storage(data_dir, activation=lease.activation)


# --------------------------------------------------------------------- #
# what the historical initializer actually does
# --------------------------------------------------------------------- #

def test_historical_initializer_mutates_an_unfenced_legacy_ledger(tmp_path):
    """Characterization, and the reason the fence is a directory.

    The actual 0.7.1 initializer, given the historical pathname, runs
    `ALTER TABLE events ADD COLUMN source_kind TEXT` on a legacy ledger
    that predates that column. Nothing in a handshake can stop it: the DDL
    runs inside `__init__`, before any protocol exists.
    """
    data_dir = tmp_path / "data"
    path = _write(data_dir, prepared=False)
    raw = sqlite3.connect(path)
    # Back to the layout of a ledger written before the column existed --
    # which is what a long-standing installation still has, since the
    # current writer never adds it to an existing table.
    raw.execute("ALTER TABLE events DROP COLUMN source_kind")
    raw.commit()
    raw.close()
    before = [r[1] for r in sqlite3.connect(path).execute(
        "PRAGMA table_info(events)")]
    assert "source_kind" not in before

    assert _historical_open(path).returncode == 0, "0.7.1 could not open it"

    after = [r[1] for r in sqlite3.connect(path).execute(
        "PRAGMA table_info(events)")]
    assert "source_kind" in after, "0.7.1 no longer performs the DDL #66 fences"


def test_historical_initializer_leaves_a_prepared_ledger_unchanged(tmp_path):
    """The other half of the characterization, and it is not the half the
    #66 plan predicted.

    #54 phase 2's rebuilt `events` already carries `source_kind`, so 0.7.1's
    one migration finds nothing to add and its `CREATE TABLE IF NOT EXISTS`
    statements find every table present. Against a *prepared* ledger the
    historical initializer therefore changes no object and no cell. Pinned
    here because the fence's justification has to rest on what the code
    does, not on what a plan said it does: the hazard 0.7.1 still presents
    is that historical session and coverage writes can succeed even though
    legacy event recording fails against the prepared events layout.
    """
    data_dir = tmp_path / "data"
    path = _write(data_dir, prepared=True)
    before = _state(path)
    assert before[0] == ledger_schema.PREPARED_VERSION
    assert _historical_open(path).returncode == 0
    assert _state(path) == before


def test_old_initializer_cannot_reopen_active_ledger(tmp_path):
    """After the transition the historical pathname is a directory, so the
    actual 0.7.1 initializer cannot open anything through it, and the
    active store is untouched."""
    data_dir = tmp_path / "data"
    _write(data_dir, prepared=True)
    _cutover(data_dir)
    active = storage.active_path(data_dir)
    before = _state(active)

    proc = _historical_open(storage.legacy_path(data_dir))
    assert proc.returncode != 0
    assert _state(active) == before
    assert storage.is_fenced(data_dir)
    assert not storage.legacy_path(data_dir).is_file()


# --------------------------------------------------------------------- #
# preservation
# --------------------------------------------------------------------- #

_WAL_WRITER = textwrap.dedent("""
    import os, sys
    sys.path.insert(0, sys.argv[1])
    from pathlib import Path
    from privacy_hud.ledger import Ledger
    from privacy_hud.matrix.loader import load_matrix
    from privacy_hud.runtime_owner import acquire_writer, unselected_activation
    root = Path(sys.argv[2])
    lease = acquire_writer(root / "wal-owner",
                           activation=unselected_activation())
    led = Ledger(root / "ledger.db", load_matrix(), writer_lease=lease)
    led.conn.execute("PRAGMA wal_autocheckpoint=0")
    led.start_session("wal", cwd="/w", model="m")
    led.record("wal", turn_id="t9", kind="exposed", data_type="email",
               source="wal.log", destination="model_context",
               value_hash=b"\\x09" * 16, masked_example="w",
               tool_name="Read", protection=None)
    os._exit(0)
""")


def test_cutover_preserves_committed_wal_cells(tmp_path):
    """A row committed into the write-ahead log and never checkpointed
    survives the cutover.

    The writer is a real process that exits with `os._exit`, so nothing
    checkpoints on close and the row is only in `-wal` when the transition
    starts. A copy that used `immutable=1`, or that moved the database
    without its log, would lose it silently — the failure this test exists
    to make loud.
    """
    data_dir = tmp_path / "data"
    _write(data_dir, prepared=False)
    proc = subprocess.run(
        [sys.executable, "-c", _WAL_WRITER, str(REPO / "src"), str(data_dir)],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    wal = storage.legacy_path(data_dir).with_name("ledger.db-wal")
    assert wal.exists() and wal.stat().st_size > 0, (
        "nothing is in the write-ahead log, so this proves nothing")
    before = _state(storage.legacy_path(data_dir))

    result = _cutover(data_dir)

    assert result.preserved_existing is True
    assert _state(storage.active_path(data_dir)) == before
    active = _raw(storage.active_path(data_dir))
    try:
        assert active.execute(
            "SELECT COUNT(*) FROM events WHERE source='wal.log'"
        ).fetchone()[0] == 1
    finally:
        active.close()


def test_cutover_preserves_generation_zero(tmp_path):
    """A generation-0 source stays generation 0. The transition does not
    migrate accounting; the daemon still does that at a genuine new-session
    boundary (#54 phase 2)."""
    data_dir = tmp_path / "data"
    _write(data_dir, prepared=False)
    before = _state(storage.legacy_path(data_dir))
    assert before[0] == 0

    result = _cutover(data_dir)

    assert result.schema_version == 0
    assert result.preserved_existing is True
    assert _state(storage.active_path(data_dir)) == before


def test_cutover_preserves_prepared_schema_exactly(tmp_path):
    """A valid 5401 source arrives with every object and every typed cell
    unchanged, and with nothing added."""
    data_dir = tmp_path / "data"
    _write(data_dir, prepared=True)
    before = _state(storage.legacy_path(data_dir))
    assert before[0] == ledger_schema.PREPARED_VERSION

    result = _cutover(data_dir)

    assert result.schema_version == ledger_schema.PREPARED_VERSION
    assert _state(storage.active_path(data_dir)) == before
    retired = storage.retired_dir(data_dir, result.transition_id) / "ledger.db"
    assert retired.is_file(), "the original was not retained"


def test_altered_prepared_schema_is_preserved_and_refused(tmp_path):
    """A prepared ledger somebody altered is not repaired, and not
    published."""
    data_dir = tmp_path / "data"
    path = _write(data_dir, prepared=True)
    raw = sqlite3.connect(path)
    raw.execute("ALTER TABLE events ADD COLUMN source_kind_extra TEXT")
    raw.close()
    before = _state(path)

    with pytest.raises(RuntimeRefusal) as refusal:
        _cutover(data_dir)
    assert refusal.value.code == "ledger_unsupported"

    assert _state(path) == before
    assert not storage.active_path(data_dir).exists()
    assert not storage.is_fenced(data_dir)


# --------------------------------------------------------------------- #
# holders and recreated paths
# --------------------------------------------------------------------- #

def test_unknown_holder_prevents_publication(tmp_path):
    """Something is answering on the daemon socket, so some process may
    still be holding the ledger. Nothing is retired, fenced or published."""
    data_dir = tmp_path / "data"
    path = _write(data_dir, prepared=False)
    before = _state(path)
    sock_dir = Path(tempfile.mkdtemp(prefix="phd"))
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(sock_dir / "daemon.sock"))
    listener.listen(1)
    (data_dir / "daemon.sock").symlink_to(sock_dir / "daemon.sock")
    try:
        with pytest.raises(RuntimeRefusal) as refusal:
            _cutover(data_dir)
        assert refusal.value.code == "holder_unknown"
    finally:
        listener.close()

    assert _state(path) == before
    assert not storage.is_fenced(data_dir)
    assert not storage.active_path(data_dir).exists()
    assert not (data_dir / "runtime.json").exists()


def test_recreated_legacy_path_is_preserved_and_refused(tmp_path):
    """A database that reappears at the fenced pathname after the original
    was retired is a second candidate, and neither is overwritten."""
    data_dir = tmp_path / "data"
    _write(data_dir, prepared=False)
    result = _cutover(data_dir)
    fence = storage.legacy_path(data_dir)
    assert fence.is_dir()
    fence.rmdir()

    intruder = sqlite3.connect(fence)
    intruder.execute("CREATE TABLE intruder(x)")
    intruder.execute("INSERT INTO intruder VALUES(1)")
    intruder.commit()
    intruder.close()
    intruder_bytes = fence.read_bytes()
    active_before = _state(storage.active_path(data_dir))
    retired = storage.retired_dir(data_dir, result.transition_id) / "ledger.db"
    retired_bytes = retired.read_bytes()

    with pytest.raises(RuntimeRefusal) as refusal:
        _cutover(data_dir)
    assert refusal.value.code == "transition_incomplete"

    assert fence.read_bytes() == intruder_bytes
    assert retired.read_bytes() == retired_bytes
    assert _state(storage.active_path(data_dir)) == active_before


# --------------------------------------------------------------------- #
# crashes
# --------------------------------------------------------------------- #

_CRASH_CHILD = textwrap.dedent("""
    import os, sys
    sys.path.insert(0, sys.argv[1])
    from pathlib import Path
    from privacy_hud import runtime_storage as storage
    from privacy_hud.runtime_owner import acquire_writer, unselected_activation

    root, stop = Path(sys.argv[2]), sys.argv[3]

    def failpoint(stage):
        if stage == stop:
            os._exit(3)

    storage._stage_failpoint = failpoint
    with storage.acquire_transition(root):
        with acquire_writer(root, activation=unselected_activation()) as lease:
            storage.prepare_storage(root, activation=lease.activation)
    os._exit(0)
""")


def _crash_at(data_dir: Path, stage: str) -> int:
    proc = subprocess.run(
        [sys.executable, "-c", _CRASH_CHILD, str(REPO / "src"),
         str(data_dir), stage], capture_output=True, text=True, timeout=180)
    assert proc.returncode in (0, 3), proc.stderr
    return proc.returncode


def test_cutover_crash_after_every_durable_step(tmp_path):
    """Kill a real transition after each durable step, then run it again.

    The second attempt must reach one of exactly two states: a complete
    activation whose active store holds every original cell, or a refusal
    that left every candidate on disk. A half-published layout, a lost row
    or a restored `ledger.db` database is none of those.
    """
    stages = storage.STAGES[:storage.STAGES.index(
        storage.FINAL_STORAGE_STAGE) + 1]
    assert len(stages) >= 7
    crashed = []
    for stage in stages:
        data_dir = tmp_path / f"crash-{stage}"
        _write(data_dir, prepared=True)
        before = _state(storage.legacy_path(data_dir))
        if _crash_at(data_dir, stage) == 3:
            crashed.append(stage)

        try:
            _cutover(data_dir)
        except RuntimeRefusal:
            preserved = [p for p in (storage.legacy_path(data_dir),
                                     storage.active_path(data_dir))
                         if p.is_file()]
            preserved += list((data_dir / storage.RETIRED_DIR_NAME).rglob(
                "ledger.db"))
            assert preserved, f"{stage}: nothing was preserved"
            for path in preserved:
                assert _state(path)[2] == before[2], f"{stage}: {path.name}"
            continue

        active = storage.active_path(data_dir)
        assert active.is_file(), stage
        assert _state(active) == before, stage
        assert storage.is_fenced(data_dir), stage
        assert not storage.legacy_path(data_dir).is_file(), stage
    assert crashed == list(stages), (
        "some stage was never reached, so it was never crash-tested")


@pytest.mark.parametrize("candidate", ["stale", "incomplete"])
def test_retry_revalidates_existing_staged_backup(tmp_path, candidate):
    data_dir = tmp_path / "data"
    source = _write(data_dir, prepared=False)
    assert _crash_at(data_dir, "backup_verified") == 3

    journal = storage.read_journal(data_dir)
    assert journal is not None
    retired = storage.retired_dir(data_dir, journal["transition_id"])
    staged = retired / storage.STAGED_DB_NAME
    assert staged.is_file()

    if candidate == "stale":
        conn = sqlite3.connect(source)
        try:
            conn.execute(
                "UPDATE sessions SET budget_score=budget_score+1 "
                "WHERE session_id='s1'"
            )
            conn.commit()
        finally:
            conn.close()
    else:
        staged.write_bytes(b"incomplete sqlite backup")

    source_before = _state(source)
    staged_before = staged.read_bytes()

    with pytest.raises(RuntimeRefusal) as refusal:
        _cutover(data_dir)

    assert refusal.value.code == "transition_incomplete"
    assert _state(source) == source_before
    assert staged.read_bytes() == staged_before
    assert not (retired / storage.LEGACY_NAME).exists()
    assert not storage.is_fenced(data_dir)
    assert not storage.active_path(data_dir).exists()


def test_retry_finishes_retirement_after_main_database_rename(tmp_path):
    data_dir = tmp_path / "data"
    _write(data_dir, prepared=False)

    writer = subprocess.run(
        [sys.executable, "-B", "-c", _WAL_WRITER,
         str(REPO / "src"), str(data_dir)],
        capture_output=True, text=True, timeout=120,
    )
    assert writer.returncode == 0, writer.stderr

    legacy = storage.legacy_path(data_dir)
    wal = legacy.with_name("ledger.db-wal")
    assert wal.is_file() and wal.stat().st_size > 0
    before = _state(legacy)

    child = textwrap.dedent("""
        import os
        import sys
        from pathlib import Path

        sys.path.insert(0, sys.argv[1])
        from privacy_hud import runtime_storage as storage
        from privacy_hud.runtime_owner import (
            acquire_writer, unselected_activation,
        )

        root = Path(sys.argv[2])
        original_replace = storage.os.replace

        def crash_after_main_move(src, dst):
            original_replace(src, dst)
            if (Path(src) == storage.legacy_path(root)
                    and Path(dst).name == storage.LEGACY_NAME):
                os._exit(3)

        storage.os.replace = crash_after_main_move
        with storage.acquire_transition(root):
            with acquire_writer(
                root, activation=unselected_activation()
            ) as lease:
                storage.prepare_storage(root, activation=lease.activation)
        os._exit(0)
    """)
    crashed = subprocess.run(
        [sys.executable, "-B", "-c", child,
         str(REPO / "src"), str(data_dir)],
        capture_output=True, text=True, timeout=120,
    )
    assert crashed.returncode == 3, crashed.stderr
    assert not legacy.exists()
    assert wal.is_file()

    result = _cutover(data_dir)

    retained = storage.retired_dir(
        data_dir, result.transition_id
    ) / storage.LEGACY_NAME
    assert _state(storage.active_path(data_dir)) == before
    assert _state(retained) == before
    assert storage.is_fenced(data_dir)
    assert not legacy.with_name("ledger.db-wal").exists()
    assert not legacy.with_name("ledger.db-shm").exists()


@pytest.mark.parametrize("operation", ["open", "fsync"])
def test_directory_durability_failure_is_not_suppressed(
    tmp_path, monkeypatch, operation
):
    import errno

    def fail(*args, **kwargs):
        raise OSError(errno.EIO, "injected durability failure")

    with monkeypatch.context() as patch:
        patch.setattr(storage.os, operation, fail)
        with pytest.raises(OSError) as failure:
            storage._fsync_dir(tmp_path)

    assert failure.value.errno == errno.EIO


def test_retirement_parent_sync_failure_prevents_publication(
    tmp_path, monkeypatch
):
    import errno

    data_dir = tmp_path / "data"
    source = _write(data_dir, prepared=False)
    before = _state(source)
    original_sync = storage._fsync_dir
    retirement_parent = data_dir / storage.RETIRED_DIR_NAME

    def fail_retirement_parent(path):
        if Path(path) == retirement_parent:
            raise OSError(errno.EIO, "injected retirement sync failure")
        original_sync(path)

    monkeypatch.setattr(storage, "_fsync_dir", fail_retirement_parent)

    with pytest.raises(OSError) as failure:
        _cutover(data_dir)

    assert failure.value.errno == errno.EIO
    assert _state(source) == before
    assert not storage.is_fenced(data_dir)
    assert not storage.active_path(data_dir).exists()


def test_historical_session_start_mutates_a_prepared_ledger(tmp_path):
    data_dir = tmp_path / "data"
    path = _write(data_dir, prepared=True)
    before = _state(path)

    child = textwrap.dedent("""
        import sys
        sys.path.insert(0, sys.argv[1])
        from privacy_hud.ledger import Ledger
        from privacy_hud.matrix.loader import load_matrix

        led = Ledger(sys.argv[2], load_matrix())
        try:
            led.start_session(
                "historical-on-prepared", cwd="/w", model="m"
            )
        finally:
            led.conn.close()
    """)
    result = subprocess.run(
        [sys.executable, "-B", "-I", "-c", child,
         str(HISTORICAL), str(path)],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr

    after = _state(path)
    assert after[:2] == before[:2]
    assert after[2] != before[2]

    conn = _raw(path)
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE session_id=?",
            ("historical-on-prepared",),
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM coverage WHERE session_id=?",
            ("historical-on-prepared",),
        ).fetchone()[0] == 1
    finally:
        conn.close()


@pytest.mark.parametrize("returncode", [0, 1])
def test_lsof_incomplete_visibility_refuses(monkeypatch, returncode):
    from types import SimpleNamespace

    completed = SimpleNamespace(
        returncode=returncode,
        stdout="",
        stderr="lsof: WARNING: can't stat() an inspected filesystem\n",
    )
    monkeypatch.setattr(storage.subprocess, "run", lambda *a, **k: completed)

    with pytest.raises(RuntimeRefusal) as failure:
        storage._lsof_holders("/usr/sbin/lsof", [Path("/review/ledger.db")])

    assert failure.value.code == "holder_unknown"


def test_unreadable_retirement_inventory_refuses(tmp_path, monkeypatch):
    def denied(path):
        raise PermissionError("private inspection error")

    monkeypatch.setattr(Path, "iterdir", denied)

    with pytest.raises(RuntimeRefusal) as failure:
        storage.holder_paths(tmp_path)

    assert failure.value.code == "holder_unknown"


def test_unstatable_holder_path_refuses(tmp_path, monkeypatch):
    def denied(path):
        raise PermissionError("private inspection error")

    monkeypatch.setattr(Path, "lstat", denied)

    with pytest.raises(RuntimeRefusal) as failure:
        storage.holder_paths(tmp_path)

    assert failure.value.code == "holder_unknown"


@pytest.mark.parametrize(
    "stat_error, link, expected",
    [
        (PermissionError(), "socket:[123]", frozenset()),
        (PermissionError(), "pipe:[123]", frozenset()),
        (PermissionError(), "anon_inode:[eventpoll]", frozenset()),
        (OSError(), "socket:[123]", frozenset()),
        (PermissionError(), "/review/ledger.db", None),
        (PermissionError(), "/alias/ledger.db", None),
        (PermissionError(), "/review/ledger.db (deleted)", None),
        (PermissionError(), "socket:[invalid]", None),
        (PermissionError(), PermissionError(), None),
        (OSError(), OSError(), None),
        (PermissionError(), FileNotFoundError(), frozenset()),
        (PermissionError(), ProcessLookupError(), frozenset()),
        (FileNotFoundError(), None, frozenset()),
        (ProcessLookupError(), None, frozenset()),
        (None, "/alias/ledger.db", frozenset({123})),
    ],
)
def test_proc_descriptor_visibility(monkeypatch, stat_error, link, expected):
    from types import SimpleNamespace

    target = Path("/review/ledger.db")
    uid = storage.os.getuid()
    reads = []

    def fake_stat(path, *args, **kwargs):
        name = str(path)
        if name == str(target):
            return SimpleNamespace(st_dev=1, st_ino=2)
        if name == "/proc/123":
            return SimpleNamespace(st_uid=uid)
        if name == "/proc/123/fd/4":
            if stat_error is not None:
                raise stat_error
            return SimpleNamespace(st_dev=1, st_ino=2)
        raise AssertionError(name)

    def fake_listdir(path):
        if str(path) == "/proc":
            return ["123"]
        if str(path) == "/proc/123/fd":
            return ["4"]
        raise AssertionError(path)

    def fake_readlink(path):
        assert path == "/proc/123/fd/4"
        reads.append(path)
        if isinstance(link, OSError):
            raise link
        assert isinstance(link, str)
        return link

    with monkeypatch.context() as patch:
        patch.setattr(storage.os, "stat", fake_stat)
        patch.setattr(storage.os, "listdir", fake_listdir)
        patch.setattr(storage.os, "readlink", fake_readlink)
        if expected is None:
            with pytest.raises(RuntimeRefusal) as refusal:
                storage._proc_holders([target])
            assert refusal.value.code == "holder_unknown"
        else:
            assert storage._proc_holders([target]) == expected

    if stat_error is None or isinstance(
        stat_error, (FileNotFoundError, ProcessLookupError)
    ):
        assert reads == []
    else:
        assert reads == ["/proc/123/fd/4"]


@pytest.mark.parametrize("failure_at", ["target", "descriptor"])
def test_proc_inspection_permission_failure_refuses(monkeypatch, failure_at):
    from types import SimpleNamespace

    target = "/review/ledger.db"
    uid = storage.os.getuid()

    def fake_stat(path, *args, **kwargs):
        name = str(path)
        if name == target:
            if failure_at == "target":
                raise PermissionError("private target error")
            return SimpleNamespace(st_dev=1, st_ino=2)
        if name == "/proc/123":
            return SimpleNamespace(st_uid=uid)
        if name == "/proc/123/fd/4":
            raise PermissionError("private descriptor error")
        raise AssertionError(name)

    def fake_listdir(path):
        if str(path) == "/proc":
            return ["123"]
        if str(path) == "/proc/123/fd":
            return ["4"]
        raise AssertionError(path)

    with monkeypatch.context() as patch:
        patch.setattr(storage.os, "stat", fake_stat)
        patch.setattr(storage.os, "listdir", fake_listdir)
        patch.setattr(storage.os, "readlink", lambda path: target)
        with pytest.raises(RuntimeRefusal) as failure:
            storage._proc_holders([Path(target)])

    assert failure.value.code == "holder_unknown"
