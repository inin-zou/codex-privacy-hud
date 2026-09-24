# tests/test_runtime_ownership.py
"""#66 Pair 3: the compatible daemon owns ledger writes, and everyone else
gets a connection SQLite itself refuses to let them write.

Nothing here simulates ownership. Every lease is the real `flock` on a real
`runtime-writer.lock` under the test's own temporary root, every read-only
connection is a real `mode=ro` SQLite connection, and the refusals asserted
are the ones a caller would actually meet.
"""
from __future__ import annotations

import socket
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from privacy_hud.daemon import AlreadyRunning, Daemon
from privacy_hud.ledger import Ledger, open_connection
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.runtime_contract import RuntimeRefusal, load_activation
from privacy_hud.runtime_owner import acquire_writer
from runtime_helpers import REPO, make_bundle, write_receipt_v2, writer_lease

M = load_matrix()

EPOCH_A = "0123456789abcdef0123456789abcdef"
EPOCH_B = "fedcba9876543210fedcba9876543210"


def _seed(tmp_path, session_id="s1"):
    """A ledger with one recorded session, written by a real lease, closed."""
    path = tmp_path / "ledger.db"
    lease = writer_lease(tmp_path)
    led = Ledger(path, M, writer_lease=lease)
    led.start_session(session_id, cwd="/w", model="m")
    led.conn.close()
    lease.close()
    return path


def _other_process_lease(data_dir) -> str:
    """Ask a real second process to take the writer lease. Returns
    `"acquired"` or the refusal code it met.

    A subprocess rather than a second `acquire_writer` here: ownership is
    reference counted within one process, so an in-process second call
    would (correctly) share this process's own lease and prove nothing
    about exclusion.
    """
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent("""
            import sys
            sys.path.insert(0, sys.argv[1])
            from privacy_hud.runtime_contract import RuntimeRefusal
            from privacy_hud.runtime_owner import (
                acquire_writer, unselected_activation)
            try:
                acquire_writer(sys.argv[2],
                               activation=unselected_activation())
            except RuntimeRefusal as refusal:
                print(refusal.code)
            else:
                print("acquired")
        """), str(REPO / "src"), str(data_dir)],
        capture_output=True, text=True, timeout=60, check=True)
    return out.stdout.strip()


def _sessions(path) -> set[str]:
    conn = open_connection(path, initialize=False, read_only=True)
    try:
        return {r[0] for r in conn.execute("SELECT session_id FROM sessions")}
    finally:
        conn.close()


# --------------------------------------------------------------------- #
# real read-only connections
# --------------------------------------------------------------------- #

def test_reader_connection_rejects_insert_and_ddl(tmp_path):
    """A reader's connection is `mode=ro`, so SQLite refuses the write —
    not the caller's good manners.

    The ALTER adds a previously absent test column, so its failure proves
    read-only enforcement rather than a duplicate-column error.
    """
    path = _seed(tmp_path)
    conn = open_connection(path, initialize=False, read_only=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute(
                "INSERT INTO sessions(session_id,started_at,cwd,model,"
                "budget_cap) VALUES('s2',1,'/w','m',120.0)")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute(
                "ALTER TABLE events ADD COLUMN readonly_probe TEXT"
            )
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM sessions")
    finally:
        conn.close()
    assert _sessions(path) == {"s1"}


def test_reader_keeps_wal_committed_rows_visible(tmp_path):
    """Regression guard: `mode=ro` must still read committed WAL contents.

    `immutable=1` would also produce a connection that cannot write, and
    would silently skip the WAL — every row committed since the last
    checkpoint would vanish from the reader's view. That is why the rule is
    `mode=ro` and why this test writes without checkpointing.
    """
    path = tmp_path / "ledger.db"
    lease = writer_lease(tmp_path)
    led = Ledger(path, M, writer_lease=lease)
    led.start_session("wal-only", cwd="/w", model="m")
    assert (path.parent / (path.name + "-wal")).exists(), (
        "the writer is not in WAL mode, so this proves nothing")
    conn = open_connection(path, initialize=False, read_only=True)
    try:
        seen = {r[0] for r in conn.execute("SELECT session_id FROM sessions")}
    finally:
        conn.close()
        led.conn.close()
        lease.close()
    assert seen == {"wal-only"}


# --------------------------------------------------------------------- #
# the lease
# --------------------------------------------------------------------- #

def test_writable_open_requires_current_lease(tmp_path):
    """No lease, no writable connection — and no file created either."""
    path = tmp_path / "ledger.db"
    with pytest.raises(RuntimeRefusal) as refusal:
        Ledger(path, M)
    assert refusal.value.code == "runtime_mismatch"
    assert not path.exists(), "a refused open must not create a ledger"

    closed = writer_lease(tmp_path)
    closed.close()
    with pytest.raises(RuntimeRefusal):
        Ledger(path, M, writer_lease=closed)
    assert not path.exists()

    # Another *process* cannot hold the ledger while this one does.
    held = writer_lease(tmp_path)
    led = Ledger(path, M, writer_lease=held)
    assert _other_process_lease(tmp_path) == "holder_unknown"
    led.conn.close()
    held.close()
    assert _other_process_lease(tmp_path) == "acquired"

    # A noninitializing open with no lease is a reader; it refuses to write.
    reader = Ledger(path, M, initialize=False)
    try:
        with pytest.raises(RuntimeRefusal):
            reader.start_session("s2", cwd="/w", model="m")
    finally:
        reader.conn.close()
    assert _sessions(path) == set()


def test_epoch_change_rolls_back_write(tmp_path):
    """A repair that activates another runtime mid-write loses the write.

    The receipt is replaced while the transaction is open. The lease checks
    before the outer COMMIT, so nothing the transaction wrote survives.
    """
    data = tmp_path / "data"
    bundle = make_bundle(tmp_path / "bundle")
    write_receipt_v2(data, bundle=bundle, python=sys.executable, epoch=EPOCH_A)
    selected = load_activation(data)
    lease = acquire_writer(data, activation=selected)
    path = data / "ledger.db"
    led = Ledger(path, M, writer_lease=lease)
    led.start_session("before", cwd="/w", model="m")

    with pytest.raises(RuntimeRefusal) as refusal:
        with led._write_transaction():
            led.conn.execute(
                "INSERT INTO sessions(session_id,started_at,cwd,model,"
                "budget_cap) VALUES('during',1,'/w','m',120.0)")
            write_receipt_v2(data, bundle=bundle, python=sys.executable,
                             epoch=EPOCH_B)
    assert refusal.value.code == "runtime_mismatch"
    assert not led.conn.in_transaction

    # And the lease stays refused afterwards, rather than recovering.
    with pytest.raises(RuntimeRefusal):
        led.start_session("after", cwd="/w", model="m")
    led.conn.close()
    lease.close()
    assert _sessions(path) == {"before"}


def test_all_mutators_require_writer_lease(tmp_path):
    """Policy, tokens, scan gaps, coverage, the session lifecycle and the
    #54 migration all go through the guarded transaction.

    Each call below is made on a reader — a ledger opened without a lease —
    and each must refuse. The ledger is then re-read with a writer's
    connection to prove none of them left a row behind.
    """
    path = _seed(tmp_path)
    reader = Ledger(path, M, initialize=False)
    mutations = {
        "start_session": lambda: reader.start_session("s2", cwd="/w",
                                                      model="m"),
        "end_session": lambda: reader.end_session("s1"),
        "record": lambda: reader.record(
            "s1", turn_id="t1", kind="exposed", data_type="email",
            source="Read", destination="api.test", value_hash=b"h" * 32,
            masked_example="a@b", tool_name="Read", protection="none"),
        "add_policy": lambda: reader.add_policy("s1", rule_type="mask",
                                                selector="email"),
        "mint_token": lambda: reader.mint_token(
            "s1", tool_name="Bash", args_hash=b"h" * 32, mode="allow_once",
            ttl_seconds=60),
        "consume_token": lambda: reader.consume_token(
            "s1", tool_name="Bash", args_hash=b"h" * 32),
        "record_scan_gap": lambda: reader.record_scan_gap(
            "s1", boundary="egress", reason="timeout"),
        "note_unobserved_hooks": lambda: reader.note_unobserved_hooks(1),
        "write_transaction": lambda: reader._write_transaction().__enter__(),
    }
    refused = []
    for name, call in mutations.items():
        with pytest.raises(RuntimeRefusal, match="runtime_mismatch"):
            call()
        refused.append(name)
    reader.conn.close()
    assert refused == list(mutations)

    conn = open_connection(path, initialize=False, read_only=True)
    try:
        counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in ("sessions", "events", "policy", "policy_tokens",
                            "scan_gaps")}
        ended = conn.execute(
            "SELECT ended_at FROM sessions WHERE session_id='s1'").fetchone()[0]
        coverage = conn.execute("SELECT COUNT(*) FROM coverage").fetchone()[0]
    finally:
        conn.close()
    assert counts == {"sessions": 1, "events": 0, "policy": 0,
                      "policy_tokens": 0, "scan_gaps": 0}
    assert ended is None
    assert coverage == 1  # the one `session_start` row `_seed` wrote


# --------------------------------------------------------------------- #
# startup order
# --------------------------------------------------------------------- #

def test_socket_conflict_precedes_ledger_open(monkeypatch, tmp_path):
    """A daemon that cannot own the socket path opens no ledger and loads
    no model.

    The conflict here is a foreign listener: something is answering on the
    socket path that never took the startup lock — an older daemon, or a
    process of another build. Refusing it *after* `new_state` means a
    ~2.8 GB model load and a writable ledger connection on behalf of a
    daemon that will never serve a request.
    """
    from privacy_hud import dispatch

    built: list[str] = []

    class RecordingModelDetector:
        def __init__(self, *args, **kwargs):
            built.append("model")

    monkeypatch.setattr(dispatch, "ModelDetector", RecordingModelDetector)

    sock_dir = Path(tempfile.mkdtemp(prefix="phd"))
    sock_path = sock_dir / "d.sock"
    foreign = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    foreign.bind(str(sock_path))
    foreign.listen(1)
    data_dir = tmp_path / "data"
    selected = writer_lease(tmp_path / "unused").activation
    try:
        with pytest.raises(AlreadyRunning):
            Daemon(sock_path, data_dir, activation=selected,
                   idle_timeout=3600, poll_interval=0.05)
    finally:
        foreign.close()
        sock_path.unlink(missing_ok=True)

    assert built == [], "a refused daemon must not initialize detectors"
    assert not (data_dir / "ledger.db").exists(), (
        "a refused daemon must not open a ledger")


# #54 Phase 4: a valid activated (5402) ledger is now this writer's own
# generation; `test_5402_writer_reopens_without_schema_changes` covers it.
@pytest.mark.parametrize("layout", ["unknown", "altered"])
def test_noninitializing_writer_validates_before_writable_open(
    tmp_path, monkeypatch, layout
):
    from privacy_hud import ledger as ledger_module, ledger_schema

    path = _seed(tmp_path)
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        if layout == "unknown":
            conn.execute("PRAGMA user_version=999")
        else:
            for statement in ledger_schema.migration_statements():
                conn.execute(statement)
            if layout == "activated":
                conn.execute("PRAGMA user_version=5402")
            else:
                conn.execute(
                    "ALTER TABLE events ADD COLUMN unexpected_column TEXT"
                )
    finally:
        conn.close()

    before = path.read_bytes()
    original_open = ledger_module.open_connection
    reads = []

    def checked_open(db_path, **kwargs):
        assert kwargs.get("read_only") is True, (
            "unsupported ledger reached a writable open"
        )
        reads.append(db_path)
        return original_open(db_path, **kwargs)

    monkeypatch.setattr(ledger_module, "open_connection", checked_open)
    with writer_lease(tmp_path) as lease:
        with pytest.raises(ledger_schema.UnsupportedAccounting):
            Ledger(path, M, initialize=False, writer_lease=lease)

    assert reads == [path]
    assert path.read_bytes() == before


def test_5402_readers_cannot_write_or_activate(tmp_path):
    """#54 Phase 4: a reader of an activated ledger reads version-2
    accounting and can neither write it nor activate anything, through the
    API or through its own SQL."""
    from accounting_fakes import crossed, event
    from test_accounting_activation import (
        PROFILE, image, seed_activated_ledger, start_observation,
    )

    path = tmp_path / "ledger.db"
    sid = seed_activated_ledger(path)
    before = image(path)
    reader = Ledger(path, M, initialize=False)
    try:
        assert reader.summary(sid).accounting_version == 2
        mutations = [
            lambda: reader.start_accounted_session(
                "new", cwd="", model="", profile=PROFILE,
                start_observation=start_observation("new")),
            lambda: reader.record_observation(crossed(sid), [event()]),
            lambda: reader.mark_accounting_unavailable(sid),
            lambda: reader.end_session(sid),
            lambda: reader.ensure_profile(PROFILE),
            lambda: reader.start_session("x", cwd="", model=""),
        ]
        for mutate in mutations:
            with pytest.raises(RuntimeRefusal):
                mutate()
        for sql in ("INSERT INTO sessions(session_id,started_at,budget_cap)"
                    " VALUES('raw',1,120.0)",
                    "UPDATE sessions SET accounting_status='unavailable'",
                    "PRAGMA user_version = 5401"):
            with pytest.raises(sqlite3.OperationalError):
                reader.conn.execute(sql)
    finally:
        reader.conn.close()
    assert image(path) == before
