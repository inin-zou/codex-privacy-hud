# tests/test_issue71_quiescence.py
"""#71: a repair refusal names the check that refused, and a heartbeat
left by a daemon that has already exited is waited out, not trusted.

The heartbeat case is reproduced here with real processes: a process
holds the ledger and publishes `hud/_daemon.json`, then exits. Its
descriptors are gone and nothing answers on the socket, but the marker's
own `updated_at` keeps it fresh for `hud_snapshot.STALE_AFTER` seconds, and
the quiescence gate refused throughout that window. The remedy is astra's
preferred one (#66 follow-up §C): wait for the marker to expire, rechecking
holders and the socket on every pass, and never delete the marker or the
socket because a process exited.

Everything is under a temporary directory; the only processes started or
signalled are the test's own.
"""
from __future__ import annotations

import io
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from pathlib import Path

import pytest

from privacy_hud import codex, hud_snapshot, runtime_messages
from privacy_hud import runtime_repair as repair
from privacy_hud import runtime_storage as storage
from privacy_hud.runtime_contract import RuntimeRefusal

#: The only keys a refusal diagnostic may carry (#71): fixed identifiers,
#: holder pids, an errno, a heartbeat age, a timestamp and the release.
#: No path, no ledger value, no id, no hash, no exception text.
ALLOWED_DIAGNOSTIC_KEYS = {
    "diagnostic", "release", "time", "check", "reason", "pids", "errno",
    "heartbeat_age", "signalled",
}


def _root() -> Path:
    """A short private data directory: a unix socket path is capped at
    about 104 bytes."""
    root = Path(tempfile.mkdtemp(prefix="ph71")).resolve()
    root.chmod(0o700)
    return root


def _seed(root: Path) -> Path:
    path = storage.legacy_path(root)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE sessions (id TEXT)")
    conn.execute("INSERT INTO sessions VALUES ('s1')")
    conn.commit()
    conn.close()
    return path


def _stamp(root: Path, updated_at: float) -> Path:
    """Write the marker the way the daemon does: whole, by rename. A
    reader must never see a half-written file, which would read as no
    marker at all."""
    marker = hud_snapshot.hud_dir(root) / "_daemon.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    tmp = marker.with_name("_daemon.json.stamp")
    tmp.write_text(json.dumps({
        "v": hud_snapshot.DAEMON_MARKER_VERSION,
        "unattributed_gaps": False, "updated_at": updated_at}),
        encoding="utf-8")
    os.replace(tmp, marker)
    return marker


#: A stand-in for a daemon: it holds the ledger and publishes the marker,
#: then waits to be told to exit. Stdlib only.
_PUBLISHER = textwrap.dedent("""
    import json, os, sqlite3, sys, time
    root = sys.argv[1]
    conn = sqlite3.connect(os.path.join(root, "ledger.db"))
    conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
    hud = os.path.join(root, "hud")
    os.makedirs(hud, exist_ok=True)
    with open(os.path.join(hud, "_daemon.json"), "w") as fh:
        json.dump({"v": 1, "unattributed_gaps": False,
                   "updated_at": time.time() - float(sys.argv[2])}, fh)
    sys.stdout.write("ready\\n")
    sys.stdout.flush()
    sys.stdin.readline()
""")

_READER = textwrap.dedent("""
    import sqlite3, sys, time
    conn = sqlite3.connect(sys.argv[1])
    conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
    sys.stdout.write("ready\\n")
    sys.stdout.flush()
    time.sleep(600)
""")


def _publish_then_exit(root: Path, backdate: float) -> None:
    """Hold the ledger, publish a heartbeat, then exit and be reaped."""
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", _PUBLISHER, str(root), str(backdate)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert proc.stdout is not None and proc.stdin is not None
    assert proc.stdout.readline().strip() == "ready"
    assert proc.pid in storage.open_holders(root)
    proc.stdin.write("\n")
    proc.stdin.flush()
    proc.wait(timeout=30)


# --------------------------------------------------------------------- #
# the reproduction
# --------------------------------------------------------------------- #

def test_heartbeat_outlives_its_exited_holder_and_is_named():
    """#71 reproduced: the holder is gone, nothing listens, and the gate
    still refuses -- and now says that the heartbeat is why."""
    root = _root()
    _seed(root)
    _publish_then_exit(root, backdate=0.0)

    assert storage.open_holders(root) == frozenset()
    with pytest.raises(storage.QuiescenceRefusal) as refusal:
        storage.check_quiescence(root)
    assert refusal.value.code == "holder_unknown"
    assert refusal.value.check == "heartbeat"
    assert refusal.value.pids == ()
    assert refusal.value.heartbeat_age is not None
    assert 0.0 <= refusal.value.heartbeat_age <= hud_snapshot.STALE_AFTER


def test_unchanged_heartbeat_is_waited_out_and_kept():
    """The unchanged marker ages past `STALE_AFTER`; the wait ends then,
    announces itself once, and deletes nothing."""
    root = _root()
    _seed(root)
    _publish_then_exit(root, backdate=hud_snapshot.STALE_AFTER - 2.0)
    marker = hud_snapshot.hud_dir(root) / "_daemon.json"
    before = marker.read_bytes()
    announced: list[str] = []

    start = time.monotonic()
    storage.await_quiescence(root, on_wait=lambda: announced.append("wait"))
    elapsed = time.monotonic() - start

    assert announced == ["wait"]
    assert 0.5 <= elapsed <= storage.HEARTBEAT_WAIT
    assert marker.read_bytes() == before, "the heartbeat was rewritten"
    storage.check_quiescence(root)


def test_wait_is_bounded_when_the_heartbeat_keeps_moving(monkeypatch):
    """A marker somebody keeps re-stamping is a live publisher. The wait
    has a fixed deadline and refuses on it."""
    root = _root()
    _seed(root)
    monkeypatch.setattr(storage, "HEARTBEAT_WAIT", 1.0)
    stop = threading.Event()

    def restamp() -> None:
        while not stop.is_set():
            _stamp(root, time.time())
            time.sleep(0.05)

    worker = threading.Thread(target=restamp, daemon=True)
    worker.start()
    try:
        start = time.monotonic()
        with pytest.raises(storage.QuiescenceRefusal) as refusal:
            storage.await_quiescence(root)
        assert time.monotonic() - start < 10.0
    finally:
        stop.set()
        worker.join(timeout=5)
    assert refusal.value.check == "heartbeat"


def test_holder_appearing_during_the_wait_refuses():
    """Every pass rechecks the holders first. A reader that opens the
    ledger while the heartbeat is being waited out ends the wait with a
    refusal naming its pid."""
    root = _root()
    path = _seed(root)
    _stamp(root, time.time() - (hud_snapshot.STALE_AFTER - 6.0))
    reader: list[subprocess.Popen] = []

    def open_reader() -> None:
        time.sleep(0.5)
        reader.append(subprocess.Popen(
            [sys.executable, "-I", "-c", _READER, str(path)],
            stdout=subprocess.PIPE, text=True))

    opener = threading.Thread(target=open_reader, daemon=True)
    opener.start()
    try:
        with pytest.raises(storage.QuiescenceRefusal) as refusal:
            storage.await_quiescence(root)
        opener.join(timeout=10)
        assert refusal.value.check == "holders"
        assert refusal.value.pids == (reader[0].pid,)
        assert reader[0].poll() is None, "the reader was signalled"
    finally:
        opener.join(timeout=10)
        for proc in reader:
            proc.terminate()
            proc.wait(timeout=30)


# --------------------------------------------------------------------- #
# every other branch names itself too
# --------------------------------------------------------------------- #

def test_live_listener_is_named():
    root = _root()
    _seed(root)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(codex.socket_path(root)))
    listener.listen(1)
    try:
        with pytest.raises(storage.QuiescenceRefusal) as refusal:
            storage.check_quiescence(root)
    finally:
        listener.close()
    assert refusal.value.check == "socket"
    assert refusal.value.reason == "live_listener"


def test_leftover_socket_is_not_a_refusal_and_is_kept():
    """A dead daemon's socket file refuses connections: not a holder, and
    not something this gate removes."""
    root = _root()
    _seed(root)
    sock = codex.socket_path(root)
    leftover = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    leftover.bind(str(sock))
    leftover.close()
    storage.check_quiescence(root)
    storage.await_quiescence(root)
    assert sock.exists()


def test_missing_inspector_is_named(monkeypatch):
    root = _root()
    _seed(root)
    monkeypatch.setattr(storage, "_inspector", lambda: None)
    with pytest.raises(storage.QuiescenceRefusal) as refusal:
        storage.check_quiescence(root)
    assert refusal.value.check == "inspection"
    assert refusal.value.reason == "no_inspector"


@pytest.mark.parametrize("script, reason", [
    ("echo 'lsof: WARNING: something' >&2; exit 1", "lsof_stderr"),
    ("exit 7", "lsof_status"),
    ("echo pNOTAPID; exit 0", "lsof_output"),
])
def test_lsof_failures_are_named(tmp_path, script, reason):
    fake = tmp_path / "lsof"
    fake.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8")
    fake.chmod(0o755)
    with pytest.raises(storage.QuiescenceRefusal) as refusal:
        storage._lsof_holders(str(fake), [tmp_path / "x"])
    assert refusal.value.check == "inspection"
    assert refusal.value.reason == reason


def test_quiescent_keeps_its_boolean_contract(monkeypatch):
    """`_quiescent` is what earlier diagnostics call directly: `False` for
    a fresh heartbeat, a refusal for an uninspectable host."""
    root = _root()
    _seed(root)
    _stamp(root, time.time())
    assert storage._quiescent(root) is False
    monkeypatch.setattr(storage, "_inspector", lambda: None)
    with pytest.raises(RuntimeRefusal):
        storage._quiescent(root)


# --------------------------------------------------------------------- #
# what repair prints
# --------------------------------------------------------------------- #

def test_refusal_diagnostic_is_allowlisted(monkeypatch):
    """The failing check reaches stderr as one line of fixed keys, inside
    the failing invocation. Nothing in it is a path or a ledger value."""
    from test_runtime_repair import seed_ledger

    root = _root()
    seed_ledger(root)
    monkeypatch.setattr(storage, "_inspector", lambda: None)
    out, err = io.StringIO(), io.StringIO()

    code = repair.main(["--bundle-root", str(repair_bundle()),
                        "--plugin-data", str(root),
                        "--python", sys.executable, "--allow-degraded"],
                       out=out, err=err)

    assert code == 1
    lines = [line for line in err.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert set(record) == ALLOWED_DIAGNOSTIC_KEYS
    assert record["diagnostic"] == "quiescence_refusal"
    assert record["check"] == "inspection"
    assert record["reason"] == "no_inspector"
    assert record["pids"] == []
    assert record["signalled"] is False
    for text in (out.getvalue(), err.getvalue()):
        assert str(root) not in text
        assert "ledger.db" not in text
        assert "Traceback" not in text


def test_repair_waits_out_a_heartbeat_left_by_a_stopped_daemon():
    """#71's sequence end to end, in one invocation: the daemon has exited,
    its heartbeat is still fresh, and repair completes after it expires
    instead of refusing and needing a retry."""
    from runtime_helpers import make_bundle, make_venv, write_receipt_v1
    from test_runtime_repair import seed_ledger, stop_runtime

    base = Path(tempfile.mkdtemp(prefix="ph71r")).resolve()
    bundle = make_bundle(base / "b")
    data = base / "d"
    data.mkdir()
    python = make_venv(base / "v")
    seed_ledger(data)
    write_receipt_v1(data, python=python)
    _stamp(data, time.time() - (hud_snapshot.STALE_AFTER - 2.0))
    progress: list[str] = []
    try:
        result = repair.repair_runtime(bundle, data, allow_degraded=True,
                                       progress=progress.append)
        assert result.preserved_existing
        assert progress == [runtime_messages.HEARTBEAT_WAITING]
        assert storage.read_journal(data)["stage"] == "ready"
    finally:
        stop_runtime(data)


_BUNDLE: list[Path] = []


def repair_bundle() -> Path:
    from runtime_helpers import shared_bundle

    if not _BUNDLE:
        _BUNDLE.append(shared_bundle())
    return _BUNDLE[0]


def test_heartbeat_copy_is_astras():
    assert runtime_messages.HEARTBEAT_WAITING == (
        "A recent Privacy HUD heartbeat remains. Waiting for it to expire "
        "and checking for active processes.")


def test_wait_bound_is_past_the_freshness_window():
    assert storage.HEARTBEAT_WAIT > hud_snapshot.STALE_AFTER
    assert storage.HEARTBEAT_WAIT <= hud_snapshot.STALE_AFTER + 5.0
