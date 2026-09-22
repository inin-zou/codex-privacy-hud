# tests/test_runtime_surfaces.py
"""#66 Pair 6: every consumer on the canonical path, and policy over RPC.

The daemon owns ledger writes (Pair 3) and the active store lives behind
the fence (Pair 4). What is left is the other half of both facts: no
surface may open a writable connection of its own, and no surface may
resolve the ledger, or the settings beside it, by guessing.

Daemons here are real `Daemon` objects on a short socket directory, and
the policy requests are real frames over a real unix socket.
"""
from __future__ import annotations

import json
import socket
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

from privacy_hud import codex, mcp_tools, runtime_commands, runtime_messages
from privacy_hud import runtime_storage as storage
from privacy_hud.daemon import Daemon
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.runtime_client import encode_frame, hello_reply
from privacy_hud.runtime_contract import RuntimeRefusal, load_activation
from privacy_hud.runtime_owner import acquire_writer, unselected_activation
from runtime_helpers import make_bundle, write_receipt_v2

M = load_matrix()


# --------------------------------------------------------------------- #
# a fenced installation
# --------------------------------------------------------------------- #

class Surface:
    """A data directory laid out the way 0.8.0 lays one out: the active
    store behind the fence, a receipt v2, and one recorded session."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="phs")).resolve()
        self.data = self.root / "d"
        self.data.mkdir(parents=True)
        self.bundle = make_bundle(self.root / "b")
        self.receipt = write_receipt_v2(self.data, bundle=self.bundle,
                                        python=Path(_executable()))
        self.activation = load_activation(self.data)
        self._seed()

    def _seed(self) -> None:
        lease = acquire_writer(self.data / "seed-owner",
                               activation=unselected_activation())
        led = Ledger(storage.legacy_path(self.data), M, writer_lease=lease)
        led.start_session("s1", cwd="/w", model="m")
        led.record("s1", turn_id="t1", kind="exposed", data_type="email",
                   source="support.log", destination="model_context",
                   value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
                   tool_name="Read", protection=None)
        led.conn.close()
        lease.close()
        # The real selection, not an unselected activation: this data
        # directory already carries a receipt v2, and a lease offered
        # anything else is correctly refused.
        with storage.acquire_transition(self.data):
            with acquire_writer(self.data,
                                activation=self.activation) as lease:
                storage.prepare_storage(self.data, activation=lease.activation)

    @property
    def socket_path(self) -> Path:
        return codex.socket_path(self.data)

    def policy_rows(self) -> list[tuple]:
        # The active store by name, not through the resolver under test:
        # a helper that asked the same question the assertions do could
        # not contradict it.
        conn = sqlite3.connect(
            f"{storage.active_path(self.data).resolve().as_uri()}?mode=ro",
            uri=True)
        try:
            return list(conn.execute(
                "SELECT rule_type, selector FROM policy"))
        finally:
            conn.close()


def _executable() -> str:
    import sys
    return sys.executable


@pytest.fixture
def surface():
    import shutil

    made = Surface()
    try:
        yield made
    finally:
        shutil.rmtree(made.root, ignore_errors=True)


class MismatchedRuntime:
    """A stand-in that speaks protocol 2 and answers as another build.

    Not a real `Daemon`: one built for another build cannot take the
    writer lease against this receipt at all, which is Pair 3's rule
    working. What this reproduces is the state a user is actually in —
    something is listening on the socket and it is not the selected
    runtime — without pretending the ownership check does not exist.
    """

    def __init__(self, surface: "Surface") -> None:
        from runtime_helpers import activation as synthetic

        self.reply = hello_reply(
            synthetic(build_id="b" * 64, bundle_root=surface.bundle), 0)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(surface.socket_path))
        self.server.listen(8)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.recv(65536)
                    conn.sendall(encode_frame(self.reply))
                except OSError:
                    pass

    def __enter__(self) -> "MismatchedRuntime":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.server.close()
        self.thread.join(timeout=5.0)


class RunningDaemon:
    """A real daemon on the surface's socket, stopped on exit."""

    def __init__(self, surface: Surface, *, activation=None) -> None:
        self.daemon = Daemon(surface.socket_path, surface.data,
                             idle_timeout=3600, poll_interval=0.05,
                             activation=activation or surface.activation)
        self.thread = threading.Thread(target=self.daemon.serve_forever,
                                       daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 10.0
        while not surface.socket_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)

    def __enter__(self) -> "RunningDaemon":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.daemon.stop()
        self.thread.join(timeout=10.0)


# --------------------------------------------------------------------- #
# policy over RPC
# --------------------------------------------------------------------- #

def test_policy_update_requires_matching_daemon(surface):
    """A policy mutation is refused before it is sent, and writes nothing.

    The surfaces that used to open their own writable connection can no
    longer do so: the daemon is the writer, and a daemon that is not the
    selected build has no authority to be handed a rule either. What the
    caller gets back is a refusal that happened before transmission, so
    "no rule was saved" is a fact about this branch rather than a guess.
    """
    with MismatchedRuntime(surface):
        with pytest.raises(RuntimeRefusal) as refusal:
            runtime_commands.update_policy(
                surface.data, activation=surface.activation,
                session_id="s1", rule_type="mask", selector="email")
    assert refusal.value.code == "runtime_mismatch"
    assert surface.policy_rows() == []


def test_policy_update_reaches_the_daemon_and_is_saved(surface):
    """The matching daemon applies the rule under its own serialized
    ledger access, and the successful result keeps its existing shape."""
    with RunningDaemon(surface):
        result = runtime_commands.update_policy(
            surface.data, activation=surface.activation,
            session_id="s1", rule_type="mask", selector="email")

    assert result["saved"] is True
    assert result["enforcement"] == "conditional"
    assert result["rule_type"] == "mask"
    assert result["selector"] == "email"
    assert result["conditions"] == mcp_tools.rule_enforcement_note(
        "mask", "email").strip()
    assert surface.policy_rows() == [("mask", "email")]


def test_policy_commit_lost_reply_reports_unknown_outcome(surface):
    """A reply lost after the request was sent is an unknown outcome.

    It is not "no rule was saved": the daemon may have written it and died
    on the way back. Saying otherwise would be the one lie this surface
    must not tell, and retrying would risk a second write of something
    that already happened. One connection, no retry, and copy that says
    what is actually known.
    """
    connections: list[int] = []
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(surface.socket_path))
    server.listen(4)

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            connections.append(1)
            with conn:
                conn.recv(65536)  # the hello
                conn.sendall(encode_frame(
                    hello_reply(surface.activation, 0)))
                conn.recv(65536)  # the request, read and never answered

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with pytest.raises(runtime_commands.PolicyOutcomeUnknown):
            runtime_commands.update_policy(
                surface.data, activation=surface.activation,
                session_id="s1", rule_type="mask", selector="email")
    finally:
        server.close()
        thread.join(timeout=5.0)

    assert connections == [1], "the lost request was retried"
    assert surface.policy_rows() == []


def test_the_unknown_outcome_message_offers_no_action(surface):
    """§D's action-free alternative, because 0.8.0 has no surface that
    lists a session's saved rules for the user to check."""
    assert runtime_messages.POLICY_OUTCOME_UNKNOWN == (
        "Privacy HUD could not confirm whether the policy rule was saved. "
        "The request was not retried.")
    assert "Check the session's saved rules" not in \
        runtime_messages.POLICY_OUTCOME_UNKNOWN


# --------------------------------------------------------------------- #
# the local browser
# --------------------------------------------------------------------- #

def test_ui_policy_mismatch_returns_503_without_write(surface, monkeypatch):
    """The browser reports the refusal honestly and shows no success."""
    from privacy_hud import local_ui_server

    monkeypatch.setenv("PLUGIN_DATA", str(surface.data))
    server = local_ui_server.serve(print_url=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[0], server.server_address[1]
        request = Request(
            f"http://{host}:{port}/api/policy",
            data=json.dumps({"session_id": "s1", "rule_type": "mask",
                             "selector": "email"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with pytest.raises(Exception) as failure:
            urlopen(request, timeout=10)
        response = failure.value
        assert getattr(response, "code", None) == 503
        body = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10.0)

    assert body["error"] == runtime_messages.POLICY_PREFLIGHT_REFUSAL
    assert "saved" not in body
    assert surface.policy_rows() == []


# --------------------------------------------------------------------- #
# readers
# --------------------------------------------------------------------- #

def test_mcp_worker_reads_use_read_only_connection(surface, monkeypatch):
    """The MCP server's one connection cannot write, whatever SQL runs.

    Its worker-thread serialization is unchanged: the SDK runs a
    synchronous tool on a thread that is not the one that opened the
    connection, and one lock still covers every use of it.
    """
    import server as mcp_server

    monkeypatch.setenv("PLUGIN_DATA", str(surface.data))
    ledger = mcp_server._open_ledger()
    try:
        assert Path(mcp_server._ledger_path()) == codex.ledger_path(
            surface.data)
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            ledger.conn.execute(
                "INSERT INTO policy(scope, rule_type, selector, "
                "created_at) VALUES('session:s1','mask','email',1)")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            ledger.conn.execute("ALTER TABLE events ADD COLUMN probe TEXT")
    finally:
        ledger.conn.close()
    assert surface.policy_rows() == []


def test_read_guard_uses_plugin_data_not_ledger_parent(surface, monkeypatch):
    """Settings live in `$PLUGIN_DATA`, which is no longer the ledger's
    parent directory.

    After the relocation `ledger_path.parent` is `$PLUGIN_DATA/ledger/`.
    A surface that kept deriving the data root from it would read a
    settings file that does not exist and report the read guard off for a
    user who turned it on.
    """
    import server as mcp_server

    monkeypatch.setenv("PLUGIN_DATA", str(surface.data))
    mcp_tools.read_guard_set(surface.data, True)
    assert (surface.data / "settings.json").is_file()
    assert codex.ledger_path(surface.data).parent != surface.data

    assert mcp_server._read_guard_status()["deny_read"] is True
    assert mcp_tools.read_guard_status(
        codex.ledger_path(surface.data).parent)["deny_read"] is False


# --------------------------------------------------------------------- #
# the audit command
# --------------------------------------------------------------------- #

def test_audit_uses_selected_bundle_and_canonical_path(surface):
    """The bundled audit reads the active store, through the bundle.

    No `python3 -m privacy_hud...`, no `$PLUGIN_DATA/ledger.db`: the one
    is whichever distribution the interpreter finds first, and the other
    is a directory now.
    """
    import os
    import subprocess
    import sys

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-I",
         str(surface.bundle / "scripts" / "runtime.py"),
         "--plugin-data", str(surface.data), "audit"],
        capture_output=True, text=True, timeout=180, env=env)

    assert proc.returncode == 0, proc.stderr
    assert "s1" in proc.stdout
    assert "Traceback" not in proc.stderr
    assert not storage.legacy_path(surface.data).is_file()


def test_skill_audit_resolves_session_once(surface, monkeypatch):
    """One resolution reaches both the rendering and the UI.

    Two separately timed resolutions can name two different sessions, and
    the shipped failure was exactly that: a table headed with one session
    beside a browser showing another.
    """
    calls: list[dict] = []
    original = mcp_tools.resolve_audit_session

    def counting(ledger, data_dir, **kwargs):
        resolved = original(ledger, data_dir, **kwargs)
        calls.append({"resolved": resolved})
        return resolved

    monkeypatch.setattr(mcp_tools, "resolve_audit_session", counting)
    result = runtime_commands.audit(surface.data,
                                    activation=surface.activation)

    assert len(calls) == 1, "the audit resolved its session more than once"
    assert result.resolved is calls[0]["resolved"]
    assert result.resolved.session_id == "s1"
    # The fallback subtitle survives: an inferred resolution is labelled
    # as inferred rather than printed as "Current session", and the id
    # itself is deliberately not in the header for that basis.
    assert "Most recently started session" in result.text


def test_history_remains_readable_during_runtime_mismatch(surface):
    """History still reads, with a banner, and no claim of monitoring."""
    with MismatchedRuntime(surface):
        result = runtime_commands.audit(surface.data,
                                        activation=surface.activation)

    assert result.runtime_mismatch is True
    assert result.banner == runtime_messages.AUDIT_RUNTIME_MISMATCH
    assert "Historical records may still be viewed." in result.banner
    assert "support.log" in result.text, "the history did not render"
    assert result.resolved.session_id == "s1"


def test_ambient_resolves_a_session_from_the_active_store(surface,
                                                          monkeypatch):
    """The ambient launcher reads the relocated ledger too.

    It spelled `$PLUGIN_DATA/ledger.db` out for itself, which after the
    transition is the directory fence: the line would go silent on a
    repaired installation and look exactly like a machine with nothing to
    report. It also passed the ledger's own parent as the data directory,
    which is where the daemon socket is not.

    Landed with the GREEN commit rather than the RED one: the defect was
    found by reading the remaining callers after the resolver changed,
    and it is recorded here rather than left to Pair 7.
    """
    from privacy_hud import ambient

    monkeypatch.setenv("PLUGIN_DATA", str(surface.data))
    assert storage.is_fenced(surface.data)
    assert not storage.legacy_path(surface.data).is_file()
    assert ambient._resolve_session_id() == "s1"
