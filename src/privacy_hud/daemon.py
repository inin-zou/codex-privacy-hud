# src/privacy_hud/daemon.py
"""Long-lived unix-socket server. Pays Presidio-scale detection cost once
per daemon lifetime instead of once per hook invocation (architecture.md
§2's "Process model").

Wire protocol (owned by `hooks/handler.py`, stdlib-only and already
Codex-verified — read that file, not architecture.md §2's illustrative
example, which no code actually parses): newline-delimited JSON over a
unix socket.

    -> {"v": 1, "op": "event", "payload": <verbatim Codex hook JSON>}
    <- <hook-output JSON, written back to Codex's stdout as-is>

`dispatch.dispatch()` builds the reply; this module is only the socket
plumbing: accept a connection, read one line, hand the payload to
`dispatch`, write one line back, chmod the socket 0600, and idle-exit
after 30 minutes with no connections.

Concurrency: see `Daemon`'s docstring and task-10-report.md for the full
locking rationale. Short version: `dispatch.State.lock` is a single,
daemon-wide `threading.Lock` guarding every access to the shared
`Ledger`/`Engine` state, because the underlying resource that must not
corrupt is one shared `sqlite3.Connection` — a resource scoped to the
whole daemon, not to any one session — so the correct lock scope is the
daemon, not the session. See dispatch.py for where that lock is actually
held.

No raw sensitive value is ever logged or printed anywhere in this module.
"""
from __future__ import annotations

import json
import os
import socketserver
import sys
import threading
import time
from pathlib import Path

from .dispatch import State, dispatch, new_state

# Brief: "Idle-exit after 30 minutes with no connections."
IDLE_TIMEOUT = 30 * 60  # seconds

# How long each `handle_request()` call blocks in select() before
# returning control to the idle-check loop. This is what makes idle-exit
# work WITHOUT a busy loop: `socketserver.BaseServer.handle_request()`
# selects on the listening socket for up to `self.timeout` seconds and
# calls the (no-op, by default) `handle_timeout()` if nothing arrived, so
# the loop below sleeps efficiently in the kernel between checks instead
# of spinning.
ACCEPT_POLL = 5.0  # seconds


class _Handler(socketserver.StreamRequestHandler):
    """Reads exactly one newline-delimited JSON request, dispatches it,
    and writes exactly one newline-delimited JSON reply.

    Never lets an exception escape to the thread's default handler (which
    would just print a traceback to stderr — acceptable, but pointless
    when the client already has fail-open/fail-closed defaults for
    "the daemon gave me nothing useful"). Any failure here degrades to no
    reply at all, which is exactly the "daemon crash mid-request" row in
    architecture.md §2's failure table and is handled by the client.
    """

    # Codex's own hook timeout is 5s (hooks.json) and the client's socket
    # read timeout is 120ms; there is no reason for this handler to ever
    # block long on a single line, but bound it anyway so one wedged
    # client can't tie up a worker thread indefinitely. Note: this must be
    # applied via `self.connection.settimeout(...)` in `setup()` —
    # `BaseRequestHandler` has no `timeout` class attribute of its own
    # (that name belongs to `BaseServer`, a different class), so merely
    # declaring one here would silently do nothing.
    request_timeout = 5.0

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.request_timeout)

    def handle(self) -> None:
        try:
            line = self.rfile.readline()
        except OSError:
            return
        if not line:
            return
        try:
            request = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(request, dict):
            return
        payload = request.get("payload")
        if not isinstance(payload, dict):
            return

        try:
            reply = dispatch(self.server.state, payload)
        except Exception:
            # A bug in one event must not take the daemon down for every
            # other session; the client's own fail-open/fail-closed
            # default takes over for THIS call when it gets no reply.
            reply = {}

        try:
            self.wfile.write((json.dumps(reply) + "\n").encode("utf-8"))
        except OSError:
            pass


class Daemon(socketserver.ThreadingUnixStreamServer):
    """`socketserver.ThreadingUnixStreamServer` at `socket_path`, backed by
    one `dispatch.State` built from `data_dir`.

    Locking strategy (stated explicitly per the task brief): a single
    `threading.Lock` on `self.state` (`dispatch.State.lock`) guards every
    access to `state.ledger`, `state.engines`, `state.salts`, and
    `state.started_at`. `dispatch()` acquires it around each block that
    touches the ledger's sqlite connection or mutates per-session dicts,
    and releases it before returning.

    This is a single daemon-wide lock, not one lock per `session_id`,
    because the resource that must not corrupt under concurrent hook
    calls — `Ledger`'s one `sqlite3.Connection` — is shared by ALL
    sessions, not scoped to one. A per-session lock would correctly
    serialize two concurrent calls for the SAME session (the case the
    brief calls out explicitly) but would NOT prevent two DIFFERENT
    sessions' worker threads from calling `self.conn.execute(...)`
    concurrently on that one connection, which is exactly the scenario
    Python's `sqlite3` docs warn is unsafe without external
    serialization. So the lock's necessary scope is set by the shared
    connection, not by session identity — "no more broadly than
    necessary" here means "covers every touch of the shared ledger",
    which in this design is the whole `dispatch()` call. Given the
    latency budget (architecture.md §10: ~5ms for the ledger write, ~6ms
    for tiers 0-2, well under the 150ms p99 target), the cost of a single
    global lock is negligible next to the correctness it buys.

    Idle-exit: overrides `serve_forever()` to loop over `handle_request()`
    (which itself blocks in `select()` for up to `ACCEPT_POLL` seconds)
    rather than the base class's fixed-`poll_interval` `serve_forever()`,
    and exits the loop once `ACCEPT_POLL`-spaced wall-clock checks show
    `idle_timeout` seconds have passed with no accepted connection. No
    busy loop: each iteration either blocks in the kernel on `select()`
    until a connection arrives, or returns (a no-op) after `ACCEPT_POLL`
    seconds.
    """

    daemon_threads = True
    allow_reuse_address = True
    # socketserver's default backlog (5) is easy to exceed even under
    # ordinary concurrency (a subagent turn can fire several PreToolUse/
    # PostToolUse calls close together); on macOS a full AF_UNIX backlog
    # makes the kernel refuse new connections outright (ECONNREFUSED)
    # rather than queue them, so a generous backlog here is not just
    # throughput — it is the difference between "queued briefly" and "the
    # client's own timeout/fail-open path fires for no real reason."
    request_queue_size = 128

    def __init__(self, socket_path, data_dir, *, idle_timeout: float = IDLE_TIMEOUT,
                 poll_interval: float = ACCEPT_POLL, state: State | None = None):
        self.socket_path = Path(socket_path)
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()

        self.state = state if state is not None else new_state(data_dir)
        self.idle_timeout = idle_timeout

        super().__init__(str(self.socket_path), _Handler)
        # Global constraint: the socket file must be 0600. bind() has
        # already created it by the time __init__ returns (base class
        # calls server_bind()/server_activate() before this constructor
        # body resumes), so chmod it here rather than relying on any
        # process umask to get this right.
        os.chmod(self.socket_path, 0o600)

        self.timeout = poll_interval  # bounds each handle_request() select()
        self._running = False
        self._last_activity = time.monotonic()
        self._activity_lock = threading.Lock()

    # -- idle tracking ---------------------------------------------------
    def verify_request(self, request, client_address) -> bool:
        """Called synchronously in the accept loop for every accepted
        connection, before the request is handed to a worker thread — the
        one hook point guaranteed to run exactly once per connection
        regardless of what that connection turns out to contain, which
        makes it the right place to record "not idle" for the idle-exit
        clock.
        """
        with self._activity_lock:
            self._last_activity = time.monotonic()
        return True

    def _idle_seconds(self) -> float:
        with self._activity_lock:
            return time.monotonic() - self._last_activity

    # -- serve loop -------------------------------------------------------
    def serve_forever(self, poll_interval: float | None = None) -> None:  # noqa: D401
        """Serve requests until `idle_timeout` seconds pass with no
        accepted connection, then close the socket and return. See the
        class docstring for why this has no busy loop.
        """
        if poll_interval is not None:
            self.timeout = poll_interval
        self._running = True
        with self._activity_lock:
            self._last_activity = time.monotonic()
        try:
            while self._running and self._idle_seconds() < self.idle_timeout:
                self.handle_request()
        finally:
            self._close()

    def stop(self) -> None:
        """Ask a running `serve_forever()` loop to exit at the next
        `handle_request()` boundary (at most `self.timeout` seconds)."""
        self._running = False

    def _close(self) -> None:
        try:
            self.server_close()
        finally:
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass


def _default_socket_path(data_dir: Path) -> Path:
    return data_dir / "daemon.sock"


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: `python -m privacy_hud.daemon` (or spawned detached
    by a future lazy-start caller). Reads `PLUGIN_DATA` for the data
    directory, same env var `hooks/handler.py` reads for the socket path.
    """
    data_dir = Path(os.environ.get("PLUGIN_DATA", "/tmp"))
    socket_path = _default_socket_path(data_dir)
    daemon = Daemon(socket_path, data_dir)
    try:
        daemon.serve_forever()  # returns on its own after idle_timeout;
                                 # its own `finally` closes the socket on
                                 # any exit path, KeyboardInterrupt included
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
