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

Concurrency: see `Daemon`'s docstring for the full locking rationale.
Short version: `dispatch.State.lock` is a single, daemon-wide
`threading.Lock`, because the underlying resource that must not corrupt is
one shared `sqlite3.Connection` — a resource scoped to the whole daemon,
not to any one session — so the correct lock *scope* is the daemon, not
the session. But it is held only across the code that touches that
connection, NOT across detection: model inference reads no sqlite, so
`dispatch()` runs `Engine.scan()` between two short lock holds. See
dispatch.py for where the lock is actually taken.

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

from .dispatch import State, _deny, dispatch, new_state

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


def _deny_for_internal_failure(payload: dict) -> dict:
    """Fail-closed reply for a `PreToolUse` payload that `dispatch()`
    raised on, for any reason (a `Matrix.boundary_for()` `UnknownKey`, a
    sqlite error, any other bug).

    Deliberately does NOT re-run `dispatch.py`'s classification logic
    (`_build_observation`'s destination/tool-name derivation) to produce a
    more specific reason: that classification is itself part of the code
    path that just raised inside `dispatch()`, and calling it again here,
    inside an exception handler whose entire job is to be a safe last
    resort, would risk a second exception before any reply is written at
    all. `dispatch._deny()` is a plain dict literal — no lookups, no
    exceptions possible — so it is safe to call directly. Precision is not
    the goal here; not silently allowing an egress call through on an
    internal bug is (I6: fail closed on egress, even when the daemon
    itself is what's failing).
    """
    tool_name = payload.get("tool_name")
    detail = f" ({tool_name})" if isinstance(tool_name, str) and tool_name else ""
    return _deny(
        "Privacy HUD hit an internal error while checking this call"
        f"{detail} and is denying it to fail closed."
    )


class _Handler(socketserver.StreamRequestHandler):
    """Reads exactly one newline-delimited JSON request, dispatches it,
    and writes exactly one newline-delimited JSON reply.

    Never lets an exception escape to the thread's default handler (which
    would just print a traceback to stderr — acceptable, but pointless
    when the client already has fail-open/fail-closed defaults for
    "the daemon gave me nothing useful"). A failure before `dispatch()` is
    even reached (bad JSON, a non-dict payload, ...) degrades to no reply
    at all, which is exactly the "daemon crash mid-request" row in
    architecture.md §2's failure table and is handled by the client.

    A failure INSIDE `dispatch()` is different: the client's fail-open/
    fail-closed logic only ever triggers on the CLIENT's own exception
    (connection refused, timeout, malformed JSON) — a reply that arrives
    cleanly, `{}` included, always reads as "proceed" (`{}` is exactly
    `dispatch._allow()`'s own shape). So for a `PreToolUse` payload — the
    only event that can ever be egress — `handle()` does not let a
    `dispatch()` exception degrade to `{}`; see `_deny_for_internal_failure`
    below and I6 ("fail closed on egress", CLAUDE.md §3, which applies to
    our own crashes, not just timeouts).
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
            # other session -- this per-request exception boundary stays.
            # But what we substitute for the failed reply must not be
            # `{}`: that is `dispatch._allow()`'s own shape, and the
            # client (hooks/handler.py) has no way to distinguish "the
            # daemon deliberately allowed this" from "the daemon crashed
            # and we defaulted to allow" -- its fail-open/fail-closed
            # logic only fires on the CLIENT's own exception, never on a
            # cleanly-received reply's content. Only `PreToolUse` can ever
            # be egress (SessionStart/PostToolUse/SessionEnd/SubagentStart
            # are ingress/propagate/lifecycle by construction — see
            # dispatch.py's mapping table), so that cheap, exception-proof
            # check is the gate: fail closed there (I6), fail open
            # everywhere else exactly as before.
            if payload.get("hook_event_name") == "PreToolUse":
                reply = _deny_for_internal_failure(payload)
            else:
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

    **Scope: daemon-wide, and that part is not negotiable.** This is one
    lock for the whole daemon, not one lock per `session_id`, because the
    resource that must not corrupt under concurrent hook calls —
    `Ledger`'s one `sqlite3.Connection` — is shared by ALL sessions, not
    scoped to one. A per-session lock would correctly serialize two
    concurrent calls for the SAME session but would NOT prevent two
    DIFFERENT sessions' worker threads from calling `self.conn.execute(...)`
    concurrently on that one connection, which is exactly the scenario
    Python's `sqlite3` docs warn is unsafe without external
    serialization. So the lock's necessary scope is set by the shared
    connection, not by session identity.

    **Hold time: only the ledger interaction, NOT detection.** "No more
    broadly than necessary" bites here, and an earlier version of this
    docstring got it wrong. It used to conclude that "covers every touch
    of the shared ledger" meant "the whole `dispatch()` call", and
    justified that with architecture.md §10's latency budget (~5ms for the
    ledger write, ~6ms for tiers 0-2, well under the 150ms p99 target).
    That estimate predates the fix that made tier 3 run unconditionally on
    every qualifying observation, and is roughly 50-100x off today: a
    single warm ingress request through this daemon measures ~540ms on this
    machine, essentially all of it one model forward pass.

    Where that actually hurt is not where a first reading suggests, so the
    numbers are worth stating precisely. Tier 3 runs on **ingress only** —
    `Engine._scan` skips it for `local` (B0) and for B3/B4, and
    `dispatch._build_observation` only ever produces `mcp_tool` (B3) or
    `external_net` (B4) for `PreToolUse`. So every expensive request is a
    `UserPromptSubmit`/`PostToolUse`, and for those `dispatch()`'s reply is
    unconditionally `{}`: ingress can never deny or rewrite (Ruling 3), so
    the scan result affects the ledger and nothing else. Meanwhile
    `PreToolUse` — the only event that can be egress, the only one whose
    reply carries a real decision, and the one I6 makes fail closed — is
    regex-only and inherently sub-millisecond.

    Holding one daemon-wide lock across inference put those two in the same
    queue. Measured on this machine (12 cores, torch 2.14, model warm, 6
    distinct session ids), before the split:

        single warm ingress request                  ~540 ms
        6 concurrent ingress, wall                 ~3230 ms  (~100% of the
                                                    fully-serialized cost)
        egress PreToolUse issued while those
        6 ingress scans are in flight              ~3060 ms

    That last row is the bug. `hooks/handler.py`'s client timeout is 2.0s,
    so a `PreToolUse` that this daemon would have answered in under a
    millisecond instead never gets answered in time, the client's exception
    path fires, and per I6 it **denies**. Demonstrated end to end with a
    benign call — `curl https://example.com/health`, no credential anywhere,
    daemon's real answer `{}` (allow) — issued with the real 2.0s client
    timeout while six ingress scans ran: before the split it took 2002ms and
    Codex was told to deny; after, 0.7ms and allow. A privacy tool that
    blocks a harmless health check because an unrelated session is busy has
    failed at being a privacy tool.

    (Worth recording what this is NOT, since it is the intuitive guess and
    it is wrong: ingress disclosures are not lost when the client times
    out. Probed directly — 10 concurrent ingress calls with the real 2.0s
    timeout, 7 clients gave up, and all 10 rows were in the ledger once the
    daemon drained. The worker thread finishes its `Ledger.record` whether
    or not anyone is still listening; only the reply is dropped, and for
    ingress the reply was `{}` anyway. What the user loses on an ingress
    timeout is a misleading "disclosure unverified" note, not a row.)

    The fix is scope, not scale: **model inference does not touch sqlite**,
    so it does not belong inside a lock whose only job is serializing
    sqlite. `Engine` splits into `scan()` (destination classification and
    tiers 0-3 detection; reads the immutable matrix and the shared
    detectors, no ledger) and `observe(obs, scan=...)` (the policy reads,
    consent-token consumption, `Ledger.record` loop and `Ledger.summary` —
    every sqlite touch in that module). `dispatch()` runs the scan between
    two short lock holds. Dedupe
    (`UNIQUE(session_id, value_hash, destination)`) and I4's monotonic
    budget are both preserved because both live entirely inside
    `Ledger.record`, hence entirely inside one uninterrupted lock hold —
    the read-modify-write is never split across the gap. See
    `Engine.observe`'s docstring for the full "what can change in between"
    argument, and `dispatch.dispatch()` for the three steps.

    **What this fix does not do, so nobody re-derives it from the diff.**
    It does not make N concurrent ingress scans finish any faster: after
    the split, 6 concurrent ingress still costs ~3250ms wall, because tier
    3 is a genuinely serial resource on this machine and `engine._TIER3_LOCK`
    now says so out loud (that lock's comment carries the measurement —
    unserialized concurrent inference segfaults the interpreter, and even
    when it survives it runs ~140% of the serialized cost at N=6,
    unchanged by `torch.set_num_threads`). Ingress throughput is bounded by
    inference, not by locking, and no amount of lock surgery moves it. What
    the split buys is that inference no longer blocks the *decision* path
    or any ledger operation: egress `PreToolUse` under the same load goes
    from ~3060ms to ~1.5ms, and `SessionStart`/`SessionEnd` stay
    sub-millisecond. Raising ingress throughput is a different change with
    a different design (taking ingress off the client's critical path
    entirely, since its reply is a constant `{}`) and different tradeoffs
    (receipt completeness at `SessionEnd`, durability of a queue the daemon
    could be killed with). It is deliberately not attempted here.

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
