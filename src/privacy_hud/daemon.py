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
`dispatch`, write one line back, chmod the socket 0600, and exit once
every Codex session it was serving has ended (see `Daemon`'s "Lifetime
policy" section — the daemon serves all concurrent sessions, so this is a
reference count, not a timeout).

Startup is single-instance: several processes may try to start a daemon
at the same socket path concurrently (the hook client spawning one on
first use), exactly one wins, and a loser exits without touching the
winner's socket. See `Daemon`'s "Single instance" section for the
mechanism and `main()` for the exit codes.

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

import errno
import fcntl
import json
import os
import socket
import socketserver
import stat
import sys
import threading
import time
from pathlib import Path

from .dispatch import State, _deny, dispatch, live_session_count, new_state

# -- daemon lifetime ---------------------------------------------------
# Every number below is argued in `Daemon`'s "Lifetime policy" section.
# Read it before changing one: the three constants are a single policy, and
# each is only defensible in terms of the other two.

# How long the daemon stays up after the LAST live session ends. Not an
# idle timeout — an interval the daemon spends betting that another session
# is about to arrive, because a wrong bet costs a 7 s cold start plus an
# unmonitored window that has been measured to swallow an entire short
# session, and a right bet costs a few more minutes of a process whose
# resident set decays to ~68 MB while it waits (measured; see the class
# docstring).
LINGER_GRACE = 5 * 60  # seconds

# A session with no hook event for this long is presumed dead and stops
# counting as a reason to stay up. This is the bound on a reference leaked
# by a Codex that crashed or was `kill -9`'d without sending `SessionEnd`.
SESSION_STALE_AFTER = 4 * 60 * 60  # seconds

# Absolute cap: exit after this long with no accepted connection of ANY
# kind, whatever the session count says. Deliberately the same 4 hours as
# `SESSION_STALE_AFTER`, and deliberately redundant with it — see the
# "Bounding a leaked reference" part of `Daemon`'s docstring for why a
# backstop that shares no code with the thing it backs up is worth keeping
# even when it can be shown to fire at almost the same moment.
IDLE_TIMEOUT = 4 * 60 * 60  # seconds

# Once the exit condition is met, how long to keep serving so in-flight
# requests can finish writing their replies. Bounded rather than
# open-ended: a request that leaks the in-flight counter (see
# `_request_finished`) must delay the exit, never prevent it. 30 s is
# comfortably above `_Handler.request_timeout` (5 s) plus the slowest
# measured request (a tier-3 ingress scan under contention, ~3 s).
DRAIN_TIMEOUT = 30.0  # seconds

# How long each `handle_request()` call blocks in select() before
# returning control to the idle-check loop. This is what makes idle-exit
# work WITHOUT a busy loop: `socketserver.BaseServer.handle_request()`
# selects on the listening socket for up to `self.timeout` seconds and
# calls the (no-op, by default) `handle_timeout()` if nothing arrived, so
# the loop below sleeps efficiently in the kernel between checks instead
# of spinning.
ACCEPT_POLL = 5.0  # seconds

# Sidecar file whose kernel-held `flock` is what makes "exactly one daemon
# per socket path" true rather than likely. See `Daemon`'s "Single
# instance" section for the whole argument; see `_acquire_startup_lock` for
# why the suffix is appended to the socket's *name* (so the lock always
# lands in the same directory as the socket it guards, whatever that
# directory is).
LOCK_SUFFIX = ".lock"

# How long the liveness probe waits for `connect()` on an existing socket
# file. A live daemon's kernel-side accept queue makes this effectively
# instant (`request_queue_size` is 128 and the listen backlog answers the
# connect without any userspace involvement), and a dead one's socket file
# refuses immediately, so this bound only ever matters for the pathological
# "something is bound here but wedged" case -- where it expires and we
# refuse to touch the file, which is the safe answer.
PROBE_TIMEOUT = 0.5  # seconds

# Exit-code contract for `main()`, read by the auto-spawning hook client.
# 0 / 1 match `privacy-hud-doctor`'s existing "usable / broken" convention;
# 3 is deliberately outside it (2 is reserved by convention for CLI usage
# errors) and means "nothing is wrong -- the daemon you wanted already
# exists".
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_ALREADY_RUNNING = 3

# Serializes the umask save/restore around `bind()` (see `Daemon.__init__`).
# `os.umask()` is process-global and read-modify-write, so two threads each
# doing "save, narrow, bind, restore" can interleave into "T1 saves 022, T2
# saves 0177, T1 restores 022, T2 restores 0177" and leave the whole process
# at 0177 for good -- after which every directory anything in the process
# creates comes out 0600, with no search bit, and unrelated code starts
# failing with EACCES. That is not hypothetical: it was observed while
# validating tests/test_daemon.py's race test, whose four racers all reach
# `bind()` when the startup lock is removed. The lock costs one uncontended
# acquire per daemon startup.
_UMASK_LOCK = threading.Lock()


class AlreadyRunning(RuntimeError):
    """Another daemon already owns `socket_path`; this one must not start.

    Not an error condition: the caller asked for a daemon at that path and
    there is one. `main()` maps this to `EXIT_ALREADY_RUNNING`, which an
    auto-spawning hook client can treat as success. It is a `RuntimeError`
    and NOT an `OSError` precisely so that "someone else owns it" cannot be
    confused with a real bind failure by either `main()` or a test.
    """

    def __init__(self, socket_path, detail: str):
        self.socket_path = Path(socket_path)
        self.detail = detail
        super().__init__(
            f"another privacy-hud daemon already owns {self.socket_path} "
            f"({detail}); not starting a second one"
        )


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

    def finish(self) -> None:
        """Flush the reply, THEN tell the server this request is done.

        Order is the point. `StreamRequestHandler.finish()` is what flushes
        `wfile` — the actual bytes of the reply, including a `SessionEnd`
        receipt — and the server's serve loop is allowed to break (and the
        process to exit) the moment the in-flight count reaches zero. So the
        decrement must be strictly after the flush, and in a `finally` so a
        flush that raises still releases the count rather than pinning the
        daemon until `DRAIN_TIMEOUT`.
        """
        try:
            super().finish()
        finally:
            self.server._request_finished()

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

    Two unrelated locks appear in this class and they guard different
    things: the **startup lock** below (a `flock` on a file, guarding "only
    one daemon per socket path") and `dispatch.State.lock` (a
    `threading.Lock` guarding one sqlite connection, "Locking strategy"
    further down). Neither is ever held while the other is taken.

    Single instance: why two daemons cannot both own one socket path
    ---------------------------------------------------------------
    `__init__` used to open with an unconditional

        if self.socket_path.exists(): self.socket_path.unlink()

    which is correct for exactly one caller: a human starting one daemon by
    hand. The moment startup is automatic (a hook client spawning the
    daemon on first use), two Codex sessions starting together both run
    that line, and the second **deletes the first's live socket** and binds
    its own. The first daemon does not notice or exit: it keeps serving a
    socket with no name, holding its resident model, until the lifetime
    policy below finally lets it go -- and every hook already talking to it
    silently falls through to `hooks/handler.py`'s fail-open/fail-closed
    defaults with nothing anywhere saying so. That trades a visible failure ("you forgot
    to start the daemon", which `privacy-hud-doctor` diagnoses in one line)
    for an invisible one, which is the class of regression CLAUDE.md §5
    exists to prevent.

    **Mechanism.** An exclusive `fcntl.flock` on a sidecar file next to the
    socket (`<socket>.lock`), taken as the FIRST thing `__init__` does and
    held for the daemon's entire life. Only while holding it does this
    process probe the socket for a live listener, unlink a stale socket
    file, and bind.

    **Why the race is closed and not merely narrowed.** The tempting fix is
    "probe with `connect()` before unlinking", and on its own it is not a
    fix at all: between a successful probe and the `bind()` there is a
    window in which the other process's probe also runs, and both conclude
    the path is theirs. The lock removes the window rather than shrinking
    it, in four steps:

    1. `flock(LOCK_EX | LOCK_NB)` is decided by the kernel against the lock
       file's inode. Two open file descriptions cannot hold it at once --
       there is no interleaving of the "check" and the "act", because the
       acquire IS the check and it is atomic. One racer gets the fd, the
       other gets `EAGAIN` immediately (no blocking, hence no deadlock and
       no retry loop, hence no livelock).
    2. The lock is held for the daemon's **whole lifetime**, not just
       across startup. So "this process holds the lock" implies "no other
       daemon that follows this protocol is alive on this path", which is
       what makes the unlink in step 3 safe: any socket file still sitting
       there must belong to a process that is gone.
    3. Both the unlink of a stale socket and, at shutdown, the unlink of
       our own socket happen under the lock. A new starter therefore cannot
       have bound in between and cannot have its socket deleted by our
       shutdown -- `_close()` unlinks the socket BEFORE releasing the lock,
       in that order, for exactly this reason.
    4. `flock` is associated with the open file description, not with the
       process, so a second `open()` in the SAME process conflicts too.
       That is not incidental: it is why the thread-level race test in
       tests/test_daemon.py is a valid test of the real thing, and it is
       why this uses `flock` and not `fcntl.lockf` -- POSIX record locks are
       per-process, so a second thread's request would silently *succeed*
       (replacing the existing lock) and both racers would bind.

    Two supporting details that are load-bearing:

    * **The lock file is created once and never unlinked.** Deleting it
      would reintroduce a race of its own: process A (exiting) unlinks the
      path while process B is already holding a lock on that now-nameless
      inode, then process C creates a fresh file at the same path and locks
      *that* inode -- B and C both "hold the lock" and both bind. A
      zero-byte file left in `PLUGIN_DATA` is the price of not having that
      bug. Nothing is ever written into it (I1: its only content is kernel
      lock state), and the kernel drops the lock when the holder dies, so
      unlike a pidfile it cannot go stale and wedge the plugin.
    * **A crashed daemon still self-heals.** `flock` dies with its process,
      so after a `kill -9` the next starter takes the lock, probes the
      leftover socket file, gets `ECONNREFUSED`, unlinks it, and binds --
      the pre-existing behavior, preserved deliberately.

    **Why not bind-a-temp-path-then-`rename()`.** `rename()` is atomic, but
    atomic *replacement* is the wrong primitive here: both processes end up
    with a successfully bound socket and the loser is the one holding the
    now-unnamed one. That is the same invisible-downgrade bug with the
    roles swapped -- last writer wins, earlier daemon keeps running
    unreachable. Atomicity of the swap was never what was missing; mutual
    exclusion between two *starters* was.

    **What this does NOT close, stated rather than papered over.** The lock
    only excludes starters that take it. A daemon from a build that predates
    this code, or any other process bound at that path, is invisible to the
    lock, and for those the `connect()` probe is the only defense and is
    genuinely best-effort: if such a process is mid-unlink-and-bind while we
    probe, either side can lose. No lock can fix a participant that does not
    take it; what the probe does guarantee is that we never unlink a socket
    that answers a connection right now, and that an unprobeable socket file
    (a non-socket, or a `connect()` failing for any reason other than
    "nobody home") is left strictly alone so `bind()` fails loudly with
    `EADDRINUSE` instead of anything being clobbered.

    **The 0600 constraint survives all of this.** The socket is still bound
    at its real path (no temp path, so no interval where it is visible under
    another name) and still chmod-ed 0600 after bind; additionally `bind()`
    now runs under a temporarily restrictive umask, which closes the small
    pre-existing window in which the freshly-created socket carried
    `0777 & ~umask` (typically 0755) between `bind()` and `chmod()`. The
    chmod stays as the authoritative guarantee -- umask is process-global
    and this narrow save-and-restore around one `bind()` call is not
    something to depend on -- and the lock file itself is created 0600.

    Exit codes for the CLI wrapper are in `main()`.

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

    Lifetime policy: exit when every Codex session has ended
    --------------------------------------------------------
    **Why this is not simply "exit on SessionEnd".** One daemon serves every
    concurrent Codex session — that is the whole reason it is a daemon and
    not a subprocess per session. Two Codex windows, or a `codex exec`
    one-shot fired from inside an interactive session (both are in this
    project's own ledger: session `01a06c30` ran entirely inside session
    `01a06821`'s 19-hour span), share one process, one model and one sqlite
    connection. Exiting on the first `SessionEnd` would take the daemon away
    from a session that is still running, and the failure is *silent*: the
    next hook gets `ECONNREFUSED`, `hooks/handler.py` answers from its
    fail-open/fail-closed defaults, and the user goes on believing the
    session is monitored while nothing is being recorded. Silently
    unmonitoring a live session is the worst outcome this module can
    produce, so the exit decision is a reference count over
    `dispatch.State.live` and never a single event.

    **The policy, in three rules.**

    1. While any session is live, do not exit on idle. An interactive
       session where nobody runs a tool for half an hour is not over; it is
       a person reading a diff. The previous rule — 30 minutes since the
       last accepted connection, full stop — took the daemon away from those
       sessions and put them back through the cold-start window
       *mid-session*, which is exactly the "the ledger does not know what it
       is missing" hole README.md's known limit 1 exists to warn about.
    2. When the last session ends, exit after `LINGER_GRACE` (5 min).
    3. Regardless of the count, a session with no hook event for
       `SESSION_STALE_AFTER` (4 h) stops counting, and the daemon exits
       after `IDLE_TIMEOUT` (4 h) with no connection of any kind.

    **Why 5 minutes and not 0.** Rule 2 is the one that is easy to get
    wrong in the tempting direction. The measured `codex exec` one-shot in
    this project's ledger ran 23:47:24 → 23:47:27 — **three seconds**, with
    `SessionEnd` firing reliably. A script looping `codex exec` therefore
    drops the count to zero every few seconds, and a grace of zero (or of
    "a few seconds") makes every iteration pay a cold start: ~7 s of model
    load before the socket binds, during which the *entire* next one-shot
    can come and go unrecorded — README.md's known limit 1 records a real
    8.2 s `codex exec` that recorded nothing at all for exactly this reason.
    That is the product failing completely, once per loop iteration.

    The two sides are not commensurable, which is what settles the number.
    Staying up costs ~0.47 GB of RSS while the daemon is working (measured;
    the 2.8 GB figure elsewhere in this repo is the on-disk weight size —
    resident is far smaller because the model is 1.5B total / 50M active
    MoE), and materially less than that while it is doing nothing, which is
    exactly the state the grace period is: measured end to end on this
    machine, a daemon's RSS decayed from 527 MB to **68 MB** within about
    two minutes of its last request, because the weight pages are clean and
    the OS reclaims them. So the thing being weighed against a hole in the
    ledger is not half a gigabyte, it is tens of megabytes of an idle
    process. Exiting early, meanwhile, costs a hole in the ledger that the
    ledger cannot report. The grace therefore wants to be as long as it can
    be while still honouring the other half of the requirement — "you quit
    Codex, the daemon goes away".

    Five minutes is where those meet. It is 43x the 7 s cold start, so the
    daemon must sit unused for far longer than restarting it would cost
    before it gives up; it covers a `codex exec` loop that also builds or
    tests between iterations (the one-shots in the ledger last 3-15 s, so
    the gap between them, not their duration, is what has to be covered);
    and against the complaint that started this, it is a 6x reduction from
    the old 30 minutes, which is the difference between "it went away when I
    quit" and "why is this still running". Going to 60 s would buy four more
    minutes of freed RSS and would start losing the loop case; going to 15
    would be the old bug with a smaller number.

    **Bounding a leaked reference.** `SessionEnd` is not guaranteed. A
    `kill -9` on Codex, an OOM, or a closed terminal leaves a reference that
    is never released, and a reference count on its own would let one such
    event pin the process — and its resident model — until the machine
    reboots. Two independent bounds, neither of which trusts the other:

    * **Staleness (rule 3, in `dispatch.live_session_count`).** A session
      with no hook event for 4 hours stops counting. This is the bound that
      still works in the case a global timer cannot see: a leaked reference
      sitting alongside a *busy* live session, whose traffic keeps any
      global idle clock permanently fresh. The sweep releases the reference
      and does nothing else — it does not end the ledger session and does
      not discard the salt, because a staleness guess must not take an
      irreversible action; `live_session_count`'s docstring carries that
      argument.
    * **An absolute cap (`IDLE_TIMEOUT`).** Exit after 4 h with no accepted
      connection at all, whatever the count says. Given the sweep this is
      almost redundant — if nothing has connected for 4 h then every session
      is stale by 4 h — and it is kept precisely because it is redundant: it
      shares no state and no code with the per-session bookkeeping, so it
      still bounds the process if that bookkeeping has a bug. A wrong
      refcount should cost one restart, not an unkillable process.

    Why 4 hours for both: it is the interval a live-but-quiet session is
    allowed before the daemon stops believing in it, so it has to clear the
    real quiet stretches of interactive work — a long build, a meeting,
    lunch — and 4 h clears all of them with room. It deliberately does NOT
    clear "left the window open overnight": keeping a process resident for
    8-14 hours on the chance that a session is still there is the wrong side
    of the trade, and being wrong costs one 7 s restart on the next
    morning's first hook. Note how low the bar for "alive" is — *any* hook resets it,
    including a local `ls` and a `PreCompact`, neither of which records
    anything (see `dispatch.note_session_live`) — so a session only goes
    stale if the user has genuinely done nothing for four hours. This number
    is reasoned, not measured: the ledger records only hooks that *detected*
    something, so it cannot show the gap between consecutive hooks, and
    claiming otherwise would be the kind of unearned precision CLAUDE.md §5
    forbids.

    **Exiting cleanly.** `SessionEnd` renders a receipt, and that reply must
    reach Codex before the process goes. `daemon_threads = True` means
    `server_close()` does not wait for worker threads, so the serve loop
    counts in-flight requests itself: `verify_request` increments
    (synchronously, in the accept loop, so a connection cannot be accepted
    and then missed by the check), `_Handler.finish()` decrements after
    `StreamRequestHandler.finish()` has flushed `wfile`, and the loop
    refuses to break while the count is non-zero. The wait is bounded by
    `DRAIN_TIMEOUT`, because the one way the counter can leak — an exception
    inside `setup()`, or a `Thread.start()` that fails — must delay the exit
    rather than prevent it. In production this guard is belt-and-braces: the
    exit condition requires 5 minutes with no accepted connection and
    `verify_request` stamps that clock at accept time, so a request in
    flight has already made the exit impossible. It is the guarantee, not
    the argument, that matters here.

    **What this does not change.** Nothing about the startup flock or the
    socket unlink: `_close()` still unlinks the socket *before* releasing
    the lock, for the reason spelled out in "Single instance" above, and a
    lifetime-policy exit reaches `_close()` by the same
    `serve_forever()`-`finally` path a `stop()` or a Ctrl-C does. And
    nothing about I6: a daemon that exits is simply restarted by the next
    hook, and until it binds the client answers from its own fail-open /
    fail-closed defaults exactly as it does for a daemon that was never
    started.

    Mechanics: `serve_forever()` overrides the base class's fixed
    `poll_interval` loop with one that calls `handle_request()` (itself
    blocking in `select()` for up to `ACCEPT_POLL` seconds) and re-evaluates
    the exit predicate between calls. No busy loop: each iteration either
    blocks in the kernel until a connection arrives, or returns (a no-op)
    after `ACCEPT_POLL` seconds. `ACCEPT_POLL` is therefore also the
    granularity of every interval above, which is why they are all minutes
    or hours and none is seconds.
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
                 poll_interval: float = ACCEPT_POLL, state: State | None = None,
                 linger_grace: float = LINGER_GRACE,
                 session_stale_after: float = SESSION_STALE_AFTER,
                 drain_timeout: float = DRAIN_TIMEOUT):
        """Raises `AlreadyRunning` if another daemon owns `socket_path`, and
        `OSError` for a real startup failure. Either way nothing is left
        behind: the startup lock is released on every failing path, and a
        failed `bind()` never unlinks anything (socketserver's own
        constructor closes the socket it could not bind, and this class only
        unlinks socket files it has proved dead or has bound itself).

        The four lifetime arguments are the policy in "Lifetime policy"
        above, made injectable so a test can compress hours into
        milliseconds and assert on the *policy* rather than on a clock.
        `idle_timeout` keeps its name and its meaning ("exit after this long
        with no accepted connection") but is now the absolute backstop
        rather than the whole rule: with a live session it is the only thing
        that can end the daemon, and with none, `linger_grace` gets there
        first.
        """
        self.socket_path = Path(socket_path)
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.socket_path.with_name(
            self.socket_path.name + LOCK_SUFFIX)
        self._lock_fd: int | None = None
        self._closed = False
        # Set only once bind() has actually returned. Nothing may unlink
        # `socket_path` unless this is True: a bind that failed with
        # EADDRINUSE means the file at that path is SOMEBODY ELSE'S, and
        # deleting it on the way out of a failed startup would be the very
        # clobber this fix exists to prevent.
        self._bound = False

        # First thing, before the expensive part: a would-be second daemon
        # must find out it is redundant BEFORE it loads a ~2.8 GB model, not
        # after.
        self._acquire_startup_lock()
        try:
            self.state = state if state is not None else new_state(data_dir)
            self.idle_timeout = idle_timeout
            self.linger_grace = linger_grace
            self.session_stale_after = session_stale_after
            self.drain_timeout = drain_timeout

            # Under the lock: decide whether the socket path is free, and
            # take it. See the class docstring for why doing this under the
            # lock is what makes the unlink safe.
            self._claim_socket_path()

            # Global constraint: the socket file must be 0600.
            #
            # bind() creates the file, and it does so with `0777 & ~umask`
            # -- typically 0755, i.e. connectable by any local process for
            # as long as it takes this constructor to reach the chmod below.
            # Narrowing the umask across the bind removes that window
            # instead of shrinking it. The save/restore is deliberately
            # wrapped around this one call and nothing else: umask is
            # process-global, and a wider scope would silently affect files
            # created by other threads. mkdir() above is outside it on
            # purpose -- a directory created under this umask would come out
            # 0600, with no execute bit, and be unusable. `_UMASK_LOCK`
            # keeps two concurrent constructions from interleaving their
            # save/restore and leaking the narrow umask process-wide; see
            # that constant's comment.
            with _UMASK_LOCK:
                prior_umask = os.umask(0o177)
                try:
                    super().__init__(str(self.socket_path), _Handler)
                finally:
                    os.umask(prior_umask)
            self._bound = True
            # And the chmod stays: it, not the umask, is the guarantee.
            os.chmod(self.socket_path, 0o600)
        except BaseException:
            # Includes AlreadyRunning, a failed bind, a failed new_state,
            # and KeyboardInterrupt during startup. Holding a lock for a
            # daemon that does not exist would make the next starter
            # wrongly believe one does.
            self._abort_startup()
            raise

        self.timeout = poll_interval  # bounds each handle_request() select()
        self._running = False
        self._last_activity = time.monotonic()
        # Guards `_last_activity` and `_inflight` together: both are stamped
        # by the same `verify_request()` call, and both are read by the same
        # exit predicate, so one lock is the honest scope.
        self._activity_lock = threading.Lock()
        # Accepted connections whose reply has not been flushed yet. See
        # "Exiting cleanly" in the class docstring.
        self._inflight = 0
        # When the exit condition first became true while requests were
        # still in flight; `None` whenever it is not currently true.
        self._draining_since: float | None = None

    # -- single-instance startup ------------------------------------------
    def _abort_startup(self) -> None:
        """Unwind a partially-completed startup, in the same order `_close()`
        uses: stop listening, remove the socket *we* bound, and only then
        release the startup lock.

        The one failure that can reach here after a successful `bind()` is
        the chmod, and "bound, listening, no serve loop, lock released" is
        exactly the reachable-by-nobody state this fix exists to make
        impossible -- so it is unwound rather than argued about. Everything
        earlier (a held lock, a failed `new_state`, a refused `bind`) leaves
        no socket of ours behind and only the lock to give back; `_bound`
        gates the unlink so a bind that failed because the path was already
        occupied never deletes what occupied it.
        """
        if self._bound:
            try:
                self.server_close()
            except Exception:
                pass
            try:
                self.socket_path.unlink()
            except OSError:
                pass
            self._bound = False
        self._release_startup_lock()

    def _acquire_startup_lock(self) -> None:
        """Take the exclusive, non-blocking `flock` that makes this process
        the only daemon allowed to touch `socket_path`.

        Non-blocking on purpose. Waiting for the other racer would buy
        nothing a caller wants -- the answer "a daemon is being started at
        this path" is already actionable, and the wait would have to be
        bounded anyway, since the holder keeps the lock for its whole
        lifetime -- which, with a live session on the other end, is now
        bounded in hours rather than in the old 30 idle minutes. `EAGAIN`
        therefore becomes `AlreadyRunning` immediately: no blocking, no
        retry loop, no deadlock, no livelock.

        The file is opened `O_CREAT` with mode 0600 (umask can only remove
        bits, so it can never come out more permissive) and is never
        written to and never unlinked -- see the class docstring for why
        deleting it would reintroduce a race.
        """
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            # EWOULDBLOCK is EAGAIN on Linux/macOS; EACCES is what some
            # platforms report for "held by someone else". Anything else
            # (a read-only filesystem, say) is a real failure and must not
            # masquerade as "already running".
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EACCES):
                raise AlreadyRunning(
                    self.socket_path,
                    f"the startup lock {self.lock_path.name} is held") from exc
            raise
        self._lock_fd = fd

    def _release_startup_lock(self) -> None:
        """Drop the startup lock. Idempotent.

        Only ever called after our socket file is gone (`_close`) or when we
        never bound one at all (`__init__`'s failure path). Closing the fd
        would release the lock by itself; the explicit `LOCK_UN` is there to
        make the release a visible event rather than a side effect of
        garbage collection.
        """
        fd, self._lock_fd = self._lock_fd, None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            os.close(fd)

    def _probe_socket_path(self) -> str:
        """Classify whatever is at `socket_path` right now, from a client's
        point of view. Returns one of:

        * `"absent"`  -- no file there; bind straight away.
        * `"stale"`   -- a socket file whose listener is gone
          (`ECONNREFUSED`): a killed daemon's leftover. Safe to unlink.
        * `"live"`    -- `connect()` succeeded, so something is listening.
        * `"unknown"` -- a file exists but its liveness could not be
          established (not a socket at all, `connect()` timing out, any
          other `OSError`). Deliberately NOT treated as stale: we do not
          delete what we cannot prove is dead, and leaving it alone makes
          `bind()` fail with `EADDRINUSE`, i.e. a loud real failure.

        The probe costs a live daemon nothing and records nothing: it opens
        a connection and closes it without sending a byte, so `_Handler`
        reads an empty line and returns before `dispatch()` is ever called
        (no session, no ledger row, no detection -- I1/I3 untouched). The
        only trace is that the accept bumps the idle clock, which is
        correct: someone did just look for this daemon.
        """
        try:
            st = os.stat(self.socket_path)
        except FileNotFoundError:
            return "absent"
        except OSError:
            return "unknown"
        if not stat.S_ISSOCK(st.st_mode):
            return "unknown"

        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(PROBE_TIMEOUT)
            probe.connect(str(self.socket_path))
        except (ConnectionRefusedError, FileNotFoundError):
            return "stale"
        except OSError:
            return "unknown"
        finally:
            probe.close()
        return "live"

    def _claim_socket_path(self) -> None:
        """Make `socket_path` bindable, or refuse to start. Must be called
        with the startup lock held -- that is what makes the unlink here
        provably safe rather than probably safe.
        """
        status = self._probe_socket_path()
        if status == "live":
            # Someone is answering on this path. It is not a daemon that
            # took our lock (we hold it), so it is a foreign or older
            # listener -- either way, clobbering it is the bug we are
            # fixing.
            raise AlreadyRunning(
                self.socket_path, "a listener answered a probe connection")
        if status == "stale":
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass

    # -- idle and in-flight tracking --------------------------------------
    def verify_request(self, request, client_address) -> bool:
        """Called synchronously in the accept loop for every accepted
        connection, before the request is handed to a worker thread — the
        one hook point guaranteed to run exactly once per connection
        regardless of what that connection turns out to contain, which
        makes it the right place both to record "not idle" and to count the
        request as in flight.

        Counting here rather than in `_Handler.setup()` closes a real
        window: `setup()` runs on the worker thread, so between
        `handle_request()` returning to the serve loop and that thread being
        scheduled there is an interval in which an accepted connection is
        invisible to the exit check. This method runs in the accept loop
        itself, so by the time `handle_request()` returns, everything it
        accepted is already counted.
        """
        with self._activity_lock:
            self._last_activity = time.monotonic()
            self._inflight += 1
        return True

    def _request_finished(self) -> None:
        """Called from `_Handler.finish()` once the reply has been flushed.
        Clamped at zero so a double-call can never drive the count negative
        and make the daemon immortal."""
        with self._activity_lock:
            if self._inflight > 0:
                self._inflight -= 1

    def _idle_seconds(self) -> float:
        with self._activity_lock:
            return time.monotonic() - self._last_activity

    def live_sessions(self) -> int:
        """Sessions this daemon is still serving, stale references swept.
        Reads `dispatch.State.live` under its own lock — never
        `State.lock` — so the accept loop can never queue behind another
        session's sqlite work just to ask this question."""
        return live_session_count(self.state,
                                  stale_after=self.session_stale_after)

    # -- exit decision ----------------------------------------------------
    def _exit_due(self) -> bool:
        """Has the lifetime policy said this daemon should go? See
        "Lifetime policy" in the class docstring for why these are the two
        branches and why the numbers are what they are.

        The absolute cap is checked first and unconditionally, so it holds
        even if `live_sessions()` is wrong — that independence is the only
        reason it earns its place next to the staleness sweep.
        """
        idle = self._idle_seconds()
        if idle >= self.idle_timeout:
            return True
        return idle >= self.linger_grace and self.live_sessions() == 0

    def _ready_to_exit(self) -> bool:
        """`_exit_due()`, plus "and no reply is still being written".

        A `SessionEnd` receipt is generated and flushed by a worker thread,
        and the exit that its own release of the last reference triggers
        must not race it. Draining is bounded by `drain_timeout`, because
        the count can in principle leak: `BaseRequestHandler.__init__` calls
        `setup()` OUTSIDE the `try`/`finally` that guarantees `finish()`, so
        an exception there is counted and never released, as is a
        `process_request` whose `Thread.start()` fails. An unbounded wait
        would turn either into a daemon that never exits — precisely the
        failure mode this whole change exists to remove — so a leak costs
        `drain_timeout` and nothing more.

        `_draining_since` measures one *contiguous* stretch of "exit due and
        requests still in flight", so it is cleared on both ways out of that
        stretch — the condition lapsing, and the queue emptying. Clearing it
        on the second is invisible to `serve_forever()` (which breaks the
        moment this returns True) but keeps the predicate honest for any
        other caller: without it, a drain window armed once would count
        against every later drain, and the guard that is supposed to protect
        an in-flight receipt would expire the instant it was armed.
        """
        if not self._exit_due():
            self._draining_since = None
            return False
        with self._activity_lock:
            inflight = self._inflight
        if inflight == 0:
            self._draining_since = None
            return True
        now = time.monotonic()
        if self._draining_since is None:
            self._draining_since = now
            return False
        return now - self._draining_since >= self.drain_timeout

    # -- serve loop -------------------------------------------------------
    def serve_forever(self, poll_interval: float | None = None) -> None:  # noqa: D401
        """Serve requests until the lifetime policy says to stop, then close
        the socket and return. See the class docstring for the policy, and
        for why this has no busy loop.
        """
        if poll_interval is not None:
            self.timeout = poll_interval
        self._running = True
        with self._activity_lock:
            self._last_activity = time.monotonic()
        self._draining_since = None
        try:
            while self._running:
                if self._ready_to_exit():
                    break
                self.handle_request()
        finally:
            self._close()

    def stop(self) -> None:
        """Ask a running `serve_forever()` loop to exit at the next
        `handle_request()` boundary (at most `self.timeout` seconds)."""
        self._running = False

    def _close(self) -> None:
        """Stop listening, remove our socket file, then release the startup
        lock -- in that order, and only that order.

        Releasing the lock before unlinking would let the next starter take
        it, probe (`ECONNREFUSED`, since `server_close()` already happened),
        bind its own socket at this path -- and then our `unlink()` would
        delete the new daemon's socket. Unlinking first means the only
        socket file we can ever remove is the one we bound, because nobody
        else could have bound while we held the lock.

        Idempotent: `serve_forever()`'s `finally` is the normal caller, and
        a second call must not unlink a successor's socket.
        """
        if self._closed:
            return
        self._closed = True
        try:
            self.server_close()
        finally:
            try:
                try:
                    self.socket_path.unlink()
                except FileNotFoundError:
                    pass
                self._bound = False
            finally:
                self._release_startup_lock()


def _default_socket_path(data_dir: Path) -> Path:
    return data_dir / "daemon.sock"


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: `python -m privacy_hud.daemon` (or spawned detached
    by a lazy-start caller). Reads `PLUGIN_DATA` for the data directory,
    same env var `hooks/handler.py` reads for the socket path.

    Exit-code contract, which an auto-spawning hook client can rely on:

    ======  ======================================================
    0       Served, then exited (the lifetime policy in `Daemon` -- the
            last session ended, or nothing has connected in hours --
            `stop()`, or Ctrl-C).
    3       Another daemon already owns the socket path. **Not a
            failure** -- the caller wanted a daemon there and there
            is one; use it. Nothing was clobbered and no model was
            loaded. `EXIT_ALREADY_RUNNING`.
    1       Real startup failure: `bind()` refused, `PLUGIN_DATA`
            unwritable, an `AF_UNIX` path over the kernel's
            ~104-byte limit, and so on. One line on stderr says
            which. `EXIT_FAILURE`.
    ======  ======================================================

    Keeping 3 distinct from 1 is the whole point: a spawner that cannot
    tell them apart either retries forever against a healthy daemon or
    reports a broken setup that is not broken. Anything not in the table
    is an unanticipated bug, and it propagates as a traceback (also exit
    1) rather than being flattened into a tidy message -- I6 is satisfied
    by the client surviving a missing daemon, not by this process hiding
    what happened to it.
    """
    data_dir = Path(os.environ.get("PLUGIN_DATA", "/tmp"))
    socket_path = _default_socket_path(data_dir)
    try:
        daemon = Daemon(socket_path, data_dir)
    except AlreadyRunning as exc:
        print(f"privacy-hud daemon: {exc}", file=sys.stderr)
        return EXIT_ALREADY_RUNNING
    except OSError as exc:
        print(f"privacy-hud daemon: cannot start on {socket_path}: {exc}",
              file=sys.stderr)
        return EXIT_FAILURE
    try:
        daemon.serve_forever()  # returns on its own once every session it
                                 # was serving has ended (see `Daemon`'s
                                 # "Lifetime policy"); its own `finally`
                                 # closes the socket and releases the
                                 # startup lock on any exit path,
                                 # KeyboardInterrupt included
    except KeyboardInterrupt:
        pass
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
