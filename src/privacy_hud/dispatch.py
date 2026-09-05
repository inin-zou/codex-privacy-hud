# src/privacy_hud/dispatch.py
"""Maps a Codex hook payload to an `Observation` and dispatches it through
the shared `Engine`, returning hook-output JSON.

This is the seam between the wire protocol owned by `hooks/handler.py`
(stdlib-only, already shipped and Codex-verified — see that file, not
architecture.md §2's illustrative `{"v":1,"decision":...}` example, which is
NOT what the client actually parses) and the Engine/Ledger/Matrix stack built
in earlier tasks.

Payload -> Observation mapping (architecture.md §10's dispatch table + the
task-10 brief, both consistent with `hooks/handler.py`'s own
`_looks_like_egress` — `tool_name.startswith("mcp")`, not `"mcp__"`):

  hook_event_name    source          destination              direction   text
  UserPromptSubmit   user prompt     model_context             ingress     prompt
  PostToolUse        tool_name       model_context             ingress     tool_response
  PreToolUse (Bash)  tool input      extract_destinations(cmd) egress      command
  PreToolUse (mcp*)  tool input      mcp_tool                  egress      json.dumps(tool_input)
  SubagentStart      main agent      subagent                  propagate   ""
  SessionStart / SessionEnd -- not Engine observations; they drive the
  ledger session lifecycle directly.

  PreToolUse whose resolved destination is "local" (a Bash command
  `extract_destinations` judges local, or any non-Bash/non-MCP tool) is
  ALSO not an Engine observation, despite direction=="egress" in the
  table above: tables.toml's taxonomy has no "PreToolUse/local" entry and
  policy_defaults has no "local" entry (only "PostToolUse/local" exists,
  because Ruling 1 in engine.py was written against local file reads, not
  local Bash commands). Building an Observation there would make
  `Engine.observe` raise `UnknownKey` for the ordinary case of a purely
  local tool call — not a bug to work around with a caught exception
  (Global Constraint I2), but a real signal that "nothing crosses a
  boundary here" should short-circuit before Engine.observe is ever
  called. See `_build_observation`'s early `return None`.

`Observation.tool_input` (added by Task 12, running in parallel on the
main tree while this task was in flight — see `src/privacy_hud/engine.py`
and `src/privacy_hud/minimize.py`): every `PreToolUse` Observation this
module builds carries the exact `tool_input` dict Codex sent, unmodified
— NOT just the flattened `text` field. `Engine.observe`'s consent-token
consumption (`consume_token`) hashes this dict via
`canonical_json`/`sha256` to match a token minted elsewhere (the `$privacy`
UI, Task 13) for exactly these arguments, and its minimization path
(`minimize_tool_input`) needs the real dict shape to know whether to
rewrite a Bash `command` string or an MCP arguments object. Leaving this
unset (None) would silently fall back to `obs.text` inside the engine,
which loses that shape distinction — `PreToolUse` is the only event
mapping in this module that populates it; `PostToolUse`/
`UserPromptSubmit`/`SubagentStart` are ingress/propagate observations the
token/rewrite path never applies to, so they correctly leave it at the
dataclass default (`None`).

Session and salt lifecycle: one `Ledger` connection and one detector set are
shared for the daemon's life; each `session_id` gets its own salt and its
own `Engine` instance wrapping that salt, created on `SessionStart` and
torn down (salt discarded, `Ledger.end_session` called) on `SessionEnd`.
Nothing here ever passes one session's salt into another session's
`Engine` — `State.salts`/`State.engines` are both keyed strictly by
`session_id`, and dropped (not overwritten) at `SessionEnd`.

Session reference counting: `State.live` maps each session id this daemon
believes is alive to the monotonic time of its last hook event. It is
maintained here (`note_session_live` / `release_session`) and read by
`daemon.Daemon`'s serve loop (`live_session_count`) to decide when the
daemon may exit — the daemon serves every concurrent session, so no single
`SessionEnd` may take it down. The *policy* built on this count, and the
reasoning behind every number in it, lives in `daemon.Daemon`'s "Lifetime
policy" section; only the bookkeeping lives here.

Lock scope: `State.lock` exists to serialize one shared resource — the
`Ledger`'s single `sqlite3.Connection` — and is therefore held only across
the code that touches it. Detection is NOT such code: `Engine.scan()` reads
the immutable matrix and the shared detectors and nothing else, so
`dispatch()` runs it between two short lock holds rather than inside one
long one. `daemon.Daemon`'s docstring carries the measurement that forced
this shape; `Engine.observe`'s docstring carries the argument for why
splitting the two phases preserves dedupe and I4.

No raw sensitive value is ever logged or printed anywhere in this module.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .detect.model import ModelDetector
from .detect.paths import PathDetector
from .detect.secrets import SecretDetector
from .detect.shell import extract_destinations
from .engine import Engine, Observation
from .ledger import Ledger
from .mask import new_salt
from .matrix.loader import Matrix, load_matrix
from .render import receipt as render_receipt

# Events with a pinned Observation mapping. Anything else that reaches this
# daemon (SubagentStop, PreCompact, ...) has no Observation defined by the
# brief's table; we allow (empty hook output) and record nothing, rather
# than guessing a mapping that was never specified.
_KNOWN_EVENTS = {
    "SessionStart", "SessionEnd", "UserPromptSubmit", "PostToolUse",
    "PreToolUse", "SubagentStart",
}


@dataclass
class State:
    """All daemon-lifetime state. One instance per daemon process."""

    data_dir: Path
    matrix: Matrix
    ledger: Ledger
    detectors: list

    # Guards every touch of `ledger` (a single shared sqlite3 connection is
    # not safe for unserialized concurrent use — see daemon.py for the full
    # locking rationale) and every read/mutation of the per-session dicts
    # below. It does NOT cover `Engine.scan()`, which touches neither: see
    # `dispatch()` and daemon.py's `Daemon` docstring.
    lock: threading.Lock = field(default_factory=threading.Lock)

    # Per-session state, keyed by session_id. Populated on SessionStart,
    # discarded on SessionEnd. Never shared across session_ids.
    salts: dict[str, bytes] = field(default_factory=dict)
    engines: dict[str, Engine] = field(default_factory=dict)
    started_at: dict[str, float] = field(default_factory=dict)

    # -- session reference count (daemon lifetime) --------------------- #
    # session_id -> `time.monotonic()` of the last hook event seen for it.
    # This is the daemon's answer to "is anyone still using me?", and
    # `daemon.Daemon` reads it (via `live_session_count`) to decide whether
    # it may exit. See that class's "Lifetime policy" section for the whole
    # argument; see `note_session_live` for why it is a timestamp map and
    # not an integer counter.
    #
    # I1: session ids and monotonic timestamps only. A session id is
    # infrastructure — it is already a column in the ledger — and a
    # monotonic timestamp is not even a wall clock, so nothing here can
    # describe what a session did, only that it did something.
    live: dict[str, float] = field(default_factory=dict)

    # Deliberately NOT `lock` above. `lock` serializes one sqlite
    # connection and is held across ledger work that can take milliseconds;
    # `live` is read once per accept-loop iteration by the daemon's serve
    # loop, and making that read queue behind another session's ledger write
    # would put sqlite latency into the accept path for no reason. Lock
    # ordering, stated so it stays true: `lock` may be taken while `live_lock`
    # is NOT held and vice versa — the two are never nested, in either
    # direction, anywhere in this module.
    live_lock: threading.Lock = field(default_factory=threading.Lock)


def new_state(data_dir) -> State:
    """Build the daemon's one-time-cost state: Matrix, Ledger (one sqlite
    connection for the daemon's life), and the detector stack (tiers 0-3).

    `ModelDetector` loads from the local HuggingFace cache only and
    degrades to `available=False` on any failure (missing weights, missing
    `transformers`) rather than raising — see detect/model.py. Building it
    here, once, per daemon lifetime, is the entire point of Task 10: this
    is the expensive step a per-hook-invocation client could never afford.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    matrix = load_matrix()
    ledger = Ledger(data_dir / "ledger.db", matrix)
    _allow_cross_thread_access(ledger, data_dir / "ledger.db")
    detectors = [PathDetector(), SecretDetector(), ModelDetector()]
    return State(data_dir=data_dir, matrix=matrix, ledger=ledger,
                 detectors=detectors)


def _allow_cross_thread_access(ledger: Ledger, db_path: Path) -> None:
    """`Ledger.__init__` opens its sqlite3 connection with the default
    `check_same_thread=True` — correct for a single-threaded caller (every
    existing test), but wrong for this daemon:
    `socketserver.ThreadingUnixStreamServer` hands each accepted
    connection to its own worker thread, and Python's `sqlite3` module
    raises `ProgrammingError` the instant a connection created on one
    thread is touched from another. Left unfixed, every ledger-touching
    dispatch() call from a worker thread would raise, be swallowed by
    daemon.py's `_Handler.handle()` broad `except Exception`, and the
    client would silently get `{}` back — indistinguishable from "nothing
    to report" and very easy to mistake for a working daemon in a demo
    that only ever tries one session at a time.

    Reopen the SAME on-disk database with `check_same_thread=False` so
    worker threads may use it, and rely on `State.lock` (a single
    process-wide lock guarding every touch of this connection — see
    `daemon.Daemon`'s docstring) for the serialization sqlite3's own docs
    say becomes the caller's responsibility once same-thread checking is
    disabled. This is a workaround at the call site rather than a change
    to `Ledger.__init__`'s signature, since `ledger.py` is outside this
    task's file list (daemon.py/dispatch.py/tests/test_daemon.py) and its
    existing single-threaded-by-default contract is correct for every
    OTHER caller.
    """
    ledger.conn.close()
    conn = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    ledger.conn = conn


# --------------------------------------------------------------------- #
# hook-output builders
#
# These produce exactly the JSON hooks/handler.py relays verbatim to
# Codex on stdout (it does `json.loads(buf.decode())` and writes that
# straight out) -- NOT architecture.md §2's `{"v":1,"decision":...}`
# sketch, which no code anywhere parses. `_deny`'s shape matches
# `hooks/handler.py`'s own `_deny()` helper exactly, since a daemon reply
# that used a different key name would be silently ignored by Codex and
# read back as an unexplained "PreToolUse always allows".
# --------------------------------------------------------------------- #

def _allow() -> dict:
    return {}


def _deny(reason: str | None) -> dict:
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason or "Privacy HUD blocked this call.",
    }}


def _allow_with_rewrite(updated_input, message: str | None) -> dict:
    out = {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "updatedInput": updated_input,
    }}
    if message:
        out["systemMessage"] = message
    return out


def _decision_to_output(decision) -> dict:
    if decision.action == "deny":
        return _deny(decision.reason or decision.system_message)
    if decision.action == "rewrite":
        if decision.updated_input is not None:
            return _allow_with_rewrite(decision.updated_input,
                                        decision.system_message)
        # Ruling from engine.py's own REWRITE_TEMPLATE: automatic masking
        # is not wired in yet (that is Task 12, explicitly out of scope
        # here). With no `updated_input` to send, allowing the call through
        # unmodified would silently defeat the mask policy — fail closed
        # instead, same as a `deny`, using the message engine.py already
        # crafted for exactly this case.
        return _deny(decision.system_message or decision.reason)
    # "allow" (and ingress observations, which Ruling 3 never denies):
    # no hook-specific output needed, Codex proceeds normally.
    return _allow()


def _as_text(value) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value)
    except TypeError:
        return str(value)


def _looks_like_mcp(tool_name: str) -> bool:
    # Mirrors hooks/handler.py's own `_looks_like_egress` predicate exactly
    # (`.startswith("mcp")`, not `"mcp__"`) so the daemon's classification
    # of "this is an MCP tool call" never disagrees with the client's.
    return tool_name.startswith("mcp")


def _get_or_start_engine(state: State, session_id: str, *, cwd: str = "",
                          model: str = "") -> Engine:
    """Return the Engine for `session_id`, creating one (with a fresh,
    session-scoped salt) if `SessionStart` was never seen for it. Caller
    must hold `state.lock`.
    """
    engine = state.engines.get(session_id)
    if engine is not None:
        return engine
    salt = state.salts.setdefault(session_id, new_salt())
    state.ledger.start_session(session_id, cwd=cwd, model=model)
    state.started_at.setdefault(session_id, time.time())
    engine = Engine(ledger=state.ledger, matrix=state.matrix, salt=salt,
                     detectors=state.detectors)
    state.engines[session_id] = engine
    return engine


def _build_observation(event: str, session_id: str, payload: dict) -> Observation | None:
    turn_id = payload.get("turn_id")

    if event == "UserPromptSubmit":
        return Observation(
            session_id=session_id, turn_id=turn_id, hook_event=event,
            direction="ingress", source="user prompt",
            destination="model_context", text=payload.get("prompt", "") or "",
            tool_name=None)

    if event == "PostToolUse":
        tool_name = payload.get("tool_name") or "tool"
        return Observation(
            session_id=session_id, turn_id=turn_id, hook_event=event,
            direction="ingress", source=tool_name,
            destination="model_context",
            text=_as_text(payload.get("tool_response", "")),
            tool_name=tool_name)

    if event == "PreToolUse":
        tool_name = payload.get("tool_name") or ""
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = {}
        if tool_name == "Bash":
            command = tool_input.get("command", "") or ""
            dests = extract_destinations(command)
            destination = dests[0] if dests else "external_net"
            if destination == "local":
                # No boundary is crossed. tables.toml's taxonomy has no
                # "PreToolUse/local" entry and policy_defaults has no
                # "local" entry either — by design, not omission: Ruling 1
                # (local always classifies as local_access) was written
                # against PostToolUse local reads (tables.toml only ever
                # defines "PostToolUse/local"), and Engine.observe would
                # raise UnknownKey (I2: never silently caught) if we built
                # an Observation here anyway. A local Bash command has
                # nothing for the engine to score — allow without an
                # Engine.observe call, same as SessionStart/SessionEnd.
                return None
            text = command
        elif _looks_like_mcp(tool_name):
            destination = "mcp_tool"
            text = json.dumps(tool_input)
        else:
            # Not pinned by the mapping table (a non-Bash, non-MCP tool,
            # e.g. a local file Write/Edit): same "no PreToolUse/local
            # taxonomy entry" situation as above — nothing crosses a
            # boundary here, so there is no Engine.observe call to make.
            return None
        return Observation(
            session_id=session_id, turn_id=turn_id, hook_event=event,
            direction="egress", source="tool input", destination=destination,
            text=text, tool_name=tool_name,
            # Task 12: the engine's consent-token and minimization path
            # (consume_token/minimize_tool_input) needs the STRUCTURED
            # tool_input dict, not just the flattened `text` above — pass
            # through exactly what Codex sent, so args_hash and any
            # rewrite are computed against the real payload shape (a bare
            # string for Bash would still work through minimize_tool_input,
            # but would not match a token minted by the UI against the
            # dict shape `{"command": ...}`, so the dict is what we pass).
            tool_input=tool_input)

    if event == "SubagentStart":
        return Observation(
            session_id=session_id, turn_id=turn_id, hook_event=event,
            direction="propagate", source="main agent",
            destination="subagent", text="", tool_name=None)

    return None


# --------------------------------------------------------------------- #
# Session reference counting.
#
# These three functions are the entire mechanism behind "the daemon exits
# once every Codex session has ended". `daemon.Daemon` owns the *policy*
# (the grace period, the staleness bound, the absolute cap) and documents
# the reasoning; this module owns the *bookkeeping*, because this is where
# a hook payload is first understood to belong to a session.
# --------------------------------------------------------------------- #

def note_session_live(state: State, session_id: str) -> None:
    """Record that `session_id` is alive right now.

    Called for every hook event carrying a session id — including the ones
    that produce no Observation and no ledger row at all (a local `ls`
    PreToolUse, `PreCompact`, `SubagentStop`). That breadth is the point: a
    session's *liveness* and its *disclosures* are different questions, and
    a session that spends an hour doing purely local work is exactly as
    alive as one leaking credentials. Keying liveness off ledger activity
    would make the quiet, well-behaved session the one whose daemon gets
    taken away.

    Also registers a session that was never `SessionStart`-ed here. That is
    not a leniency, it is the mid-session restart case: when a daemon exits
    and the next hook starts a fresh one, that new daemon's first sight of
    an ongoing session is some ordinary `PreToolUse`, and it must treat it
    as a reason to stay up. `SessionStart` is a strong signal, not the only
    one.

    A timestamp map rather than an integer refcount, for two reasons the
    integer cannot express. (1) `SessionEnd` is not guaranteed — a `kill -9`
    on Codex increments and never decrements — so a reference has to be able
    to *expire*, which requires knowing when it was last real. (2) Hook
    events for one session arrive concurrently on several worker threads;
    with an integer, "increment on first sight" needs a separate
    already-counted set to stay idempotent, which is the map again with an
    extra failure mode. Assigning `live[session_id] = now` is idempotent by
    construction.
    """
    if not session_id:
        return
    with state.live_lock:
        state.live[session_id] = time.monotonic()


def release_session(state: State, session_id: str) -> None:
    """Drop `session_id`'s reference. Idempotent — a duplicate `SessionEnd`,
    or an end for a session this daemon never saw start, is a no-op.

    Only `SessionEnd` calls this. The staleness sweep in
    `live_session_count` deliberately does NOT: see its docstring for why
    presuming a session dead and *declaring* it ended are different acts.
    """
    if not session_id:
        return
    with state.live_lock:
        state.live.pop(session_id, None)


def live_session_count(state: State, *, stale_after: float) -> int:
    """How many sessions this daemon believes are still alive, after
    dropping any whose last hook event is older than `stale_after` seconds.

    The sweep is the liveness fallback for the one thing reference counting
    cannot survive on its own: `SessionEnd` never arriving. Codex crashing,
    being `kill -9`'d, or a terminal window closing all leave a reference
    that will never be released, and without a sweep one such event pins the
    daemon — and its resident model — for as long as the machine is up.

    **The sweep releases the reference and nothing else.** It does not call
    `Ledger.end_session`, does not discard the salt, and does not drop the
    Engine. Those are `SessionEnd`'s acts and they are irreversible: ending
    a ledger session nulls its `value_hash` column (see `Ledger`), and
    discarding a salt makes every later hash for that session incomparable
    with the earlier ones. A staleness sweep is a *guess* — the session may
    be a real one whose user went to lunch — and a guess must not be allowed
    to take an irreversible action. So a swept session that turns out to be
    alive simply re-registers on its next hook and carries on with the same
    Engine, same salt, same ledger row; the only thing that happened is that
    the daemon stopped counting it as a reason to stay up.

    Called from the daemon's accept loop once per poll interval, so it is
    written to be cheap: one uncontended lock and a pass over a dict that
    holds one entry per concurrent Codex session.
    """
    cutoff = time.monotonic() - stale_after
    with state.live_lock:
        stale = [sid for sid, seen in state.live.items() if seen < cutoff]
        for sid in stale:
            del state.live[sid]
        return len(state.live)


def _handle_session_start(state: State, session_id: str, payload: dict) -> dict:
    with state.lock:
        salt = new_salt()
        state.salts[session_id] = salt
        state.ledger.start_session(session_id, cwd=payload.get("cwd", "") or "",
                                    model=payload.get("model", "") or "")
        state.engines[session_id] = Engine(
            ledger=state.ledger, matrix=state.matrix, salt=salt,
            detectors=state.detectors)
        state.started_at[session_id] = time.time()
    # Outside the lock: `live_lock` and `lock` are never nested (State's
    # `live_lock` comment states the ordering rule this keeps true).
    note_session_live(state, session_id)
    return _allow()


def _handle_session_end(state: State, session_id: str, payload: dict) -> dict:
    with state.lock:
        summary = state.ledger.summary(session_id)
        rows = state.ledger.list_events(session_id, "exposed")
        started = state.started_at.pop(session_id, None)
        state.ledger.end_session(session_id)
        # Discard the session's salt and Engine now — SessionEnd is the one
        # place a salt is destroyed, per the session/salt lifecycle
        # contract above. Any hook event for this session_id that arrives
        # after this point gets a brand-new salt via
        # `_get_or_start_engine`, never the old one.
        state.salts.pop(session_id, None)
        state.engines.pop(session_id, None)

    try:
        minutes = 0
        if started is not None:
            minutes = max(0, int((time.time() - started) // 60))

        message = render_receipt(session_id, summary, rows, minutes)
        return {"systemMessage": message}
    finally:
        # The reference is released only once the receipt exists, and in a
        # `finally` so a rendering bug cannot leak it. Ordering is the
        # cheap half of the guarantee, not the load-bearing half: this is
        # the last session's `SessionEnd` in the common case, so releasing
        # here is what lets the daemon start its exit grace — and the reply
        # still has to be *written* after this function returns. What
        # actually keeps that write from being cut off is `Daemon`'s
        # in-flight drain (see its "Lifetime policy" section); this ordering
        # just means the daemon does not even begin considering exit while
        # the receipt is still being built.
        release_session(state, session_id)


def dispatch(state: State, payload: dict) -> dict:
    """Route one hook payload to the right handler and return hook-output
    JSON. Never raises `UnknownKey`/`KeyError` silently — an observation
    whose destination the matrix cannot classify propagates, which is a
    daemon-level bug worth crashing that one request over (the socket
    handler in daemon.py is what turns that into a safe empty reply for
    the client's own fail-open/fail-closed defaults; it is not swallowed
    here).

    Lock scope for the Engine path is three steps, not one — see the module
    docstring's "Lock scope" note, `Engine.observe`'s docstring for the
    safety argument, and `daemon.Daemon`'s for the measurement:

      1. locked, microseconds: resolve (or start) this session's Engine.
      2. UNLOCKED, ~500ms on ingress (tier 3) and sub-millisecond on egress
         (regex only): `Engine.scan()`. Detection only; no sqlite.
      3. locked, milliseconds: `Engine.observe(obs, scan=...)`. Every ledger
         read and write for this observation, in one critical section.
    """
    event = payload.get("hook_event_name")
    session_id = payload.get("session_id") or ""

    if event == "SessionStart":
        return _handle_session_start(state, session_id, payload)
    if event == "SessionEnd":
        return _handle_session_end(state, session_id, payload)

    # Everything else is evidence that `session_id` is still alive, and is
    # counted as such BEFORE the `_KNOWN_EVENTS` filter and before
    # `_build_observation` can return None. Those two short-circuits are
    # about whether there is anything to *score* — a `PreCompact`, a
    # `SubagentStop`, a purely local Bash command — and none of them mean
    # the session is over. Counting liveness only where a ledger row happens
    # to be produced would take the daemon away from precisely the sessions
    # that are behaving well. Payloads with no session id (the doctor's
    # round-trip probe) register nothing: a health check is an observer, not
    # a session, and must not keep the daemon alive.
    note_session_live(state, session_id)

    if event not in _KNOWN_EVENTS:
        return _allow()

    obs = _build_observation(event, session_id, payload)
    if obs is None:
        return _allow()

    cwd = payload.get("cwd", "") or ""
    model = payload.get("model", "") or ""

    with state.lock:
        engine = _get_or_start_engine(state, session_id, cwd=cwd, model=model)

    # Detection runs here, outside the lock. `Engine.scan()` touches no
    # sqlite and no per-session daemon state (that is the contract its
    # docstring states and the reason it is a separate method), so nothing
    # it does needs serializing — while tier 3's model inference dominates
    # the cost of the whole request. Holding `state.lock` across it made
    # every concurrent hook call in EVERY session queue behind one forward
    # pass; see daemon.Daemon's docstring for the measurement.
    scan = engine.scan(obs)

    with state.lock:
        # Re-resolve rather than reusing the Engine from step 1. A
        # `SessionEnd` for this session_id can land while the scan above is
        # running, and it pops `state.engines`/`state.salts`; re-resolving
        # means we then use the fresh Engine and fresh salt, which is
        # exactly the behavior `_handle_session_end` already documents for
        # any event arriving after SessionEnd ("gets a brand-new salt via
        # `_get_or_start_engine`, never the old one"). Findings are
        # salt-independent (see Engine.observe's docstring), so this is a
        # legal serialization of the two operations, not a reinterpretation
        # of the scan. `_get_or_start_engine` is idempotent, so in the
        # ordinary case this is a dict lookup.
        engine = _get_or_start_engine(state, session_id, cwd=cwd, model=model)
        decision = engine.observe(obs, scan=scan)

    return _decision_to_output(decision)
