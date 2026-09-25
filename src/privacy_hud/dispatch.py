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

  hook_event_name    source              destination              direction   text
  UserPromptSubmit   user prompt         model_context             ingress     prompt
  PostToolUse        origin or tool_name model_context             ingress     tool_response
  PreToolUse (Bash)  tool input          extract_destinations(cmd) egress      command
  PreToolUse (mcp*)  tool input          mcp_tool                  egress      json.dumps(tool_input)
  SubagentStart      main agent          subagent                  propagate   ""
  SessionStart / SessionEnd -- not Engine observations; they drive the
  ledger session lifecycle directly.

  `PostToolUse`'s source is `origin.extract_origin(tool_name, tool_input)`
  when it can name a path or a program the output came from (#40); `None`
  keeps `tool_name`, exactly as before origins existed.

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

Coverage: this module is where "was anyone watching?" is first knowable, so it
is where it is written down. Two writes, both into `ledger.py`'s `coverage`
table and both explained in full where they happen: `_get_or_start_engine`
records `attached` when its first sight of a session is a mid-session event
(the daemon cold-started late, or replaced one that died), and `new_state`
records `unobserved_hooks` at startup when the hook client's spawn-attempt
latch shows hooks were answered with no daemon listening at all. Neither is a
guess; see `_record_unobserved_hooks` for the one thing the latch cannot say
(which session) and the one case that leaves no trace at all.

Session reference counting: `State.live` maps each session id this daemon
believes is alive to the monotonic time of its last hook event. It is
maintained here (`note_session_live` / `release_session`) and read by
`daemon.Daemon`'s serve loop (`live_session_count`) to decide when the
daemon may exit — the daemon serves every concurrent session, so no single
`SessionEnd` may take it down. The *policy* built on this count, and the
reasoning behind every number in it, lives in `daemon.Daemon`'s "Lifetime
policy" section; only the bookkeeping lives here.

That same map answers a second question it was not built for but is the only
thing in the system that can: *which session is the user asking from right
now* (`active_sessions`, served over the wire as the daemon's
`active_sessions` op). `$privacy` needs it because the ledger cannot supply
it — see that function's docstring for why "most recently started" and
"most recently disclosing" are both wrong answers.

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

import dataclasses
import json
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import codex, ledger_schema, runtime_storage
from .accounting import ObservationRecord, ScoringProfile
from .detect.model import ModelDetector
from .detect.paths import PathDetector
from .detect.secrets import SecretDetector
from .detect.shell import extract_destinations
from .engine import Engine, Observation, ScanResult
from .hook_evidence import (
    DELIVERY_KEY_ABSENT,
    CurrentHookAdapter,
    HookEvidenceAdapter,
    normalize_delivery_key,
)
from .hud_snapshot import HudPublisher
from .ledger import Ledger, open_connection
from .mask import new_salt
from .matrix.loader import Matrix, load_matrix
from .origin import OriginKind, extract_origin
from .prompt_hold import confirmed_message, held_reason
from .render import receipt as render_receipt
from .runtime import latch_path
from .runtime_owner import WriterLease
from .settings import Settings

# Every HUD failure below is logged through this at DEBUG and nowhere else.
# I1: the message carries the exception's *class name* and nothing else --
# never `str(exc)`, which for an OSError is a path and for a sqlite error can
# quote a row. A display surface that could not be written is a diagnostic,
# and a diagnostic that leaks what it was writing about is a disclosure.
_log = logging.getLogger(__name__)

# Events with a pinned Observation mapping. Anything else that reaches this
# daemon (SubagentStop, PreCompact, ...) has no Observation defined by the
# brief's table; we allow (empty hook output) and record nothing, rather
# than guessing a mapping that was never specified.
#
# The names themselves are Codex's, so they live in `codex.py` with the rest
# of what this package knows about the platform (`codex.KNOWN_EVENTS` is
# every event Codex sends; this is the subset with a mapping). Kept under the
# old private name because `tests/matrix/test_matrix_covers_the_code.py`
# imports it from here to assert the taxonomy covers it, and because a rename
# would ripple through this file for no gain.
_KNOWN_EVENTS = codex.OBSERVED_EVENTS


@dataclass
class State:
    """All daemon-lifetime state. One instance per daemon process."""

    data_dir: Path
    matrix: Matrix
    ledger: Ledger
    detectors: list
    hud: HudPublisher
    # #36: `Settings(data_dir)` -- re-read on change so `$privacy read on/off`
    # (run from a different process) lands inside this running daemon
    # without a restart. `new_state` builds the real one on `PLUGIN_DATA`;
    # `Engine.__init__`'s own default covers any caller (tests included)
    # that never sets this at all.
    settings: Settings | None = None

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
    # #54 Phase 4: this daemon's version-2 accounting keys, one per session
    # whose activation this process committed. The daemon is the only
    # production owner of these keys; none is ever persisted, logged or
    # recreated. Discarded at SessionEnd and at shutdown.
    accounting_keys: dict[str, bytes] = field(default_factory=dict)
    # How a delivered hook is normalized into accounting evidence. The
    # production adapter claims nothing terminal; a test may install
    # another as a Python object, and nothing else can select one.
    hook_adapter: HookEvidenceAdapter = field(
        default_factory=CurrentHookAdapter)
    # #37: the monotonic clock every session's credential-prompt gate reads.
    # A test may install another; nothing on the wire can select one.
    prompt_clock: Callable[[], float] = time.monotonic

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


def new_state(data_dir, *, writer_lease: WriterLease) -> State:
    """Build the daemon's one-time-cost state: Matrix, Ledger (one sqlite
    connection for the daemon's life), and the detector stack (tiers 0-3).

    `ModelDetector` loads from the local HuggingFace cache only and
    degrades to `available=False` on any failure (missing weights, missing
    `transformers`) rather than raising — see detect/model.py. Building it
    here, once, per daemon lifetime, is the entire point of Task 10: this
    is the expensive step a per-hook-invocation client could never afford.

    `writer_lease` is required and has no default (#66). This function
    opens the one writable ledger connection in the system, so the caller
    has to have taken ownership before calling it — and taken it *first*,
    because the alternative is loading a ~2.8 GB model on behalf of a
    daemon that then discovers it may not write.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    matrix = load_matrix()
    # The writer opens the active store once the historical pathname is
    # fenced, and the historical pathname until then (#66). The two never
    # both exist: `prepare_storage` retires one as it publishes the other.
    path = runtime_storage.resolved_ledger_path(data_dir)
    ledger = Ledger(path, matrix, writer_lease=writer_lease)
    try:
        _allow_cross_thread_access(ledger, path)
        _record_unobserved_hooks(ledger, data_dir)
        detectors = [PathDetector(), SecretDetector(), ModelDetector()]
        hud = HudPublisher(data_dir)
        settings = Settings(data_dir)
        state = State(data_dir=data_dir, matrix=matrix, ledger=ledger,
                      detectors=detectors, hud=hud, settings=settings)
        # #54 Phase 4: before this daemon publishes anything or accepts a
        # hook. A failure here fails startup: open version-2 sessions must
        # never be served as available by a process that has none of their
        # keys.
        _invalidate_missing_accounting_keys(state)
    except BaseException:
        ledger.conn.close()
        raise
    try:
        hud.sweep()
        hud.mark_daemon(unattributed_gaps=bool(ledger.unattributed_gaps()))
    except Exception as exc:
        # I6: housekeeping for a display surface never blocks the daemon.
        _log.debug("hud startup housekeeping failed: %s", type(exc).__name__)
    return state


def _record_unobserved_hooks(ledger: Ledger, data_dir: Path) -> None:
    """Turn the hook client's spawn-attempt latch into a durable coverage record.

    **This is the only evidence a session the daemon never saw can leave.** The
    incident behind `ledger.py`'s `coverage` table went like this: no daemon was
    listening, a short `codex exec` ran to completion, every one of its hooks
    failed to `connect()` and was answered "unverified", the daemon finished
    loading its model after the session had already ended, and the ledger's
    session count went 8 → 8. Nothing about that session exists in the ledger,
    and nothing can — a session whose beginning was never recorded leaves no
    trace by construction.

    But the *hooks* left one, and it was already on disk. `hooks/handler.py`
    writes `$PLUGIN_DATA/daemon.spawn-attempt` on every spawn attempt (that file
    is a cooldown latch; see `runtime.SPAWN_COOLDOWN`), and its `at` timestamp is
    the moment a hook event was answered without being checked. Reading it here
    is inference-free: the latch exists *because* a hook could not be served, so
    "at least one hook event went unobserved around `at`" is recorded fact, not a
    heuristic. What it cannot say is WHICH session, or how many events — the
    latch carries neither, and `Ledger.note_unobserved_hooks` files it
    unattributed rather than guessing.

    Reading it at daemon startup, exactly once per daemon instance, is the right
    moment for two reasons: it is the first time a process capable of writing to
    the ledger exists after the drop, and `INSERT OR IGNORE` on
    `(UNATTRIBUTED_SESSION, observer)` then bounds the table at one row per cold
    start rather than one per hook.

    A stale latch (this daemon was started by hand, or by the doctor, and the
    latch is days old) is recorded with its own old timestamp and is therefore
    harmless: `Ledger.coverage`'s bound only relates a gap to sessions that
    started at or before it, so an old gap cannot retroactively mark a new
    session.

    Every failure is silence, deliberately: no latch, an unreadable one,
    malformed JSON, a missing `at`. A daemon must not refuse to start because it
    could not read an advisory file, and I1 forbids logging what it found. The
    cost is honest and worth stating: when `PLUGIN_DATA` is unwritable, or
    auto-spawn is off (`PRIVACY_HUD_NO_SPAWN`), no latch is written at all and
    the gap leaves no trace anywhere. That case is undetectable, full stop.
    """
    try:
        with open(latch_path(data_dir)) as handle:
            record = json.load(handle)
        at = record["at"]
        # A latch that recorded neither a launched pid nor an error is not a
        # spawn attempt this code understands; treat it as no evidence rather
        # than as evidence of nothing.
        if not (record.get("pid") or record.get("error")):
            return
        ledger.note_unobserved_hooks(int(float(at)))
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        return


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
    disabled. This daemon reopens its connection with thread affinity
    disabled and serializes access with `State.lock`. MCP uses a separate
    connection and lock; the browser UI hands its connection to one
    sequential request thread.
    """
    ledger.conn.close()
    # The same helper every ledger connection uses, so this one keeps
    # foreign keys, the busy wait and full synchronous writes. The observer
    # id stays the instance's: it identifies this daemon in `coverage`.
    ledger.conn = open_connection(db_path, initialize=True,
                                  check_same_thread=False)


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
    out: dict[str, Any] = {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "updatedInput": updated_input,
    }}
    if message:
        out["systemMessage"] = message
    return out


def _decision_to_output(decision, *, hook_event: str | None = None) -> dict:
    if hook_event == "UserPromptSubmit" and decision.action == "deny":
        # #37: a prompt hold is exactly `decision` + `reason`. Codex records
        # additional context returned alongside a valid block into model
        # context, and refuses a block whose reason is empty (the prompt
        # would then go through), so neither is ever sent.
        reason = decision.reason
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("invalid prompt hold reason")
        return {"decision": "block", "reason": reason}
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
    # "allow" (and ingress observations, which Ruling 3 never denies): no
    # permission decision needed, Codex proceeds normally either way. But
    # #36's once-per-session read-guard notice rides on exactly this branch
    # (a local read is never denied unless the guard is on), and an allow
    # with a message must still surface it -- same bare `{"systemMessage":
    # ...}` shape `_handle_session_end` already uses, not the
    # `hookSpecificOutput` wrapper `_allow_with_rewrite` needs for its
    # `updatedInput`. An allow with no message keeps returning `{}` exactly
    # as before.
    if decision.system_message:
        return {"systemMessage": decision.system_message}
    return _allow()


def _as_text(value) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value)
    except TypeError:
        return str(value)


def _get_or_start_engine(state: State, session_id: str, *, cwd: str = "",
                          model: str = "") -> Engine:
    """Return the Engine for `session_id`, creating one (with a fresh,
    session-scoped salt) if `SessionStart` was never seen for it. Caller
    must hold `state.lock`.

    **`observed_start=False` is the load-bearing argument here.** Reaching this
    branch means the daemon's first sight of this session was NOT a
    `SessionStart` — either it cold-started after the session began, or it
    replaced a daemon that died mid-session. Either way there is a stretch of
    that session nobody recorded, and the session's ledger row would otherwise
    be byte-identical to one belonging to a session watched from its first
    keystroke. `Ledger.start_session` writes an `attached` coverage row instead
    of a `session_start` one, which is what makes the two distinguishable
    afterwards; `INSERT OR IGNORE` means a daemon that DID see the
    `SessionStart` keeps its stronger record when it later re-resolves through
    here (after a `SessionEnd`, say).
    """
    session = state.ledger.conn.execute(
        "SELECT * FROM sessions WHERE session_id=?",
        (session_id,)).fetchone()
    if session is not None and session["ended_at"] is not None:
        # Enforcement can run after end, but this engine and its randomness
        # must not become session accounting state. Ledger.record persists
        # late findings with NULL hashes and zero contributions.
        return Engine(
            ledger=state.ledger, matrix=state.matrix, salt=new_salt(),
            detectors=state.detectors, settings=state.settings,
            prompt_clock=state.prompt_clock)

    engine = state.engines.get(session_id)
    if engine is not None:
        return engine
    if _is_version_2(session):
        # #54 Phase 4: a version-2 session first met here after a restart.
        # Its key is gone; its accounting is marked unavailable before
        # anything is recorded, and no key is generated.
        engine = _attach_keyless_v2(state, session_id, session, cwd=cwd,
                                    model=model, observed_start=False)
        _publish_hud(state, session_id)
        return engine
    salt = state.salts.setdefault(session_id, new_salt())
    state.ledger.start_session(session_id, cwd=cwd, model=model,
                                observed_start=False)
    state.started_at.setdefault(session_id, time.time())
    engine = Engine(ledger=state.ledger, matrix=state.matrix, salt=salt,
                     detectors=state.detectors, settings=state.settings,
                     prompt_clock=state.prompt_clock)
    state.engines[session_id] = engine
    # A session the daemon first meets here -- typically the one whose
    # SessionStart hook spawned this daemon and got no answer -- has no
    # snapshot yet, so the status-line item stays blank until the first
    # observation lands. Publish the ledger's zero now: the item then shows
    # 0% from the first hook rather than nothing. Same call as SessionStart.
    _publish_hud(state, session_id)
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
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = {}
        # Where the data came from, when it can be named (#40). `source`
        # keeps the tool name when it cannot: "no origin" is not the same
        # fact as "an origin that happens to be a tool name", and only a
        # real origin gets a rule offered for it.
        origin = extract_origin(tool_name, tool_input)
        return Observation(
            session_id=session_id, turn_id=turn_id, hook_event=event,
            direction="ingress", source=origin.value if origin else tool_name,
            destination="model_context",
            text=_as_text(payload.get("tool_response", "")),
            tool_name=tool_name, origin=origin)

    if event == "PreToolUse":
        tool_name = payload.get("tool_name") or ""
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = {}
        if tool_name == codex.SHELL_TOOL:
            command = tool_input.get("command", "") or ""
            dests = extract_destinations(command)
            destination = dests[0] if dests else "external_net"
            if destination == "local":
                # #36: a local read is no longer nothing to score. When the
                # origin names a file, the engine decides whether reading it
                # is allowed -- the one interception point that acts BEFORE
                # the bytes exist, rather than recording them after.
                #
                # Everything else local still returns early: a COMMAND
                # origin or none at all leaves nothing to decide, and
                # `Engine.observe` would raise UnknownKey for a row the
                # taxonomy does not define (I2: never silently caught).
                origin = extract_origin(tool_name, tool_input)
                if origin is None or origin.kind is not OriginKind.PATH:
                    return None
                return Observation(
                    session_id=session_id, turn_id=turn_id, hook_event=event,
                    direction="local", source=origin.value,
                    destination="local", text=command, tool_name=tool_name,
                    tool_input=tool_input, origin=origin)
            text = command
        # `codex.is_mcp_tool` is the same predicate `hooks/handler.py`
        # applies client-side (`.startswith("mcp")`, not `"mcp__"`), so the
        # daemon's classification of "this is an MCP tool call" cannot
        # disagree with the client's fail-closed gate for the same call.
        elif codex.is_mcp_tool(tool_name):
            destination = "mcp_tool"
            text = json.dumps(tool_input)
        else:
            # A non-shell, non-MCP tool (`apply_patch`, or one a plugin
            # added). Not scored, and NOT read-guarded — deliberately.
            #
            # `extract_origin` would in fact name a path here if the call
            # carried one of `origin.PATH_KEYS`: that loop runs for any
            # tool, ahead of the command parsing. What stops us using it is
            # that nothing says such a path was *read*. Codex's only native
            # writer is `codex.PATCH_TOOL`, and a tool that takes a
            # `file_path` is as likely to write it as to read it — so
            # denying one under "blocked a read" would be a false block
            # with false copy, which the spec weighs as the worse error.
            #
            # This costs no coverage on Codex today: `codex.SHELL_TOOL` is
            # how a file gets read, and the guard has that branch. Known
            # limit 14 states the confinement rather than leaving it to be
            # discovered from here.
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


def active_sessions(state: State, *, stale_after: float
                    ) -> list[tuple[str, float]]:
    """Every session this daemon believes is alive, most recently active
    first, each paired with how many seconds ago its last hook event arrived.

    **Why this signal, and why the two obvious answers are both wrong.** The
    question a caller actually has is "which session is the user asking from
    right now" — `$privacy` has to audit the session it was typed in. Neither
    of the answers the ledger can give is that:

    * `sessions ORDER BY started_at DESC LIMIT 1` is "most recently
      *started*". Open a second Codex window and run `$privacy` in the first
      one and it names the second window's session, silently. Measured on a
      real ledger: most-recently-started and most-recently-active were
      different sessions.
    * `MAX(events.ts)` is "most recently *disclosing*". A session that has
      disclosed nothing has no `events` rows at all, so a brand-new, clean
      session is skipped entirely and some older session's id comes back —
      the same bug wearing different clothes, and worst precisely where this
      tool must be most trustworthy.

    `State.live` is the answer to a third question — "who fired a hook most
    recently" — and it is maintained for *every* hook carrying a session id,
    including the ones that write no ledger row (`note_session_live`). It
    therefore covers the clean session, and it is what a caller means by
    "current": running `$privacy` itself fires hooks (the skill runs bash,
    which is a `PreToolUse` in the asking session), so by the time anyone
    asks this question the asking session is the most recently active one by
    construction rather than by guess.

    **Ages, not timestamps.** `State.live` holds `time.monotonic()` values,
    which are meaningful only inside this process — another process's
    monotonic clock has an unrelated origin, and a wall clock would drag in
    NTP steps for no benefit. An age in seconds is comparable anywhere, which
    is what a client needs to decide whether two sessions were active in the
    same moment (see `mcp_tools.resolve_audit_session`).

    **Does not sweep.** Unlike `live_session_count`, this deliberately
    filters stale entries without deleting them: answering a question must
    not change the daemon's own lifetime accounting. Deciding a session is
    dead is the accept loop's act, taken on its own schedule, and a
    read-only query that quietly retired a reference would make the daemon's
    exit depend on how often somebody ran `$privacy`.
    """
    now = time.monotonic()
    with state.live_lock:
        seen = list(state.live.items())
    fresh = [(sid, now - last) for sid, last in seen
             if now - last <= stale_after]
    fresh.sort(key=lambda pair: pair[1])
    return fresh


def _publish_hud(state: State, session_id: str) -> None:
    """Contract A, after a ledger change. Reads summary and coverage under
    the caller's lock and hands the numbers to the publisher. I6: any
    failure here is swallowed; a hook must never fail because a display
    file could not be written — but it is swallowed *loudly*, at DEBUG,
    because a status item that silently stops updating with no way to find
    out why is how a display bug becomes a "the tool is broken" report.
    I3: the summary is the ledger's, verbatim; the publisher maps a legacy
    summary to accounting 1 and an unrecorded one to accounting 0."""
    try:
        summary = state.ledger.summary(session_id)
        coverage = state.ledger.coverage(session_id)
        state.hud.publish(session_id, summary=summary,
                          unverified=not coverage.verified)
    except Exception as exc:
        _log.debug("hud publish failed: %s", type(exc).__name__)


def _invalidate_missing_accounting_keys(state: State) -> None:
    """Mark every open, available version-2 session unavailable (#54
    Phase 4). Runs during fresh daemon-state initialization, before any
    snapshot is published or hook accepted: a new process holds none of
    those sessions' keys, and a key is never recreated, so their accounting
    stays unavailable for the rest of each session. Ended sessions keep
    their final status.

    One owned write transaction; a failure propagates and fails startup.
    Afterwards each such session's inherited snapshot is retired, so an old
    available reading is neither served as current nor heartbeated."""
    ledger = state.ledger
    with state.lock:
        with ledger._write_transaction():
            # Only activated storage can hold a session a daemon activated
            # and keyed: activation always commits generation 5402. The
            # version-2 sessions of a prepared (5401) ledger are the private
            # synthetic constructor's, which no daemon ever keyed.
            if ledger_schema.validate_schema(ledger.conn) != \
                    ledger_schema.ACTIVATED_VERSION:
                return
            open_v2 = [row[0] for row in ledger.conn.execute(
                "SELECT session_id FROM sessions WHERE accounting_version=2"
                " AND ended_at IS NULL ORDER BY session_id")]
            for session_id in open_v2:
                if session_id not in state.accounting_keys:
                    ledger.mark_accounting_unavailable(session_id)
        for session_id in open_v2:
            if session_id in state.accounting_keys:
                continue
            try:
                state.hud.retire(session_id)
            except Exception as exc:
                # It is not in this publisher's heartbeat set, so an
                # unretirable file goes stale rather than staying current.
                _log.debug("hud retire failed: %s", type(exc).__name__)


def _discard_session_identity(state: State, session_id: str) -> None:
    """Drop everything that identifies `session_id` in this process: clear
    its registered engine first, then remove the engine, its accounting
    key, its enforcement salt and its start time (#54 Phase 4). Requires
    `State.lock`. Writes nothing to the ledger, and is idempotent.

    Discards references; it does not promise that Python memory is
    wiped."""
    if not state.lock.locked():
        raise RuntimeError("session identity is discarded under State.lock")
    engine = state.engines.get(session_id)
    if engine is not None:
        engine.clear_session_identity()
    state.engines.pop(session_id, None)
    state.accounting_keys.pop(session_id, None)
    state.salts.pop(session_id, None)
    state.started_at.pop(session_id, None)


def _is_version_2(row) -> bool:
    return (row is not None and "accounting_version" in row.keys()
            and row["accounting_version"] == 2)


def _attach_keyless_v2(state: State, session_id: str, row, *, cwd: str,
                       model: str, observed_start: bool) -> Engine:
    """Register an enforcement engine for an open version-2 session this
    process holds no key for. Caller holds `state.lock`.

    Its accounting is marked unavailable first, before anything else is
    recorded, and no key is generated: a lost key is never replaced. The
    engine enforces with its own salt and carries no accounting key. This
    observer's coverage is recorded as for any other session."""
    ledger = state.ledger
    if row["accounting_status"] == "available" \
            and session_id not in state.accounting_keys:
        ledger.mark_accounting_unavailable(session_id)
    ledger.start_session(session_id, cwd=cwd, model=model,
                         observed_start=observed_start)
    salt = state.salts.setdefault(session_id, new_salt())
    state.started_at.setdefault(session_id, time.time())
    engine = Engine(ledger=ledger, matrix=state.matrix, salt=salt,
                    detectors=state.detectors, settings=state.settings,
                    prompt_clock=state.prompt_clock)
    state.engines[session_id] = engine
    return engine


def _activate_session(state: State, session_id: str, payload: dict, *,
                      delivery_key: str) -> None:
    """Activate version-2 accounting for the genuine start of an absent
    session. Caller holds `state.lock` and has confirmed the session is
    absent.

    The key and salt are candidates until `start_accounted_session`
    returns True, which it does only after its own outer COMMIT; only then
    are they installed. A failure before that installs nothing. If
    installation itself fails after the COMMIT, the candidates are
    discarded and the session's accounting is marked unavailable before
    anything else can be recorded for it."""
    ledger = state.ledger
    key = os.urandom(32)
    salt = new_salt()
    evidence = state.hook_adapter.normalize(
        payload=payload, delivery_key=delivery_key, accounting_key=key)
    start = _lifecycle_record(session_id, evidence)
    if not ledger.start_accounted_session(
            session_id, cwd=payload.get("cwd", "") or "",
            model=payload.get("model", "") or "",
            profile=ScoringProfile.from_matrix(state.matrix),
            start_observation=start):
        return
    try:
        engine = Engine(ledger=ledger, matrix=state.matrix, salt=salt,
                        detectors=state.detectors, settings=state.settings,
                        accounting_key=key, prompt_clock=state.prompt_clock)
        state.accounting_keys[session_id] = key
        state.salts[session_id] = salt
        state.engines[session_id] = engine
        state.started_at[session_id] = time.time()
    except BaseException:
        _discard_session_identity(state, session_id)
        ledger.mark_accounting_unavailable(session_id)
        raise


def _handle_session_start(
    state: State,
    session_id: str,
    payload: dict,
    *,
    delivery_key: str,
) -> dict:
    """A genuine `SessionStart`. For a session the ledger does not hold yet,
    this is the one place #54's structural rebuild may run: it and the new
    session commit in one write transaction, or neither does. A replayed
    start for a known session changes nothing structural.

    An absent session is activated under version-2 accounting (#54 Phase
    4) and its key installed after COMMIT; an existing
    version-2 session without a key here stays unavailable. An empty or
    non-string session ID is a probe and writes nothing."""
    if not isinstance(session_id, str) or not session_id:
        return _allow()
    with state.lock:
        ledger = state.ledger
        session = ledger.conn.execute(
            "SELECT * FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()
        if session is not None and session["ended_at"] is not None:
            return _allow()
        if session_id in state.engines:
            # A replay must not replace an existing live matching namespace.
            return _allow()

        cwd = payload.get("cwd", "") or ""
        model = payload.get("model", "") or ""
        if session is None:
            _activate_session(state, session_id, payload,
                              delivery_key=delivery_key)
        elif _is_version_2(session):
            # A version-2 session this process holds no key for: a restart
            # lost it. Never replaced.
            _attach_keyless_v2(state, session_id, session, cwd=cwd,
                               model=model, observed_start=True)
        else:
            salt = new_salt()
            with ledger._write_transaction():
                if not ledger.session_exists(session_id):
                    ledger.prepare_session_boundary(session_id)
                ledger.start_session(session_id, cwd=cwd, model=model)
            engine = Engine(
                ledger=state.ledger, matrix=state.matrix, salt=salt,
                detectors=state.detectors, settings=state.settings,
                prompt_clock=state.prompt_clock)
            state.salts[session_id] = salt
            state.engines[session_id] = engine
            state.started_at[session_id] = time.time()
        _publish_hud(state, session_id)
    # Outside the lock: `live_lock` and `lock` are never nested (State's
    # `live_lock` comment states the ordering rule this keeps true).
    note_session_live(state, session_id)
    return _allow()


def _handle_session_end(
    state: State,
    session_id: str,
    payload: dict,
    *,
    delivery_key: str,
) -> dict:
    """Retire a session and return its receipt as hook output.

    `summary` is a `ledger.py` summary variant, and the raw legacy rows are
    projected with `to_exposure()` before they reach `render_receipt`. The
    return value stays a plain dict — it is Codex's hook wire format, whose
    shape the host dictates, not ours to type. With no recorded start time
    the receipt omits the duration rather than printing `0 min`.

    `coverage` is read BEFORE `end_session`, which is not incidental:
    `end_session` stamps `ended_at`, and `Ledger.coverage` uses that column to
    decide whether an unattributed gap still falls inside this session's window.
    Reading afterwards would narrow the window at the exact moment the receipt
    is being written, so a gap that occurred during the session's final seconds
    could drop out of the very artifact meant to account for it.

    For a version-2 session (#54 Phase 4) the SessionEnd lifecycle
    observation, the pre-end coverage reading and `end_session` (with its
    identity-hash erasure) are one outer write transaction: they commit
    together or roll back together. The receipt is rendered only from the
    committed summary. Identity destruction and snapshot retirement are in
    a `finally` that covers every step, reads included, and liveness is
    released in an outer `finally`, outside the lock. A failure propagates
    to the daemon's exception boundary; no receipt is fabricated.
    """
    try:
        with state.lock:
            try:
                ledger = state.ledger
                session = ledger.conn.execute(
                    "SELECT * FROM sessions WHERE session_id=?",
                    (session_id,)).fetchone()
                if _is_version_2(session):
                    evidence = state.hook_adapter.normalize(
                        payload=payload, delivery_key=delivery_key,
                        accounting_key=_usable_key(state, session_id,
                                                   session))
                    with ledger._atomic_accounting_write():
                        ledger.record_observation(
                            _lifecycle_record(session_id, evidence), ())
                        coverage = ledger.coverage(session_id)
                        ledger.end_session(session_id)
                    summary = ledger.summary(session_id)
                    rows = [r.to_exposure() for r in
                            ledger.list_events(session_id, "exposed")]
                else:
                    summary = ledger.summary(session_id)
                    coverage = ledger.coverage(session_id)
                    rows = [r.to_exposure() for r in
                            ledger.list_events(session_id, "exposed")]
                    ledger.end_session(session_id)
                started = state.started_at.get(session_id)
            finally:
                # Discard the session's salt, accounting key and Engine now
                # -- SessionEnd is the one place a session's identity is
                # destroyed, per the session/salt lifecycle contract above,
                # and it is destroyed whether or not the end persisted. A
                # hook event for this session_id that arrives after this
                # point is enforced with a temporary engine whose salt never
                # becomes session state (`_get_or_start_engine`), and its
                # findings are recorded with a NULL hash and no charge. A
                # version-2 session whose end failed is marked unavailable
                # on its next touch.
                _discard_session_identity(state, session_id)
                try:
                    state.hud.retire(session_id)
                except Exception as exc:
                    _log.debug("hud retire failed: %s", type(exc).__name__)

        minutes = None
        if started is not None:
            minutes = max(0, int((time.time() - started) // 60))

        message = render_receipt(session_id, summary, rows, minutes,
                                  coverage=coverage)
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


def _usable_key(state: State, session_id: str, session) -> bytes | None:
    """This process's accounting key for `session_id`, or None when the
    session is ended, its accounting is unavailable, or no key is held.
    Read under `State.lock`, at the moment it is used."""
    if (session is None or session["ended_at"] is not None
            or session["accounting_status"] != "available"):
        return None
    return state.accounting_keys.get(session_id)


def _lifecycle_record(session_id: str, evidence) -> ObservationRecord:
    return ObservationRecord(
        session_id=session_id, delivery_key=evidence.delivery_key,
        action_id=evidence.action_id, turn_id=evidence.turn_id,
        ts=int(time.time()), hook_event=evidence.hook_event,
        phase=evidence.phase, action_kind=evidence.action_kind,
        boundary=evidence.boundary, decision="none",
        evidence=evidence.evidence,
        resolution_scope=evidence.resolution_scope,
        potential_crossing=evidence.potential_crossing, scan_gap=None)


def _accounting_for(state: State, session_id: str, payload: dict,
                    delivery_key: str):
    """The delivery's version-2 evidence, normalized now with the session's
    current key, or None for a session that is not version-2 accounted.
    Caller holds `State.lock`; nothing here is carried across scanning."""
    session = state.ledger.conn.execute(
        "SELECT * FROM sessions WHERE session_id=?",
        (session_id,)).fetchone()
    if not _is_version_2(session):
        return None
    return state.hook_adapter.normalize(
        payload=payload, delivery_key=delivery_key,
        accounting_key=_usable_key(state, session_id, session))


def _metadata_observation(event: str, session_id: str,
                          payload: dict) -> Observation:
    """A registered hook with no legacy observation mapping -- a local
    command, a non-shell tool, a lifecycle or subagent-stop event -- as a
    zero-text observation, so a version-2 session still records that it
    was delivered. Nothing is scanned for it."""
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    destination = "subagent" if event == "SubagentStop" else "local"
    direction = "local" if event == "PreToolUse" else "lifecycle"
    return Observation(
        session_id=session_id, turn_id=payload.get("turn_id"),
        hook_event=event, direction=direction, source="lifecycle",
        destination=destination, text="",
        tool_name=tool_name if isinstance(tool_name, str) else None,
        tool_input=tool_input)


def dispatch(
    state: State,
    payload: dict,
    *,
    delivery_key: str | None = None,
) -> dict:
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
      2. UNLOCKED, ~500ms on ingress (tier 3): `Engine.scan()`. Detection
         only; no sqlite. Egress was sub-millisecond and regex-only until
         #47 item 1 put tier 3 back on B3/B4. Egress uses a requested
         timeout based on the remaining budget and an inclusive completion
         cutoff; neither guarantees elapsed time. See
         `engine.TIER3_EGRESS_BUDGET`. When an applicable deep scan
         supplied no accepted result, that scan gap is recorded per
         observation and counted per session, including observations with
         no event row.
      3. locked, milliseconds: `Engine.observe(obs, scan=...)`. Every ledger
         read and write for this observation, in one critical section.

    `delivery_key` is the daemon-normalized protocol-2 delivery key (#54
    Phase 4); the daemon always supplies one. It identifies this delivery
    to version-2 accounting and is never read from the payload.

    A `UserPromptSubmit` carrying a hold-eligible credential (#37) takes a
    preflight between steps 1 and 2: the regex-only credential scan runs
    unlocked, then the session's confirmation gate rules under the lock. A
    hold is recorded and returned there, without the deep scan, so a cold
    or busy model never delays it; an allowed prompt continues through the
    three steps unchanged.
    """
    # #37: when this submission arrived, before any lock wait, so a queued
    # accidental double submit cannot pass for a deliberate resubmission.
    submitted_at = state.prompt_clock()
    event = payload.get("hook_event_name")
    session_id = payload.get("session_id")

    if not isinstance(session_id, str) or not session_id:
        # A probe, not a session (the doctor's round trip; #54 Phase 4): no
        # session, observation, coverage or liveness is written for it. An
        # outbound call that names no session cannot be attributed or
        # verified, so it keeps the fail-closed answer (I6).
        if event in codex.EGRESS_EVENTS:
            return _deny(None)
        return _allow()
    if delivery_key is None:
        delivery_key = normalize_delivery_key(DELIVERY_KEY_ABSENT)
    if event == "SessionStart":
        return _handle_session_start(state, session_id, payload,
                                     delivery_key=delivery_key)
    if event == "SessionEnd":
        return _handle_session_end(state, session_id, payload,
                                   delivery_key=delivery_key)

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

    obs = (_build_observation(event, session_id, payload)
           if event in _KNOWN_EVENTS else None)

    cwd = payload.get("cwd", "") or ""
    model = payload.get("model", "") or ""
    if not isinstance(cwd, str):
        cwd = ""

    if obs is None:
        # Nothing to score -- but a version-2 session still records that a
        # registered hook was delivered (#54 Phase 4). Anything else keeps
        # the empty allow, and an unknown session is not created for it.
        if event not in codex.KNOWN_EVENTS:
            return _allow()
        with state.lock:
            session = state.ledger.conn.execute(
                "SELECT * FROM sessions WHERE session_id=?",
                (session_id,)).fetchone()
            if not _is_version_2(session):
                return _allow()
            engine = _get_or_start_engine(state, session_id, cwd=cwd,
                                          model=model)
            accounting = _accounting_for(state, session_id, payload,
                                         delivery_key)
            meta = _metadata_observation(event, session_id, payload)
            dest = meta.destination
            decision = engine.observe(
                dataclasses.replace(meta, accounting=accounting, cwd=cwd),
                scan=ScanResult(dest_kind=dest,
                                boundary=state.matrix.boundary_for(dest),
                                findings=(), degraded=False))
            _publish_hud(state, session_id)
        return _decision_to_output(decision, hook_event=event)

    with state.lock:
        engine = _get_or_start_engine(state, session_id, cwd=cwd, model=model)

    confirmed: tuple[str, ...] = ()
    matches = engine.scan_prompt_credentials(obs)
    if matches:
        with state.lock:
            # Re-resolved for the same reason as step 3 below: a SessionEnd
            # may have landed since step 1.
            engine = _get_or_start_engine(state, session_id, cwd=cwd,
                                          model=model)
            gate = engine.prompt_gate
            saved = gate.snapshot()
            verdict = gate.decide(
                {m.finding.value: m.kind for m in matches},
                delivery_key=delivery_key, submitted_at=submitted_at)
            if verdict.hold:
                try:
                    accounting = _accounting_for(state, session_id, payload,
                                                 delivery_key)
                    held = obs
                    if accounting is not None:
                        held = dataclasses.replace(obs, accounting=accounting,
                                                   cwd=cwd)
                    decision = engine.record_prompt_hold(
                        held, matches, held_reason(m.kind for m in matches))
                except BaseException:
                    # A hold that was not recorded must not leave a pending
                    # confirmation behind.
                    gate.restore(saved)
                    raise
                _publish_hud(state, session_id)
                return _decision_to_output(decision, hook_event=event)
            confirmed = verdict.confirmed

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
        # then returns a temporary engine for the ended session, the
        # behavior `_handle_session_end` documents for any event arriving
        # after SessionEnd: enforcement runs, and the ledger records the
        # findings with a NULL hash and no charge. Findings are
        # salt-independent (see Engine.observe's docstring), so this is a
        # legal serialization of the two operations, not a reinterpretation
        # of the scan. `_get_or_start_engine` is idempotent, so in the
        # ordinary case this is a dict lookup.
        engine = _get_or_start_engine(state, session_id, cwd=cwd, model=model)
        # #54 Phase 4: normalized only now, with the key current at this
        # moment; no key or resolved identity crossed the unlocked scan.
        accounting = _accounting_for(state, session_id, payload,
                                     delivery_key)
        if accounting is not None:
            obs = dataclasses.replace(
                obs, accounting=accounting, cwd=cwd,
                evaluated_path=(obs.origin.evaluated_path
                                if obs.origin is not None else None))
        decision = engine.observe(obs, scan=scan)
        _publish_hud(state, session_id)

    if confirmed:
        # Authorizes this plugin's allow decision only; it does not establish
        # that the prompt reached model context.
        notice = confirmed_message(confirmed)
        decision.system_message = (
            notice if not decision.system_message
            else decision.system_message + "\n\n" + notice)
    return _decision_to_output(decision, hook_event=event)
