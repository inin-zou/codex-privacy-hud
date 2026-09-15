"""Append-only disclosure ledger. Metadata only — see architecture.md §5.

The schema is the privacy guarantee: there is no `content`, `prompt`,
`raw_value`, `snippet`, or `text` column anywhere. A column that does not
exist cannot leak.

Dedupe key is (session_id, value_hash, destination): the same value reaching
the same destination twice is one disclosure — increment `count`, budget
delta is 0.0. The same value reaching a NEW destination is a new disclosure.
This makes replayed hook events idempotent.

Only `kind == "exposed"` rows move the budget. `prevented`, `local_access`,
`detected` and `retention` rows are recorded but always score 0.0.

Append-only: the only permitted UPDATEs are incrementing `count` and, at
`end_session`, nulling `value_hash` for the session. No deletes, no rewrites.

**The read side is typed.** `summary()` and `list_events()` used to return
bare dicts, and the three modules downstream of them (`mcp_tools`, `render`,
`local_ui_server`) agreed on their shape only through string literals. That is
not a hypothetical risk here: `detect/model.py`'s `LABEL_MAP` shipped with the
wrong keys (`EMAIL` where the model emits `private_email`), so tier 3 silently
returned nothing until someone traced a live session by hand. A mistyped key
is either a `KeyError` at the worst possible moment or, worse, a `.get()`
returning `None` that renders as an empty cell nobody notices. The dataclasses
below exist so that failure mode has somewhere to fail loudly instead:
`SessionSummary`, `ExposureRow` and `EventRow` are the read contract, and the
JSON boundary is an explicit `as_dict()` rather than an accident of whatever
the dict happened to hold.

**A ledger that recorded nothing looks exactly like a ledger with nothing to
record — unless it also records whether it was watching.** That is what the
`coverage` table is for, and it is the third state this schema previously could
not express. `summary()` answers an unknown session with a well-formed zero,
and zero events / 0% is also what a genuinely clean session looks like, so the
product's central number conflated "nothing sensitive was disclosed" with "I
have no idea what was disclosed". This is not hypothetical: an I7 self-audit
(CLAUDE.md §3) once read as a clean pass — zero events, budget 0.0/120.0 —
against a session the daemon had never seen at all, because it cold-started
after the `codex exec` had already finished. The session count went 8 → 8 and
nothing in the ledger said so. `coverage` is the row that now says so; see
`SessionCoverage` for exactly what it can and cannot prove.
"""
from __future__ import annotations

import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, fields
from pathlib import Path

from .budget import contribution, percent
from .matrix.loader import Matrix

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  session_id   TEXT PRIMARY KEY,
  started_at   INTEGER NOT NULL,
  ended_at     INTEGER,
  cwd          TEXT,
  model        TEXT,
  budget_score REAL NOT NULL DEFAULT 0,
  budget_cap   REAL NOT NULL DEFAULT 120
);

CREATE TABLE IF NOT EXISTS events (       -- append-only; never UPDATE except count
  id            INTEGER PRIMARY KEY,
  session_id    TEXT NOT NULL REFERENCES sessions,
  turn_id       TEXT,
  ts            INTEGER NOT NULL,
  kind          TEXT NOT NULL,            -- exposed|prevented|local_access|detected|retention
  data_type     TEXT NOT NULL,            -- email|credential|person|hostname|path|...
  source        TEXT NOT NULL,            -- support.log | user prompt | tool input
  destination   TEXT NOT NULL,            -- model_context|subagent:<id>|mcp:<server>|net:<host>
  boundary      TEXT NOT NULL,            -- B0..B4
  count         INTEGER NOT NULL DEFAULT 1,
  value_hash    BLOB,                     -- salted, session-scoped; NULL after SessionEnd
  masked_example TEXT,                    -- 'jo•••@acme.com'; NULL for credentials
  budget_delta  REAL NOT NULL DEFAULT 0,
  protection    TEXT,                     -- none|masked|minimized|blocked
  tool_name     TEXT,
  UNIQUE(session_id, value_hash, destination)
);

CREATE TABLE IF NOT EXISTS flows (        -- multi-hop chains for the L3 flow line
  id         INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL,
  value_hash BLOB NOT NULL,
  hop_index  INTEGER NOT NULL,
  node       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy (
  id         INTEGER PRIMARY KEY,
  scope      TEXT NOT NULL,               -- global|session:<id>
  rule_type  TEXT NOT NULL,               -- mask|block_source|allow_dest
  selector   TEXT NOT NULL,               -- data_type / path glob / destination
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS coverage (     -- append-only; who was watching, when
  id          INTEGER PRIMARY KEY,
  session_id  TEXT NOT NULL,            -- '' when the gap is not attributable
  ts          INTEGER NOT NULL,
  observer    TEXT NOT NULL,            -- opaque per-Ledger-instance id
  reason      TEXT NOT NULL,            -- session_start|attached|unobserved_hooks
  UNIQUE(session_id, observer)          -- one row per observer per session
);

CREATE TABLE IF NOT EXISTS policy_tokens (  -- one-shot consent, §8
  token      TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  tool_name  TEXT NOT NULL,
  args_hash  BLOB NOT NULL,
  mode       TEXT NOT NULL,               -- allow_once|minimize
  expires_at INTEGER NOT NULL,
  consumed   INTEGER NOT NULL DEFAULT 0
);
"""

#: `coverage.reason` values. Three, and the list is closed on purpose: each one
#: names a *specific piece of evidence*, not a guess. Nothing may be added here
#: that a heuristic inferred — an unmarked gap you cannot see is the bug this
#: table exists to fix, and a marked gap you invented is the same bug wearing a
#: warning label.
#:
#: `session_start`     — this observer created the session row from a real
#:                       `SessionStart` hook, so it watched from the beginning.
#: `attached`          — this observer's first sight of the session was some
#:                       later event (`dispatch._get_or_start_engine`'s lazy
#:                       path). Whatever happened before that point is not in
#:                       the ledger and cannot be reconstructed from it.
#: `unobserved_hooks`  — a daemon found, at startup, the hook client's
#:                       spawn-attempt latch: proof that at least one hook event
#:                       was answered "unverified" because nothing was
#:                       listening. Carries a timestamp but no session id (the
#:                       latch has none), so it is filed under
#:                       `UNATTRIBUTED_SESSION`.
COVERAGE_SESSION_START = "session_start"
COVERAGE_ATTACHED = "attached"
COVERAGE_UNOBSERVED_HOOKS = "unobserved_hooks"

#: `coverage.session_id` for a gap that is real but not attributable to any one
#: session. The empty string rather than NULL so `UNIQUE(session_id, observer)`
#: still dedupes it (SQLite treats NULLs as distinct, which would let one daemon
#: write the same gap twice).
UNATTRIBUTED_SESSION = ""

#: `policy.scope` for a rule that applies to every session in this ledger.
#: No caller mints one today (`add_policy` writes session scope), but the
#: schema documents it as a first-class scope, so `policy_selectors` honours
#: it: a rule nobody can write is a comment, a rule the reader silently skips
#: is protection that looks applied and is not.
POLICY_SCOPE_GLOBAL = "global"


def _session_scope(session_id: str) -> str:
    """`policy.scope` for a rule bound to one session.

    The one place the `session:<id>` spelling from SCHEMA's `policy.scope`
    comment is built. Writer and reader used to spell it separately, in two
    modules, and a rule whose scope string does not match the one the reader
    asks for is silently never enforced — no error, no row, just protection
    the user was told was applied.
    """
    return f"session:{session_id}"


@dataclass(frozen=True, kw_only=True)
class SessionCoverage:
    """Whether the ledger's account of one session is known to be complete.

    **Why this exists as a separate reading from `SessionSummary`.** A summary
    is four numbers about what happened; this is one bit about whether those
    numbers are a full account. Folding it into `SessionSummary` was rejected
    because the two have different lifetimes and different failure modes: a
    summary is recomputed from `events` on every read, while coverage is a
    durable claim written once, at the moment observation began, and it has to
    survive the daemon restarting — restarts being precisely when gaps happen.

    Every field below is a *recorded* fact or a direct consequence of one. In
    particular `verified` is never an estimate: it is true only when the ledger
    holds positive evidence of continuous observation, so absence of evidence
    reads as unverified rather than as clean.

    **What this can prove:**

    - `recorded` — there is a `sessions` row at all.
    - `observers` — how many distinct `Ledger` instances (in practice, daemon
      processes) recorded observing this session. More than one means the
      daemon was replaced mid-session, and nothing was listening in between.
    - `attached` — at least one observer's first sight of the session was a
      mid-session event, so the session was already under way before anyone was
      watching.
    - `unobserved_hooks` — a daemon recorded hook events that reached no daemon
      at all.

    **What it cannot prove, and must not be read as proving:** that a session
    with `verified is True` saw every event. A hook that Codex never fired, a
    hook whose 2 s client timeout expired against a busy daemon, a hosted tool
    that bypasses local hooks entirely (README known limits) — each of those is
    an event that leaves no trace anywhere, by construction, while a single
    daemon stays up throughout. `verified` means "nothing on record contradicts
    a complete account", which is the strongest claim the evidence supports and
    deliberately weaker than "complete".
    """

    recorded: bool
    observers: int
    attached: bool
    unobserved_hooks: bool

    @property
    def verified(self) -> bool:
        """True only when nothing on record says the account is partial.

        Note the conjunction includes `observers == 1`: zero observers is a
        session row written by a `Ledger` that predates this table (or by a
        caller that bypassed `start_session`), and "I have no record of when
        observation began" is not the same claim as "observation began at the
        beginning". It reads unverified, which is the honest answer.
        """
        return (self.recorded and self.observers == 1 and not self.attached
                and not self.unobserved_hooks)

    @property
    def reason(self) -> str:
        """A short phrase naming the *evidence*, for the L2 banner. Empty when
        `verified`.

        Ordered most-specific first, and each phrase describes only what the
        ledger recorded. None of them promises the missing events can be
        recovered, because they cannot be (I5): the ledger is the only record,
        and what it did not write down is gone.
        """
        if not self.recorded:
            return "this session was never recorded"
        if self.observers == 0:
            return "there is no record of when observation began"
        if self.attached:
            return "observation began after this session was already under way"
        if self.observers > 1:
            return "Privacy HUD restarted during this session"
        if self.unobserved_hooks:
            return "tool calls went unverified with no daemon listening"
        return ""

    def as_dict(self) -> dict:
        """The JSON shape served by the local UI's `/api/summary`. `verified`
        and `reason` are included even though they are derived: a client that
        recomputed them from the raw fields would be a second implementation of
        the honesty rule, and the two would drift."""
        return {
            "verified": self.verified,
            "reason": self.reason,
            "recorded": self.recorded,
            "observers": self.observers,
            "attached": self.attached,
            "unobserved_hooks": self.unobserved_hooks,
        }


@dataclass(frozen=True, kw_only=True)
class SessionSummary:
    """The four L2 tiles (design.md §5), and nothing else.

    The invariant this protects is I3: `percent` is the disclosure number,
    `exposed_items`/`destinations` count only `kind='exposed'` rows, and
    `prevented` is a separate count that contributes exactly zero to the
    budget. Four same-typed integers next to each other in a dict is precisely
    the shape a transposition survives silently -- swap `destinations` and
    `prevented` at a call site and every test that checks "is it an int" still
    passes while the HUD lies about how far the disclosure went. Named,
    keyword-only fields make that swap a construction error.

    Frozen because I4 says the budget is monotonic within a session: a summary
    is a reading taken at a moment, not a mutable accumulator. Nothing
    downstream needs to write to one, so nothing can.
    """

    percent: int
    exposed_items: int
    destinations: int
    prevented: int

    def as_dict(self) -> dict:
        """The JSON payload of `privacy.get_session_summary` -- key order
        included, since `ui/app.js` and every MCP client read this."""
        return {
            "percent": self.percent,
            "exposed_items": self.exposed_items,
            "destinations": self.destinations,
            "prevented": self.prevented,
        }


#: Exactly the keys `privacy.list_exposures` / `privacy.get_exposure_detail`
#: have always put on the wire, in order. This tuple, not `dataclasses.asdict`,
#: is what `ExposureRow.as_dict()` emits: the MCP tools are a public
#: contract, so their JSON shape must be a decision recorded in one place
#: rather than a side effect of which fields a dataclass happens to declare.
#: Adding a field to `ExposureRow` therefore does NOT silently widen the wire
#: format -- a new key has to be added here on purpose.
_EXPOSURE_JSON_FIELDS = (
    "id", "turn_id", "ts", "kind", "data_type", "source", "destination",
    "boundary", "count", "masked_example", "budget_delta", "protection",
    "tool_name",
)

#: L3-only fields (`render.detail`, design.md §6). Emitted only when set, which
#: is what keeps a list row's JSON identical to what it was before these fields
#: existed -- and what lets `render.detail()` distinguish "no budget cap known"
#: from a cap of 0 without a sentinel.
_DETAIL_JSON_FIELDS = ("first_seen", "last_seen", "hops", "budget_cap")


@dataclass(frozen=True, kw_only=True)
class ExposureRow:
    """One ledger event as any consumer outside the ledger may see it.

    **The field list IS the I1 allow-list.** This replaced a `_project()`
    helper in `mcp_tools` that filtered a full row dict through a tuple of
    string keys; the filter and the thing being filtered could drift, and
    nothing would have noticed. Now the projection is a type: `EventRow.
    to_exposure()` can only produce these fields, so "no raw sensitive content
    leaves the ledger" is a property of the declaration rather than of a
    correctly-maintained key list. Every field here is an id, a count, a type,
    a source or destination label, a timestamp, a boundary, a protection state,
    or the `masked_example` that `mask.py` already masked long before the value
    reached the ledger. There is no `text`, `content`, `prompt` or `raw_value`
    field, and adding one would be an I1 violation, not a feature.

    `degraded` is not a ledger column. It is a render-time flag (Task 8's
    bounded-deep-scan gap and an unavailable model both surface through it --
    see `render.audit`'s "Deep scan unavailable" banner), set by a caller that
    has the `Decision` in hand, and it is deliberately absent from
    `_EXPOSURE_JSON_FIELDS` because it was never part of the wire format.

    The four L3 fields (`first_seen`, `last_seen`, `hops`, `budget_cap`) live
    on this same type rather than on a separate detail class. The L3 payload
    genuinely IS a list row with more fields populated -- `get_exposure_detail`
    returns the same curated projection plus `first_seen` and the session's
    `budget_cap` -- and `render.detail()` was already written to treat them as
    optional. A second class would have duplicated fourteen fields to add four,
    and would have forced `render.audit()` and `render.detail()` to take
    different types when they are looking at the same row.

    Frozen: a row is a record of something that already happened. I4 says
    disclosure is irreversible and there is no removal path, so there is no
    legitimate reason for a consumer to rewrite one.
    """

    id: int
    turn_id: str | None
    ts: int
    kind: str
    data_type: str
    source: str
    destination: str
    boundary: str
    count: int
    masked_example: str | None
    budget_delta: float
    protection: str | None
    tool_name: str | None

    #: Render-time only; see the class docstring. Never serialized.
    degraded: bool = False

    #: L3 (design.md §6). `None` means "not asked for / not known", which is
    #: why `as_dict()` omits rather than nulls them.
    first_seen: int | None = None
    last_seen: int | None = None
    hops: tuple[str, ...] | None = None
    budget_cap: float | None = None

    def as_dict(self) -> dict:
        """The explicit serialization step at the JSON boundary.

        Called by `local_ui_server` and `mcp/server.py` immediately before
        `json.dumps` / the MCP transport. Having it be a method rather than
        letting `dataclasses.asdict` run implicitly is what makes the wire
        format reviewable: the keys come from `_EXPOSURE_JSON_FIELDS`, the
        optional L3 keys appear only when populated, and a field that is not
        in either list (`degraded`, and `EventRow`'s two) cannot reach a
        client by accident.
        """
        payload = {k: getattr(self, k) for k in _EXPOSURE_JSON_FIELDS}
        for k in _DETAIL_JSON_FIELDS:
            value = getattr(self, k)
            if value is not None:
                payload[k] = value
        return payload


@dataclass(frozen=True, kw_only=True)
class EventRow(ExposureRow):
    """A raw `events` row, as `Ledger.list_events` reads it.

    An `EventRow` is an `ExposureRow` plus the two columns that must never
    leave the ledger, which is why it subclasses rather than sits beside it:
    everywhere a consumer accepts a row -- `render.audit`, `render.receipt`,
    the tab tables -- an `EventRow` is substitutable, and `dispatch.
    _handle_session_end` relies on exactly that when it feeds `list_events`
    output straight into `render.receipt` with no projection step.

    `session_id` is redundant to every caller (they asked for one session) and
    `value_hash` is a salted BLOB that is not JSON at all. Neither is in
    `_EXPOSURE_JSON_FIELDS`, so the inherited `as_dict()` cannot emit them --
    that is deliberate, and it is the reason `tests/test_mcp.py`'s "rows carry
    no value_hash bytes" assertion is now structural rather than a coincidence
    of which keys someone remembered to strip.

    Construction is `EventRow(**dict(sqlite_row))`, so a column added to the
    schema without a matching field here raises `TypeError` on the next read
    instead of being silently dropped.
    """

    session_id: str
    value_hash: bytes | None = None

    def to_exposure(self) -> ExposureRow:
        """Narrow to what a consumer outside the ledger may see (the old
        `mcp_tools._project`). Explicit, because "which fields cross this
        boundary" is an I1 decision and deserves to be a visible call."""
        return ExposureRow(**{f.name: getattr(self, f.name)
                              for f in fields(ExposureRow)})


@dataclass(frozen=True, kw_only=True)
class SessionOrigin:
    """Where a session was running, as `Ledger.session_origin` reads it.

    Two strings that are trivially transposable and mean completely different
    things — a clean session opened with the model in its `cwd` column would
    file every later disclosure against a working directory that is not one.
    Named, keyword-only fields make that a construction error, for the same
    reason `SessionSummary`'s four integers are named.

    Both fields are empty strings when the ledger has no row, or a NULL column,
    for the session: `start_session` writes what it is given, and "" is what it
    was always given in that case. Nothing here is serialized — this type does
    not cross the JSON boundary, so it has no `as_dict()`.
    """

    cwd: str
    model: str


class Ledger:
    def __init__(self, path: Path, matrix: Matrix, *, observer: str | None = None):
        """`observer` identifies this `Ledger` instance in the `coverage` table.

        One id per instance, defaulted to a fresh random one, because "who was
        watching" is a property of the *process* holding the connection: the
        daemon builds exactly one `Ledger` for its lifetime (`dispatch.
        new_state`), so a per-instance id is a per-daemon-instance id, and a
        second id appearing against one session is direct evidence that the
        daemon was replaced while that session was running. It is opaque and
        random rather than a pid or a hostname — I1: it must identify a process
        to us without describing the machine to anyone reading the file.
        """
        self.matrix = matrix
        self.observer = observer or uuid.uuid4().hex[:16]
        self.conn = sqlite3.connect(path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        Path(path).chmod(0o600)

    def start_session(self, session_id: str, *, cwd: str, model: str,
                      observed_start: bool = True) -> None:
        """Open (or re-open) a session row, and record that this observer is
        now watching it.

        `observed_start=False` says: this call is creating the session row
        *lazily*, from an event in the middle of a session, so the beginning was
        not observed. Only `dispatch._get_or_start_engine` passes it — the one
        code path that knows the session began before the daemon did. The
        default is True because every other caller genuinely is at a session's
        beginning (a real `SessionStart` hook, or `mcp_tools.
        start_clean_session` minting a brand-new id), and defaulting to False
        would flag every one of them with a gap that does not exist.

        Both writes are `INSERT OR IGNORE`, which is what makes this idempotent
        in the two ways it has to be. For `sessions` it always was: replayed
        hook events must not restart a session. For `coverage` it means a second
        call from the SAME observer changes nothing — so a `SessionStart`
        followed by a hundred lazy re-resolutions leaves the one
        `session_start` row intact — while a call from a DIFFERENT observer
        inserts a new row, which is exactly the mid-session-restart evidence
        `SessionCoverage.observers` counts. Note the ordering consequence:
        `session_start` recorded first cannot be downgraded to `attached` by a
        later lazy call from the same daemon, and that is correct — that daemon
        really did watch from the start.
        """
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions(session_id,started_at,cwd,model,budget_cap)"
            " VALUES(?,?,?,?,?)",
            (session_id, int(time.time()), cwd, model, self.matrix.budget_cap))
        self.conn.execute(
            "INSERT OR IGNORE INTO coverage(session_id,ts,observer,reason)"
            " VALUES(?,?,?,?)",
            (session_id, int(time.time()), self.observer,
             COVERAGE_SESSION_START if observed_start else COVERAGE_ATTACHED))

    def note_unobserved_hooks(self, ts: int) -> None:
        """Record that hook events at around `ts` reached no daemon at all.

        Called once per daemon startup, from `dispatch.new_state`, when the hook
        client's spawn-attempt latch shows it had to start us — see that
        function for where the timestamp comes from and why the latch is
        evidence rather than inference. This is the only trace a session the
        daemon never saw can leave, and without it the incident in this module's
        docstring is undetectable: a session that produced no rows is
        indistinguishable from a session that never existed.

        Filed under `UNATTRIBUTED_SESSION` because the latch carries no session
        id, and guessing one would be exactly the heuristic this table refuses
        to hold. `SessionCoverage` therefore relates it to sessions by time
        alone — see `coverage()` for the bound, which is deliberately narrow.

        `INSERT OR IGNORE` on `(UNATTRIBUTED_SESSION, observer)` caps this at
        one row per daemon instance, so a long-lived machine accumulates one row
        per cold start rather than one per read.
        """
        self.conn.execute(
            "INSERT OR IGNORE INTO coverage(session_id,ts,observer,reason)"
            " VALUES(?,?,?,?)",
            (UNATTRIBUTED_SESSION, int(ts), self.observer,
             COVERAGE_UNOBSERVED_HOOKS))

    def unattributed_gaps(self) -> int:
        """How many `unobserved_hooks` records this ledger holds in total.

        The one question a caller with no session id can still ask, and the
        reason it exists: a ledger holding zero sessions but a recorded gap is
        not an idle installation, it is an installation that watched nothing
        happen. `ambient.py` uses this to tell those two apart.
        """
        return self.conn.execute(
            "SELECT COUNT(*) FROM coverage WHERE session_id=? AND reason=?",
            (UNATTRIBUTED_SESSION, COVERAGE_UNOBSERVED_HOOKS)).fetchone()[0]

    def coverage(self, session_id: str) -> SessionCoverage:
        """Whether this ledger's account of `session_id` is known to be complete.

        Read `SessionCoverage` first for what the answer means. This method is
        only the evidence-gathering half, and it makes exactly one judgement
        call worth stating plainly:

        **When does an unattributed `unobserved_hooks` record count against a
        session?** Only when it is at or after that session's `started_at`, AND
        the session is either still open or is the newest session in the ledger.
        Two cases, one rule:

        - Still open: hook events were dropped while this session was running.
          That is a hole in *its* record, full stop.
        - Ended, but still the newest row: this is the incident. The hooks that
          went unobserved belong to some session that came after it — a session
          the ledger has no row for and can never describe. A caller that
          resolved "the current session" by taking the newest row is therefore
          looking at a number that is not an answer to the question it asked,
          and it must not be shown as one.

        A session that ended and was followed by another *recorded* session is
        unaffected: whatever was dropped afterwards belongs to that later
        session, not to this one. Widening the bound past that would let one
        cold start three days ago mark every historical session unverified,
        which is noise, and noise is how a warning gets trained away.

        An empty `session_id` returns `recorded=False` rather than reading the
        unattributed rows as if they were a session.
        """
        if not session_id:
            return SessionCoverage(recorded=False, observers=0, attached=False,
                                   unobserved_hooks=False)

        srow = self.conn.execute(
            "SELECT started_at, ended_at FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()

        rows = self.conn.execute(
            "SELECT reason FROM coverage WHERE session_id=?",
            (session_id,)).fetchall()
        reasons = [r["reason"] for r in rows]

        if srow is None:
            return SessionCoverage(recorded=False, observers=len(reasons),
                                   attached=COVERAGE_ATTACHED in reasons,
                                   unobserved_hooks=False)

        started_at, ended_at = srow["started_at"], srow["ended_at"]
        newer = self.conn.execute(
            "SELECT 1 FROM sessions WHERE started_at>? LIMIT 1",
            (started_at,)).fetchone()
        in_scope = ended_at is None or newer is None
        gap = bool(in_scope and self.conn.execute(
            "SELECT 1 FROM coverage WHERE session_id=? AND reason=? AND ts>=?"
            " LIMIT 1",
            (UNATTRIBUTED_SESSION, COVERAGE_UNOBSERVED_HOOKS, started_at)
        ).fetchone())

        return SessionCoverage(recorded=True, observers=len(reasons),
                               attached=COVERAGE_ATTACHED in reasons,
                               unobserved_hooks=gap)

    def record(self, session_id: str, *, turn_id, kind, data_type, source,
               destination, value_hash, masked_example, tool_name,
               protection) -> float:
        # I2: unmapped destinations must raise (UnknownKey), never silently
        # score zero — propagate rather than catch.
        boundary = self.matrix.boundary_for(destination)

        existing = self.conn.execute(
            "SELECT id FROM events WHERE session_id=? AND value_hash=? AND destination=?",
            (session_id, value_hash, destination)).fetchone()
        if existing is not None:
            self.conn.execute("UPDATE events SET count=count+1 WHERE id=?",
                               (existing["id"],))
            return 0.0

        # I3: only `exposed` events move the budget.
        delta = (contribution(self.matrix, data_type, 1, destination)
                 if kind == "exposed" else 0.0)

        self.conn.execute(
            "INSERT INTO events(session_id,turn_id,ts,kind,data_type,source,"
            "destination,boundary,value_hash,masked_example,budget_delta,"
            "protection,tool_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (session_id, turn_id, int(time.time()), kind, data_type, source,
             destination, boundary, value_hash, masked_example, delta,
             protection, tool_name))
        if delta:
            self.conn.execute(
                "UPDATE sessions SET budget_score=budget_score+? WHERE session_id=?",
                (delta, session_id))
        return delta

    def summary(self, session_id: str) -> SessionSummary:
        """The four L2 tiles for one session (design.md §5).

        Returns `SessionSummary`, not a dict: see that class for why four
        interchangeable integers are worth naming. An unknown `session_id` is
        not an error -- it reads as a clean session (score 0 against the
        matrix's own cap), which is what `ambient.py` and `doctor.py` need
        when they open a ledger before any session has started.
        """
        row = self.conn.execute(
            "SELECT budget_score, budget_cap FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()
        score = row["budget_score"] if row else 0.0
        cap = row["budget_cap"] if row else self.matrix.budget_cap

        exposed_items = self.conn.execute(
            "SELECT COUNT(*) FROM events WHERE session_id=? AND kind='exposed'",
            (session_id,)).fetchone()[0]
        destinations = self.conn.execute(
            "SELECT COUNT(DISTINCT destination) FROM events"
            " WHERE session_id=? AND kind='exposed'",
            (session_id,)).fetchone()[0]
        prevented = self.conn.execute(
            "SELECT COUNT(*) FROM events WHERE session_id=? AND kind='prevented'",
            (session_id,)).fetchone()[0]

        return SessionSummary(
            percent=percent(score, cap),
            exposed_items=exposed_items,
            destinations=destinations,
            prevented=prevented,
        )

    def list_events(self, session_id: str, kind: str) -> list[EventRow]:
        """Every event of one `kind`, oldest first.

        `EventRow`, not a dict: `SELECT *` is splatted into the dataclass, so a
        schema column with no matching field raises `TypeError` here rather
        than reaching a consumer that silently never looks at it. Rows carry
        `value_hash` because the ledger's own callers (`end_session`, the
        dedupe path, `tests/test_ledger.py`) need it; `EventRow.as_dict()`
        cannot serialize it, so it stops at this boundary.
        """
        rows = self.conn.execute(
            "SELECT * FROM events WHERE session_id=? AND kind=? ORDER BY id",
            (session_id, kind)).fetchall()
        return [EventRow(**dict(r)) for r in rows]

    def end_session(self, session_id: str) -> None:
        self.conn.execute(
            "UPDATE sessions SET ended_at=? WHERE session_id=?",
            (int(time.time()), session_id))
        self.conn.execute(
            "UPDATE events SET value_hash=NULL WHERE session_id=?",
            (session_id,))

    # -- policy and one-shot consent tokens (SCHEMA's last two tables) -----
    #
    # Both tables are read and written only through the methods below. They
    # decide *whether the next call is allowed*, which makes them the one part
    # of this schema where a caller's hand-written SQL could widen an
    # authorization rather than merely miscount one — the token invariant in
    # `consume_token` in particular is a single `WHERE` clause standing between
    # "the user consented to this call" and "the user consented to something".

    def add_policy(self, session_id: str, *, rule_type: str,
                   selector: str) -> None:
        """Record a forward-looking rule for `session_id` (design.md §6's
        "Protect future occurrences" / "Block this source").

        Scoped to the session that asked for it, never globally: a rule the
        user wrote while looking at one session's disclosures is consent about
        that session, and silently widening it to every future session would
        be a promise they never made. `rule_type` is not validated here —
        `mcp_tools.apply_policy` owns the closed set of rule types and refuses
        an unknown one before any row is written.

        Append-only like the rest of this ledger: a rule is a decision the user
        made at a time, so there is no update path and no retroactive effect.
        Data disclosed before the rule was written stays disclosed (P4).
        """
        self.conn.execute(
            "INSERT INTO policy(scope, rule_type, selector, created_at)"
            " VALUES(?,?,?,?)",
            (_session_scope(session_id), rule_type, selector, int(time.time())))

    def policy_selectors(self, session_id: str, rule_type: str) -> set[str]:
        """Every `selector` of `rule_type` that applies to `session_id`: the
        session's own rules plus any `global` ones.

        What this defends is that a user-written rule is actually consulted.
        `Engine.observe` calls this on every egress observation ahead of its
        own matrix defaults, so a selector missing from this set is a rule the
        UI told the user was in force and the engine never saw. Hence both
        scopes, and hence no `except` around the read: a malformed `policy` row
        must fail loud, exactly like an unmapped destination (I2), rather than
        read as "no rules".

        A set, not a list: callers ask "is this source/data_type covered", and
        duplicate rows for the same selector are the same rule written twice.
        """
        rows = self.conn.execute(
            "SELECT selector FROM policy WHERE rule_type=? AND scope IN (?, ?)",
            (rule_type, POLICY_SCOPE_GLOBAL, _session_scope(session_id)),
        ).fetchall()
        return {r["selector"] for r in rows}

    def mint_token(self, session_id: str, *, tool_name: str, args_hash: bytes,
                   mode: str, ttl_seconds: int) -> str:
        """Mint a one-shot consent token and return it (architecture.md §8).

        The token authorizes one thing: a call to `tool_name`, in this session,
        whose arguments hash to `args_hash`, once, before it expires. Every one
        of those four is a column here rather than a caller's convention,
        because each is a way consent could be stretched past what was given —
        a different tool, another session, different arguments, a retry an hour
        later.

        `args_hash` arrives already computed (`minimize._args_hash`): the
        ledger stores a hash, never the arguments, so a token row cannot
        describe the call it authorized (I1). Which bytes are hashed is the
        caller's decision and has to match at consumption time, so it lives
        with the caller that hashes them.

        The token is 16 random bytes from the OS, not a counter or a hash of
        the row: it is a bearer credential, and one a caller could predict
        would authorize a call the user never saw.
        """
        token = os.urandom(16).hex()
        self.conn.execute(
            "INSERT INTO policy_tokens(token,session_id,tool_name,args_hash,mode,"
            "expires_at,consumed) VALUES(?,?,?,?,?,?,0)",
            (token, session_id, tool_name, args_hash, mode,
             int(time.time()) + ttl_seconds))
        return token

    def consume_token(self, session_id: str, *, tool_name: str,
                      args_hash: bytes) -> str | None:
        """Spend the token minted for exactly this call and return its `mode`,
        or `None` when there is none to spend.

        **This is where "one token, one argument set, once" is enforced**, and
        it is one condition per way that guarantee could fail:

        * `session_id`/`tool_name`/`args_hash` must all match what was minted.
          Different arguments are a different call — the whole point of the
          binding is that consent to `curl https://x.test` is not consent to
          `curl https://evil.test`, and the arguments are compared by hash so
          the ledger never has to hold them.
        * `expires_at>` now: consent granted two minutes ago for a call that
          was about to happen is not consent for a call that happens later.
        * Consumption is a `DELETE` of the matching row, so a replayed call
          with identical arguments finds nothing. A blocked tool call that
          Codex retries in a loop gets exactly one pass.

        No match is `None`, not an error: "no token" is the ordinary state of
        almost every call, and the caller's next step (deny) is the safe one.
        A caller that treated an exception as "no token" would be one `except`
        away from treating it as "allowed".

        The lookup is by arguments rather than by the token string because the
        engine never sees a token: it re-hashes the arguments of the call in
        front of it and asks whether consent exists for *that*. A caller who
        could present a token id would be authorizing a call by name.
        """
        row = self.conn.execute(
            "SELECT token, mode FROM policy_tokens WHERE session_id=? AND tool_name=?"
            " AND args_hash=? AND consumed=0 AND expires_at>?",
            (session_id, tool_name, args_hash, int(time.time()))).fetchone()
        if row is None:
            return None
        self.conn.execute("DELETE FROM policy_tokens WHERE token=?",
                          (row["token"],))
        return row["mode"]

    def session_origin(self, session_id: str) -> SessionOrigin:
        """Where a session was running and under which model — the two fields
        a replacement session has to inherit.

        Exists for `mcp_tools.start_clean_session`, which retires a session and
        opens a fresh one that must look like the same work continuing. An
        unknown session reads as empty strings rather than raising: a clean
        session started against an id this ledger never saw is still a valid
        request, and refusing it would leave the caller with a retired session
        and no replacement.
        """
        row = self.conn.execute(
            "SELECT cwd, model FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()
        if row is None:
            return SessionOrigin(cwd="", model="")
        return SessionOrigin(cwd=row["cwd"] or "", model=row["model"] or "")
