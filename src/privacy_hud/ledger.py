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
`LegacySessionSummary`/`UnrecordedSessionSummary`, `LegacyExposureRow` and
`LegacyEventRow` are the read contract, and the JSON boundary is an explicit
`as_dict()` rather than an accident of whatever the dict happened to hold.

**Every recorded session is legacy-accounted (#54 phase 1).** The readers
label its numbers as legacy and route to `events` or, after #54's rebuild,
`events_legacy_v1`, deciding which inside each read. Readers open without
initializing (`Ledger(..., initialize=False)`); only the daemon applies the
schema.

**A ledger that recorded nothing looks exactly like a ledger with nothing to
record — unless it also records whether it was watching.** That is what the
`coverage` table is for, and it is the third state this schema previously could
not express. `summary()` used to answer an unknown session with a well-formed
zero, and zero events / 0% is also what a genuinely clean session looks like,
so the product's central number conflated "nothing sensitive was disclosed" with "I
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
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Literal

from . import ledger_schema
from .budget import contribution, percent
from .matrix.loader import Matrix

#: The legacy schema; see `ledger_schema` for all three generations.
SCHEMA = ledger_schema.LEGACY_SCHEMA


def open_connection(path: Path, *, initialize: bool,
                    check_same_thread: bool) -> sqlite3.Connection:
    """One ledger connection, configured the same way everywhere.

    Autocommit (`isolation_level=None`) with explicit transactions, row
    access by name, foreign keys enforced, a one-second busy wait and full
    synchronous writes. Only the initializing daemon connection sets WAL,
    which persists in the file. `initialize=False` opens an existing file
    read-write and fails on a missing one rather than creating it; no
    connection-level setting here changes the file.
    """
    if initialize:
        conn = sqlite3.connect(path, isolation_level=None,
                               check_same_thread=check_same_thread)
    else:
        conn = sqlite3.connect(
            f"{Path(path).resolve().as_uri()}?mode=rw", uri=True,
            isolation_level=None, check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=1000")
    conn.execute("PRAGMA synchronous=FULL")
    if initialize:
        conn.execute("PRAGMA journal_mode=WAL")
    return conn


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
    #: How many observations in this session had a scan gap: an applicable
    #: deep scan supplied no accepted result (`engine.GAP_*` has the
    #: histories). Each observed scan gap is recorded per observation and
    #: counted per session, including observations with no event row;
    #: written by `record_scan_gap`. Unlike the three fields above, this one does not
    #: say a stretch of the session went unwatched: the hooks fired, the
    #: cheap tiers ran, and the row (if any) is in `events`. What is missing
    #: is the tier-3 finding types on those specific calls, which is why it
    #: is the least severe entry in `reason` and still enough to make
    #: `verified` false.
    shallow_scans: int = 0

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
                and not self.unobserved_hooks and not self.shallow_scans)

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
        if self.shallow_scans:
            n = self.shallow_scans
            return (f"{n} observation{'' if n == 1 else 's'} had scan gaps "
                    "— fast-path results only")
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
            "shallow_scans": self.shallow_scans,
        }


#: The label every legacy number carries, on every surface (CLAUDE.md §4).
LEGACY_SCORE_LABEL: Literal["legacy permitted-crossing score"] = (
    "legacy permitted-crossing score")

#: The caveat that travels with a legacy summary. A closed copy constant,
#: not stored data.
LEGACY_ACCOUNTING_NOTE = (
    "Historical accounting includes permitted crossings and may collapse "
    "different outcomes. It does not establish confirmed disclosure.")

#: The label and caveat for a session this ledger has no row for.
UNRECORDED_SCORE_LABEL: Literal["No session on record"] = (
    "No session on record")
UNRECORDED_ACCOUNTING_NOTE = (
    "No session record is available in this ledger. The percentage and "
    "counts are unavailable.")


#: Re-exported: raised for a schema or session the running code cannot
#: describe or write honestly (see `ledger_schema.UnsupportedAccounting`).
UnsupportedAccounting = ledger_schema.UnsupportedAccounting


@dataclass(frozen=True, kw_only=True)
class LegacySessionSummary:
    """One recorded session under the legacy writer's accounting (#54).

    The numbers are the stored ones: `legacy_score` and `legacy_cap` come
    from the session row, `legacy_percent` is the existing `budget.percent`
    of the two, and the counts are the existing row counts. What changed is
    what they are called. The legacy writer records a permitted crossing as
    `exposed`, dedupes on (value, destination) and increments whatever row
    it finds first, so its score counts permitted crossings and its rows
    may collapse different outcomes (known limits 17 and 18). Every field
    name says `legacy`, and `score_label` and the accounting note travel
    with the numbers, so no surface can present them as confirmed
    disclosure.

    Frozen because I4 says the budget is monotonic within a session: a
    summary is a reading taken at a moment, not a mutable accumulator.
    """

    accounting_version: Literal[1]
    legacy_score: float
    legacy_cap: float
    legacy_percent: int
    legacy_permitted_crossing_rows: int
    legacy_boundary_kinds: int
    legacy_prevented_rows: int
    score_label: Literal["legacy permitted-crossing score"]

    def as_dict(self) -> dict:
        """The JSON payload of `privacy.get_session_summary`, key order
        included."""
        return {
            "accounting_version": self.accounting_version,
            "legacy_score": self.legacy_score,
            "legacy_cap": self.legacy_cap,
            "legacy_percent": self.legacy_percent,
            "legacy_permitted_crossing_rows":
                self.legacy_permitted_crossing_rows,
            "legacy_boundary_kinds": self.legacy_boundary_kinds,
            "legacy_prevented_rows": self.legacy_prevented_rows,
            "score_label": self.score_label,
            "accounting_note": LEGACY_ACCOUNTING_NOTE,
        }


@dataclass(frozen=True, kw_only=True)
class UnrecordedSessionSummary:
    """A session this ledger has no row for.

    Not a clean session. It used to read as one, a well-formed zero
    against the matrix's cap, which is also exactly what a session with
    nothing to record looks like. It has no score, cap or counts, and
    `percent` is `None` so no caller can print a number for it.
    """

    accounting_version: Literal[0]
    percent: None
    score_label: Literal["No session on record"]

    def as_dict(self) -> dict:
        return {
            "accounting_version": self.accounting_version,
            "percent": self.percent,
            "score_label": self.score_label,
            "accounting_note": UNRECORDED_ACCOUNTING_NOTE,
        }


#: What `Ledger.summary` returns. A type alias, not a constructible class.
SessionSummary = LegacySessionSummary | UnrecordedSessionSummary


#: Exactly the keys `privacy.list_exposures` / `privacy.get_exposure_detail`
#: put on the wire, in order. This tuple, not `dataclasses.asdict`, is what
#: `LegacyExposureRow.as_dict()` emits: the MCP tools are a public contract,
#: so their JSON shape must be a decision recorded in one place rather than
#: a side effect of which fields a dataclass happens to declare. Adding a
#: field to the row type therefore does NOT silently widen the wire format.
#: `accounting_version` leads and is always 1: these are legacy rows.
_EXPOSURE_JSON_FIELDS = (
    "accounting_version",
    "id", "turn_id", "ts", "kind", "data_type", "source", "source_kind",
    "destination", "boundary", "count", "masked_example", "budget_delta",
    "protection", "tool_name",
)

#: L3-only fields (`render.detail`, design.md §6). Emitted only when set, which
#: is what keeps a list row's JSON free of them -- and what lets
#: `render.detail()` distinguish "no budget cap known" from a cap of 0
#: without a sentinel.
_DETAIL_JSON_FIELDS = ("first_seen", "last_seen", "hops", "budget_cap")

#: The stored legacy columns, in the order the readers select them.
_LEGACY_COLUMNS = (
    "id", "session_id", "turn_id", "ts", "kind", "data_type", "source",
    "source_kind", "destination", "boundary", "count", "value_hash",
    "masked_example", "budget_delta", "protection", "tool_name",
)

#: Columns a legacy table added after its first release; selected as NULL
#: from a historical table that lacks them, never added by a reader.
_LEGACY_OPTIONAL_COLUMNS = frozenset({"source_kind"})


@dataclass(frozen=True, kw_only=True)
class LegacyExposureRow:
    """One legacy ledger event as any consumer outside the ledger may see it.

    **The field list IS the I1 allow-list.** `LegacyEventRow.to_exposure()`
    can only produce these fields, so "no raw sensitive content leaves the
    ledger" is a property of the declaration rather than of a
    correctly-maintained key list. Every field here is an id, a count, a
    type, a source or destination label, a timestamp, a boundary, a stored
    intervention label, or the `masked_example` that `mask.py` already
    masked long before the value reached the ledger. There is no `text`,
    `content`, `prompt` or `raw_value` field, and adding one would be an I1
    violation, not a feature.

    **Legacy meanings.** `kind`, `protection`, `count` and `budget_delta`
    keep the legacy writer's meanings: `exposed` is a permitted crossing,
    not a confirmed delivery; `blocked`/`masked` record what Privacy HUD
    returned, not what the host applied; `count` is a repetition count, not
    a distinct-value or call count. The renderers label them so. This type
    is not a base of any future accounting type.

    `degraded` is not a ledger column. It is a render-time flag -- True when
    the row's observation had a scan gap: an applicable deep scan supplied no
    accepted result -- set by a caller that has the `Decision` in hand, and
    it is deliberately absent from `_EXPOSURE_JSON_FIELDS`.

    Frozen: a row is a record of something that already happened.
    """

    id: int
    turn_id: str | None
    ts: int
    kind: str
    data_type: str
    source: str
    source_kind: str | None
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

    @property
    def accounting_version(self) -> Literal[1]:
        return 1

    def as_dict(self) -> dict:
        """The explicit serialization step at the JSON boundary. The keys
        come from `_EXPOSURE_JSON_FIELDS`, the optional L3 keys appear only
        when populated, and a field in neither list (`degraded`, and
        `LegacyEventRow`'s two) cannot reach a client by accident."""
        payload = {k: getattr(self, k) for k in _EXPOSURE_JSON_FIELDS}
        for k in _DETAIL_JSON_FIELDS:
            value = getattr(self, k)
            if value is not None:
                payload[k] = value
        return payload


@dataclass(frozen=True, kw_only=True)
class LegacyEventRow(LegacyExposureRow):
    """A raw legacy row, as `Ledger.list_events` reads it: the public
    projection plus the two columns that must never leave the ledger.

    `session_id` is redundant to every caller and `value_hash` is a salted
    BLOB that is not JSON at all. Neither is in `_EXPOSURE_JSON_FIELDS`, so
    the inherited `as_dict()` cannot emit them. Callers outside the ledger
    project with `to_exposure()` before handing a row on.

    Built from explicitly selected columns, so a column added to the schema
    without a matching field here is not read by accident.
    """

    session_id: str
    value_hash: bytes | None = None

    def to_exposure(self) -> LegacyExposureRow:
        """Narrow to what a consumer outside the ledger may see. Explicit,
        because "which fields cross this boundary" is an I1 decision and
        deserves to be a visible call."""
        return LegacyExposureRow(**{f.name: getattr(self, f.name)
                                    for f in fields(LegacyExposureRow)})


class Ledger:
    def __init__(self, path: Path, matrix: Matrix, *,
                 observer: str | None = None,
                 check_same_thread: bool = True,
                 initialize: bool = True):
        """`observer` identifies this `Ledger` instance in the `coverage` table.

        One id per instance, defaulted to a fresh random one, because "who was
        watching" is a property of the *process* holding the connection: the
        daemon builds exactly one `Ledger` for its lifetime (`dispatch.
        new_state`), so a per-instance id is a per-daemon-instance id, and a
        second id appearing against one session is direct evidence that the
        daemon was replaced while that session was running. It is opaque and
        random rather than a pid or a hostname — I1: it must identify a process
        to us without describing the machine to anyone reading the file.

        Thread affinity is enforced by default. A caller passing
        `check_same_thread=False` must serialize every use and closure of this
        connection.

        `initialize=False` is the reader's open (MCP, the local UI, ambient,
        the skill). It opens an existing database read-write, without
        `SCHEMA`, a journal-mode change or a chmod, and fails
        on a missing file rather than creating one. It permits the existing
        policy writes; it is not a read-only connection. Only the daemon
        initializes, so a reader never changes the structure of the ledger
        it is reading, including across #54's rebuild.
        """
        self.matrix = matrix
        self.observer = observer or uuid.uuid4().hex[:16]
        #: Depth of the write transaction this instance owns; 0 when none.
        self._write_depth = 0
        #: Test-only hook called after each migration statement executes.
        #: Not settable from any configuration, environment or tool input.
        self._migration_failpoint: Callable[[str], None] | None = None
        self.conn = open_connection(path, initialize=initialize,
                                    check_same_thread=check_same_thread)
        if not initialize:
            return
        # A failure here propagates: the daemon must not come up against a
        # schema it cannot describe. I6 covers what the hooks do when no
        # daemon answers (open on ingress, closed on egress).
        version = ledger_schema.validate_schema(self.conn)
        if version == ledger_schema.ACTIVATED_VERSION:
            raise UnsupportedAccounting(
                "this ledger uses activated accounting; this version of "
                "Privacy HUD cannot write it")
        if version == 0:
            # A new file gets the legacy schema; an existing legacy ledger
            # gains only a table it lacks. No column is added to an existing
            # table: a historical `events` without `source_kind` keeps its
            # layout, and the legacy writer omits the column.
            with self._write_transaction():
                for statement in ledger_schema.legacy_statements():
                    self.conn.execute(statement)
        Path(path).chmod(0o600)

    def _table_exists(self, name: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,)).fetchone() is not None

    @contextmanager
    def _read_transaction(self) -> Iterator[None]:
        """One consistent snapshot for a read that spans several queries.

        The connection autocommits (`isolation_level=None`), so without this
        each query sees whatever was committed when it ran, and a schema
        inspection followed by a select could straddle #54's rebuild.
        Starts a deferred transaction only when none is open, and ends only
        the transaction it started: a caller already inside one keeps it.
        """
        if self.conn.in_transaction:
            yield
            return
        self.conn.execute("BEGIN DEFERRED")
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        """A `BEGIN IMMEDIATE` write transaction this instance owns.

        Joins a write transaction this instance already owns. Refuses to
        run inside a read transaction rather than silently promoting it.
        Ends only the transaction it began: commit on success, rollback on
        any exception.
        """
        if self._write_depth:
            self._write_depth += 1
            try:
                yield
            finally:
                self._write_depth -= 1
            return
        if self.conn.in_transaction:
            raise RuntimeError("a read transaction is already open")
        self.conn.execute("BEGIN IMMEDIATE")
        self._write_depth = 1
        try:
            yield
            self.conn.execute("COMMIT")
        except BaseException:
            if self.conn.in_transaction:
                try:
                    self.conn.execute("ROLLBACK")
                except sqlite3.Error:
                    # An unusable connection must not expose pending state
                    # or accept subsequent ledger operations.
                    self.conn.close()
            raise
        finally:
            self._write_depth = 0

    def session_exists(self, session_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM sessions WHERE session_id=?",
            (session_id,)).fetchone() is not None

    def prepare_session_boundary(self, session_id: str) -> None:
        """Run #54's structural rebuild, if it has not run, for the genuine
        start of the absent session `session_id` (CLAUDE.md §4).

        Requires a write transaction the caller owns, and an absent session:
        the caller creates the session in the same transaction, so the
        rebuild and the session that triggered it commit together or not at
        all. Each statement is executed individually; nothing here commits.
        A prepared ledger is left alone.
        """
        if not self._write_depth:
            raise RuntimeError("the session boundary needs a write transaction")
        if self.session_exists(session_id):
            raise RuntimeError("the session boundary needs an absent session")
        if ledger_schema.validate_schema(self.conn) != 0:
            return
        for statement in ledger_schema.migration_statements():
            self.conn.execute(statement)
            if self._migration_failpoint is not None:
                self._migration_failpoint(statement)
        ledger_schema.validate_schema(self.conn)

    def _legacy_events_table(self) -> Literal["events", "events_legacy_v1"]:
        """Where this ledger's legacy rows are, decided now.

        `events_legacy_v1` after #54's rebuild, `events` before it. Read
        inside the caller's transaction and never cached: a long-lived MCP
        or UI connection can span the rebuild. A pre-rebuild `events` that
        lacks a stored legacy column is not a layout this reader knows.
        """
        with self._read_transaction():
            table: Literal["events", "events_legacy_v1"] = (
                "events_legacy_v1"
                if self._table_exists("events_legacy_v1") else "events")
            present = self._columns(table)
            missing = set(_LEGACY_COLUMNS) - _LEGACY_OPTIONAL_COLUMNS - present
            if missing:
                raise UnsupportedAccounting(
                    "the legacy events table does not have the required layout")
            return table

    def _columns(self, table: str) -> set[str]:
        return {r["name"] for r in
                self.conn.execute(f"PRAGMA table_info({table})")}

    def _legacy_select(self, table: str) -> str:
        """The explicit legacy column list for `table`. A historical table
        without an optional column projects NULL for it; the reader never
        adds the column."""
        present = self._columns(table)
        return ", ".join(
            name if name in present else f"NULL AS {name}"
            for name in _LEGACY_COLUMNS)

    def _legacy_session(self, session_id: str):
        """The session row, or `None`. Raises for a session a legacy reader
        must not describe: one with a non-legacy accounting version."""
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()
        if row is not None and "accounting_version" in row.keys() \
                and row["accounting_version"] != 1:
            raise UnsupportedAccounting(
                "this session is not recorded under legacy accounting")
        return row

    def start_session(self, session_id: str, *, cwd: str, model: str,
                      observed_start: bool = True) -> None:
        """Open (or re-open) a session row, and record that this observer is
        now watching it.

        `observed_start=False` says: this call is creating the session row
        *lazily*, from an event in the middle of a session, so the beginning was
        not observed. Only `dispatch._get_or_start_engine` passes it — the one
        code path that knows the session began before the daemon did. The
        default is True because every other caller genuinely is at a session's
        beginning (a real `SessionStart` hook), and defaulting to False
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

        Both writes are one write transaction, joining the caller's when it
        owns one (the session boundary, which may run #54's rebuild first).
        A new session is legacy-accounted: the prepared schema's column
        defaults say so.
        """
        with self._write_transaction():
            self.conn.execute(
                "INSERT OR IGNORE INTO sessions(session_id,started_at,cwd,"
                "model,budget_cap) VALUES(?,?,?,?,?)",
                (session_id, int(time.time()), cwd, model,
                 self.matrix.budget_cap))
            self.conn.execute(
                "INSERT OR IGNORE INTO coverage(session_id,ts,observer,reason)"
                " VALUES(?,?,?,?)",
                (session_id, int(time.time()), self.observer,
                 COVERAGE_SESSION_START if observed_start
                 else COVERAGE_ATTACHED))

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

    def record_scan_gap(self, session_id: str, *, boundary: str,
                        reason: str, ts: float | None = None) -> None:
        """Write down one scan gap: an applicable deep scan supplied no
        accepted result. Each observed scan gap is recorded per observation
        and counted per session, including observations with no event row.
        Append-only; never deduped.

        **Why this is a row and not a column on `events`.** The case that
        matters most is the one that writes no event at all: an outbound
        call whose cheap tiers found nothing and which had a scan gap
        produces zero `events` rows, and is therefore indistinguishable in
        the ledger from a call that was fully scanned and was clean. A
        column could only mark rows that exist. This table records the
        *scan*, so a clean-looking session that was never properly looked at
        stops reading as clean — which is the whole job of `coverage`.

        `reason` is one of `engine.GAP_*`, and like `COVERAGE_*` above each
        value names evidence rather than a guess; `engine.GAP_*` lists the
        history each one covers. This module does not import `engine` (engine imports
        ledger), so the values are not validated here — `engine` owns the
        taxonomy and `tests/test_ledger.py` pins the two lists together.

        I1: a row is a session id, a timestamp, a boundary and a reason.
        Nothing about what the payload contained. A row makes no claim about
        whether inference executed: a `timeout` row can describe inference
        that was running or had completed, so a scan gap is not proof the
        payload was unread.
        """
        self.conn.execute(
            "INSERT INTO scan_gaps(session_id,ts,boundary,reason)"
            " VALUES(?,?,?,?)",
            (session_id, int(time.time() if ts is None else ts), boundary,
             reason))

    def scan_gaps(self, session_id: str) -> int:
        """How many observations in `session_id` had a scan gap."""
        return self.conn.execute(
            "SELECT COUNT(*) FROM scan_gaps WHERE session_id=?",
            (session_id,)).fetchone()[0]

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
                               unobserved_hooks=gap,
                               shallow_scans=self.scan_gaps(session_id))

    def record(self, session_id: str, *, turn_id, kind, data_type, source,
               destination, value_hash, masked_example, tool_name,
               protection, source_kind: str | None = None) -> float:
        """Record one legacy event; see `_record_legacy`.

        Refuses a session under any other accounting: a later accounting
        writer records observations, not legacy rows.
        """
        with self._write_transaction():
            row = self.conn.execute(
                "SELECT * FROM sessions WHERE session_id=?",
                (session_id,)).fetchone()
            if row is not None and "accounting_version" in row.keys() \
                    and row["accounting_version"] != 1:
                raise UnsupportedAccounting(
                    "legacy records require a legacy-accounted session")
            return self._record_legacy(
                session_id, turn_id=turn_id, kind=kind, data_type=data_type,
                source=source, destination=destination,
                value_hash=value_hash, masked_example=masked_example,
                tool_name=tool_name, protection=protection,
                source_kind=source_kind)

    def _record_legacy(self, session_id: str, *, turn_id, kind, data_type,
                       source, destination, value_hash, masked_example,
                       tool_name, protection,
                       source_kind: str | None = None) -> float:
        """Write legacy evidence inside the caller's write transaction.

        Open sessions retain legacy arithmetic and dedupe. Ended sessions
        append evidence with a null value hash and zero contribution;
        their stored scores remain frozen. Historical rows are unchanged.
        Omit source_kind when the legacy table lacks that column.
        """
        # I2: unmapped destinations must raise (UnknownKey), never silently
        # score zero — propagate rather than catch.
        boundary = self.matrix.boundary_for(destination)
        table = self._legacy_events_table()

        # The caller owns BEGIN IMMEDIATE: end-state inspection, insertion,
        # and any charge are serialized with end_session.
        session = self.conn.execute(
            "SELECT ended_at FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()
        ended = session is not None and session["ended_at"] is not None
        if ended:
            # Late evidence must not establish a new matching namespace.
            # SQL equality with NULL intentionally finds no dedupe match.
            value_hash = None

        existing = self.conn.execute(
            f"SELECT id FROM {table} WHERE session_id=? AND value_hash=?"
            " AND destination=?",
            (session_id, value_hash, destination)).fetchone()
        if existing is not None:
            self.conn.execute(
                f"UPDATE {table} SET count=count+1 WHERE id=?",
                (existing["id"],))
            return 0.0

        # Only exposed events in an open session can add a legacy charge.
        delta = (contribution(self.matrix, data_type, 1, destination)
                 if kind == "exposed" and not ended else 0.0)

        values = {
            "session_id": session_id, "turn_id": turn_id,
            "ts": int(time.time()), "kind": kind, "data_type": data_type,
            "source": source, "source_kind": source_kind,
            "destination": destination, "boundary": boundary,
            "value_hash": value_hash, "masked_example": masked_example,
            "budget_delta": delta, "protection": protection,
            "tool_name": tool_name,
        }
        present = self._columns(table)
        names = [name for name in values if name in present]
        self.conn.execute(
            f"INSERT INTO {table}({','.join(names)})"
            f" VALUES({','.join('?' * len(names))})",
            tuple(values[name] for name in names))
        if delta:
            self.conn.execute(
                "UPDATE sessions SET budget_score=budget_score+?"
                " WHERE session_id=?", (delta, session_id))
        return delta

    def summary(self, session_id: str) -> SessionSummary:
        """The session's accounting summary (design.md §5's tiles).

        A recorded session is `LegacySessionSummary`: the stored score and
        cap, the existing percentage arithmetic, and the existing row
        counts, under legacy names. A session with no row is
        `UnrecordedSessionSummary`, not a clean zero: see that class.
        Existence is read before the counts, inside one transaction.
        """
        with self._read_transaction():
            row = self._legacy_session(session_id)
            if row is None:
                return UnrecordedSessionSummary(
                    accounting_version=0, percent=None,
                    score_label=UNRECORDED_SCORE_LABEL)
            table = self._legacy_events_table()
            score, cap = row["budget_score"], row["budget_cap"]
            exposed_rows = self.conn.execute(
                f"SELECT COUNT(*) FROM {table}"
                " WHERE session_id=? AND kind='exposed'",
                (session_id,)).fetchone()[0]
            boundary_kinds = self.conn.execute(
                f"SELECT COUNT(DISTINCT destination) FROM {table}"
                " WHERE session_id=? AND kind='exposed'",
                (session_id,)).fetchone()[0]
            prevented_rows = self.conn.execute(
                f"SELECT COUNT(*) FROM {table}"
                " WHERE session_id=? AND kind='prevented'",
                (session_id,)).fetchone()[0]
        return LegacySessionSummary(
            accounting_version=1,
            legacy_score=score,
            legacy_cap=cap,
            legacy_percent=percent(score, cap),
            legacy_permitted_crossing_rows=exposed_rows,
            legacy_boundary_kinds=boundary_kinds,
            legacy_prevented_rows=prevented_rows,
            score_label=LEGACY_SCORE_LABEL,
        )

    def list_events(self, session_id: str, kind: str) -> list[LegacyEventRow]:
        """Every legacy event of one `kind`, oldest first.

        Rows carry `value_hash` because the ledger's own callers need it;
        `as_dict()` cannot serialize it, and callers outside the ledger
        project with `to_exposure()`. An unknown session has no rows.
        """
        with self._read_transaction():
            if self._legacy_session(session_id) is None:
                return []
            table = self._legacy_events_table()
            rows = self.conn.execute(
                f"SELECT {self._legacy_select(table)} FROM {table}"
                " WHERE session_id=? AND kind=? ORDER BY id",
                (session_id, kind)).fetchall()
        return [LegacyEventRow(**dict(r)) for r in rows]

    def get_event(self, session_id: str, event_id: int) -> LegacyExposureRow:
        """One public legacy row, scoped to both `session_id` and
        `event_id`, with `first_seen` and the session's stored `budget_cap`.

        Raises `LookupError` when nothing matches, including an id that
        exists in another session: one session's audit can never read
        another's row by guessing an id. The row and the cap are read in
        one transaction.
        """
        with self._read_transaction():
            session = self._legacy_session(session_id)
            if session is None:
                raise LookupError(
                    f"no event {event_id!r} in session {session_id!r}")
            table = self._legacy_events_table()
            row = self.conn.execute(
                f"SELECT {self._legacy_select(table)} FROM {table}"
                " WHERE session_id=? AND id=?",
                (session_id, event_id)).fetchone()
            if row is None:
                raise LookupError(
                    f"no event {event_id!r} in session {session_id!r}")
            cap = session["budget_cap"]
        public = LegacyEventRow(**dict(row)).to_exposure()
        return LegacyExposureRow(
            **{f.name: getattr(public, f.name)
               for f in fields(LegacyExposureRow)
               if f.name not in ("first_seen", "budget_cap")},
            first_seen=public.ts, budget_cap=cap)

    def end_session(self, session_id: str) -> None:
        """End the session and null its legacy value hashes, in one write
        transaction. An ended session keeps its first end time."""
        with self._write_transaction():
            self.conn.execute(
                "UPDATE sessions SET ended_at=? WHERE session_id=?"
                " AND ended_at IS NULL", (int(time.time()), session_id))
            table = self._legacy_events_table()
            self.conn.execute(
                f"UPDATE {table} SET value_hash=NULL WHERE session_id=?",
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
        "Mask detected <type> in future calls").

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
        """Every `selector` of `rule_type` written for `session_id`.

        Session scope only. The schema once documented a `global` scope and
        this reader honoured it, but nothing could write one: `add_policy` is
        session-scoped on purpose, and no action in design.md offers a rule
        for every session. A reader for a scope the product does not offer is
        a promise the schema makes and the UI never does, so it is gone.

        What this defends is that a user-written rule is actually consulted.
        `Engine.observe` calls this on every egress observation ahead of its
        own matrix defaults, so a selector missing from this set is a rule the
        UI told the user was in force and the engine never saw. Hence no
        `except` around the read: a malformed `policy` row
        must fail loud, exactly like an unmapped destination (I2), rather than
        read as "no rules".

        A set, not a list: callers ask "is this source/data_type covered", and
        duplicate rows for the same selector are the same rule written twice.
        """
        rows = self.conn.execute(
            "SELECT selector FROM policy WHERE rule_type=? AND scope=?",
            (rule_type, _session_scope(session_id)),
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
        # A second consent for the same call replaces the first rather than
        # stacking with it: two rows would let a retried call through twice,
        # and "once" is the whole grant.
        self.conn.execute(
            "DELETE FROM policy_tokens WHERE session_id=? AND tool_name=?"
            " AND args_hash=?", (session_id, tool_name, args_hash))
        self.conn.execute(
            "INSERT INTO policy_tokens(token,session_id,tool_name,args_hash,mode,"
            "expires_at) VALUES(?,?,?,?,?,?)",
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
          Codex retries in a loop gets exactly one pass. `mint_token`
          replaces an earlier token for the same call, so there is at most
          one row to find; the `ORDER BY` only makes the choice deterministic
          in a ledger written before that rule existed.

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
            " AND args_hash=? AND expires_at>? ORDER BY expires_at DESC LIMIT 1",
            (session_id, tool_name, args_hash, int(time.time()))).fetchone()
        if row is None:
            return None
        self.conn.execute("DELETE FROM policy_tokens WHERE token=?",
                          (row["token"],))
        return row["mode"]
