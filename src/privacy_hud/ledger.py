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
"""
from __future__ import annotations

import sqlite3
import time
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
#: is what `ExposureRow.as_dict()` emits: the six MCP tools are a public
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


class Ledger:
    def __init__(self, path: Path, matrix: Matrix):
        self.matrix = matrix
        self.conn = sqlite3.connect(path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        Path(path).chmod(0o600)

    def start_session(self, session_id: str, *, cwd: str, model: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions(session_id,started_at,cwd,model,budget_cap)"
            " VALUES(?,?,?,?,?)",
            (session_id, int(time.time()), cwd, model, self.matrix.budget_cap))

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
