# src/privacy_hud/mcp_tools.py
"""Pure functions behind the `privacy.*` MCP tools (Task 13).

Every function here takes an already-open `Ledger` (the SAME ledger the
daemon is writing to — see `mcp/server.py` for how a real MCP process
opens it against `$PLUGIN_DATA/ledger.db`, `dispatch.new_state`'s same
path) and returns a plain, JSON-serializable `dict`/`list[dict]`. No I/O
beyond the ledger's own sqlite connection, no network calls, no raw
sensitive value ever leaves any of these functions (I1) — every returned
field is an ID, a count, a type, a source/destination label, a timestamp,
or the pre-masked `masked_example` the ledger already stored (mask.py runs
long before any row reaches here). `tests/test_mcp.py`'s
`test_no_raw_value_survives_json_round_trip` is the enforcement gate for
that claim, run against a JSON dump of every function's return value.

**`apply_policy` and enforcement — read before wiring UI actions to this.**
`apply_policy` writes a row to the `policy` table (schema from ledger.py /
architecture.md §5) exactly as `Engine.observe` needs to read it to make
"Block this source" / "Protect future occurrences" real. As of commit
`2387e40`, `Engine.observe` (src/privacy_hud/engine.py) DOES query the
`policy` table on every egress observation, before falling back to
`Matrix.default_action()` (the static mask/block table in tables.toml) —
a user-written `block_source`/`mask` rule outranks the matrix defaults in
`Engine.observe`'s precedence chain. So a rule written by `apply_policy`
is durable, correctly shaped, and **enforced on the next matching call** —
"Block this source" and "Protect future occurrences" are genuinely real,
not cosmetic: a `block_source` rule denies a later call from that source,
a `mask` rule forces a rewrite for that data type. This still does not
apply retroactively (design.md P4): data already disclosed before the
rule was written stays disclosed — the rule only changes what happens on
the *next* call, not what already happened, and no caller of this module
should claim otherwise.

`get_exposure_detail`'s selector: the `events` table already has a stable,
unique, integer `id` primary key (see ledger.py's SCHEMA), and every row
`list_events`/`list_exposures` returns already carries it. A composite key
like `(data_type, source, destination)` was considered and rejected: it is
NOT unique per row — the ledger's own dedupe key is `(session_id,
value_hash, destination)`, so two distinct values of the same type from
the same source to the same destination (different `value_hash`es) get
two distinct `events` rows sharing that composite. The row `id` is unique
by construction and requires no new bookkeeping, so that is what
`get_exposure_detail` takes.
"""
from __future__ import annotations

import time
import uuid

from .minimize import mint_token

# Curated event-row projection returned to every MCP-facing caller. Deliberately
# excludes `value_hash` (a BLOB, not JSON-serializable, and not on the "IDs,
# counts, types, destinations, timestamps, masked_example" allow-list even if
# it were hex-encoded) and any column that does not exist in the schema in the
# first place (there is no raw-value column to exclude -- see ledger.py's
# SCHEMA docstring).
_EVENT_FIELDS = (
    "id", "turn_id", "ts", "kind", "data_type", "source", "destination",
    "boundary", "count", "masked_example", "budget_delta", "protection",
    "tool_name",
)

# design.md §5: "All events" is the forensic view -- every kind the ledger
# can hold, not just exposed/prevented. `detected`/`retention` are part of
# the schema's documented kind enum (ledger.py SCHEMA, architecture.md §5)
# even though no current caller writes them (dispatch.py never routes
# SessionStart/PreCompact/SessionEnd through Engine.observe) -- included
# here so "All events" stays complete if/when that changes, rather than
# silently dropping a kind the schema already anticipates.
_ALL_EVENT_KINDS = ("exposed", "prevented", "local_access", "detected", "retention")

_TAB_KINDS = {
    "Exposed": ("exposed",),
    "Prevented": ("prevented",),
    "All events": _ALL_EVENT_KINDS,
}

_POLICY_RULE_TYPES = {"mask", "block_source", "allow_dest"}


def _project(row: dict) -> dict:
    return {k: row.get(k) for k in _EVENT_FIELDS}


def get_session_summary(ledger, session_id: str) -> dict:
    """The four L2 tiles (design.md §5): percent, exposed_items,
    destinations, prevented. `Ledger.summary` already returns exactly
    this shape and nothing beyond it -- no raw value is reachable from
    session-level counts in the first place."""
    return dict(ledger.summary(session_id))


def list_exposures(ledger, session_id: str, tab: str) -> list[dict]:
    """Rows for one of design.md §5's three tabs: `"Exposed"`,
    `"Prevented"`, or `"All events"`. Each row is the curated projection
    from `_EVENT_FIELDS` -- metadata only, plus the ledger's pre-masked
    `masked_example`, never a raw value.

    Does not aggregate by `(data_type, source, destination)` the way
    design.md's mockup groups rows for display -- `render.audit()` (Task
    11) already accepts and sorts per-row data exactly like this (see
    `dispatch.py`'s `_handle_session_end`, which feeds `list_events`'
    output straight into `render.receipt` with no aggregation step); doing
    the same aggregation twice, in two different ways, is a bug waiting to
    happen. If the UI wants grouped rows for display, that groups this
    function's rows by `(data_type, source, destination)` at render time.
    """
    kinds = _TAB_KINDS.get(tab)
    if kinds is None:
        raise ValueError(f"unknown tab {tab!r}; expected one of {sorted(_TAB_KINDS)}")

    rows: list[dict] = []
    for kind in kinds:
        rows.extend(_project(r) for r in ledger.list_events(session_id, kind))
    return rows


def get_exposure_detail(ledger, session_id: str, event_id: int) -> dict:
    """The L3 payload for one flow (design.md §6), keyed by the `events`
    table's own integer `id` -- see this module's docstring for why that
    selector was chosen over a composite key. Scoped to `session_id`: an
    id that exists but belongs to a different session is treated as not
    found, not silently returned, so one session's audit can never read
    another's row by guessing an id.

    Raises `LookupError` (not `None`/`{}`) when nothing matches -- a
    detail view for a nonexistent flow is a caller bug worth surfacing,
    not a value worth rendering as if it were empty.

    `budget_cap` is included (fetched from the session's own row, not
    hardcoded -- see render.py's `detail()` docstring for why a literal
    120 would go stale) so `render.detail()`'s optional "+N pts of {cap}"
    tail can be shown; the field is safely omitted by that function when
    absent.
    """
    row = ledger.conn.execute(
        "SELECT id, turn_id, ts, kind, data_type, source, destination,"
        " boundary, count, masked_example, budget_delta, protection,"
        " tool_name FROM events WHERE session_id=? AND id=?",
        (session_id, event_id)).fetchone()
    if row is None:
        raise LookupError(
            f"no event {event_id!r} in session {session_id!r}")

    detail = _project(dict(row))
    detail["first_seen"] = detail["ts"]

    cap_row = ledger.conn.execute(
        "SELECT budget_cap FROM sessions WHERE session_id=?",
        (session_id,)).fetchone()
    if cap_row is not None:
        detail["budget_cap"] = cap_row["budget_cap"]

    return detail


def apply_policy(ledger, session_id: str, *, rule_type: str, selector: str) -> None:
    """Write a forward-looking policy rule (design.md §6's "Protect future
    occurrences" / "Block this source" actions), scoped to this session.

    `rule_type` must be one of the schema's own documented values
    (ledger.py SCHEMA's `policy.rule_type` comment: `mask|block_source|
    allow_dest`) -- an unrecognized rule_type raises `ValueError` rather
    than being written silently, since a policy row the engine can never
    match is worse than an error: it looks like protection was applied
    when nothing was.

    See this module's top-level docstring: `Engine.observe` now consults
    this table (ahead of its own matrix defaults) on every subsequent
    egress observation, so a rule written here is genuinely enforced on
    the *next* matching call -- not merely recorded. It still does not
    apply retroactively: data already disclosed before the rule was
    written stays disclosed (design.md P4).
    """
    if rule_type not in _POLICY_RULE_TYPES:
        raise ValueError(
            f"unknown rule_type {rule_type!r}; expected one of "
            f"{sorted(_POLICY_RULE_TYPES)}")
    ledger.conn.execute(
        "INSERT INTO policy(scope, rule_type, selector, created_at)"
        " VALUES(?,?,?,?)",
        (f"session:{session_id}", rule_type, selector, int(time.time())))


def allow_once(ledger, session_id: str, *, tool_name: str, tool_input,
               reviewed: bool) -> None:
    """Mint a single-use consent token for exactly `(tool_name,
    tool_input)` (design.md §8 / architecture.md §8's token binding),
    consumed by `Engine.observe` -> `minimize.consume_token` the next time
    Codex retries that exact call.

    `reviewed` must be truthy or this raises `PermissionError` and mints
    nothing. This encodes design.md §8's rule verbatim: `Allow once`
    requires the user to have seen the L3 detail first -- "consent
    without information is not consent." The caller (the UI / skill) is
    responsible for setting `reviewed=True` only after the user has
    actually opened `get_exposure_detail` for the flow in question; this
    function has no way to verify that itself, since a `Ledger` alone
    carries no view-history state, so it enforces the one part of the
    rule it CAN enforce coercively: no token is minted at all without an
    explicit, affirmative claim that the review happened.
    """
    if not reviewed:
        raise PermissionError(
            "allow_once requires reviewed=True: the exposure detail must "
            "be shown before a one-shot allowance can be granted "
            "(design.md §8 -- consent without information is not consent).")
    mint_token(ledger, session_id, tool_name, tool_input, mode="allow_once")


def start_clean_session(ledger, session_id: str) -> str:
    """Design.md §6's "Start a clean session" action (offered only in the
    red band). Properly retires `session_id` -- via `Ledger.end_session`,
    which nulls every stored `value_hash` for it (the on-disk half of "the
    old salt must not stay discoverable": no salted hash computed under
    the old session's salt survives past this call) and stamps
    `ended_at` -- then opens a brand-new session row under a fresh id and
    returns it, rather than reusing `session_id` or leaving the old row
    looking still-active.

    Scope note: this function receives only a `Ledger`, never the
    daemon's in-memory `dispatch.State` -- the actual per-session salt
    bytes (`mask.new_salt()`) live in `State.salts`, held by a running
    daemon process, and are outside what any `mcp_tools` function can
    reach or discard directly (see dispatch.py's session/salt lifecycle
    docstring: a salt is retired only when the daemon itself processes a
    `SessionEnd` hook event for that `session_id`). Calling this does the
    part reachable from the ledger alone -- closing out the stored,
    salt-derived hashes and starting a fresh session row -- and returns
    the new id so a caller can begin using it; a live daemon will drop
    the old in-memory salt and mint a new one once it next sees the
    matching real `SessionStart`/`SessionEnd` hook pair for these ids.
    """
    old = ledger.conn.execute(
        "SELECT cwd, model FROM sessions WHERE session_id=?",
        (session_id,)).fetchone()

    ledger.end_session(session_id)

    new_id = f"{session_id}-clean-{uuid.uuid4().hex[:12]}"
    ledger.start_session(
        new_id,
        cwd=(old["cwd"] if old is not None else "") or "",
        model=(old["model"] if old is not None else "") or "")
    return new_id
