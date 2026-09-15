# src/privacy_hud/mcp_tools.py
"""Pure functions behind the `privacy.*` MCP tools (Task 13).

Every function here takes an already-open `Ledger` (the SAME ledger the
daemon is writing to — see `mcp/server.py` for how a real MCP process
opens it against `$PLUGIN_DATA/ledger.db`, `dispatch.new_state`'s same
path) and returns one of `ledger.py`'s read-contract dataclasses:
`SessionSummary` or `ExposureRow`. No I/O
beyond the ledger's own sqlite connection — with exactly one documented
exception, `resolve_audit_session`, which also asks the local daemon over its
AF_UNIX socket which session is live right now, because that is the one
question the ledger cannot answer (see that function). A unix socket is a
filesystem rendezvous with a process on this machine, not a network call: I2
is untouched and `tests/test_network_isolation.py`'s transport tests are what
keep that true. No raw
sensitive value ever leaves any of these functions (I1) — every returned
field is an ID, a count, a type, a source/destination label, a timestamp,
or the pre-masked `masked_example` the ledger already stored (mask.py runs
long before any row reaches here). `tests/test_mcp.py`'s
`test_no_raw_value_survives_json_round_trip` is the enforcement gate for
that claim, run against a JSON dump of every function's return value.

**Serializing is an explicit step, and the wire format is unchanged.** These
functions used to return bare dicts assembled from a tuple of string keys
(`_EVENT_FIELDS` + `_project`), which is what made the `privacy.*` tools'
JSON shape an emergent property of a key list nobody was checking against the
schema. The shape is now `ExposureRow`/`SessionSummary`, and the two callers
that put it on a wire — `local_ui_server` (browser JSON) and `mcp/server.py`
(the MCP transport) — call `.as_dict()` themselves. That call is the contract
boundary: `ledger._EXPOSURE_JSON_FIELDS` pins the keys and their order, so
adding a field to the row type cannot silently widen what a client receives,
and a dataclass can never reach `json.dumps` unserialized.

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

from dataclasses import dataclass
from pathlib import Path

from .ledger import ExposureRow, SessionCoverage, SessionSummary
from .minimize import mint_token

# The curated event-row projection that used to live here as `_EVENT_FIELDS` +
# `_project()` is now `ledger.ExposureRow`, and narrowing a ledger row to it is
# `EventRow.to_exposure()`. The reason for the move: a tuple of string keys and
# the rows it filtered were two things that had to agree, with nothing checking
# that they did — the same shape of bug as `detect/model.py`'s wrong `LABEL_MAP`
# keys, which silently disabled tier 3 entirely. A type cannot drift from
# itself: `to_exposure()` can only produce `ExposureRow`'s fields, so
# `value_hash` (a salted BLOB, not JSON at all) and `session_id` are excluded
# structurally rather than by a maintained list. See `ExposureRow`'s docstring
# for the I1 argument in full.

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

#: How close two sessions' last hook events have to be, in seconds, before
#: "which of these is the caller?" stops being answerable.
#:
#: The signal `resolve_audit_session` ranks on is "who fired a hook most
#: recently", and the caller's own hook (the `PreToolUse` for the bash the
#: skill runs) landed a fraction of a second before the question was asked. A
#: second session that has not fired a hook in the last few seconds therefore
#: cannot be the caller and needs no caveat — which is the ordinary
#: two-windows case, where the other window is idle while its user reads.
#:
#: The window is seconds and not milliseconds because a *tight* window would
#: be worse than none: a second session in an active tool loop can easily fire
#: a hook between the caller's hook and the caller's query, taking the top
#: rank by a margin a millisecond-scale window would wave through as
#: certainty. Five seconds is comfortably wider than that interleaving and
#: still narrow enough that an idle window does not trip it.
CONCURRENT_WITHIN = 5.0


@dataclass(frozen=True)
class ResolvedSession:
    """Which session an audit is about, and how confidently.

    The second half is the point. Every field but `session_id` exists so a
    caller can say what it is showing without overclaiming (CLAUDE.md §5): an
    audit that silently prints another window's numbers under the heading
    "your session" is a worse failure for this tool than one that admits it
    had to guess.

    `basis` is one of:

    ``"explicit"``
        The user named the id (`$privacy <id>`). Nothing was inferred.
    ``"active"``
        The daemon named it: the session whose last hook event is the most
        recent. Load-bearing property — running `$privacy` fires hooks, so the
        asking session is the most recently active one by construction.
    ``"started_at"``
        Fallback. The most recently *started* session in the ledger, which is
        the right session only when there is exactly one.
    ``"none"``
        The ledger holds no session at all; `session_id` is `None`.

    `also_active` names the other sessions that fired a hook within
    `CONCURRENT_WITHIN` of the chosen one — genuinely concurrent windows, which
    this signal cannot tell apart. `daemon_answered` distinguishes the two
    fallback cases, which have different meanings for the user: a daemon that
    did not answer means the session is not being recorded *at all* right now
    (README known limit 1), while a daemon that answered with no live session
    means it started after the session did.

    I1: ids and a couple of enum-ish strings. Nothing here describes what any
    session did.
    """

    session_id: str | None
    basis: str
    also_active: tuple[str, ...] = ()
    daemon_answered: bool = True

    @property
    def certain(self) -> bool:
        """Whether this names the caller's own session without qualification."""
        return (self.basis == "explicit"
                or (self.basis == "active" and not self.also_active))

    @property
    def note(self) -> str:
        """The caveat to print with the audit, or `""` when there is none.

        Copy rules (design.md §9) apply here as much as to `render.py`: no
        "undo", no "your data is protected", no severity adjectives, and no
        claim about recall. Shaped like `render._coverage_banner`'s
        `⚠ … — …` line because it sits in the same place and answers the
        neighbouring question: that banner says whether the numbers are a full
        account, this says whether they are the account of the session you are
        in.
        """
        if self.certain:
            return ""
        if self.basis == "active":
            others = ", ".join(self.also_active)
            return ("⚠ More than one Codex session was active in the same "
                    f"moment — also active: {others}. This audit is of the "
                    "session that acted most recently, which may not be the "
                    "window you typed in. Run `$privacy <session id>` to "
                    "audit a specific one.")
        if self.basis == "started_at" and not self.daemon_answered:
            # Deliberately does NOT point at the coverage banner. Coverage
            # describes the record up to now, and a session observed earlier
            # by a daemon that has since exited still reads `verified` — so a
            # note that promised a line below it would be pointing at a line
            # that is not there. What is true right now is stated here
            # instead, in one sentence, and `Ledger.coverage` keeps answering
            # its own (different) question beside it.
            return ("⚠ The Privacy HUD daemon did not answer, so this is the "
                    "most recently started session on record — not "
                    "necessarily the one you are in. Nothing is being "
                    "recorded for any session while no daemon is listening.")
        if self.basis == "started_at":
            return ("⚠ The daemon has no live session on record, so this is "
                    "the most recently started session on record, not "
                    "necessarily the one you are in.")
        return "No session has been recorded in this ledger yet."


def _most_recently_started(ledger) -> str | None:
    """The ledger's own best guess: the most recently started session.

    Kept as a named function so the fallback is one call and one docstring
    rather than a SQL string copied into every caller — the "most recently
    started session" query had been duplicated into three surfaces in this
    project and each copy was a place the same wrong answer could be
    reintroduced. There is one copy now: `local_ui_server._latest_session_id`
    is an alias onto this, and `ambient` calls `resolve_audit_session` rather
    than resolving for itself.

    Wrong as a *primary* answer for the reason `resolve_audit_session`
    documents; correct as a fallback because with one session it is the same
    answer, and with no daemon there is nothing better to have.
    """
    row = ledger.conn.execute(
        "SELECT session_id FROM sessions ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    return row["session_id"] if row is not None else None


def _ask_daemon(data_dir) -> list[dict] | None:
    """`daemon.query_active_sessions` against `$PLUGIN_DATA`'s socket, or
    `None` if it could not be asked.

    The import is deferred, and the `except` around it is deliberate rather
    than defensive: importing `daemon` pulls in `dispatch` and the detector
    stack, which this module's other callers (the MCP server, the UI) have no
    need of, and an interpreter that cannot import it is in exactly the same
    position as one that cannot reach the socket — no answer available. One
    degradation path, not two.
    """
    try:
        from .daemon import _default_socket_path, query_active_sessions
        return query_active_sessions(_default_socket_path(Path(data_dir)))
    except Exception:
        return None


def resolve_audit_session(ledger, data_dir, *, explicit: str | None = None,
                          concurrent_within: float = CONCURRENT_WITHIN,
                          ) -> ResolvedSession:
    """Decide which session an audit (`$privacy`, the local UI's default view)
    should describe, and how honestly it can be labelled.

    **Why this is not a one-line SQL query.** Both answers the ledger can give
    are wrong, and each is wrong in a way that looks right:

    * `ORDER BY started_at DESC LIMIT 1` — the most recently *started*
      session. Open a second Codex window, then run `$privacy` in the first,
      and it audits the second window's session with nothing saying so. This
      was the shipped behavior and it was confirmed against a real ledger,
      where most-recently-started and most-recently-active were two different
      sessions.
    * `ORDER BY MAX(events.ts) DESC` — the most recently *disclosing* session.
      A session that has disclosed nothing has no `events` rows at all, so the
      cleanest possible session is skipped and an older one's audit is served
      in its place. The fix must work for a brand-new session with an empty
      ledger, which rules this out on its own.

    The daemon is the only process that knows, because it sees every hook —
    including the ones that write no ledger row (`dispatch.note_session_live`)
    — and Codex exposes no session id to a skill (verified: the CLI prints one
    in its startup banner, and no environment variable carries it into a
    skill's shell). So this asks the daemon, and the property that makes the
    answer sound rather than lucky is that **asking fires hooks**: the skill
    runs bash, bash is a `PreToolUse` in the asking session, so that session's
    last-hook time is a fraction of a second old by the time this function
    runs. "Most recently active" is the caller by construction.

    **Two concurrent sessions are a real state, not an edge case**, and this
    does not paper over it: any other session that fired a hook within
    `concurrent_within` of the chosen one is returned in `also_active`, and
    `ResolvedSession.note` says so in the audit's own output. Picking one
    silently is what this whole function exists to stop doing.

    **`explicit` wins outright.** `$privacy <id>` is a deep link; a user who
    names a session gets that session, daemon or no daemon, and gets no
    caveat because nothing was inferred.

    Falls back to the ledger when the daemon cannot be asked, because the
    alternative is a skill that stops working exactly when the user has the
    least information — but the fallback is labelled (`basis`,
    `daemon_answered`), so the caller cannot present it as "your current
    session". Note what a missing daemon also means: no daemon listening is no
    session being recorded (README known limit 1), which is `Ledger.coverage`'s
    territory and why every caller of this should render
    `get_session_coverage` beside it.

    Never raises for a missing daemon. A genuinely broken ledger still
    raises — that is a real failure and worth surfacing.
    """
    if explicit:
        return ResolvedSession(explicit, "explicit")

    sessions = _ask_daemon(data_dir)
    if sessions:
        chosen = sessions[0]
        cutoff = chosen["age"] + concurrent_within
        others = tuple(s["session_id"] for s in sessions[1:]
                       if s["age"] <= cutoff)
        return ResolvedSession(chosen["session_id"], "active", others)

    latest = _most_recently_started(ledger)
    if latest is None:
        return ResolvedSession(None, "none",
                               daemon_answered=sessions is not None)
    return ResolvedSession(latest, "started_at",
                           daemon_answered=sessions is not None)


def get_session_summary(ledger, session_id: str) -> SessionSummary:
    """The four L2 tiles (design.md §5): percent, exposed_items,
    destinations, prevented. `Ledger.summary` already returns exactly
    this shape and nothing beyond it -- no raw value is reachable from
    session-level counts in the first place.

    Returned straight through, with no copy. The defensive `dict(...)` this
    used to make existed because a mutable dict handed to a caller is a dict
    that caller can quietly rewrite; `SessionSummary` is frozen, so there is
    nothing left to defend against."""
    return ledger.summary(session_id)


def get_session_coverage(ledger, session_id: str) -> SessionCoverage:
    """Whether the ledger's account of this session is known to be complete.

    Deliberately a SECOND call rather than a field on `get_session_summary`'s
    return value, for the reason `SessionCoverage` gives: the summary's four
    numbers say what happened, and this says whether those numbers are the whole
    story. Two questions, two answers — and keeping them separate is what let
    `SessionSummary.as_dict()`'s pinned key order stay pinned.

    Every caller that renders a summary should ask this too. A caller that shows
    `get_session_summary` without it is showing a number that cannot tell "0%
    because nothing was disclosed" from "0% because nothing was recorded",
    which is the conflation this function exists to end.

    Metadata only, so no I1 question arises: a boolean, a count, and a short
    phrase from a closed set of literals in `ledger.py`. No session content, no
    path, no value.
    """
    return ledger.coverage(session_id)


def list_exposures(ledger, session_id: str, tab: str) -> list[ExposureRow]:
    """Rows for one of design.md §5's three tabs: `"Exposed"`,
    `"Prevented"`, or `"All events"`. Each row is an `ExposureRow`, the
    curated projection whose field list is itself the I1 allow-list --
    metadata only, plus the ledger's pre-masked `masked_example`, never a
    raw value.

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

    rows: list[ExposureRow] = []
    for kind in kinds:
        rows.extend(r.to_exposure() for r in ledger.list_events(session_id, kind))
    return rows


def get_exposure_detail(ledger, session_id: str, event_id: int) -> ExposureRow:
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
    absent — and, on the wire, omitted from `as_dict()` entirely rather than
    serialized as `null`, so "no cap known" stays distinguishable from a cap
    of 0.

    The return type is the same `ExposureRow` `list_exposures` yields, with its
    L3 fields populated — see that class's docstring for why the detail payload
    is not a separate type. `render.detail()` and `render.audit()` therefore
    accept one type, not two.
    """
    row = ledger.conn.execute(
        "SELECT id, turn_id, ts, kind, data_type, source, destination,"
        " boundary, count, masked_example, budget_delta, protection,"
        " tool_name FROM events WHERE session_id=? AND id=?",
        (session_id, event_id)).fetchone()
    if row is None:
        raise LookupError(
            f"no event {event_id!r} in session {session_id!r}")

    cap_row = ledger.conn.execute(
        "SELECT budget_cap FROM sessions WHERE session_id=?",
        (session_id,)).fetchone()

    columns = dict(row)
    return ExposureRow(
        **columns,
        first_seen=columns["ts"],
        budget_cap=cap_row["budget_cap"] if cap_row is not None else None)


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
    ledger.add_policy(session_id, rule_type=rule_type, selector=selector)


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


# -- Level 1 toggle (spec §5.4) ---------------------------------------------

def hud_status(data_dir, session_id: str) -> dict:
    """What the status line would draw for `session_id` right now, and why.
    Reads contract A only; never opens the ledger.

    `state` is the answer, and it distinguishes the two failures `present:
    False` used to collapse together:

    * `"absent"` — no snapshot file (no session here, or it ended).
    * `"stale"` — a file, older than `STALE_AFTER` seconds. Both readers
      treat it as absent, but it means something entirely different: the
      daemon that writes it is gone or wedged, which is worth telling a
      user who just asked why their status item disappeared, because the
      same daemon is what records their disclosures.
    * `"hidden"` — fresh, and contract B says do not draw it.
    * `"shown"` — fresh, and drawn.

    `present` is True only for the last two — it is "would the item be on
    screen", which is what the `$privacy hud` caller is asking — and
    `hidden` stays `None` whenever there is no fresh snapshot to ask about.
    """
    from .hud_snapshot import read_snapshot
    snap = read_snapshot(data_dir, session_id)
    if snap is not None:
        return {"session_id": session_id, "present": True,
                "hidden": snap.hidden,
                "state": "hidden" if snap.hidden else "shown"}
    # No fresh snapshot. A file that is merely old is a different diagnosis
    # from no file at all; a malformed one is not a diagnosis at all, and
    # reads as absent exactly as the status line reads it.
    aged = read_snapshot(data_dir, session_id, ignore_staleness=True)
    return {"session_id": session_id, "present": False, "hidden": None,
            "state": "stale" if aged is not None else "absent"}


def hud_set_hidden(data_dir, session_id: str, hidden: bool) -> dict:
    """Contract B. `$privacy hud off` / `on`. Flips the snapshot's `hidden`
    flag and nothing else; `/statusline` in Codex is the other, independent
    switch (whether the item is configured at all). Does not touch
    config.toml."""
    from .hud_snapshot import HudPublisher
    HudPublisher(data_dir).set_hidden(session_id, bool(hidden))
    return hud_status(data_dir, session_id)
