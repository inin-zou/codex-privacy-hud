# src/privacy_hud/mcp_tools.py
"""Pure functions behind the `privacy.*` MCP tools (Task 13).

Every function here takes an already-open `Ledger` (the SAME ledger the
daemon is writing to — see `mcp/server.py` for how a real MCP process
opens it against `$PLUGIN_DATA/ledger.db`, `dispatch.new_state`'s same
path) and returns one of `ledger.py`'s read-contract dataclasses:
a `SessionSummary` variant or `LegacyExposureRow`. No I/O
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
schema. The shape is now `LegacyExposureRow`/`SessionSummary`, and the two callers
that put it on a wire — `local_ui_server` (browser JSON) and `mcp/server.py`
(the MCP transport) — call `.as_dict()` themselves. That call is the contract
boundary: `ledger._EXPOSURE_JSON_FIELDS` pins the keys and their order, so
adding a field to the row type cannot silently widen what a client receives,
and a dataclass can never reach `json.dumps` unserialized.

**`apply_policy` and enforcement — read before wiring UI actions to this.**
`apply_policy` writes a row to the `policy` table (schema from ledger.py /
architecture.md §5) exactly as `Engine.observe` needs to read it to make
"Mask detected <type> in future calls" real. `Engine.observe`
(src/privacy_hud/engine.py) queries the `policy` table on every egress
observation, before falling back to `Matrix.default_action()` (the static
mask/block table in tables.toml): a user-written `mask` rule forces a
rewrite of a later outbound call carrying a finding of that data type.
This does not apply retroactively (design.md P4): data already disclosed
before the rule was written stays disclosed, and no caller of this module
should claim otherwise.

That ordering — policy first, matrix defaults second — has one exception,
and it is what lets every caller say "tighten-only" and mean it: the mask
branch is skipped entirely when the observation carries a finding of a
`HARD_BLOCKED_DATA_TYPES` type, so no rule this function writes can stand in
front of the plugin's one unconditional deny. The guard is in the engine
rather than in the rules this function accepts because the branch's
selector test looked at *every* finding on the observation: a mask rule on
any innocuous type that co-occurred with a credential used to skip the block
for the whole call, and no refusal keyed on a selector can reach that.
`_MASK_WOULD_DOWNGRADE` still refuses `mask` on a hard-blocked selector —
now because such a rule is inert, and as defence in depth. Read that
constant and `Engine.observe`'s mask branch together; neither is the whole
argument on its own.

"Block this source" (`block_source`) is withdrawn (#38): `apply_policy`
refuses it and `Engine.observe` ignores any such row an older ledger still
holds. It matched a rule's selector against the *outbound* observation's
`source` at enforcement time, which is always the fixed label `"tool
input"` -- never the file or command a value came from -- so no selector
could target a source at all. `block_path`/`block_command` (#40) are the
replacement: they match a rule's selector against the `Origin` a finding's
value was first seen with (Task 2/3's `source_kind`/`source` on the
*ingress* row), independent of what the later outbound call's own `source`
says.

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

from .accounting import AccountingEventRow, Evidence
from .ledger import ExposureRow, Ledger, SessionCoverage, SessionSummary
from .matrix.loader import HARD_BLOCKED_DATA_TYPES
from .minimize import mint_token

# The curated event-row projection that used to live here as `_EVENT_FIELDS` +
# `_project()` is now `ledger.LegacyExposureRow`, and narrowing a ledger row to it is
# `LegacyEventRow.to_exposure()`. The reason for the move: a tuple of string keys and
# the rows it filtered were two things that had to agree, with nothing checking
# that they did — the same shape of bug as `detect/model.py`'s wrong `LABEL_MAP`
# keys, which silently disabled tier 3 entirely. A type cannot drift from
# itself: `to_exposure()` can only produce `LegacyExposureRow`'s fields, so
# `value_hash` (a salted BLOB, not JSON at all) and `session_id` are excluded
# structurally rather than by a maintained list. See `LegacyExposureRow`'s docstring
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

#: The same three tabs over a version-2 session (#54 Phase 3), whose "All
#: events" also includes `permitted`. The legacy map above is unchanged.
_V2_TAB_KINDS = {
    "Exposed": ("exposed",),
    "Prevented": ("prevented",),
    "All events": ("detected", "local_access", "permitted", "exposed",
                   "prevented", "retention"),
}

_POLICY_RULE_TYPES = {"mask", "block_path", "block_command"}

#: Why `block_source` is refused rather than written (#38). The rule compared
#: its selector with an observation's `source`, and `dispatch` only ever puts
#: fixed labels there ("tool input" on every outbound call, the tool name or
#: "user prompt" on the way in). No selector could mean "this source": one
#: taken from a tool-output row matched nothing, one taken from an outbound
#: row denied every outbound call. That is still true today and is why the
#: type stays refused permanently, not just until origins existed: the type
#: itself names a label, not a source, regardless of what the ledger now
#: records. `block_path`/`block_command` (#40) are the real replacement --
#: matched against `Origin` values the ledger records since Task 2/3 --
#: rather than a repair of `block_source`, because reviving the name would
#: revive the confusion it caused the first time.
_BLOCK_SOURCE_WITHDRAWN = (
    "block_source is not available: it names a label, not a source, so no "
    "rule written that way could ever match an origin (#38) — use "
    "block_path or block_command, which name a real origin (#40)")

#: Why `allow_dest` is refused rather than written. It named a destination
#: to stop treating as sensitive, and nothing ever enforced it: `Engine.observe`
#: reads `mask` (its own matrix defaults behind it) and the two origin rule
#: types, and compares `rule_type` against nothing else. So a row went in, the
#: caller was told `{"applied": True}`, and every later call was decided
#: exactly as if the rule did not exist. `2026-09-03-decisions.md` recorded it
#: as a placeholder -- "untouched because nothing mints it yet" -- and wiring
#: the MCP server is what would have started minting it. Refused for #38's
#: reason, in #38's words: a policy row the engine can never match is worse
#: than an error, because it looks like protection was applied when nothing
#: was. An allow rule failing to apply is the safe direction; saying it
#: applied is not.
_ALLOW_DEST_WITHDRAWN = (
    "allow_dest is not available: no code path has ever enforced it, so a "
    "rule written that way decides nothing while reporting success (#38's "
    "reason) — there is no replacement, because nothing minted it")

#: Why a `mask` rule on a hard-blocked data type is refused: the rule cannot
#: do anything, and an unremovable rule that decides nothing is #38's defect.
#:
#: **This refusal is no longer what keeps the hard block safe.** It was, or
#: was believed to be: `Engine.observe` applied a user `mask` rule ahead of
#: its matrix defaults and the default deny only ran while the action was
#: still "allow", so a mask rule on a hard-blocked type replaced the deny
#: with an executed, masked call. The argument for closing that here was
#: that `mask` + a hard-blocked selector was the only combination that could
#: loosen anything, so refusing it at the mint site was provably complete.
#: **That argument was wrong.** The engine intersected its mask selectors
#: with *every* finding on the observation, not with the finding that
#: triggered the block, so a mask rule on any type that merely co-occurred
#: with a hard-blocked one — a path on the same command line, the selector
#: one click of the audit UI's mask action writes — skipped
#: the block for the whole call. Those selectors are innocuous and this
#: function accepts them, so no refusal keyed on a selector could ever have
#: covered that case.
#:
#: The precedence now lives where the decision is made: the mask branch in
#: `Engine.observe` does not run at all when the observation carries a
#: hard-blocked finding, whatever the rule's selector says. Read that branch's
#: comment for what it costs (the observation falls through to
#: `Matrix.default_action`, which is never weaker than the mask the rule
#: asked for).
#:
#: What this refusal still does, and why it stays: with the engine holding
#: the line, a `mask` rule on a hard-blocked type is *inert*. Writing it
#: would tell the caller protection was applied, record a rule no path
#: removes (known limit 13), and change no decision — which is exactly the
#: reason `block_source` and `allow_dest` are refused above. It is defence
#: in depth for the same reason: if the branch's guard is ever lost, this
#: keeps the rule that would exploit it from being written in the first
#: place. Refused here rather than in one caller because both callers need
#: it — the model-callable `privacy.update_policy` tool and the local audit
#: UI's button, which called this function and, on a credential exposure,
#: was *downgrading* the user's protection when clicked.
_MASK_WOULD_DOWNGRADE = (
    "mask is not available for {selector!r}: a value of that type on an "
    "outbound call is already denied, and that deny takes precedence over "
    "every mask rule, so this rule would decide nothing while reporting "
    "that protection was applied — and no path removes a rule once written "
    "(known limit 13). Nothing to do: the block is already the stronger "
    "outcome.")

#: The data types the always-on cheap tiers can produce, and therefore the
#: only ones a rule can match without an accepted deep-scan result: `path` from
#: `detect/paths.py` and `credential` from `detect/secrets.py`. Everything
#: else in `detect/model.py`'s LABEL_MAP — person, address, email, phone,
#: url, date, account — exists only in an accepted deep-scan result.
#:
#: This distinction is why `rule_enforcement_note` does not give every rule
#: the same caveat. Telling a user that a `path` rule might not fire because
#: of a scan gap would be its own false statement, in the opposite
#: direction: the path detector runs on every observation, at every
#: boundary, at any size.
CHEAP_DATA_TYPES = frozenset({"path", "credential"})

#: What a saved rule can and cannot promise, appended to every confirmation.
#:
#: Saving a rule is not enforcing it, and the gap between the two is not a
#: detail: a user who reads "enforced" and goes on to send the data has made
#: a decision this plugin then cannot honour and cannot reverse (I5). Each
#: clause below is a way a written rule leaves a value unchanged, and none
#: of them is visible to the person clicking the button.
#:
#: Three strings rather than one, because the caveat is not uniform and a
#: uniform one would be its own false statement. The first draft of this
#: had exactly that bug: it keyed only on `selector`, so a `block_path` rule
#: on `/home/u/.env` — whose selector is a file path, not a data type —
#: fell through to the deep-scan text and was told its matching "needs the
#: deep scan", while an origin that happened to be named `path` got the
#: cheap text. An origin rule matches on where a value came from, which is
#: a different question from which tier found it.
_RULE_CONDITIONS_DEEP = (
    " Matching {selector} requires an accepted deep-scan result. A scan gap "
    "means an applicable deep scan supplied no accepted result (known limit "
    "21); on that call this rule has no matching deep-scan finding. "
    "Detection can also miss values, and hosted tools never reach this "
    "plugin at all.")

_RULE_CONDITIONS_CHEAP = (
    " Detection is heuristic and can miss values, and hosted tools never "
    "reach this plugin at all — on a call where nothing is detected the "
    "rule matches nothing.")

_RULE_CONDITIONS_ORIGIN = (
    " The value must be detected on ingress and again on egress. When "
    "either detection depends on the deep scan, a scan gap can prevent this "
    "rule from matching (known limit 21). Detection is heuristic and can "
    "miss values, and hosted tools never reach this plugin at all.")


#: The common final sentence of every rule note. A denial or rewritten input
#: is what Privacy HUD returns to the host; no current hook reports whether
#: the host applied it (#54's evidence baseline).
_RULE_HOST_CAVEAT = (
    "Host application of a denial or rewritten input is not confirmed by "
    "these hooks.")


def rule_enforcement_note(rule_type: str, selector: str) -> str:
    """The conditions clause for one saved rule.

    `rule_type` decides the shape of the question and `selector` only
    refines it: an origin rule's selector is a path or a command, and
    asking whether *that* is a cheap data type is a category error.
    """
    if rule_type in ("block_path", "block_command"):
        conditions = _RULE_CONDITIONS_ORIGIN
    elif selector in CHEAP_DATA_TYPES:
        conditions = _RULE_CONDITIONS_CHEAP
    else:
        conditions = _RULE_CONDITIONS_DEEP.format(selector=selector)
    return conditions + " " + _RULE_HOST_CAVEAT


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


@dataclass(frozen=True)
class AuditReading:
    """Audit projections read from one SQLite snapshot."""

    summary: SessionSummary
    rows: list[ExposureRow]
    coverage: SessionCoverage
    all_events_count: int


def read_audit(
    ledger: Ledger, session_id: str, tab: str,
) -> AuditReading:
    """Read one session's audit and tab count in one read transaction."""
    with ledger._read_transaction():
        summary = get_session_summary(ledger, session_id)
        rows = list_exposures(ledger, session_id, tab)
        coverage = get_session_coverage(ledger, session_id)
        all_events_count = (
            len(rows) if tab == "All events"
            else len(list_exposures(ledger, session_id, "All events"))
        )
        return AuditReading(
            summary=summary,
            rows=rows,
            coverage=coverage,
            all_events_count=all_events_count,
        )


def get_session_summary(
    ledger: Ledger, session_id: str,
) -> SessionSummary:
    """The session's accounting summary, passed through as the discriminated
    type `Ledger.summary` returns: `LegacySessionSummary` for a recorded
    session, `UnrecordedSessionSummary` (no percentage, no counts) for one
    the ledger has no row for. Frozen, so there is nothing to copy."""
    return ledger.summary(session_id)


def get_session_coverage(ledger, session_id: str) -> SessionCoverage:
    """Whether the ledger's account of this session is known to be complete.

    Deliberately a SECOND call rather than a field on `get_session_summary`'s
    return value, for the reason `SessionCoverage` gives: the summary's four
    numbers say what happened, and this says whether those numbers are the whole
    story. Two questions, two answers — and keeping them separate is what
    keeps each summary variant's key order pinned.

    Every caller that renders a summary should ask this too. A legacy summary
    shown without it cannot say whether its numbers are a full account of the
    session's record.

    Metadata only, so no I1 question arises: a boolean, a count, and a short
    phrase from a closed set of literals in `ledger.py`. No session content, no
    path, no value.
    """
    return ledger.coverage(session_id)


def list_exposures(
    ledger: Ledger, session_id: str, tab: str,
) -> list[ExposureRow]:
    """Rows for one of design.md §5's three tabs: `"Exposed"`,
    `"Prevented"`, or `"All events"`. For a legacy session the tab arguments
    select stored legacy classifications; the surfaces label them "Legacy
    permitted crossings", "Legacy prevented rows" and "All legacy events".
    For a version-2 session (#54 Phase 3) they select version-2 event kinds,
    and "All events" includes `permitted`. Each row is a public projection
    whose field list is itself the I1 allow-list. An unrecorded session has
    no rows, which is not evidence that no events occurred.

    The version and every kind of the tab are read in one read transaction.

    Does not aggregate by `(data_type, source, destination)`: every surface
    renders one row per ledger event, and doing the same aggregation twice,
    in two different ways, is a bug waiting to happen.
    """
    if tab not in _TAB_KINDS:
        raise ValueError(f"unknown tab {tab!r}; expected one of {sorted(_TAB_KINDS)}")

    rows: list[ExposureRow] = []
    with ledger._read_transaction():
        version2 = ledger._accounting_version(session_id) == 2
        if version2 and tab == "Prevented":
            # #54 Phase 4: interventions are prevention evidence OR an
            # issued rewrite, each row once, in event-ID order -- the same
            # selection `AccountingSummary.intervention_events` counts.
            found: list[AccountingEventRow] = []
            for kind in _V2_TAB_KINDS["All events"]:
                found.extend(
                    r for r in ledger.list_events(session_id, kind)
                    if isinstance(r, AccountingEventRow)
                    and (r.kind == "prevented"
                         or bool(r.evidence & Evidence.REWRITE_ISSUED)))
            found.sort(key=lambda r: r.id)
            return [r.to_exposure() for r in found]
        kinds = (_V2_TAB_KINDS if version2 else _TAB_KINDS)[tab]
        for kind in kinds:
            rows.extend(r.to_exposure()
                        for r in ledger.list_events(session_id, kind))
    return rows


def get_exposure_detail(
    ledger: Ledger, session_id: str, event_id: int,
) -> ExposureRow:
    """The L3 payload for one legacy row (design.md §6), keyed by its
    integer row `id` -- see this module's docstring for why that selector
    was chosen over a composite key. Delegates to `Ledger.get_event`, which
    scopes the lookup to both identifiers, routes to whichever table holds
    legacy rows, and adds `first_seen` and the session's stored
    `budget_cap`.

    Raises `LookupError` (not `None`/`{}`) when nothing matches, including
    an id from another session and any id in an unrecorded session.
    """
    return ledger.get_event(session_id, event_id)


def apply_policy(ledger, session_id: str, *, rule_type: str, selector: str) -> None:
    """Save a policy rule scoped to this session. The mask action is
    "Mask detected <type> in future calls" (design.md §6).

    `rule_type` must be one of the schema's own documented values
    (ledger.py SCHEMA's `policy.rule_type` comment) -- an unrecognized
    rule_type raises `ValueError` rather than being written silently, since
    a policy row the engine can never match is worse than an error: it looks
    like protection was applied when nothing was. `block_source` is refused
    for exactly that reason (`_BLOCK_SOURCE_WITHDRAWN`, #38).

    A `mask` rule whose selector is a hard-blocked data type is refused too,
    for the same reason rather than the opposite one: since C1, the engine
    keeps its hard block ahead of every mask rule, so such a rule matches
    nothing it could change. What makes "this call can only tighten
    enforcement" true of every caller — the MCP tool the model can call and
    the local audit UI's button alike — is that precedence in
    `Engine.observe`, not this refusal; the refusal additionally stops a rule
    that would be silently inert, and stands as defence in depth if the
    precedence is ever lost. See `_MASK_WOULD_DOWNGRADE`.

    See this module's top-level docstring: `Engine.observe` consults `mask`
    rules (ahead of its own matrix defaults) on every later egress
    observation that has a finding of that data type. It does not apply
    retroactively: data already disclosed before the rule was written stays
    disclosed (design.md P4).
    """
    validate_policy_rule(rule_type=rule_type, selector=selector)
    ledger.add_policy(session_id, rule_type=rule_type, selector=selector)


def validate_policy_rule(*, rule_type: str, selector: str) -> None:
    """Refuse a rule no engine could ever match, without a ledger.

    Split out of `apply_policy` for #66 Pair 6: a policy mutation now
    travels to the daemon, and a rule that is wrong on its face must be
    refused *before* the request is transmitted. Otherwise the caller
    learns about it from a reply — and a reply that never arrives is an
    unknown outcome, which is a much worse thing to say about a request
    that was never valid.

    `apply_policy` still calls it, so the daemon validates again on its
    own side: the client's check is about honest reporting, not about
    being the only gate.
    """
    if rule_type == "block_source":
        raise ValueError(_BLOCK_SOURCE_WITHDRAWN)
    if rule_type == "allow_dest":
        raise ValueError(_ALLOW_DEST_WITHDRAWN)
    if rule_type == "mask" and selector in HARD_BLOCKED_DATA_TYPES:
        raise ValueError(_MASK_WOULD_DOWNGRADE.format(selector=selector))
    if rule_type not in _POLICY_RULE_TYPES:
        raise ValueError(
            f"unknown rule_type {rule_type!r}; expected one of "
            f"{sorted(_POLICY_RULE_TYPES)}")


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


# -- Read guard toggle (#36, Task 2) -----------------------------------------

def read_guard_status(data_dir) -> dict:
    """Whether reads of known-sensitive paths are blocked (`#36`).

    `settings.json` is not a file the user can see from Codex, so this and
    `privacy-hud-doctor` are how they find out what it says.
    """
    from .settings import Settings
    return {"deny_read": Settings(data_dir).deny_read}


def read_guard_set(data_dir, enabled: bool) -> dict:
    """`$privacy read off` / `on`. Writes the toggle in `settings.json`
    (see `settings.py`) and returns the state that resulted, the same
    shape `read_guard_status` returns -- so a caller never has to make a
    second call just to confirm what it set.

    A `PLUGIN_DATA` the plugin cannot write is that same answer with an
    `error` beside it, not an exception: this runs inside the skill's
    heredoc, where an escaping `PermissionError` is a traceback on the
    user's screen and no statement of what the setting now says. The
    caller must be able to tell them the write did not stick, and that
    the guard goes on reading the file as it was -- so `deny_read` here
    is re-read from disk rather than echoed back from `enabled`.

    Not a hook path: a read is never denied by this failing (I6).
    """
    from .settings import Settings
    settings = Settings(data_dir)
    try:
        settings.set_deny_read(enabled)
    except OSError as err:
        out = read_guard_status(data_dir)
        out["error"] = (f"could not write {settings.path}: "
                        f"{err.strerror or err}. The setting is unchanged.")
        return out
    return read_guard_status(data_dir)
