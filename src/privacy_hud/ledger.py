"""Versioned session accounting and legacy ledger access.

Production sessions use legacy accounting. Phase 3 also implements an
inactive version-2 core for isolated synthetic tests and the private-copy
rehearsal.

Legacy records retain their stored scores, counts and classifications.
Version-2 observations, events and disclosures are separate immutable
records. Only a new chargeable disclosure increases a version-2 score.

Version-2 identity inputs are hashed before persistence. Labels and
exemplars use explicit allowlists; the absence of a raw-content column
alone does not establish that arbitrary metadata is safe.

Readers select the session's accounting version inside a read transaction
and never initialize, migrate or activate a ledger. SessionEnd erases
matching hashes while retaining opaque identities and accounting joins;
this is logical erasure, not a secure-deletion guarantee.
"""
from __future__ import annotations

import os
import re
import sqlite3
import time
import unicodedata
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Literal, get_args

from . import ledger_schema
from .accounting import (
    PATH_RULE_IDS, SOURCE_LABELS, AccountingEventRow, AccountingExposureRow,
    AccountingSummary, ActionKind, Boundary, DataType, Decision, EventKind,
    EventRecord, Evidence, HookEvent, ObservationRecord, OutcomeEvent,
    OutcomeObservation, RecipientInput, RecordResult, ResolutionScope, ScanGap,
    ScoringProfile, SubjectInput, UnavailableReason, resolve_outcomes,
)
from .budget import contribution, next_disclosure_delta, percent
from .matrix.loader import Matrix
from .runtime_contract import RuntimeRefusal
from .runtime_owner import WriterLease

#: The legacy schema; see `ledger_schema` for all three generations.
SCHEMA = ledger_schema.LEGACY_SCHEMA


def open_connection(path: Path, *, initialize: bool,
                    check_same_thread: bool = True,
                    read_only: bool = False) -> sqlite3.Connection:
    """One ledger connection, configured the same way everywhere.

    Autocommit (`isolation_level=None`) with explicit transactions, row
    access by name, foreign keys enforced, a one-second busy wait and full
    synchronous writes. Only the initializing daemon connection sets WAL,
    which persists in the file. `initialize=False` opens an existing file
    and fails on a missing one rather than creating it.

    `read_only=True` opens `mode=ro`: SQLite itself then refuses every
    INSERT, UPDATE, DELETE and ALTER on this connection, which is the whole
    point: reader intent alone does not prevent accidental DDL or data
    mutations (#66). It is deliberately **not** `immutable=1`: that would also
    produce an unwritable connection and would additionally ignore the
    write-ahead log, so every row committed since the last checkpoint would
    be invisible on a live database. `mode=ro` reads the WAL.

    `initialize=True, read_only=True` is a contradiction and raises
    `ValueError` rather than quietly preferring one of the two.
    """
    if initialize and read_only:
        raise ValueError(
            "an initializing connection cannot be read-only")
    if initialize:
        conn = sqlite3.connect(path, isolation_level=None,
                               check_same_thread=check_same_thread)
    else:
        mode = "ro" if read_only else "rw"
        conn = sqlite3.connect(
            f"{Path(path).resolve().as_uri()}?mode={mode}", uri=True,
            isolation_level=None, check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=1000")
    conn.execute("PRAGMA synchronous=FULL")
    if initialize:
        conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _refuse_unsupported(path: Path, check_same_thread: bool) -> None:
    """Validate an existing ledger's schema on a read-only connection.

    Raises whatever `ledger_schema.validate_schema` raises, plus
    `UnsupportedAccounting` for activated accounting. Nothing about the
    file changes either way — that is the point of doing it here rather
    than after the writable open.
    """
    probe = open_connection(path, initialize=False, read_only=True,
                            check_same_thread=check_same_thread)
    try:
        version = ledger_schema.validate_schema(probe)
    finally:
        probe.close()
    if version == ledger_schema.ACTIVATED_VERSION:
        raise UnsupportedAccounting(
            "this ledger uses activated accounting; this version of "
            "Privacy HUD cannot write it")


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
SessionSummary = (
    LegacySessionSummary | UnrecordedSessionSummary | AccountingSummary
)


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


#: A raw ledger row of either accounting, and its public projection.
EventRow = LegacyEventRow | AccountingEventRow
ExposureRow = LegacyExposureRow | AccountingExposureRow


# -- version-2 record validation (#54 Phase 3) ------------------------------
#
# The writer validates the complete batch before its first write, so an
# invalid record never reaches SQL. The schema's own CHECKs and triggers
# stay as a second line; the closed messages below carry no input.

_INVALID_PROFILE = "invalid scoring profile"
_INVALID_OBSERVATION = "invalid accounting observation"
_INVALID_EVENT = "invalid accounting event"
_INVALID_V2_SESSION = "invalid version-2 session"
_INVALID_STORED_PROFILE = "invalid stored scoring profile"

_OPAQUE_ID = re.compile(r"[0-9a-f]{32}")
_MAX_INTEGER = 2 ** 63

#: The phase each hook event's observation must carry.
_HOOK_PHASE = {
    "PreToolUse": "pre",
    "UserPromptSubmit": "pre",
    "PostToolUse": "post",
    "SessionStart": "lifecycle",
    "SessionEnd": "lifecycle",
    "SubagentStart": "lifecycle",
    "SubagentStop": "lifecycle",
    "PreCompact": "lifecycle",
}
assert set(_HOOK_PHASE) == set(get_args(HookEvent))

#: Evidence the schema requires for each event kind: any one of the bits.
_KIND_EVIDENCE = {
    "detected": Evidence.LOCAL_DETECTION,
    "local_access": Evidence.EXECUTION_OBSERVED,
    "permitted": Evidence.PERMISSION_ISSUED,
    "exposed": Evidence.CROSSING_CONFIRMED,
    "prevented": (Evidence.DENY_ISSUED | Evidence.DENY_ENFORCED
                  | Evidence.REWRITE_ENFORCED
                  | Evidence.REJECTED_BEFORE_CROSSING),
    "retention": Evidence.PERSISTENCE_OBSERVED,
}
assert set(_KIND_EVIDENCE) == set(get_args(EventKind))

#: Evidence that lets an observation resolve an action's outcome.
_RESOLVING_EVIDENCE = (Evidence.DENY_ENFORCED | Evidence.REWRITE_ENFORCED
                       | Evidence.CROSSING_CONFIRMED
                       | Evidence.REJECTED_BEFORE_CROSSING)

_DOT = "•"


def _is_opaque_id(value: object) -> bool:
    return isinstance(value, str) and _OPAQUE_ID.fullmatch(value) is not None


def _is_count(value: object, low: int) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)
            and low <= value < _MAX_INTEGER)


def _valid_evidence(value: object) -> bool:
    return isinstance(value, Evidence) and 0 <= int(value) <= 2047


def _check_observation(o: ObservationRecord) -> None:
    ok = (
        _is_opaque_id(o.delivery_key)
        and _is_opaque_id(o.action_id)
        and (o.turn_id is None or _is_opaque_id(o.turn_id))
        and _is_count(o.ts, 0)
        and o.hook_event in _HOOK_PHASE
        and o.phase == _HOOK_PHASE[o.hook_event]
        and o.action_kind in get_args(ActionKind)
        and o.boundary in get_args(Boundary)
        and o.decision in get_args(Decision)
        and _valid_evidence(o.evidence)
        and o.resolution_scope in get_args(ResolutionScope)
        and type(o.potential_crossing) is bool
        and (o.scan_gap is None or (o.scan_gap in get_args(ScanGap)
                                    and o.phase != "lifecycle"))
    )
    if not ok:
        raise ValueError(_INVALID_OBSERVATION)
    evidence = o.evidence
    if ((Evidence.DENY_ISSUED in evidence and o.decision != "deny")
            or (Evidence.REWRITE_ISSUED in evidence
                and o.decision != "rewrite")
            or (Evidence.PERMISSION_ISSUED in evidence
                and o.decision not in ("allow", "rewrite"))
            or (o.resolution_scope != "none"
                and not evidence & _RESOLVING_EVIDENCE)):
        raise ValueError(_INVALID_OBSERVATION)


def _is_safe_exemplar(data_type: str, masked: object) -> bool:
    """Null, or exactly one of the version-2 masking formats. Credentials
    and paths have none."""
    if masked is None:
        return True
    if data_type in ("credential", "path") or not isinstance(masked, str):
        return False
    if masked == _DOT * 4:
        return True
    return (len(masked) == 6 and masked[2:5] == _DOT * 3
            and not any(unicodedata.category(c) == "Cc"
                        for c in masked[:2] + masked[5]))


def _check_event(e: EventRecord, o: ObservationRecord,
                 profile: ScoringProfile) -> None:
    ok = (
        isinstance(e, EventRecord)
        and isinstance(e.subject, SubjectInput)
        and isinstance(e.recipient, RecipientInput)
        and e.kind in _KIND_EVIDENCE
        and _valid_evidence(e.evidence)
        and e.data_type in get_args(DataType)
        and e.boundary in get_args(Boundary)
        and (e.rule_id is None or e.rule_id in PATH_RULE_IDS)
        and _is_count(e.occurrences, 1)
        and isinstance(e.source_label, str)
        and e.source_label in SOURCE_LABELS
    )
    if not ok or not _is_safe_exemplar(e.data_type, e.masked_example):
        raise ValueError(_INVALID_EVENT)
    if ((e.evidence & o.evidence) != e.evidence
            or e.boundary != o.boundary
            or e.boundary != profile.destination_boundary[
                e.recipient.destination_kind]
            or not e.evidence & _KIND_EVIDENCE[e.kind]
            or (e.kind == "exposed" and e.boundary == "B0")
            or (e.kind == "local_access" and e.boundary != "B0")):
        raise ValueError(_INVALID_EVENT)


def _descriptor_key(descriptor: SubjectInput | RecipientInput) -> tuple:
    kind = (descriptor.subject_kind if isinstance(descriptor, SubjectInput)
            else descriptor.destination_kind)
    if descriptor.identity_hash is not None:
        return (kind, "resolved", descriptor.identity_hash)
    return (kind, "unresolved", descriptor.unresolved_token)


def _chargeable(e: EventRecord, profile: ScoringProfile) -> bool:
    """Event-side charge eligibility; the session side (version 2,
    available, not ended) is checked by the caller."""
    return (e.kind == "exposed"
            and Evidence.CROSSING_CONFIRMED in e.evidence
            and e.boundary != "B0"
            and e.boundary == profile.destination_boundary[
                e.recipient.destination_kind]
            and e.subject.identity_hash is not None
            and e.recipient.identity_hash is not None)


def _subject_label(subject_id: str, subject: SubjectInput) -> str:
    if subject.subject_kind == "file":
        if subject.safe_suffix is not None:
            return f"file {subject_id} ({subject.safe_suffix})"
        return f"file {subject_id}"
    if subject.identity_hash is None:
        return f"unresolved value {subject_id}"
    return f"value {subject_id}"


def _recipient_label(recipient_id: str, recipient: RecipientInput) -> str:
    if recipient.identity_hash is None:
        return f"unresolved recipient {recipient_id}"
    return {
        "local": "local",
        "model_context": "model context",
        "mcp_tool": f"MCP recipient {recipient_id}",
        "external_net": f"network recipient {recipient_id}",
        "subagent": f"subagent {recipient_id}",
    }[recipient.destination_kind]


def _stored_evidence(value: object) -> Evidence:
    if not isinstance(value, int) or isinstance(value, bool) \
            or not 0 <= value <= 2047:
        raise UnsupportedAccounting(_INVALID_V2_SESSION)
    return Evidence(value)


def _observation_record(row: sqlite3.Row) -> ObservationRecord:
    return ObservationRecord(
        session_id=row["session_id"], delivery_key=row["delivery_key"],
        action_id=row["action_id"], turn_id=row["turn_id"], ts=row["ts"],
        hook_event=row["hook_event"], phase=row["phase"],
        action_kind=row["action_kind"], boundary=row["boundary"],
        decision=row["decision"], evidence=_stored_evidence(row["evidence"]),
        resolution_scope=row["resolution_scope"],
        potential_crossing=bool(row["potential_crossing"]),
        scan_gap=row["scan_gap"])


class Ledger:
    def __init__(self, path: Path, matrix: Matrix, *,
                 observer: str | None = None,
                 check_same_thread: bool = True,
                 initialize: bool = True,
                 writer_lease: "WriterLease | None" = None):
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
        the skill). It opens an existing database, without `SCHEMA`, a
        journal-mode change or a chmod, and fails on a missing file rather
        than creating one. Only the daemon initializes, so a reader never
        changes the structure of the ledger it is reading, including across
        #54's rebuild.

        **`writer_lease` is what makes this instance a writer** (#66).
        Without one, `initialize=False` opens `mode=ro` and every mutator
        below refuses; SQLite refuses too, so a caller that reaches around
        these methods with its own SQL gets the same answer. Initializing
        requires a lease, since applying `SCHEMA` and switching the file to
        WAL are writes. A noninitializing writer must pass its lease
        explicitly: nothing acquires one on a caller's behalf, and no
        argument, environment variable or configuration turns ownership
        off.

        An unsupported schema is refused *before* any of that. The check
        runs on its own `mode=ro` connection, so a ledger this build cannot
        write is neither opened read-write nor switched to WAL — a
        journal-mode change is a write to a file we have just decided we do
        not understand.
        """
        self.matrix = matrix
        self.observer = observer or uuid.uuid4().hex[:16]
        #: The lease authorizing this instance to write, or `None` for a
        #: reader.
        self._lease = writer_lease
        #: Depth of the write transaction this instance owns; 0 when none.
        self._write_depth = 0
        #: Test-only hook called after each migration statement executes.
        #: Not settable from any configuration, environment or tool input.
        self._migration_failpoint: Callable[[str], None] | None = None
        if writer_lease is None:
            if initialize:
                raise RuntimeRefusal("runtime_mismatch")
        else:
            writer_lease.assert_current()
        if writer_lease is not None and Path(path).exists():
            # Read-only, and before any writable connection exists. A
            # failure here propagates: the daemon must not come up against a
            # schema it cannot describe. I6 covers what the hooks do when no
            # daemon answers (open on ingress, closed on egress).
            _refuse_unsupported(path, check_same_thread)
        self.conn = open_connection(path, initialize=initialize,
                                    check_same_thread=check_same_thread,
                                    read_only=writer_lease is None
                                    and not initialize)
        if not initialize:
            return
        with self._write_transaction():
            # Validated again inside the transaction that may change it:
            # between the read-only check above and `BEGIN IMMEDIATE`,
            # another writer could have prepared this ledger.
            version = ledger_schema.validate_schema(self.conn)
            if version == ledger_schema.ACTIVATED_VERSION:
                raise UnsupportedAccounting(
                    "this ledger uses activated accounting; this version of "
                    "Privacy HUD cannot write it")
            if version == 0:
                # A new file gets the legacy schema; an existing legacy
                # ledger gains only a table it lacks. No column is added to
                # an existing table: a historical `events` without
                # `source_kind` keeps its layout, and the legacy writer
                # omits the column.
                for statement in ledger_schema.legacy_statements():
                    self.conn.execute(statement)
                ledger_schema.validate_schema(self.conn)
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

        **Every write in this class goes through here**, which is what makes
        the lease check one check rather than one per mutator. A reader has
        no lease, so it refuses before touching the connection at all.

        The lease is checked three times, and each one covers a different
        window (#66):

        * before `BEGIN IMMEDIATE`, so a runtime that is no longer selected
          never takes the database's write lock;
        * once the transaction is held, because acquiring it can block on
          another writer for up to `busy_timeout`, and the selection can
          move during that wait;
        * before the outer `COMMIT`, so a repair that activates a
          replacement while this transaction was open loses the write
          instead of committing it.

        Joins a write transaction this instance already owns. Refuses to
        run inside a read transaction rather than silently promoting it.
        Ends only the transaction it began: commit on success, rollback on
        any exception, including a refused lease.
        """
        if self._lease is None:
            raise RuntimeRefusal("runtime_mismatch")
        if self._write_depth:
            self._lease.assert_current()
            self._write_depth += 1
            try:
                yield
            finally:
                self._write_depth -= 1
            return
        if self.conn.in_transaction:
            raise RuntimeError("a read transaction is already open")
        self._lease.assert_current()
        self.conn.execute("BEGIN IMMEDIATE")
        self._write_depth = 1
        try:
            self._lease.assert_current()
            yield
            self._lease.assert_current()
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

    # -- version-2 accounting (#54 Phase 3; no production caller) ----------

    def _require_prepared(self) -> None:
        """Version-2 accounting is written only at generation 5401 in
        Phase 3; a legacy or activated ledger is refused."""
        if ledger_schema.validate_schema(self.conn) != \
                ledger_schema.PREPARED_VERSION:
            raise UnsupportedAccounting(
                "version-2 accounting requires a prepared ledger")

    def ensure_profile(self, profile: ScoringProfile) -> str:
        """Store `profile` under its content ID unless it is already stored,
        and return the ID. An existing row is reused, never replaced; one
        whose stored content does not match the ID is corruption."""
        if not isinstance(profile, ScoringProfile):
            raise ValueError(_INVALID_PROFILE)
        with self._write_transaction():
            self._require_prepared()
            profile_id = profile.profile_id
            row = self.conn.execute(
                "SELECT * FROM scoring_profiles WHERE profile_id=?",
                (profile_id,)).fetchone()
            if row is not None:
                if self._stored_profile(row) != profile:
                    raise UnsupportedAccounting(_INVALID_STORED_PROFILE)
                return profile_id
            self.conn.execute(
                "INSERT INTO scoring_profiles(profile_id,format_version,"
                "matrix_version,created_at,budget_cap,parameters_json)"
                " VALUES(?,?,?,?,?,?)",
                (profile_id, profile.format_version, profile.matrix_version,
                 int(time.time()), profile.budget_cap,
                 profile.as_canonical_json()))
            return profile_id

    @staticmethod
    def _stored_profile(row: sqlite3.Row) -> ScoringProfile:
        """The profile a `scoring_profiles` row holds, after checking its
        document, digest and duplicated columns. Never the live matrix."""
        try:
            profile = ScoringProfile.from_canonical_json(
                row["parameters_json"])
        except (ValueError, TypeError):
            raise UnsupportedAccounting(_INVALID_STORED_PROFILE) from None
        if (profile.profile_id != row["profile_id"]
                or profile.format_version != row["format_version"]
                or profile.matrix_version != row["matrix_version"]
                or profile.budget_cap != row["budget_cap"]):
            raise UnsupportedAccounting(_INVALID_STORED_PROFILE)
        return profile

    def _v2_session(self, session_id: str) -> tuple[sqlite3.Row,
                                                     ScoringProfile]:
        """The version-2 session row and its validated frozen profile."""
        self._require_prepared()
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()
        if row is None or row["accounting_version"] != 2 \
                or row["profile_id"] is None:
            raise UnsupportedAccounting(_INVALID_V2_SESSION)
        stored = self.conn.execute(
            "SELECT * FROM scoring_profiles WHERE profile_id=?",
            (row["profile_id"],)).fetchone()
        if stored is None:
            raise UnsupportedAccounting(_INVALID_STORED_PROFILE)
        profile = self._stored_profile(stored)
        if profile.budget_cap != row["budget_cap"]:
            raise UnsupportedAccounting(_INVALID_STORED_PROFILE)
        return row, profile

    def profile_for_session(self, session_id: str) -> ScoringProfile:
        """The frozen profile of a version-2 session, validated on read."""
        with self._read_transaction():
            return self._v2_session(session_id)[1]

    def _start_v2_session(
        self,
        session_id: str,
        *,
        cwd: str,
        model: str,
        profile: ScoringProfile,
    ) -> None:
        """Create a synthetic version-2 session: tests and the private-copy
        rehearsal only (#54 Phase 3). Requires a write transaction the
        caller owns, a prepared ledger and an absent nonempty session ID.
        `cwd` and `model` are accepted and deliberately not stored."""
        del cwd, model
        if not self._write_depth:
            raise RuntimeError("a version-2 session needs a write transaction")
        self._require_prepared()
        if not isinstance(session_id, str) or not session_id \
                or self.session_exists(session_id):
            raise ValueError(_INVALID_V2_SESSION)
        profile_id = self.ensure_profile(profile)
        now = int(time.time())
        self.conn.execute(
            "INSERT INTO sessions(session_id,started_at,cwd,model,"
            "budget_score,budget_cap,accounting_version,accounting_status,"
            "profile_id) VALUES(?,?,NULL,NULL,0,?,2,'available',?)",
            (session_id, now, profile.budget_cap, profile_id))
        self.conn.execute(
            "INSERT INTO coverage(session_id,ts,observer,reason)"
            " VALUES(?,?,?,?)",
            (session_id, now, self.observer, COVERAGE_SESSION_START))

    @contextmanager
    def _atomic_accounting_write(self) -> Iterator[None]:
        """One version-2 operation: a savepoint inside the write transaction
        this instance owns or joins. A failure rolls back to the savepoint
        and propagates, so a caller that catches it inside an outer
        transaction commits none of the operation's partial writes.
        `_write_transaction` alone decides COMMIT or ROLLBACK."""
        with self._write_transaction():
            name = f"accounting_{uuid.uuid4().hex}"
            self.conn.execute(f"SAVEPOINT {name}")
            try:
                yield
            except BaseException:
                self.conn.execute(f"ROLLBACK TO {name}")
                self.conn.execute(f"RELEASE {name}")
                raise
            self.conn.execute(f"RELEASE {name}")

    def record_observation(
        self,
        observation: ObservationRecord,
        events: Sequence[EventRecord],
    ) -> RecordResult:
        """Record one delivered observation and everything it implies —
        identities, events, first disclosures, the cached score and its
        scan gap — atomically. A delivery key already recorded in the
        session returns its original result and writes nothing."""
        with self._atomic_accounting_write():
            return self._record_observation(observation, events)

    def _record_observation(self, observation: ObservationRecord,
                            events: Sequence[EventRecord]) -> RecordResult:
        if not isinstance(observation, ObservationRecord) \
                or not isinstance(observation.session_id, str) \
                or not observation.session_id:
            raise ValueError(_INVALID_OBSERVATION)
        session_id = observation.session_id
        session, profile = self._v2_session(session_id)
        if not _is_opaque_id(observation.delivery_key):
            raise ValueError(_INVALID_OBSERVATION)
        existing = self.conn.execute(
            "SELECT observation_id FROM observations"
            " WHERE session_id=? AND delivery_key=?",
            (session_id, observation.delivery_key)).fetchone()
        if existing is not None:
            return self._recorded_result(session_id,
                                         existing["observation_id"])

        batch = tuple(events) if isinstance(events, (list, tuple)) else None
        if batch is None:
            raise ValueError(_INVALID_EVENT)
        _check_observation(observation)
        kinds = {r[0] for r in self.conn.execute(
            "SELECT DISTINCT action_kind FROM observations"
            " WHERE session_id=? AND action_id=?",
            (session_id, observation.action_id))}
        if kinds - {observation.action_kind}:
            raise ValueError(_INVALID_OBSERVATION)
        open_session = (session["accounting_status"] == "available"
                        and session["ended_at"] is None)
        keys = set()
        for record in batch:
            _check_event(record, observation, profile)
            if not open_session and (
                    record.subject.identity_hash is not None
                    or record.recipient.identity_hash is not None):
                raise ValueError(_INVALID_EVENT)
            key = (_descriptor_key(record.subject),
                   _descriptor_key(record.recipient), record.kind)
            if key in keys:
                raise ValueError(_INVALID_EVENT)
            keys.add(key)

        observation_id = uuid.uuid4().hex
        self.conn.execute(
            "INSERT INTO observations(observation_id,session_id,delivery_key,"
            "action_id,turn_id,ts,hook_event,phase,action_kind,boundary,"
            "decision,evidence,resolution_scope,potential_crossing,scan_gap)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (observation_id, session_id, observation.delivery_key,
             observation.action_id, observation.turn_id, observation.ts,
             observation.hook_event, observation.phase,
             observation.action_kind, observation.boundary,
             observation.decision, int(observation.evidence),
             observation.resolution_scope,
             1 if observation.potential_crossing else 0,
             observation.scan_gap))

        local_subjects: dict[tuple, str] = {}
        local_recipients: dict[tuple, str] = {}
        event_ids: list[int] = []
        disclosure_ids: list[int] = []
        deltas: list[float] = []
        for record in batch:
            subject_id = self._subject_id(session_id, observation_id,
                                          record, local_subjects)
            recipient_id = self._recipient_id(session_id, observation_id,
                                              record, local_recipients)
            event_id = self.conn.execute(
                "INSERT INTO events(session_id,observation_id,subject_id,"
                "recipient_id,kind,evidence,data_type,rule_id,occurrences,"
                "source_label,source_kind,boundary,masked_example)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,NULL,?,?)",
                (session_id, observation_id, subject_id, recipient_id,
                 record.kind, int(record.evidence), record.data_type,
                 record.rule_id, record.occurrences, record.source_label,
                 record.boundary, record.masked_example)).lastrowid
            assert event_id is not None
            event_ids.append(event_id)
            if not (open_session and _chargeable(record, profile)):
                continue
            if self.conn.execute(
                    "SELECT 1 FROM disclosures WHERE session_id=?"
                    " AND subject_id=? AND recipient_id=?",
                    (session_id, subject_id, recipient_id)).fetchone():
                continue
            n = self.conn.execute(
                "SELECT COUNT(*) FROM disclosures WHERE session_id=?"
                " AND charged_data_type=? AND recipient_id=?",
                (session_id, record.data_type, recipient_id)).fetchone()[0]
            delta = next_disclosure_delta(
                profile, record.data_type,
                record.recipient.destination_kind, n)
            disclosure_id = self.conn.execute(
                "INSERT INTO disclosures(session_id,subject_id,recipient_id,"
                "first_event_id,charged_data_type,profile_id,group_n,"
                "budget_delta) VALUES(?,?,?,?,?,?,?,?)",
                (session_id, subject_id, recipient_id, event_id,
                 record.data_type, profile.profile_id, n + 1,
                 delta)).lastrowid
            assert disclosure_id is not None
            disclosure_ids.append(disclosure_id)
            deltas.append(delta)

        total = sum(deltas, 0.0)
        if deltas:
            self.conn.execute(
                "UPDATE sessions SET budget_score=budget_score+?"
                " WHERE session_id=?", (total, session_id))
        if observation.scan_gap is not None:
            self.conn.execute(
                "INSERT INTO scan_gaps(session_id,ts,boundary,reason)"
                " VALUES(?,?,?,?)",
                (session_id, observation.ts, observation.boundary,
                 observation.scan_gap))
        return RecordResult(
            observation_id=observation_id, event_ids=tuple(event_ids),
            disclosure_ids=tuple(disclosure_ids), budget_delta=total,
            duplicate_delivery=False)

    def _recorded_result(self, session_id: str,
                         observation_id: str) -> RecordResult:
        """An already-recorded delivery's result, rebuilt from immutable
        rows: its events, and only the disclosures those events first
        charged. Independent of identity erasure."""
        event_ids = tuple(r[0] for r in self.conn.execute(
            "SELECT id FROM events WHERE session_id=? AND observation_id=?"
            " ORDER BY id", (session_id, observation_id)))
        rows = self.conn.execute(
            "SELECT d.disclosure_id, d.budget_delta FROM disclosures d"
            " JOIN events e ON e.id = d.first_event_id"
            " WHERE d.session_id=? AND e.observation_id=?"
            " ORDER BY d.disclosure_id",
            (session_id, observation_id)).fetchall()
        return RecordResult(
            observation_id=observation_id, event_ids=event_ids,
            disclosure_ids=tuple(r[0] for r in rows),
            budget_delta=sum((r[1] for r in rows), 0.0),
            duplicate_delivery=True)

    def _subject_id(self, session_id: str, observation_id: str,
                    record: EventRecord, local: dict[tuple, str]) -> str:
        subject = record.subject
        if subject.identity_hash is None:
            key = (subject.subject_kind, subject.unresolved_token)
            if key in local:
                return local[key]
        else:
            row = self.conn.execute(
                "SELECT subject_id FROM subjects WHERE session_id=?"
                " AND subject_kind=? AND identity_hash=?",
                (session_id, subject.subject_kind,
                 subject.identity_hash)).fetchone()
            if row is not None:
                return row[0]
        subject_id = uuid.uuid4().hex
        resolved = subject.identity_hash is not None
        self.conn.execute(
            "INSERT INTO subjects(subject_id,session_id,subject_kind,"
            "resolution,identity_hash,label,unresolved_observation_id)"
            " VALUES(?,?,?,?,?,?,?)",
            (subject_id, session_id, subject.subject_kind,
             "resolved" if resolved else "unresolved", subject.identity_hash,
             _subject_label(subject_id, subject),
             None if resolved else observation_id))
        if not resolved:
            local[(subject.subject_kind, subject.unresolved_token)] = subject_id
        return subject_id

    def _recipient_id(self, session_id: str, observation_id: str,
                      record: EventRecord, local: dict[tuple, str]) -> str:
        to = record.recipient
        if to.identity_hash is None:
            key = (to.destination_kind, to.unresolved_token)
            if key in local:
                return local[key]
        else:
            row = self.conn.execute(
                "SELECT recipient_id FROM recipients WHERE session_id=?"
                " AND destination_kind=? AND identity_hash=?",
                (session_id, to.destination_kind,
                 to.identity_hash)).fetchone()
            if row is not None:
                return row[0]
        recipient_id = uuid.uuid4().hex
        resolved = to.identity_hash is not None
        self.conn.execute(
            "INSERT INTO recipients(recipient_id,session_id,destination_kind,"
            "resolution,identity_hash,label,unresolved_observation_id)"
            " VALUES(?,?,?,?,?,?,?)",
            (recipient_id, session_id, to.destination_kind,
             "resolved" if resolved else "unresolved", to.identity_hash,
             _recipient_label(recipient_id, to),
             None if resolved else observation_id))
        if not resolved:
            local[(to.destination_kind, to.unresolved_token)] = recipient_id
        return recipient_id

    def _accounting_version(self, session_id: str) -> Literal[0, 1, 2]:
        """How `session_id` is accounted, read inside the caller's
        transaction: 0 for no session row, 1 legacy, 2 version 2. Any other
        stored version is refused."""
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE session_id=?",
            (session_id,)).fetchone()
        if row is None:
            return 0
        if "accounting_version" not in row.keys():
            return 1
        version = row["accounting_version"]
        if version == 1:
            return 1
        if version == 2:
            return 2
        raise UnsupportedAccounting(_INVALID_V2_SESSION)

    def _summary_v2(self, session_id: str) -> AccountingSummary:
        """The version-2 summary, every quantity from one read snapshot.
        Stored charges are read, never recomputed from the live matrix."""
        with self._read_transaction():
            session, _profile = self._v2_session(session_id)
            observations = [
                OutcomeObservation(observation_id=r["observation_id"],
                                   record=_observation_record(r))
                for r in self.conn.execute(
                    "SELECT * FROM observations WHERE session_id=?"
                    " ORDER BY rowid", (session_id,))]
            event_rows = self.conn.execute(
                "SELECT e.*, s.resolution AS subject_resolution,"
                " r.resolution AS recipient_resolution"
                " FROM events e"
                " JOIN subjects s ON s.session_id = e.session_id"
                "  AND s.subject_id = e.subject_id"
                " JOIN recipients r ON r.session_id = e.session_id"
                "  AND r.recipient_id = e.recipient_id"
                " WHERE e.session_id=? ORDER BY e.id",
                (session_id,)).fetchall()
            disclosures = self.conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT recipient_id)"
                " FROM disclosures WHERE session_id=?",
                (session_id,)).fetchone()
            verified = self.coverage(session_id).verified

        outcome_events = [
            OutcomeEvent(observation_id=r["observation_id"],
                         subject_id=r["subject_id"],
                         recipient_id=r["recipient_id"],
                         subject_resolution=r["subject_resolution"],
                         recipient_resolution=r["recipient_resolution"],
                         kind=r["kind"], evidence=_stored_evidence(
                             r["evidence"]))
            for r in event_rows]
        outcomes = resolve_outcomes(observations, outcome_events)
        unresolved_subjects = sum(
            1 for r in event_rows if r["subject_resolution"] == "unresolved")
        unresolved_recipients = sum(
            1 for r in event_rows
            if r["recipient_resolution"] == "unresolved")
        status = session["accounting_status"]
        if status not in ("available", "unavailable"):
            raise UnsupportedAccounting(_INVALID_V2_SESSION)
        reasons: list[UnavailableReason] = []
        if status == "unavailable":
            reasons.append("accounting_unavailable")
        if outcomes.unresolved_actions:
            reasons.append("unresolved_actions")
        if unresolved_subjects:
            reasons.append("unresolved_subjects")
        if unresolved_recipients:
            reasons.append("unresolved_recipients")
        if not verified:
            reasons.append("coverage_incomplete")
        score, cap = float(session["budget_score"]), float(session["budget_cap"])
        return AccountingSummary(
            accounting_version=2,
            accounting_status=status,
            profile_id=session["profile_id"],
            confirmed_points=score,
            budget_cap=cap,
            percent=None if reasons else percent(score, cap),
            observations=len(observations),
            event_rows=len(event_rows),
            finding_occurrences=sum(r["occurrences"] for r in event_rows),
            distinct_subjects=len({
                r["subject_id"] for r in event_rows
                if r["subject_resolution"] == "resolved"}),
            exposure_events=sum(1 for r in event_rows
                                if r["kind"] == "exposed"),
            intervention_events=sum(
                1 for r in event_rows
                if r["kind"] == "prevented"
                or r["evidence"] & Evidence.REWRITE_ISSUED),
            distinct_disclosures=disclosures[0],
            concrete_recipients=disclosures[1],
            permission_actions=outcomes.permission_actions,
            denials_issued=outcomes.denials_issued,
            denials_enforced=outcomes.denials_enforced,
            reads_stopped=outcomes.reads_stopped,
            rewrite_actions_issued=outcomes.rewrite_actions_issued,
            rewrite_actions_enforced=outcomes.rewrite_actions_enforced,
            unresolved_actions=outcomes.unresolved_actions,
            unresolved_subject_events=unresolved_subjects,
            unresolved_recipient_events=unresolved_recipients,
            percentage_unavailable_reasons=tuple(reasons),
        )

    def _v2_events(self, session_id: str, *, kind: str | None = None,
                   event_id: int | None = None) -> list[AccountingEventRow]:
        """Version-2 event rows of one session, oldest first. A row's
        `budget_delta` is the delta of the disclosure it first charged, and
        0.0 for every other row."""
        where = "e.session_id=?"
        params: list[object] = [session_id]
        if kind is not None:
            where += " AND e.kind=?"
            params.append(kind)
        if event_id is not None:
            where += " AND e.id=?"
            params.append(event_id)
        rows = self.conn.execute(
            "SELECT e.id, e.observation_id, o.action_id, o.turn_id, o.ts,"
            " o.hook_event, o.phase, o.action_kind, e.kind, e.evidence,"
            " e.data_type, e.rule_id, e.occurrences, e.subject_id,"
            " s.subject_kind, s.resolution AS subject_resolution,"
            " s.label AS subject_label, e.recipient_id,"
            " r.resolution AS recipient_resolution, r.destination_kind,"
            " r.label AS recipient_label, e.source_label, e.source_kind,"
            " e.boundary, e.masked_example,"
            " COALESCE(d.budget_delta, 0.0) AS budget_delta, o.scan_gap,"
            " x.budget_cap, e.session_id"
            " FROM events e"
            " JOIN observations o ON o.session_id = e.session_id"
            "  AND o.observation_id = e.observation_id"
            " JOIN subjects s ON s.session_id = e.session_id"
            "  AND s.subject_id = e.subject_id"
            " JOIN recipients r ON r.session_id = e.session_id"
            "  AND r.recipient_id = e.recipient_id"
            " JOIN sessions x ON x.session_id = e.session_id"
            " LEFT JOIN disclosures d ON d.session_id = e.session_id"
            "  AND d.first_event_id = e.id"
            f" WHERE {where} ORDER BY e.id", params).fetchall()
        out = []
        for row in rows:
            values = dict(row)
            if values["source_kind"] is not None:
                raise UnsupportedAccounting(_INVALID_V2_SESSION)
            values["evidence"] = _stored_evidence(values["evidence"])
            values["budget_delta"] = float(values["budget_delta"])
            values["budget_cap"] = float(values["budget_cap"])
            out.append(AccountingEventRow(**values))
        return out

    def mark_accounting_unavailable(self, session_id: str) -> None:
        """Mark a version-2 session's accounting unavailable, permanently.
        Idempotent. Changes only the status: score, cap, profile, history
        and (while the session is open) identity hashes are untouched."""
        with self._atomic_accounting_write():
            if self._accounting_version(session_id) != 2:
                raise UnsupportedAccounting(_INVALID_V2_SESSION)
            self._v2_session(session_id)
            self.conn.execute(
                "UPDATE sessions SET accounting_status='unavailable'"
                " WHERE session_id=? AND accounting_status='available'",
                (session_id,))

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
        with self._write_transaction():
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
        with self._write_transaction():
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
            if self._accounting_version(session_id) == 2:
                return self._summary_v2(session_id)
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

    def list_events(self, session_id: str, kind: str) -> list[EventRow]:
        """Every legacy event of one `kind`, oldest first.

        Rows carry `value_hash` because the ledger's own callers need it;
        `as_dict()` cannot serialize it, and callers outside the ledger
        project with `to_exposure()`. An unknown session has no rows.
        """
        with self._read_transaction():
            if self._accounting_version(session_id) == 2:
                self._v2_session(session_id)
                return list(self._v2_events(session_id, kind=kind))
            if self._legacy_session(session_id) is None:
                return []
            table = self._legacy_events_table()
            rows = self.conn.execute(
                f"SELECT {self._legacy_select(table)} FROM {table}"
                " WHERE session_id=? AND kind=? ORDER BY id",
                (session_id, kind)).fetchall()
        return [LegacyEventRow(**dict(r)) for r in rows]

    def get_event(self, session_id: str, event_id: int) -> ExposureRow:
        """One public legacy row, scoped to both `session_id` and
        `event_id`, with `first_seen` and the session's stored `budget_cap`.

        Raises `LookupError` when nothing matches, including an id that
        exists in another session: one session's audit can never read
        another's row by guessing an id. The row and the cap are read in
        one transaction.
        """
        with self._read_transaction():
            if self._accounting_version(session_id) == 2:
                self._v2_session(session_id)
                found = self._v2_events(session_id, event_id=event_id)
                if not found:
                    raise LookupError(
                        f"no event {event_id!r} in session {session_id!r}")
                return found[0].to_exposure()
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
            if self._accounting_version(session_id) == 2:
                self._end_v2_session(session_id)
                return
            self.conn.execute(
                "UPDATE sessions SET ended_at=? WHERE session_id=?"
                " AND ended_at IS NULL", (int(time.time()), session_id))
            table = self._legacy_events_table()
            self.conn.execute(
                f"UPDATE {table} SET value_hash=NULL WHERE session_id=?",
                (session_id,))

    def _end_v2_session(self, session_id: str) -> None:
        """End a version-2 session in one accounting savepoint: set the end
        time if it is unset, then null the identity hashes of its subjects
        and recipients. Opaque IDs, labels, resolution, history and charges
        are kept. This is ledger erasure only; it does not destroy any
        accounting key."""
        with self._atomic_accounting_write():
            self._v2_session(session_id)
            self.conn.execute(
                "UPDATE sessions SET ended_at=? WHERE session_id=?"
                " AND ended_at IS NULL", (int(time.time()), session_id))
            self.conn.execute(
                "UPDATE subjects SET identity_hash=NULL WHERE session_id=?"
                " AND identity_hash IS NOT NULL", (session_id,))
            self.conn.execute(
                "UPDATE recipients SET identity_hash=NULL WHERE session_id=?"
                " AND identity_hash IS NOT NULL", (session_id,))

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
        with self._write_transaction():
            self.conn.execute(
                "INSERT INTO policy(scope, rule_type, selector, created_at)"
                " VALUES(?,?,?,?)",
                (_session_scope(session_id), rule_type, selector,
                 int(time.time())))

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
        with self._write_transaction():
            # A second consent for the same call replaces the first rather
            # than stacking with it: two rows would let a retried call
            # through twice, and "once" is the whole grant. The replacement
            # and the insert share one transaction, so a failure between
            # them cannot leave the earlier grant deleted and no new one in
            # its place.
            self.conn.execute(
                "DELETE FROM policy_tokens WHERE session_id=? AND tool_name=?"
                " AND args_hash=?", (session_id, tool_name, args_hash))
            self.conn.execute(
                "INSERT INTO policy_tokens(token,session_id,tool_name,"
                "args_hash,mode,expires_at) VALUES(?,?,?,?,?,?)",
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
        with self._write_transaction():
            # The lookup is inside the transaction with the DELETE: two
            # callers racing the same token would otherwise both read it and
            # both spend it, which is the one thing "once" has to mean.
            row = self.conn.execute(
                "SELECT token, mode FROM policy_tokens WHERE session_id=?"
                " AND tool_name=? AND args_hash=? AND expires_at>?"
                " ORDER BY expires_at DESC LIMIT 1",
                (session_id, tool_name, args_hash, int(time.time()))).fetchone()
            if row is None:
                return None
            self.conn.execute("DELETE FROM policy_tokens WHERE token=?",
                              (row["token"],))
            return row["mode"]
