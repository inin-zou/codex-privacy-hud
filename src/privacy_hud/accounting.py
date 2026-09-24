"""Version-2 accounting: the pure core (#54 Phase 3).

Vocabulary, the frozen scoring profile, identity inputs and value-finding
normalization. Nothing here performs I/O, and no production path uses it in
Phase 3: sessions are still created under legacy (version-1) accounting.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from enum import IntFlag
from types import MappingProxyType
from typing import Any, Literal, cast, get_args

from .detect.base import Finding
from .matrix.loader import Matrix

DataType = Literal[
    "credential", "financial", "health", "email", "phone",
    "person", "address", "ssn", "account", "url", "date",
    "hostname", "path", "ip", "repo",
]
Boundary = Literal["B0", "B1", "B2", "B3", "B4"]
DestinationKind = Literal[
    "local", "model_context", "subagent", "mcp_tool", "external_net",
]
EventKind = Literal[
    "detected", "local_access", "permitted",
    "exposed", "prevented", "retention",
]
HookEvent = Literal[
    "SessionStart", "SessionEnd", "UserPromptSubmit",
    "PreToolUse", "PostToolUse", "SubagentStart",
    "SubagentStop", "PreCompact",
]
Phase = Literal["pre", "post", "lifecycle"]
ActionKind = Literal[
    "read", "tool", "prompt", "subagent", "lifecycle", "other",
]
Decision = Literal["none", "allow", "deny", "rewrite"]
ResolutionScope = Literal["none", "pairs", "boundary"]
Resolution = Literal["resolved", "unresolved"]
ScanGap = Literal["oversize", "unavailable", "busy", "timeout"]
SafeSuffix = Literal[".pem", ".p12", ".pfx", ".keystore"]
BandName = Literal["safe", "warn", "danger"]
UnavailableReason = Literal[
    "accounting_unavailable",
    "unresolved_actions",
    "unresolved_subjects",
    "unresolved_recipients",
    "coverage_incomplete",
]


_DATA_TYPES: tuple[str, ...] = get_args(DataType)
_BOUNDARIES: tuple[str, ...] = get_args(Boundary)
_DESTINATIONS: tuple[str, ...] = get_args(DestinationKind)
_SAFE_SUFFIXES: tuple[str, ...] = get_args(SafeSuffix)
_BAND_NAMES: tuple[str, ...] = get_args(BandName)
_CHARGED_TYPE_RULE: Literal["first_crossing_max_severity_then_name_v1"] = (
    "first_crossing_max_severity_then_name_v1")

_INVALID_PROFILE = "invalid scoring profile"
_INVALID_IDENTITY = "invalid accounting identity"
_INVALID_OBSERVATION = "invalid accounting observation"

_TOKEN = re.compile(r"[0-9a-f]{32}")


class Evidence(IntFlag):
    PERMISSION_ISSUED = 1
    DENY_ISSUED = 2
    DENY_ENFORCED = 4
    REWRITE_ISSUED = 8
    REWRITE_ENFORCED = 16
    EXECUTION_OBSERVED = 32
    CROSSING_CONFIRMED = 64
    REJECTED_BEFORE_CROSSING = 128
    LOCAL_DETECTION = 256
    PERSISTENCE_OBSERVED = 512
    HOOK_OBSERVED = 1024


def evidence_names(evidence: Evidence) -> tuple[str, ...]:
    """The set bits of `evidence` as their serialized names, in bit order."""
    if not isinstance(evidence, Evidence):
        raise ValueError(_INVALID_OBSERVATION)
    return tuple(member.name.lower() for member in Evidence
                 if member.name is not None and member in evidence)


def _weight(value: object) -> float:
    # Booleans are ints to Python; they are not weights.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(_INVALID_PROFILE)
    try:
        number = float(value)
    except OverflowError:
        raise ValueError(_INVALID_PROFILE) from None
    if not math.isfinite(number) or number < 0:
        raise ValueError(_INVALID_PROFILE)
    # `+ 0.0` turns -0.0 into 0.0, so equal weights spell identically.
    return number + 0.0


def _weights(value: object, keys: tuple[str, ...]) -> MappingProxyType:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        raise ValueError(_INVALID_PROFILE)
    return MappingProxyType({key: _weight(value[key]) for key in keys})


def _destinations(value: object) -> MappingProxyType:
    if not isinstance(value, Mapping) or set(value) != set(_DESTINATIONS):
        raise ValueError(_INVALID_PROFILE)
    frozen = {}
    for key in _DESTINATIONS:
        boundary = value[key]
        if not isinstance(boundary, str) or boundary not in _BOUNDARIES:
            raise ValueError(_INVALID_PROFILE)
        frozen[key] = boundary
    return MappingProxyType(frozen)


def _bound(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(_INVALID_PROFILE)
    return value


def _bands(value: object) -> tuple[tuple[int, int, BandName], ...]:
    """Three bands named safe, warn, danger in that order, covering 0-100
    exactly, without gaps or overlaps."""
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(_INVALID_PROFILE)
    bands: list[tuple[int, int, BandName]] = []
    expected_lo = 0
    for entry, name in zip(value, _BAND_NAMES, strict=False):
        if (isinstance(entry, (str, bytes)) or not isinstance(entry, Sequence)
                or len(entry) != 3):
            raise ValueError(_INVALID_PROFILE)
        lo, hi = _bound(entry[0]), _bound(entry[1])
        if entry[2] != name or lo != expected_lo or hi < lo:
            raise ValueError(_INVALID_PROFILE)
        bands.append((lo, hi, cast(BandName, name)))
        expected_lo = hi + 1
    if len(value) != len(_BAND_NAMES) or expected_lo != 101:
        raise ValueError(_INVALID_PROFILE)
    return tuple(bands)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(_INVALID_PROFILE)
        document[key] = value
    return document


def _reject_constant(_name: str) -> float:
    # NaN and the infinities are not JSON; the default parser accepts them.
    raise ValueError(_INVALID_PROFILE)


def _exact_keys(value: object, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(_INVALID_PROFILE)
    return value


@dataclass(frozen=True, kw_only=True)
class ScoringProfile:
    """The complete, immutable scoring inputs a version-2 session is charged
    under. Every construction path validates and deep-freezes: maps become
    read-only copies, bands become tuples, and later changes to the matrix
    or to the caller's arguments cannot reach the profile or its ID."""

    format_version: Literal[1]
    matrix_version: str
    budget_cap: float
    severity: Mapping[DataType, float]
    boundary_multiplier: Mapping[Boundary, float]
    destination_boundary: Mapping[DestinationKind, Boundary]
    bands: tuple[tuple[int, int, BandName], ...]
    charged_type_rule: Literal[
        "first_crossing_max_severity_then_name_v1"
    ]

    def __post_init__(self) -> None:
        if (isinstance(self.format_version, bool)
                or not isinstance(self.format_version, int)
                or self.format_version != 1):
            raise ValueError(_INVALID_PROFILE)
        if not isinstance(self.matrix_version, str) or not self.matrix_version:
            raise ValueError(_INVALID_PROFILE)
        cap = _weight(self.budget_cap)
        if not 0 < cap < 1e100:
            raise ValueError(_INVALID_PROFILE)
        if self.charged_type_rule != _CHARGED_TYPE_RULE:
            raise ValueError(_INVALID_PROFILE)
        freeze = object.__setattr__
        freeze(self, "budget_cap", cap)
        freeze(self, "severity", _weights(self.severity, _DATA_TYPES))
        freeze(self, "boundary_multiplier",
               _weights(self.boundary_multiplier, _BOUNDARIES))
        freeze(self, "destination_boundary",
               _destinations(self.destination_boundary))
        freeze(self, "bands", _bands(self.bands))

    def __hash__(self) -> int:
        return hash(self.profile_id)

    @classmethod
    def from_matrix(cls, matrix: Matrix) -> ScoringProfile:
        raw = matrix.raw
        return cls(
            format_version=1,
            matrix_version=matrix.version,
            budget_cap=matrix.budget_cap,
            severity=dict(raw["severity"]),
            boundary_multiplier=dict(raw["boundary_multiplier"]),
            destination_boundary=dict(raw["destination_boundary"]),
            bands=_bands(matrix.bands),
            charged_type_rule=_CHARGED_TYPE_RULE,
        )

    @classmethod
    def from_canonical_json(cls, text: str) -> ScoringProfile:
        """Decode a canonical profile document. Duplicate keys, non-JSON
        constants, missing or extra keys, and any spelling other than the
        canonical one are refused."""
        if not isinstance(text, str):
            raise ValueError(_INVALID_PROFILE)
        try:
            document = json.loads(text, object_pairs_hook=_reject_duplicate_keys,
                                  parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            raise ValueError(_INVALID_PROFILE) from None
        top = _exact_keys(document, {"format_version", "matrix_version",
                                     "budget_cap", "parameters"})
        params = _exact_keys(top["parameters"], {
            "severity", "boundary_multiplier", "destination_boundary",
            "bands", "charged_type_rule"})
        if not isinstance(params["bands"], list):
            raise ValueError(_INVALID_PROFILE)
        bands = []
        for band in params["bands"]:
            entry = _exact_keys(band, {"lo", "hi", "name"})
            bands.append((entry["lo"], entry["hi"], entry["name"]))
        profile = cls(
            format_version=top["format_version"],
            matrix_version=top["matrix_version"],
            budget_cap=top["budget_cap"],
            severity=params["severity"],
            boundary_multiplier=params["boundary_multiplier"],
            destination_boundary=params["destination_boundary"],
            bands=tuple(bands),
            charged_type_rule=params["charged_type_rule"],
        )
        if profile.as_canonical_json() != text:
            raise ValueError(_INVALID_PROFILE)
        return profile

    def as_canonical_json(self) -> str:
        document = {
            "format_version": 1,
            "matrix_version": self.matrix_version,
            "budget_cap": self.budget_cap,
            "parameters": {
                "severity": dict(self.severity),
                "boundary_multiplier": dict(self.boundary_multiplier),
                "destination_boundary": dict(self.destination_boundary),
                "bands": [
                    {"lo": lo, "hi": hi, "name": name}
                    for lo, hi, name in self.bands
                ],
                "charged_type_rule":
                    "first_crossing_max_severity_then_name_v1",
            },
        }
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )

    @property
    def profile_id(self) -> str:
        return hashlib.sha256(
            self.as_canonical_json().encode("utf-8")).hexdigest()


def _check_hash(identity_hash: object) -> None:
    if identity_hash is not None and not (
            type(identity_hash) is bytes and len(identity_hash) == 32):
        raise ValueError(_INVALID_IDENTITY)


def _settle_token(descriptor: object, identity_hash: bytes | None,
                  token: object) -> None:
    """A resolved descriptor carries no token. An unresolved one carries a
    random token unless the caller deliberately reuses one it knows names
    the same unresolved entity. Tokens are transient: never persisted,
    serialized or used as a key outside one observation."""
    if identity_hash is not None:
        if token is not None:
            raise ValueError(_INVALID_IDENTITY)
        return
    if token is None:
        object.__setattr__(descriptor, "unresolved_token",
                           secrets.token_hex(16))
    elif not isinstance(token, str) or not _TOKEN.fullmatch(token):
        raise ValueError(_INVALID_IDENTITY)


@dataclass(frozen=True, kw_only=True)
class SubjectInput:
    subject_kind: Literal["value", "file"]
    identity_hash: bytes | None
    safe_suffix: SafeSuffix | None = None
    unresolved_token: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.subject_kind not in ("value", "file"):
            raise ValueError(_INVALID_IDENTITY)
        _check_hash(self.identity_hash)
        if self.safe_suffix is not None and (
                self.subject_kind != "file"
                or self.safe_suffix not in _SAFE_SUFFIXES):
            raise ValueError(_INVALID_IDENTITY)
        _settle_token(self, self.identity_hash, self.unresolved_token)


@dataclass(frozen=True, kw_only=True)
class RecipientInput:
    destination_kind: DestinationKind
    identity_hash: bytes | None
    unresolved_token: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.destination_kind not in _DESTINATIONS:
            raise ValueError(_INVALID_IDENTITY)
        _check_hash(self.identity_hash)
        _settle_token(self, self.identity_hash, self.unresolved_token)


@dataclass(frozen=True, kw_only=True)
class ValueFinding:
    subject: SubjectInput
    data_type: DataType
    occurrences: int
    masked_example: str | None


def _offset(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(_INVALID_OBSERVATION)
    return value


def coalesce_value_findings(
    profile: ScoringProfile,
    key: bytes,
    findings: Sequence[Finding],
) -> tuple[ValueFinding, ...]:
    """One `ValueFinding` per exact value, in first-occurrence order.

    The type is the highest-severity type any detector gave the value, ties
    broken by ascending type name, so detector order cannot change it.
    Occurrences are distinct `(start, end)` spans: two detectors reporting
    one span count once. Only the identity hash, type, count and a safe
    exemplar leave this function; values and spans do not."""
    from .identity import safe_masked_example, value_identity

    if not isinstance(profile, ScoringProfile):
        raise ValueError(_INVALID_OBSERVATION)
    groups: dict[bytes, tuple[str, set[DataType], set[tuple[int, int]]]] = {}
    for finding in findings:
        if not isinstance(finding, Finding):
            raise ValueError(_INVALID_OBSERVATION)
        start, end = _offset(finding.start), _offset(finding.end)
        if (finding.data_type not in profile.severity
                or not isinstance(finding.value, str)
                or start < 0 or end <= start
                or end - start != len(finding.value)):
            raise ValueError(_INVALID_OBSERVATION)
        identity = value_identity(key, finding.value)
        _value, types, spans = groups.setdefault(
            identity, (finding.value, set(), set()))
        types.add(cast(DataType, finding.data_type))
        spans.add((start, end))
    out = []
    for identity, (value, types, spans) in groups.items():
        data_type = min(types, key=lambda t: (-profile.severity[t], t))
        out.append(ValueFinding(
            subject=SubjectInput(subject_kind="value", identity_hash=identity),
            data_type=data_type,
            occurrences=len(spans),
            masked_example=safe_masked_example(data_type, value),
        ))
    return tuple(out)


#: Detector rule identifiers an event may carry in Phase 3: the committed
#: guarded-path rules. Every other rule identifier is null.
PATH_RULE_IDS = frozenset({
    "path.env",
    "path.ssh_private_key",
    "path.key_container",
    "path.aws_credentials",
    "path.credentials_json",
    "path.ssh_config",
})

#: The source labels an event may carry.
SOURCE_LABELS = frozenset({
    "user prompt",
    "tool input",
    "tool result",
    "main agent",
    "local file",
    "lifecycle",
})


@dataclass(frozen=True, kw_only=True)
class ObservationRecord:
    session_id: str
    delivery_key: str
    action_id: str
    turn_id: str | None
    ts: int
    hook_event: HookEvent
    phase: Phase
    action_kind: ActionKind
    boundary: Boundary
    decision: Decision
    evidence: Evidence
    resolution_scope: ResolutionScope
    potential_crossing: bool
    scan_gap: ScanGap | None


@dataclass(frozen=True, kw_only=True)
class EventRecord:
    subject: SubjectInput
    recipient: RecipientInput
    kind: EventKind
    evidence: Evidence
    data_type: DataType
    rule_id: str | None
    occurrences: int
    source_label: str
    boundary: Boundary
    masked_example: str | None


@dataclass(frozen=True, kw_only=True)
class RecordResult:
    observation_id: str
    event_ids: tuple[int, ...]
    disclosure_ids: tuple[int, ...]
    budget_delta: float
    duplicate_delivery: bool


# -- shared version-2 copy (#54 Phase 3, §C) ---------------------------------

ACCOUNTING_SCORE_LABEL = "confirmed disclosure points"

ACCOUNTING_NOTE = (
    "This score is a versioned policy index over evidenced disclosures, "
    "not a measurement of harm. Permission, a returned denial, a returned "
    "rewrite, and a successful tool result do not by themselves confirm "
    "disclosure or host enforcement."
)

PHASE3_SURFACE_UNSUPPORTED = (
    "This Privacy HUD surface does not support version-2 accounting "
    "in 0.8.2."
)


# -- outcomes ----------------------------------------------------------------

@dataclass(frozen=True, kw_only=True)
class OutcomeObservation:
    observation_id: str
    record: ObservationRecord


@dataclass(frozen=True, kw_only=True)
class OutcomeEvent:
    observation_id: str
    subject_id: str
    recipient_id: str
    subject_resolution: Resolution
    recipient_resolution: Resolution
    kind: EventKind
    evidence: Evidence


@dataclass(frozen=True, kw_only=True)
class OutcomeCounts:
    permission_actions: int
    denials_issued: int
    denials_enforced: int
    reads_stopped: int
    rewrite_actions_issued: int
    rewrite_actions_enforced: int
    unresolved_actions: int


_STOPPED = Evidence.DENY_ENFORCED | Evidence.REJECTED_BEFORE_CROSSING
_EXECUTED = Evidence.EXECUTION_OBSERVED | Evidence.CROSSING_CONFIRMED
#: The obligation a potential crossing with no identified pair creates.
_ZERO_FINDING = ("", "")


def _pair(event: OutcomeEvent) -> tuple[str, str] | None:
    """The event's pair, or None when either identity is unresolved: an
    unresolved reference is never matched to any receipt."""
    if event.subject_resolution != "resolved" \
            or event.recipient_resolution != "resolved":
        return None
    return (event.subject_id, event.recipient_id)


def _partition_unresolved(observations: Sequence[OutcomeObservation],
                          events_of: Mapping[str, list[OutcomeEvent]]
                          ) -> bool:
    """Whether one action/boundary partition leaves any outcome unresolved.

    Obligations: a crossing outcome for each identified pair of a potential
    crossing (or one for the whole boundary when it identified none), a
    denial outcome for an issued denial, and a removal outcome for each
    pair an issued rewrite names. Receipts resolve them only within their
    `resolution_scope`; conflicts stay unresolved and subtract nothing."""
    crossing: set[tuple[str, str]] = set()
    rewrites: set[tuple[str, str]] = set()
    denied_pairs: set[tuple[str, str]] = set()
    executed_pairs: set[tuple[str, str]] = set()
    crossing_facts: set[tuple[str, str]] = set()
    stop_facts: set[tuple[str, str]] = set()
    removal_facts: set[tuple[str, str]] = set()
    deny_unidentified = False
    unmatchable = deny_pending = rewrite_unidentified = executed = False
    crossed: set[tuple[str, str]] = set()
    stopped: set[tuple[str, str]] = set()
    removed: set[tuple[str, str]] = set()
    boundary_stopped = zero_receipt = False

    for observation in observations:
        record = observation.record
        events = events_of.get(observation.observation_id, [])
        # Scope controls resolution, not whether contradictory facts exist.
        for event in events:
            pair = _pair(event)
            if pair is None:
                continue
            if event.evidence & _EXECUTED:
                executed_pairs.add(pair)
            if Evidence.CROSSING_CONFIRMED in event.evidence:
                crossing_facts.add(pair)
            if event.evidence & _STOPPED:
                stop_facts.add(pair)
            if Evidence.REWRITE_ENFORCED in event.evidence:
                removal_facts.add(pair)
        if record.evidence & _EXECUTED:
            executed = True
        if record.potential_crossing:
            if not events:
                crossing.add(_ZERO_FINDING)
            for event in events:
                pair = _pair(event)
                if pair is None:
                    unmatchable = True
                else:
                    crossing.add(pair)
        if Evidence.DENY_ISSUED in record.evidence:
            deny_pending = True
            if not events:
                deny_unidentified = True
            for event in events:
                pair = _pair(event)
                if pair is None:
                    deny_unidentified = True
                else:
                    denied_pairs.add(pair)
        if Evidence.REWRITE_ISSUED in record.evidence:
            named = [e for e in events if Evidence.REWRITE_ISSUED in e.evidence]
            if not named:
                rewrite_unidentified = True
            for event in named:
                pair = _pair(event)
                if pair is None:
                    unmatchable = True
                else:
                    rewrites.add(pair)
        if record.resolution_scope == "pairs":
            for event in events:
                pair = _pair(event)
                if pair is None:
                    continue
                if Evidence.CROSSING_CONFIRMED in event.evidence:
                    crossed.add(pair)
                if event.evidence & _STOPPED:
                    stopped.add(pair)
                if Evidence.REWRITE_ENFORCED in event.evidence:
                    removed.add(pair)
        elif record.resolution_scope == "boundary":
            if record.evidence & _STOPPED:
                boundary_stopped = True
            if Evidence.CROSSING_CONFIRMED in record.evidence and not events:
                zero_receipt = True

    if (executed_pairs & stop_facts
            or crossing_facts & removal_facts):
        return True
    if boundary_stopped and executed:
        return True
    if unmatchable and not boundary_stopped:
        return True
    for pair in crossing:
        if pair == _ZERO_FINDING:
            if not (boundary_stopped or zero_receipt):
                return True
        elif not (boundary_stopped or pair in crossed | stopped | removed):
            return True
    if deny_pending:
        pairs = (crossing | denied_pairs) - {_ZERO_FINDING}
        pair_stopped = (bool(pairs) and not deny_unidentified
                        and _ZERO_FINDING not in crossing
                        and pairs <= stopped)
        if executed or not (boundary_stopped or pair_stopped):
            return True
    for pair in rewrites:
        if not (boundary_stopped or pair in removed):
            return True
    return rewrite_unidentified and not boundary_stopped


def resolve_outcomes(
    observations: Sequence[OutcomeObservation],
    events: Sequence[OutcomeEvent],
) -> OutcomeCounts:
    """Action outcome counts for one session.

    Issuance and enforcement counts are distinct action IDs carrying the
    bit, recorded even when a conflict leaves the action unresolved. An
    action is unresolved once if any of its boundaries is. A stopped read
    is a read action with an enforced denial, no execution or crossing, and
    nothing unresolved."""
    events_of: dict[str, list[OutcomeEvent]] = {}
    for event in events:
        events_of.setdefault(event.observation_id, []).append(event)
    partitions: dict[tuple[str, str], list[OutcomeObservation]] = {}
    carried: dict[str, Evidence] = {}
    kinds: dict[str, set[str]] = {}
    for observation in observations:
        record = observation.record
        partitions.setdefault((record.action_id, record.boundary),
                              []).append(observation)
        carried[record.action_id] = (
            carried.get(record.action_id, Evidence(0)) | record.evidence)
        kinds.setdefault(record.action_id, set()).add(record.action_kind)

    unresolved = {action for (action, _boundary), group in partitions.items()
                  if _partition_unresolved(group, events_of)}

    def with_bit(bit: Evidence) -> int:
        return sum(1 for evidence in carried.values() if bit in evidence)

    reads_stopped = sum(
        1 for action, evidence in carried.items()
        if "read" in kinds[action]
        and Evidence.DENY_ENFORCED in evidence
        and not evidence & _EXECUTED
        and action not in unresolved)
    return OutcomeCounts(
        permission_actions=with_bit(Evidence.PERMISSION_ISSUED),
        denials_issued=with_bit(Evidence.DENY_ISSUED),
        denials_enforced=with_bit(Evidence.DENY_ENFORCED),
        reads_stopped=reads_stopped,
        rewrite_actions_issued=with_bit(Evidence.REWRITE_ISSUED),
        rewrite_actions_enforced=with_bit(Evidence.REWRITE_ENFORCED),
        unresolved_actions=len(unresolved),
    )


# -- read models -------------------------------------------------------------

@dataclass(frozen=True, kw_only=True)
class AccountingSummary:
    """One version-2 session's summary. `percent` is null whenever any
    reason in `percentage_unavailable_reasons` holds."""

    accounting_version: Literal[2]
    accounting_status: Literal["available", "unavailable"]
    profile_id: str
    confirmed_points: float
    budget_cap: float
    percent: int | None
    observations: int
    event_rows: int
    finding_occurrences: int
    distinct_subjects: int
    exposure_events: int
    intervention_events: int
    distinct_disclosures: int
    concrete_recipients: int
    permission_actions: int
    denials_issued: int
    denials_enforced: int
    reads_stopped: int
    rewrite_actions_issued: int
    rewrite_actions_enforced: int
    unresolved_actions: int
    unresolved_subject_events: int
    unresolved_recipient_events: int
    percentage_unavailable_reasons: tuple[UnavailableReason, ...]

    @property
    def score_label(self) -> str:
        return ACCOUNTING_SCORE_LABEL

    @property
    def accounting_note(self) -> str:
        return ACCOUNTING_NOTE

    def as_dict(self) -> dict:
        payload: dict[str, Any] = {
            f.name: getattr(self, f.name) for f in fields(self)}
        payload["percentage_unavailable_reasons"] = list(
            self.percentage_unavailable_reasons)
        payload["score_label"] = self.score_label
        payload["accounting_note"] = self.accounting_note
        return payload


@dataclass(frozen=True, kw_only=True)
class AccountingExposureRow:
    """One version-2 event as a consumer outside the ledger may see it. The
    field list is the allow-list: no session ID, hash, unresolved token or
    delivery key. Not derived from any legacy row type."""

    id: int
    observation_id: str
    action_id: str
    turn_id: str | None
    ts: int
    hook_event: HookEvent
    phase: Phase
    action_kind: ActionKind
    kind: EventKind
    evidence: Evidence
    data_type: DataType
    rule_id: str | None
    occurrences: int
    subject_id: str
    subject_kind: Literal["value", "file"]
    subject_resolution: Resolution
    subject_label: str
    recipient_id: str
    recipient_resolution: Resolution
    destination_kind: DestinationKind
    recipient_label: str
    source_label: str
    source_kind: None
    boundary: Boundary
    masked_example: str | None
    budget_delta: float
    scan_gap: ScanGap | None
    budget_cap: float

    @property
    def accounting_version(self) -> Literal[2]:
        return 2

    def as_dict(self) -> dict:
        payload: dict[str, Any] = {"accounting_version": 2}
        for f in fields(AccountingExposureRow):
            payload[f.name] = getattr(self, f.name)
        payload["evidence"] = list(evidence_names(self.evidence))
        return payload


@dataclass(frozen=True, kw_only=True)
class AccountingEventRow(AccountingExposureRow):
    session_id: str

    def to_exposure(self) -> AccountingExposureRow:
        return AccountingExposureRow(**{
            f.name: getattr(self, f.name)
            for f in fields(AccountingExposureRow)})
