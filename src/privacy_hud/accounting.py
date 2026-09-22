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
from dataclasses import dataclass, field
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
