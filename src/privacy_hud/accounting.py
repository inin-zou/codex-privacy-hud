"""Version-2 accounting: the pure core (#54 Phase 3).

Vocabulary, the frozen scoring profile, identity inputs and value-finding
normalization. Nothing here performs I/O, and no production path uses it in
Phase 3: sessions are still created under legacy (version-1) accounting.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import IntFlag
from typing import Literal, NoReturn

from .detect.base import Finding
from .ledger_schema import UnsupportedAccounting
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


def _scaffold() -> NoReturn:
    # P3-C1 contract scaffolding: the operation is declared, not implemented.
    raise UnsupportedAccounting("version-2 accounting is not implemented")


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
    _scaffold()


@dataclass(frozen=True, kw_only=True)
class ScoringProfile:
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

    @classmethod
    def from_matrix(cls, matrix: Matrix) -> ScoringProfile:
        _scaffold()

    @classmethod
    def from_canonical_json(cls, text: str) -> ScoringProfile:
        _scaffold()

    def as_canonical_json(self) -> str:
        _scaffold()

    @property
    def profile_id(self) -> str:
        _scaffold()


@dataclass(frozen=True, kw_only=True)
class SubjectInput:
    subject_kind: Literal["value", "file"]
    identity_hash: bytes | None
    safe_suffix: SafeSuffix | None = None
    unresolved_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True, kw_only=True)
class RecipientInput:
    destination_kind: DestinationKind
    identity_hash: bytes | None
    unresolved_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True, kw_only=True)
class ValueFinding:
    subject: SubjectInput
    data_type: DataType
    occurrences: int
    masked_example: str | None


def coalesce_value_findings(
    profile: ScoringProfile,
    key: bytes,
    findings: Sequence[Finding],
) -> tuple[ValueFinding, ...]:
    _scaffold()
