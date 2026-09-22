"""Pure scoring math. No I/O, no constants — every number comes from Matrix."""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from .accounting import DataType, DestinationKind, ScoringProfile
from .matrix.loader import Matrix


def volume(n: int) -> float:
    """Sublinear volume factor: the 100th email matters less than the first."""
    if n < 1:
        raise ValueError("count must be >= 1")
    return 1.0 + math.log(n)


def contribution(m: Matrix, data_type: str, n: int, destination: str) -> float:
    boundary = m.boundary_for(destination)
    return m.severity(data_type) * volume(n) * m.multiplier(boundary)


def percent(score: float, cap: float) -> int:
    if cap <= 0:
        raise ValueError("cap must be > 0")
    return min(100, round(100 * score / cap))


@dataclass
class Budget:
    """Monotonic accumulator. Disclosure is irreversible, so there is no
    subtract path — an attempt to remove score is a bug, not a use case."""

    score: float = field(default=0.0)

    def add(self, delta: float) -> None:
        if delta < 0:
            raise ValueError("budget is monotonic; negative delta rejected")
        self.score += delta

    def percent(self, cap: float) -> int:
        return percent(self.score, cap)


_INVALID_SCORE = "invalid disclosure score"

#: Scores are stored as SQLite REAL and must stay well inside its range.
_STORABLE_LIMIT = 1e100


def _storable(score: float) -> float:
    if not math.isfinite(score) or not 0.0 <= score < _STORABLE_LIMIT:
        raise ValueError(_INVALID_SCORE)
    return score


def group_score(
    profile: ScoringProfile,
    data_type: DataType,
    destination_kind: DestinationKind,
    n: int,
) -> float:
    """Version-2 score of one group — `n` distinct disclosures of one data
    type to one recipient: `F(0) = 0`, otherwise
    `severity * multiplier * (1 + ln n)`. Separate from the legacy per-row
    `contribution`, which is unchanged."""
    if not isinstance(profile, ScoringProfile):
        raise ValueError(_INVALID_SCORE)
    # Keys are checked before the count, so an unknown key fails at n == 0.
    if (data_type not in profile.severity
            or destination_kind not in profile.destination_boundary):
        raise ValueError(_INVALID_SCORE)
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError(_INVALID_SCORE)
    if n == 0:
        return 0.0
    weight = (profile.severity[data_type]
              * profile.boundary_multiplier[
                  profile.destination_boundary[destination_kind]])
    return _storable(weight * (1.0 + math.log(n)))


def next_disclosure_delta(
    profile: ScoringProfile,
    data_type: DataType,
    destination_kind: DestinationKind,
    n: int,
) -> float:
    """What the next disclosure in a group of `n` adds: `F(n+1) - F(n)`.
    Positive and decreasing for a positive weight, zero for a zero one."""
    current = group_score(profile, data_type, destination_kind, n)
    following = group_score(profile, data_type, destination_kind, n + 1)
    return _storable(following - current)
