"""Pure scoring math. No I/O, no constants — every number comes from Matrix."""
from __future__ import annotations

import math
from dataclasses import dataclass, field

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
