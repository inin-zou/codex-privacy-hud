from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Finding:
    data_type: str
    value: str
    start: int
    end: int


class Detector(Protocol):
    def scan(self, text: str, ctx: dict) -> list[Finding]: ...
