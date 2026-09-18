# src/privacy_hud/matrix/loader.py
"""Declarative tuning layer.

Every tunable number and classification in Privacy HUD lives in tables.toml.
Logic modules read them through Matrix and never hardcode a value, so tuning
the product is a data change, not a code change.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TABLES = Path(__file__).with_name("tables.toml")

#: The data types `[policy_defaults]` decides — and therefore the only data
#: types this plugin can hard-block. `Engine.observe` consults
#: `Matrix.default_action()` only when a finding of one of these is present,
#: and every egress destination in that table (`mcp_tool`, `external_net`)
#: is `"block"`, so "in this set" and "denied on the way out" are the same
#: statement.
#:
#: It lives here, beside the table whose comment used to be the only record
#: of it ("when a credential is present"), because two ends need the same
#: fact and neither may guess it:
#:
#:   * `engine.py` gates the hard block on it;
#:   * `mcp_tools.apply_policy` refuses a `mask` rule whose selector is one
#:     of these, because such a rule *replaces* that deny with an executed,
#:     masked call — the one combination of rule type and selector that
#:     loosens enforcement rather than tightening it.
#:
#: Two literals would drift, and a drift here is silent in the direction
#: that matters: the refusal would stop covering a type the engine still
#: blocks. That is #38's defect exactly, and this branch withdrew a rule
#: type over it. `tests/test_mcp_surface.py::test_the_hard_block_set_has_one
#: _definition` pins the two readers to this object.
HARD_BLOCKED_DATA_TYPES = frozenset({"credential"})


class UnknownKey(KeyError):
    """A lookup missed the matrix.

    Raised rather than defaulting: an unmapped data type that silently scored
    zero would hide a real disclosure.
    """


@dataclass(frozen=True)
class Matrix:
    raw: dict
    version: str
    budget_cap: float
    bands: tuple[tuple[int, int, str], ...]

    def severity(self, data_type: str) -> float:
        try:
            return float(self.raw["severity"][data_type])
        except KeyError as exc:
            raise UnknownKey(f"no severity for data type {data_type!r}") from exc

    def multiplier(self, boundary: str) -> float:
        try:
            return float(self.raw["boundary_multiplier"][boundary])
        except KeyError as exc:
            raise UnknownKey(f"no multiplier for boundary {boundary!r}") from exc

    def boundary_for(self, destination: str) -> str:
        try:
            return self.raw["destination_boundary"][destination]
        except KeyError as exc:
            raise UnknownKey(f"no boundary for destination {destination!r}") from exc

    def classify(self, hook_event: str, direction: str) -> str:
        try:
            return self.raw["taxonomy"][f"{hook_event}/{direction}"]
        except KeyError as exc:
            raise UnknownKey(f"no classification for {hook_event}/{direction}") from exc

    def default_action(self, destination: str) -> str:
        try:
            return self.raw["policy_defaults"][destination]
        except KeyError as exc:
            raise UnknownKey(f"no default action for {destination!r}") from exc

    def band(self, percent: int) -> str:
        for lo, hi, name in self.bands:
            if lo <= percent <= hi:
                return name
        raise UnknownKey(f"no band for percent {percent}")


def load_matrix(path: Path | None = None) -> Matrix:
    data = tomllib.loads((path or DEFAULT_TABLES).read_text())
    bands = tuple((b["lo"], b["hi"], b["name"]) for b in data["bands"])
    return Matrix(
        raw=data,
        version=str(data["version"]),
        budget_cap=float(data["budget_cap"]),
        bands=bands,
    )
