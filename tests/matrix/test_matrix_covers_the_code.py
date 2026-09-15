# tests/matrix/test_matrix_covers_the_code.py
"""Every key the code can look up has a row in tables.toml.

`Matrix` raises `UnknownKey` rather than scoring zero for an unmapped key
(`loader.py:16-21`), which is the right choice and is also why the cost of a
missing row is paid in a user's session instead of here: adding a label to
`LABEL_MAP`, or a pattern with a new `data_type`, is a one-line change that
every existing test still passes. These tests enumerate the keys the detectors
and the dispatcher can actually produce and assert the table answers for each.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from privacy_hud.detect.model import LABEL_MAP
from privacy_hud.dispatch import _KNOWN_EVENTS
from privacy_hud.matrix.loader import load_matrix

DETECT = Path(__file__).resolve().parents[2] / "src" / "privacy_hud" / "detect"


def _literal_finding_types(module: str) -> set[str]:
    """The `data_type` strings a regex detector hands to `Finding(...)`, by AST.

    The regex detectors name their type inline at the construction site rather
    than in a table, so the construction site is where the value lives. Parsed
    rather than obtained by running the detector over sample text, which would
    only find the types the samples happen to trigger.
    """
    tree = ast.parse((DETECT / module).read_text(encoding="utf-8"), module)
    return {node.args[0].value for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Finding"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)}


def _detector_data_types() -> set[str]:
    types = set(LABEL_MAP.values())
    for module in ("paths.py", "secrets.py"):
        found = _literal_finding_types(module)
        assert found, f"no literal Finding data type in detect/{module}"
        types |= found
    return types


@pytest.mark.parametrize("data_type", sorted(_detector_data_types()))
def test_every_detector_data_type_has_a_severity_row(data_type):
    """A `Finding` whose type has no `[severity]` row raises `UnknownKey` the
    first time a real payload contains that kind of value — inside the daemon,
    mid-session, on the hot path of a tool call. The three detectors and the
    table are edited independently (a model release changes `LABEL_MAP`, a
    regex is added to `paths.py`), so the only thing keeping them in step is
    this assertion."""
    load_matrix().severity(data_type)


def test_taxonomy_covers_every_event_dispatch_maps():
    """`[taxonomy]` keys are `<hook_event>/<direction>`, and every event with a
    pinned `Observation` mapping reaches `Matrix.classify`. An event added to
    `dispatch._KNOWN_EVENTS` without a taxonomy row raises `UnknownKey` for
    exactly the events that get as far as the engine — the sort of partial
    failure that looks like a flake."""
    events = {key.split("/", 1)[0] for key in load_matrix().raw["taxonomy"]}
    assert _KNOWN_EVENTS <= events
