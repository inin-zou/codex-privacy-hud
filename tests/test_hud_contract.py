# tests/test_hud_contract.py
"""Contract A (spec §4.1) and the shared rendering golden, pinned.

Two files under tests/matrix/ are read by code in two languages. This test is
what makes a change to either of them a deliberate act: the schema is checked
with a stdlib-only validator (the plugin has no dependencies and jsonschema is
not going to become one), and the golden is checked for the two properties the
Rust side depends on -- ten cells, and Python's round-half-to-even fill.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

MATRIX = Path(__file__).parent / "matrix"
SCHEMA = json.loads((MATRIX / "hud_snapshot.schema.json").read_text())
GOLDEN = json.loads((MATRIX / "hud_golden.json").read_text())

VALID = {"v": 1, "percent": 28, "blocked": 2, "unverified": False,
         "hidden": False, "updated_at": 1757900000.0}


def validate(doc: dict, schema: dict = SCHEMA) -> list[str]:
    """Minimal validator for exactly the subset of JSON Schema the contract
    uses: object, additionalProperties=false, required, integer/number/boolean,
    const, minimum, maximum. Returns a list of problems; empty means valid."""
    problems = []
    if not isinstance(doc, dict):
        return ["not an object"]
    props = schema["properties"]
    for key in schema["required"]:
        if key not in doc:
            problems.append(f"missing {key}")
    for key in doc:
        if key not in props:
            problems.append(f"unexpected {key}")
    for key, rule in props.items():
        if key not in doc:
            continue
        val = doc[key]
        t = rule["type"]
        if t == "integer" and not (isinstance(val, int) and not isinstance(val, bool)):
            problems.append(f"{key} not integer")
        elif t == "number" and not (isinstance(val, (int, float)) and not isinstance(val, bool)):
            problems.append(f"{key} not number")
        elif t == "boolean" and not isinstance(val, bool):
            problems.append(f"{key} not boolean")
        if "const" in rule and val != rule["const"]:
            problems.append(f"{key} != {rule['const']}")
        if "minimum" in rule and isinstance(val, (int, float)) and val < rule["minimum"]:
            problems.append(f"{key} below minimum")
        if "maximum" in rule and isinstance(val, (int, float)) and val > rule["maximum"]:
            problems.append(f"{key} above maximum")
    return problems


def test_schema_accepts_the_canonical_sample():
    assert validate(VALID) == []


@pytest.mark.parametrize("mutation", [
    {"v": 2},
    {"percent": 101},
    {"percent": -1},
    {"percent": 28.5},
    {"blocked": -1},
    {"unverified": "no"},
    {"hidden": 0},
    {"updated_at": "now"},
    {"note": "hello"},          # any string field is a contract violation (I1)
])
def test_schema_rejects_each_violation(mutation):
    doc = {**VALID, **mutation}
    assert validate(doc) != []


def test_schema_has_no_string_typed_field():
    types = {k: v["type"] for k, v in SCHEMA["properties"].items()}
    assert "string" not in types.values()
    assert SCHEMA["additionalProperties"] is False


def test_golden_covers_every_rounding_tie():
    # Python's round() is half-to-even; every x5 percent is a tie and the Rust
    # port must reproduce all ten of them.
    percents = {g["percent"] for g in GOLDEN}
    assert {5, 15, 25, 35, 45, 55, 65, 75, 85, 95} <= percents
    assert {0, 100} <= percents


def test_golden_core_shape():
    for g in GOLDEN:
        bar, pct = g["core"].split(" ", 1)
        assert len(bar) == 10 and set(bar) <= {"█", "░"}
        assert pct == f"{g['percent']:>2}%"
        assert bar.count("█") == round(g["percent"] / 10)


def test_patch_embeds_the_same_golden_file():
    patch = (Path(__file__).parents[1] / "patches" / "privacy-status-line.patch").read_text()
    expected = (MATRIX / "hud_golden.json").read_text().splitlines()
    # Every line of the golden must appear as an added line in the patch.
    added = {line[1:] for line in patch.splitlines() if line.startswith("+")}
    missing = [l for l in expected if l and l not in added]
    assert missing == [], missing
