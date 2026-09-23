"""#54 Phase 3: the frozen, content-addressed scoring profile.

A version-2 session is scored against the profile it started with, not
against whatever `tables.toml` says later. These tests pin that the profile
is an independent deep copy of the matrix inputs, that its canonical JSON and
ID are stable, and that nothing invalid can be constructed or decoded.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from types import MappingProxyType
from typing import get_args

import pytest

from privacy_hud.accounting import (
    Boundary, DataType, DestinationKind, ScoringProfile,
)
from privacy_hud.matrix.loader import load_matrix

RULE = "first_crossing_max_severity_then_name_v1"
INVALID = "invalid scoring profile"


def _kwargs() -> dict:
    """Constructor arguments taken straight from the current matrix, without
    going through `from_matrix`."""
    m = load_matrix()
    return {
        "format_version": 1,
        "matrix_version": m.version,
        "budget_cap": m.budget_cap,
        "severity": dict(m.raw["severity"]),
        "boundary_multiplier": dict(m.raw["boundary_multiplier"]),
        "destination_boundary": dict(m.raw["destination_boundary"]),
        "bands": m.bands,
        "charged_type_rule": RULE,
    }


def _canonical(document: dict) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def test_profile_is_deeply_frozen_and_content_addressed():
    m = load_matrix()
    profile = ScoringProfile.from_matrix(m)
    text = profile.as_canonical_json()
    profile_id = profile.profile_id
    email, b3 = profile.severity["email"], profile.boundary_multiplier["B3"]
    cap, bands = profile.budget_cap, profile.bands

    m.raw["severity"]["email"] = 999.0
    m.raw["boundary_multiplier"]["B3"] = 99.0
    m.raw["destination_boundary"]["mcp_tool"] = "B4"
    m.raw["bands"][0]["hi"] = 50
    m.raw["budget_cap"] = 1.0

    assert profile.as_canonical_json() == text
    assert profile.profile_id == profile_id
    assert profile.severity["email"] == email == 6.0
    assert profile.boundary_multiplier["B3"] == b3 == 1.5
    assert profile.destination_boundary["mcp_tool"] == "B3"
    assert profile.budget_cap == cap == 120.0
    assert profile.bands == bands == ((0, 33, "safe"), (34, 66, "warn"),
                                      (67, 100, "danger"))
    assert profile_id == hashlib.sha256(text.encode("utf-8")).hexdigest()

    with pytest.raises(TypeError):
        profile.severity["email"] = 1.0  # type: ignore[index]
    with pytest.raises(TypeError):
        profile.boundary_multiplier["B1"] = 0.0  # type: ignore[index]
    with pytest.raises(TypeError):
        profile.destination_boundary["local"] = "B4"  # type: ignore[index]
    with pytest.raises(TypeError):
        profile.bands[0] = (0, 100, "safe")  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.budget_cap = 1.0  # type: ignore[misc]

    # Direct construction takes a copy too; it is not a way around freezing.
    kwargs = _kwargs()
    severity = kwargs["severity"]
    bands = [list(b) for b in kwargs["bands"]]
    kwargs["bands"] = bands
    direct = ScoringProfile(**kwargs)
    severity["email"] = 999.0
    bands[0][1] = 50
    assert isinstance(direct.severity, MappingProxyType)
    assert isinstance(direct.boundary_multiplier, MappingProxyType)
    assert isinstance(direct.destination_boundary, MappingProxyType)
    assert direct.severity["email"] == 6.0
    assert direct.bands == profile.bands
    assert direct.profile_id == profile_id


def test_profile_canonical_round_trip():
    profile = ScoringProfile.from_matrix(load_matrix())

    # Integer-valued weights and cap are the same numbers as their floats.
    kwargs = _kwargs()
    kwargs["budget_cap"] = 120
    kwargs["severity"] = {k: int(v) if float(v).is_integer() else v
                          for k, v in kwargs["severity"].items()}
    kwargs["boundary_multiplier"] = {
        k: int(v) if float(v).is_integer() else v
        for k, v in kwargs["boundary_multiplier"].items()}
    equivalent = ScoringProfile(**kwargs)
    assert equivalent.as_canonical_json() == profile.as_canonical_json()
    assert equivalent.profile_id == profile.profile_id
    assert equivalent == profile

    text = profile.as_canonical_json()
    expected = _canonical({
        "format_version": 1,
        "matrix_version": "1",
        "budget_cap": 120.0,
        "parameters": {
            "severity": {k: float(v) for k, v in _kwargs()["severity"].items()},
            "boundary_multiplier": {
                k: float(v)
                for k, v in _kwargs()["boundary_multiplier"].items()},
            "destination_boundary": _kwargs()["destination_boundary"],
            "bands": [{"lo": 0, "hi": 33, "name": "safe"},
                      {"lo": 34, "hi": 66, "name": "warn"},
                      {"lo": 67, "hi": 100, "name": "danger"}],
            "charged_type_rule": RULE,
        },
    })
    assert text == expected

    decoded = ScoringProfile.from_canonical_json(text)
    assert decoded == profile
    assert decoded.as_canonical_json() == text
    assert decoded.profile_id == profile.profile_id
    assert ScoringProfile.from_canonical_json(
        decoded.as_canonical_json()).as_canonical_json() == text

    # Not canonical text: the same document, differently spelled.
    with pytest.raises(ValueError, match=INVALID):
        ScoringProfile.from_canonical_json(
            json.dumps(json.loads(text), indent=2))


def _mutations():
    def band(bands):
        return lambda kw: kw.__setitem__("bands", bands)

    def drop(name, key):
        return lambda kw: kw[name].pop(key)

    def put(name, key, value):
        return lambda kw: kw[name].__setitem__(key, value)

    def top(name, value):
        return lambda kw: kw.__setitem__(name, value)

    return {
        "severity_missing": drop("severity", "repo"),
        "severity_extra": put("severity", "zipcode", 1.0),
        "severity_bool": put("severity", "email", True),
        "severity_negative": put("severity", "email", -1.0),
        "severity_nan": put("severity", "email", float("nan")),
        "severity_inf": put("severity", "email", float("inf")),
        "severity_string": put("severity", "email", "6"),
        "multiplier_missing": drop("boundary_multiplier", "B4"),
        "multiplier_extra": put("boundary_multiplier", "B5", 1.0),
        "multiplier_bool": put("boundary_multiplier", "B1", False),
        "multiplier_negative": put("boundary_multiplier", "B1", -0.5),
        "multiplier_inf": put("boundary_multiplier", "B1", float("inf")),
        "destination_missing": drop("destination_boundary", "local"),
        "destination_extra": put("destination_boundary", "email_out", "B1"),
        "destination_unknown_boundary": put(
            "destination_boundary", "mcp_tool", "B9"),
        "destination_bool": put("destination_boundary", "mcp_tool", True),
        "severity_not_a_map": top("severity", [("email", 6.0)]),
        "cap_zero": top("budget_cap", 0.0),
        "cap_negative": top("budget_cap", -1.0),
        "cap_too_large": top("budget_cap", 1e100),
        "cap_inf": top("budget_cap", float("inf")),
        "cap_nan": top("budget_cap", float("nan")),
        "cap_bool": top("budget_cap", True),
        "cap_string": top("budget_cap", "120"),
        "format_version": top("format_version", 2),
        "format_version_bool": top("format_version", True),
        "matrix_version_empty": top("matrix_version", ""),
        "matrix_version_not_text": top("matrix_version", 1),
        "rule": top("charged_type_rule", "last_crossing"),
        "bands_missing": band(((0, 50, "safe"), (51, 100, "warn"))),
        "bands_order": band(((0, 33, "warn"), (34, 66, "safe"),
                             (67, 100, "danger"))),
        "bands_gap": band(((0, 33, "safe"), (35, 66, "warn"),
                           (67, 100, "danger"))),
        "bands_overlap": band(((0, 34, "safe"), (34, 66, "warn"),
                               (67, 100, "danger"))),
        "bands_short": band(((0, 33, "safe"), (34, 66, "warn"),
                             (67, 99, "danger"))),
        "bands_not_from_zero": band(((1, 33, "safe"), (34, 66, "warn"),
                                     (67, 100, "danger"))),
        "bands_inverted": band(((0, 33, "safe"), (66, 34, "warn"),
                                (67, 100, "danger"))),
        "bands_float_bound": band(((0, 33.0, "safe"), (34, 66, "warn"),
                                   (67, 100, "danger"))),
        "bands_bool_bound": band(((False, 33, "safe"), (34, 66, "warn"),
                                  (67, 100, "danger"))),
        "bands_unknown_name": band(((0, 33, "safe"), (34, 66, "amber"),
                                    (67, 100, "danger"))),
        "bands_duplicate_name": band(((0, 33, "safe"), (34, 66, "safe"),
                                      (67, 100, "danger"))),
        "bands_wrong_arity": band(((0, 33), (34, 66, "warn"),
                                   (67, 100, "danger"))),
    }


_MUTATIONS = _mutations()

#: Defects of the JSON document itself rather than of a parameter value.
_DOCUMENT_EDITS = (
    "missing_parameters", "missing_bands", "extra_top_level",
    "extra_parameter", "created_at", "not_an_object", "not_json",
)


def _edited_document(edit: str) -> str:
    document = json.loads(
        ScoringProfile.from_matrix(load_matrix()).as_canonical_json())
    if edit == "missing_parameters":
        del document["parameters"]
    elif edit == "missing_bands":
        del document["parameters"]["bands"]
    elif edit == "extra_top_level":
        document["profile_id"] = "0" * 64
    elif edit == "extra_parameter":
        document["parameters"]["taxonomy"] = {}
    elif edit == "created_at":
        document["created_at"] = 1
    elif edit == "not_an_object":
        return _canonical([document])  # type: ignore[arg-type]
    elif edit == "not_json":
        return "{"
    return _canonical(document)


@pytest.mark.parametrize(
    "case", sorted(_MUTATIONS) + [f"document_{e}" for e in _DOCUMENT_EDITS])
def test_profile_rejects_invalid_or_nonfinite_parameters(case):
    valid = ScoringProfile(**_kwargs())
    assert valid.profile_id == ScoringProfile.from_matrix(
        load_matrix()).profile_id

    if case.startswith("document_"):
        with pytest.raises(ValueError, match=INVALID):
            ScoringProfile.from_canonical_json(
                _edited_document(case.removeprefix("document_")))
        return

    kwargs = _kwargs()
    _MUTATIONS[case](kwargs)
    with pytest.raises(ValueError, match=INVALID):
        ScoringProfile(**kwargs)

    # The same defect cannot be decoded from JSON either. The document is
    # spelled canonically where JSON can express it, so only its content is
    # wrong.
    document = json.loads(valid.as_canonical_json())
    params = document["parameters"]
    for name in ("severity", "boundary_multiplier", "destination_boundary"):
        params[name] = kwargs[name]
    params["bands"] = (
        [{"lo": b[0], "hi": b[1], "name": b[2]} if len(b) == 3
         else {"lo": b[0], "hi": b[1]} for b in kwargs["bands"]])
    params["charged_type_rule"] = kwargs["charged_type_rule"]
    document["budget_cap"] = kwargs["budget_cap"]
    document["format_version"] = kwargs["format_version"]
    document["matrix_version"] = kwargs["matrix_version"]
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    with pytest.raises(ValueError, match=INVALID):
        ScoringProfile.from_canonical_json(text)


def test_profile_json_rejects_duplicate_keys():
    text = ScoringProfile.from_matrix(load_matrix()).as_canonical_json()
    duplicated = {
        "top_level": text.replace('{"budget_cap":120.0,',
                                  '{"budget_cap":120.0,"budget_cap":120.0,', 1),
        "severity": text.replace('"email":6.0,', '"email":6.0,"email":7.0,', 1),
        "destination": text.replace('"local":"B0",',
                                    '"local":"B0","local":"B4",', 1),
        "band": text.replace('{"hi":33,"lo":0,', '{"hi":33,"lo":0,"lo":0,', 1),
    }
    for name, candidate in duplicated.items():
        assert candidate != text, name
        with pytest.raises(ValueError, match=INVALID):
            ScoringProfile.from_canonical_json(candidate)
    for bad in ('NaN', 'Infinity', '-Infinity'):
        with pytest.raises(ValueError, match=INVALID):
            ScoringProfile.from_canonical_json(
                text.replace('"email":6.0', f'"email":{bad}', 1))


def test_profile_contains_complete_current_matrix_inputs():
    m = load_matrix()
    profile = ScoringProfile.from_matrix(m)
    assert profile.format_version == 1
    assert profile.matrix_version == m.version == "1"
    assert profile.budget_cap == m.budget_cap == 120.0
    assert profile.charged_type_rule == RULE

    assert len(get_args(DataType)) == 15
    assert set(profile.severity) == set(get_args(DataType))
    for data_type in get_args(DataType):
        assert profile.severity[data_type] == m.severity(data_type)
        assert type(profile.severity[data_type]) is float

    assert len(get_args(Boundary)) == 5
    assert set(profile.boundary_multiplier) == set(get_args(Boundary))
    for boundary in get_args(Boundary):
        assert profile.boundary_multiplier[boundary] == m.multiplier(boundary)

    assert len(get_args(DestinationKind)) == 5
    assert set(profile.destination_boundary) == set(get_args(DestinationKind))
    for destination in get_args(DestinationKind):
        assert (profile.destination_boundary[destination]
                == m.boundary_for(destination))

    assert profile.bands == m.bands
    assert len(profile.bands) == 3
