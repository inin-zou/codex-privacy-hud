# tests/matrix/test_loader.py
import pytest
from privacy_hud.matrix.loader import load_matrix, UnknownKey


def test_version_and_cap_load():
    m = load_matrix()
    assert m.version == "1"
    assert m.budget_cap == 120.0


def test_severity_lookup():
    m = load_matrix()
    # Assert the loader reads what the table says, not a hardcoded number —
    # this is a policy-tunable weight and will be recalibrated again.
    assert m.severity("credential") == m.raw["severity"]["credential"]
    assert m.severity("email") == m.raw["severity"]["email"]
    # The semantic invariant that must survive any recalibration: a
    # credential is always weighted above a direct PII value like email.
    assert m.severity("credential") > m.severity("email")


def test_unknown_data_type_raises_not_zero():
    # Silently scoring 0 for an unmapped type would hide disclosures.
    m = load_matrix()
    with pytest.raises(UnknownKey):
        m.severity("passport_number")


def test_destination_maps_to_boundary_multiplier():
    m = load_matrix()
    assert m.boundary_for("mcp_tool") == "B3"
    assert m.multiplier(m.boundary_for("mcp_tool")) == 1.5


def test_classify_event():
    m = load_matrix()
    assert m.classify("PreToolUse", "blocked") == "prevented"
    assert m.classify("PostToolUse", "ingress") == "exposed"


def test_every_destination_boundary_has_a_multiplier():
    m = load_matrix()
    for boundary in m.raw["destination_boundary"].values():
        assert m.multiplier(boundary) >= 0.0


def test_bands_cover_zero_to_hundred_without_gaps():
    m = load_matrix()
    covered = sorted((lo, hi) for lo, hi, _ in m.bands)
    assert covered[0][0] == 0
    assert covered[-1][1] == 100
    for (_, prev_hi), (next_lo, _) in zip(covered, covered[1:]):
        assert next_lo == prev_hi + 1
