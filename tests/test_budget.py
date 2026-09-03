import math
import pytest
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.budget import volume, contribution, percent, Budget

M = load_matrix()


def test_volume_is_one_plus_log():
    assert volume(1) == 1.0
    assert volume(12) == pytest.approx(1 + math.log(12))


def test_contribution_multiplies_severity_volume_destination():
    # email(6) * volume(1)=1 * mcp_tool boundary B3 (1.5) == 9.0
    assert contribution(M, "email", 1, "mcp_tool") == pytest.approx(9.0)


def test_invariant_prevented_contributes_zero():
    # Prevented events never reach contribution(); local destination is B0 == 0.0
    assert contribution(M, "credential", 99, "local") == 0.0


def test_invariant_one_credential_never_reads_as_safe():
    pct = percent(contribution(M, "credential", 1, "model_context"), M.budget_cap)
    assert M.band(pct) != "safe"
    pct_external = percent(contribution(M, "credential", 1, "external_net"), M.budget_cap)
    assert M.band(pct_external) == "danger"


def test_invariant_budget_is_monotonic():
    b = Budget()
    b.add(10.0)
    with pytest.raises(ValueError):
        b.add(-1.0)
    assert b.score == 10.0


def test_percent_clamps_at_hundred():
    assert percent(10_000.0, 120.0) == 100
    assert percent(0.0, 120.0) == 0
