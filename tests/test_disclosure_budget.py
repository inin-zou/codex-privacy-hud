"""#54 Phase 3: grouped disclosure math.

Version-2 accounting charges a group — one data type sent to one recipient —
by `F(n) = severity * multiplier * (1 + ln n)`, with `F(0) = 0`, and each new
disclosure adds `F(n+1) - F(n)`. The legacy per-row `contribution` stays as
it is; these are separate functions.
"""
from __future__ import annotations

import math
from typing import get_args

import pytest

from privacy_hud.accounting import DestinationKind, ScoringProfile
from privacy_hud.budget import (
    contribution, group_score, next_disclosure_delta, percent,
)
from privacy_hud.matrix.loader import load_matrix

INVALID = "invalid disclosure score"


def _profile(**severity_or_multiplier) -> ScoringProfile:
    base = ScoringProfile.from_matrix(load_matrix())
    if not severity_or_multiplier:
        return base
    severity = dict(base.severity)
    multiplier = dict(base.boundary_multiplier)
    for key, value in severity_or_multiplier.items():
        (multiplier if key.startswith("B") else severity)[key] = value
    return ScoringProfile(
        format_version=1, matrix_version=base.matrix_version,
        budget_cap=base.budget_cap, severity=severity,
        boundary_multiplier=multiplier,
        destination_boundary=dict(base.destination_boundary),
        bands=base.bands, charged_type_rule=base.charged_type_rule)


def test_group_score_zero_and_sublinear_increment():
    profile = _profile()
    for destination in get_args(DestinationKind):
        for data_type in ("credential", "email", "url"):
            assert group_score(profile, data_type, destination, 0) == 0.0
            weight = (profile.severity[data_type]
                      * profile.boundary_multiplier[
                          profile.destination_boundary[destination]])
            deltas = [next_disclosure_delta(profile, data_type, destination, n)
                      for n in range(0, 30)]
            if weight == 0.0:
                assert deltas == [0.0] * 30
                assert group_score(profile, data_type, destination, 7) == 0.0
                continue
            assert deltas[0] == pytest.approx(weight)
            assert all(d > 0 for d in deltas)
            assert all(a > b for a, b in zip(deltas, deltas[1:], strict=False))
            for n, delta in enumerate(deltas):
                assert delta == pytest.approx(
                    group_score(profile, data_type, destination, n + 1)
                    - group_score(profile, data_type, destination, n))

    # Keys are validated even when there is nothing to score.
    for data_type, destination in (("zipcode", "model_context"),
                                   ("email", "nowhere"), (None, "local")):
        with pytest.raises(ValueError, match=INVALID):
            group_score(profile, data_type, destination, 0)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match=INVALID):
            next_disclosure_delta(profile, data_type, destination, 0)  # type: ignore[arg-type]


def test_group_score_rejects_invalid_counts():
    profile = _profile()
    for n in (-1, 1.5, 2.0, True, False, "3", None):
        with pytest.raises(ValueError, match=INVALID):
            group_score(profile, "email", "model_context", n)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match=INVALID):
            next_disclosure_delta(profile, "email", "model_context", n)  # type: ignore[arg-type]


def test_twelve_confirmed_b1_emails_are_20_91_points():
    profile = _profile()
    score = group_score(profile, "email", "model_context", 12)
    assert score == pytest.approx(20.909439898728, abs=1e-9)
    assert percent(score, profile.budget_cap) == 17
    assert sum(next_disclosure_delta(profile, "email", "model_context", n)
               for n in range(12)) == pytest.approx(score, rel=1e-12, abs=1e-12)
    # The legacy per-row arithmetic is unchanged and is not this.
    assert 12 * contribution(load_matrix(), "email", 1, "model_context") == 72.0


def test_second_mcp_recipient_has_a_separate_group():
    profile = _profile()
    one_recipient = group_score(profile, "email", "mcp_tool", 12)
    two_recipients = one_recipient + group_score(profile, "email", "mcp_tool", 12)
    expected = 2 * 1.5 * group_score(profile, "email", "model_context", 12)
    assert two_recipients == pytest.approx(expected, rel=1e-12, abs=1e-12)
    charged = sum(next_disclosure_delta(profile, "email", "mcp_tool", n)
                  for _recipient in range(2) for n in range(12))
    assert charged == pytest.approx(expected, rel=1e-12, abs=1e-12)
    # One group of 24 would be less: grouping is per recipient.
    assert group_score(profile, "email", "mcp_tool", 24) < expected


def test_scoring_rejects_nonfinite_or_unstorable_results():
    storable = _profile(email=1e99)
    assert group_score(storable, "email", "model_context", 1) == 1e99

    over_limit = _profile(email=1e99, B1=20.0)
    overflow = _profile(email=1e200, B1=1e200)
    # 1e99 * (1 + ln 10_000) is just over 1e100.
    for profile, n in ((over_limit, 1), (overflow, 1), (storable, 10_000)):
        with pytest.raises(ValueError, match=INVALID):
            group_score(profile, "email", "model_context", n)
    for profile, n in ((over_limit, 0), (overflow, 0), (storable, 9_999)):
        with pytest.raises(ValueError, match=INVALID):
            next_disclosure_delta(profile, "email", "model_context", n)
    assert math.isfinite(next_disclosure_delta(storable, "email",
                                               "model_context", 0))
