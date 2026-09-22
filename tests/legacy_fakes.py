"""Legacy readings for tests that need one without a ledger.

`HudPublisher.publish` takes a summary and `render.hud_line` takes a
snapshot reading (#54 phase 1). Tests that used to pass a bare percentage
and prevented count build the equivalent legacy objects here, so the
arithmetic they assert on is the one they state.
"""
from __future__ import annotations

from privacy_hud.hud_snapshot import Snapshot
from privacy_hud.ledger import LEGACY_SCORE_LABEL, LegacySessionSummary
from privacy_hud.render import hud_line


def legacy_summary(percent: int, prevented_rows: int = 0) -> LegacySessionSummary:
    return LegacySessionSummary(
        accounting_version=1, legacy_score=percent * 1.2, legacy_cap=120.0,
        legacy_percent=percent, legacy_permitted_crossing_rows=0,
        legacy_boundary_kinds=0, legacy_prevented_rows=prevented_rows,
        score_label=LEGACY_SCORE_LABEL)


def legacy_reading(percent: int, prevented_rows: int = 0, *,
                   unverified: bool = False) -> Snapshot:
    return Snapshot(accounting_version=1, percent=percent,
                    confirmed_points=None, denials_issued=None,
                    legacy_prevented_rows=prevented_rows,
                    unresolved_actions=None, unverified=unverified,
                    hidden=False, updated_at=0.0)


def legacy_line(percent: int, width: int, prevented_rows: int = 0, *,
                unverified: bool = False) -> str:
    return hud_line(legacy_reading(percent, prevented_rows,
                                   unverified=unverified), width)
