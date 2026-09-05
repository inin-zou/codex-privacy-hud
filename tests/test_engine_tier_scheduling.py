"""Characterization tests for *which detectors the engine runs, when*.

Written before the `Detector` tier/cost refactor and deliberately phrased
against observable behavior only — `Engine.scan()`'s findings and
`degraded` flag, and the ledger rows `observe()` produces. Nothing here
names `_is_tier3_detector`, `hasattr`, or any other mechanism, so the file
is a fixed point: it pins the scheduling contract, not the implementation
that happens to satisfy it today.

If a change to the detector stack makes one of these fail, the change
altered *which detectors run for which observations*. That is a behavior
change, not a rebaseline — the whole point of Ruling 4 and of
architecture.md's "never on local" is that the expensive tier's schedule is
a deliberate, auditable decision rather than an emergent one.

Why `scan()` rather than `observe()` for most of it: `scan()` is the phase
that does detection and nothing else (no policy, no ledger, no salt), so a
`ScanResult` is the most direct statement of "these detectors ran on this
observation". A handful of tests below go through `observe()` as well,
because the ledger rows are what a user actually sees and they must agree.
"""
from __future__ import annotations

import pytest

from privacy_hud.detect.model import StubModelDetector
from privacy_hud.detect.paths import PathDetector
from privacy_hud.detect.secrets import SecretDetector
from privacy_hud.engine import MAX_TIER3_CHARS, Engine, Observation
from privacy_hud.ledger import Ledger
from privacy_hud.mask import new_salt
from privacy_hud.matrix.loader import load_matrix

M = load_matrix()

# One text that every tier finds something different in, so a single scan
# says which tiers ran:
#   tier 0 (PathDetector)   -> "path"        (".env")
#   tier 1 (SecretDetector) -> "credential"  (the sk- key)
#   tier 3 (the stub)       -> "email"       ("jordan@acme.com" at [8:23])
# The stub only fires when text[8:23] == "jordan@acme.com" holds exactly
# (its offset invariant), so "contact " must stay 8 characters long.
TEXT = "contact jordan@acme.com .env sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm"
EMAIL_FINDING = ("email", "jordan@acme.com", 8, 23)

CHEAP_TYPES = {"path", "credential"}
TIER3_TYPE = "email"


def _engine(tmp_path, detectors, name="l"):
    led = Ledger(tmp_path / f"{name}.db", M)
    led.start_session("s1", cwd="/r", model="gpt-5")
    return Engine(ledger=led, matrix=M, salt=new_salt(), detectors=detectors)


def _full_stack(tmp_path, name="l"):
    return _engine(tmp_path, [PathDetector(), SecretDetector(),
                              StubModelDetector([EMAIL_FINDING])], name=name)


def _obs(**kw):
    base = dict(session_id="s1", turn_id="t1", hook_event="PostToolUse",
                direction="ingress", source="support.log",
                destination="model_context", text=TEXT, tool_name="Read")
    base.update(kw)
    return Observation(**base)


def _types(scan):
    return {f.data_type for f in scan.findings}


# ---------------------------------------------------------------------------
# The (destination kind, boundary) schedule for the expensive tier.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("destination,boundary", [
    ("model_context", "B1"),
    ("subagent", "B2"),
])
def test_tier3_runs_for_b1_and_b2_destinations(tmp_path, destination, boundary):
    scan = _full_stack(tmp_path).scan(_obs(destination=destination))
    assert scan.boundary == boundary
    assert TIER3_TYPE in _types(scan)
    assert scan.degraded is False


@pytest.mark.parametrize("destination,boundary", [
    ("local", "B0"),
    ("mcp_tool", "B3"),
    ("external_net", "B4"),
])
def test_tier3_is_skipped_for_local_and_for_b3_b4(tmp_path, destination, boundary):
    scan = _full_stack(tmp_path).scan(_obs(destination=destination))
    assert scan.boundary == boundary
    assert TIER3_TYPE not in _types(scan)


@pytest.mark.parametrize("destination", ["local", "mcp_tool", "external_net"])
def test_skipping_tier3_by_schedule_does_not_mark_the_scan_degraded(
        tmp_path, destination):
    """`degraded` means "the deep scan would have applied here and did not
    run", not "the deep scan did not run". A local read or a B3/B4 egress
    is *out of the deep scan's domain by design*, so surfacing design.md
    §5's "fast-path results only" banner for it would tell the user the
    tool is impaired when it is behaving exactly as specified."""
    scan = _full_stack(tmp_path).scan(_obs(destination=destination))
    assert scan.degraded is False


@pytest.mark.parametrize("destination", ["local", "model_context", "subagent",
                                          "mcp_tool", "external_net"])
def test_cheap_tiers_run_for_every_destination_and_boundary(tmp_path, destination):
    """Tiers 0-2 are unconditional. No boundary, and no size, turns them off."""
    scan = _full_stack(tmp_path).scan(_obs(destination=destination))
    assert CHEAP_TYPES <= _types(scan)


def test_detection_order_is_cheap_tiers_first_then_the_expensive_tier(tmp_path):
    """Pinned because the ledger records findings in this order, so a
    reshuffle is user-visible in `list_events` and in every masked
    exemplar's row order."""
    scan = _full_stack(tmp_path).scan(_obs())
    assert [f.data_type for f in scan.findings] == ["path", "credential", "email"]


# ---------------------------------------------------------------------------
# Ruling 4's size cap: degrade, never truncate-and-scan.
# ---------------------------------------------------------------------------

def test_oversized_payload_degrades_instead_of_scanning(tmp_path):
    big = TEXT + ("x" * MAX_TIER3_CHARS)
    scan = _full_stack(tmp_path).scan(_obs(text=big))
    assert len(big) > MAX_TIER3_CHARS
    assert scan.degraded is True
    assert TIER3_TYPE not in _types(scan)
    # ... and the cheap tiers are untouched by the cap.
    assert CHEAP_TYPES <= _types(scan)


def test_payload_exactly_at_the_cap_still_runs_the_expensive_tier(tmp_path):
    """The bound is `> MAX_TIER3_CHARS`, not `>=`. Pinned so a refactor
    cannot quietly move the boundary by one character."""
    text = TEXT + ("x" * (MAX_TIER3_CHARS - len(TEXT)))
    assert len(text) == MAX_TIER3_CHARS
    scan = _full_stack(tmp_path).scan(_obs(text=text))
    assert scan.degraded is False
    assert TIER3_TYPE in _types(scan)


def test_the_cap_does_not_apply_where_the_expensive_tier_is_out_of_scope(tmp_path):
    """An oversized *local* read is not degraded: tier 3 was never going to
    run there, so there is nothing lost to report."""
    scan = _full_stack(tmp_path).scan(
        _obs(destination="local", text=TEXT + ("x" * MAX_TIER3_CHARS)))
    assert scan.degraded is False


# ---------------------------------------------------------------------------
# Availability: a tier-3 detector that cannot work degrades the scan.
# ---------------------------------------------------------------------------

def test_unavailable_expensive_detector_marks_the_scan_degraded(tmp_path):
    stub = StubModelDetector([EMAIL_FINDING])
    stub.available = False          # the no-weights case ModelDetector reports
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(), stub])
    scan = eng.scan(_obs())
    assert scan.degraded is True
    assert TIER3_TYPE not in _types(scan)
    assert CHEAP_TYPES <= _types(scan)


def test_one_available_expensive_detector_is_enough_to_avoid_degrading(tmp_path):
    dead = StubModelDetector([EMAIL_FINDING])
    dead.available = False
    live = StubModelDetector([EMAIL_FINDING])
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(), dead, live])
    scan = eng.scan(_obs())
    assert scan.degraded is False
    assert TIER3_TYPE in _types(scan)


def test_an_engine_with_no_expensive_detector_at_all_is_not_degraded(tmp_path):
    """No deep scan was configured, so no deep scan is missing. This is the
    tiers-0-2-only deployment, and it must not permanently fly the
    "fast-path results only" banner."""
    eng = _engine(tmp_path, [PathDetector(), SecretDetector()])
    scan = eng.scan(_obs())
    assert scan.degraded is False
    assert _types(scan) == CHEAP_TYPES


# ---------------------------------------------------------------------------
# The same schedule, seen from the ledger (what the user actually reads).
# ---------------------------------------------------------------------------

def test_ledger_shows_tier3_findings_on_ingress_to_model_context(tmp_path):
    eng = _full_stack(tmp_path)
    eng.observe(_obs())
    types = {r.data_type for r in eng.ledger.list_events("s1", "exposed")}
    assert types == CHEAP_TYPES | {TIER3_TYPE}


def test_ledger_shows_only_cheap_tier_findings_for_a_local_read(tmp_path):
    eng = _full_stack(tmp_path)
    d = eng.observe(_obs(destination="local"))
    types = {r.data_type for r in eng.ledger.list_events("s1", "local_access")}
    assert types == CHEAP_TYPES
    # I3: a local read is local_access, never an exposure, and the budget
    # does not move for it.
    assert eng.ledger.list_events("s1", "exposed") == []
    assert d.budget_percent == 0


def test_oversized_ingress_records_cheap_findings_and_reports_degraded(tmp_path):
    eng = _full_stack(tmp_path)
    d = eng.observe(_obs(text=TEXT + ("x" * MAX_TIER3_CHARS)))
    assert d.degraded is True
    types = {r.data_type for r in eng.ledger.list_events("s1", "exposed")}
    assert types == CHEAP_TYPES
