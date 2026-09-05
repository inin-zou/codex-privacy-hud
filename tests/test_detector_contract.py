"""The `Detector` contract: a detector declares its own tier and cost.

These are the tests for the defect the tier/cost refactor closes. Before it,
`engine._is_tier3_detector()` inferred "this is the expensive model tier"
from `hasattr(detector, "available")`, which conflated three independent
facts:

  * what the detector *is*        (its tier in the taxonomy)
  * what one scan *costs*         (whether the engine may run it on every
                                   observation, or must gate it behind the
                                   boundary check, the size cap and
                                   `_TIER3_LOCK`)
  * whether it can work right now (availability — weights present, ruleset
                                   compiled, optional config readable)

Two silent misclassifications followed, and both are pinned below:

  1. A *cheap* detector that happens to track availability — a perfectly
     ordinary thing for a detector needing an optional ruleset — was
     reclassified as tier 3. It stopped running on local destinations and on
     B3/B4, and got skipped past the size cap. Nothing errored; it just
     quietly stopped seeing most of the traffic it was written for.
  2. An *expensive* detector that does not expose `available` ran
     unconditionally on every observation, local reads included, with no
     size cap and no serialization — the exact synchronous-latency risk
     Ruling 4 exists to bound.

Both are now decided by a declaration the detector makes about itself, and
a detector that makes no declaration is rejected loudly at wiring time
rather than silently sorted into whichever class the sniff happens to pick.
"""
from __future__ import annotations

import pytest

from privacy_hud.detect.base import (
    Cost,
    DetectorProfile,
    UndeclaredDetector,
    Finding,
    is_available,
    profile_of,
)
from privacy_hud.detect.model import ModelDetector, StubModelDetector
from privacy_hud.detect.paths import PathDetector
from privacy_hud.detect.secrets import SecretDetector
from privacy_hud.engine import MAX_TIER3_CHARS, Engine, Observation
from privacy_hud.ledger import Ledger
from privacy_hud.mask import new_salt
from privacy_hud.matrix.loader import load_matrix

M = load_matrix()

TEXT = "contact jordan@acme.com .env sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm"


def _engine(tmp_path, detectors, name="l"):
    led = Ledger(tmp_path / f"{name}.db", M)
    led.start_session("s1", cwd="/r", model="gpt-5")
    return Engine(ledger=led, matrix=M, salt=new_salt(), detectors=detectors)


def _obs(**kw):
    base = dict(session_id="s1", turn_id="t1", hook_event="PostToolUse",
                direction="ingress", source="support.log",
                destination="model_context", text=TEXT, tool_name="Read")
    base.update(kw)
    return Observation(**base)


class _CheapDetectorThatTracksAvailability:
    """The detector that used to be misfiled as tier 3.

    Nothing model-shaped about it: a compiled ruleset it loads from an
    optional config file, so it knows whether it can work — and that is the
    *only* reason it has an `available` attribute. It is microseconds per
    scan and must run on every observation, local reads included.
    """

    profile = DetectorProfile(tier=2, cost=Cost.CHEAP)

    def __init__(self, available: bool = True):
        self.available = available
        self.calls = 0

    def scan(self, text: str, ctx: dict) -> list[Finding]:
        self.calls += 1
        return [Finding("repo", "acme/api", 0, 0)] if "contact" in text else []


class _ExpensiveDetectorWithoutAvailability:
    """The mirror-image defect: something genuinely expensive (a second
    model, an out-of-process classifier) that simply never fails to load,
    so it has no `available` flag to sniff for. It used to run
    unconditionally on every observation."""

    profile = DetectorProfile(tier=3, cost=Cost.EXPENSIVE)

    def __init__(self):
        self.calls = 0

    def scan(self, text: str, ctx: dict) -> list[Finding]:
        self.calls += 1
        return []


class _DetectorWithNoProfile:
    """A new detector whose author forgot to declare a tier."""

    def scan(self, text: str, ctx: dict) -> list[Finding]:
        return []


# ---------------------------------------------------------------------------
# Defect 1 — a cheap detector that tracks availability is not tier 3.
# ---------------------------------------------------------------------------

def test_cheap_detector_with_available_attribute_still_runs_on_local(tmp_path):
    cheap = _CheapDetectorThatTracksAvailability()
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(), cheap])
    scan = eng.scan(_obs(destination="local"))
    assert scan.boundary == "B0"
    assert cheap.calls == 1
    assert "repo" in {f.data_type for f in scan.findings}


@pytest.mark.parametrize("destination", ["local", "mcp_tool", "external_net"])
def test_cheap_detector_with_available_attribute_runs_where_tier3_may_not(
        tmp_path, destination):
    cheap = _CheapDetectorThatTracksAvailability()
    eng = _engine(tmp_path, [cheap], name=f"l-{destination}")
    eng.scan(_obs(destination=destination))
    assert cheap.calls == 1


def test_cheap_detector_with_available_attribute_is_not_capped_by_size(tmp_path):
    cheap = _CheapDetectorThatTracksAvailability()
    eng = _engine(tmp_path, [cheap])
    scan = eng.scan(_obs(text=TEXT + "x" * MAX_TIER3_CHARS))
    assert cheap.calls == 1
    # And its absence-of-weights story is its own business: a cheap
    # detector never flies the "deep scan unavailable" banner.
    assert scan.degraded is False


def test_an_unavailable_cheap_detector_does_not_degrade_the_deep_scan(tmp_path):
    """`degraded` is a statement about the *deep scan*, which is what
    design.md §5's banner names. A cheap detector that cannot load its
    optional ruleset must not make the HUD claim the model tier is down."""
    cheap = _CheapDetectorThatTracksAvailability(available=False)
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(), cheap,
                             StubModelDetector([("email", "jordan@acme.com", 8, 23)])])
    scan = eng.scan(_obs())
    assert scan.degraded is False
    assert "email" in {f.data_type for f in scan.findings}


# ---------------------------------------------------------------------------
# Defect 2 — an expensive detector without `available` is still cost-gated.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("destination", ["local", "mcp_tool", "external_net"])
def test_expensive_detector_without_available_is_skipped_where_tier3_is(
        tmp_path, destination):
    pricey = _ExpensiveDetectorWithoutAvailability()
    eng = _engine(tmp_path, [pricey], name=f"l-{destination}")
    eng.scan(_obs(destination=destination))
    assert pricey.calls == 0


def test_expensive_detector_without_available_obeys_the_size_cap(tmp_path):
    pricey = _ExpensiveDetectorWithoutAvailability()
    eng = _engine(tmp_path, [pricey])
    scan = eng.scan(_obs(text=TEXT + "x" * MAX_TIER3_CHARS))
    assert pricey.calls == 0
    assert scan.degraded is True


def test_expensive_detector_without_available_still_runs_where_it_should(tmp_path):
    pricey = _ExpensiveDetectorWithoutAvailability()
    eng = _engine(tmp_path, [pricey])
    scan = eng.scan(_obs(destination="model_context"))
    assert pricey.calls == 1
    assert scan.degraded is False


# ---------------------------------------------------------------------------
# A forgotten declaration fails loudly, at wiring time.
# ---------------------------------------------------------------------------

def test_detector_with_no_declared_profile_is_rejected_at_engine_construction(tmp_path):
    led = Ledger(tmp_path / "l.db", M)
    led.start_session("s1", cwd="/r", model="gpt-5")
    with pytest.raises(UndeclaredDetector) as exc:
        Engine(ledger=led, matrix=M, salt=new_salt(),
               detectors=[PathDetector(), _DetectorWithNoProfile()])
    # The message must name the offender and say what to add; a loud
    # failure nobody can act on is only marginally better than a quiet one.
    assert "_DetectorWithNoProfile" in str(exc.value)
    assert "DetectorProfile" in str(exc.value)


def test_a_profile_lookalike_is_rejected_rather_than_duck_typed(tmp_path):
    """Accepting anything with a `.cost` attribute would reintroduce
    attribute sniffing one level up. The declaration is a
    `DetectorProfile` or it is not a declaration."""

    class _Lookalike:
        profile = "tier 3, expensive"

        def scan(self, text, ctx):
            return []

    led = Ledger(tmp_path / "l.db", M)
    led.start_session("s1", cwd="/r", model="gpt-5")
    with pytest.raises(UndeclaredDetector):
        Engine(ledger=led, matrix=M, salt=new_salt(), detectors=[_Lookalike()])


def test_profile_of_rejects_an_undeclared_detector():
    with pytest.raises(UndeclaredDetector):
        profile_of(_DetectorWithNoProfile())


def test_a_detector_swapped_in_after_construction_is_also_checked(tmp_path):
    """`dispatch` and the daemon tests both assemble the detector list on a
    shared `State` and hand it to freshly constructed Engines, but nothing
    stops a caller reassigning `engine.detectors`. The scan path re-reads
    the declaration rather than trusting a partition cached at
    construction, so that route fails loudly too."""
    eng = _engine(tmp_path, [PathDetector()])
    eng.detectors = [_DetectorWithNoProfile()]
    with pytest.raises(UndeclaredDetector):
        eng.scan(_obs())


# ---------------------------------------------------------------------------
# The shipped stack declares itself, and availability stays a separate axis.
# ---------------------------------------------------------------------------

def test_shipped_detectors_declare_tier_and_cost():
    # Read off the classes, not instances: constructing a `ModelDetector`
    # loads 1.5B parameters, and the declaration must not depend on that
    # having succeeded.
    assert PathDetector.profile == DetectorProfile(tier=0, cost=Cost.CHEAP)
    assert SecretDetector.profile == DetectorProfile(tier=1, cost=Cost.CHEAP)
    assert ModelDetector.profile == DetectorProfile(tier=3, cost=Cost.EXPENSIVE)
    assert StubModelDetector.profile == DetectorProfile(tier=3, cost=Cost.EXPENSIVE)


def test_the_stub_declares_the_same_profile_as_the_thing_it_stands_in_for():
    """A test double that is scheduled differently from the real detector
    makes every test using it a fiction."""
    assert StubModelDetector.profile == ModelDetector.profile


def test_tier_and_availability_are_independent_axes():
    # Cheap detectors may or may not track availability...
    assert is_available(PathDetector()) is True          # no flag: assumed usable
    assert is_available(_CheapDetectorThatTracksAvailability()) is True
    assert is_available(_CheapDetectorThatTracksAvailability(available=False)) is False
    # ...and an expensive one may or may not either.
    assert is_available(_ExpensiveDetectorWithoutAvailability()) is True
    stub = StubModelDetector([])
    assert is_available(stub) is True
    stub.available = False
    assert is_available(stub) is False


def test_a_detector_profile_is_immutable():
    """The declaration is read on every scan from a shared, process-wide
    detector list; it must not be something one session can rewrite for
    every other session."""
    with pytest.raises(Exception):
        PathDetector.profile.tier = 3


def test_default_detectors_are_all_declared_and_ordered_by_tier():
    from privacy_hud.detect import default_detectors

    detectors = default_detectors()
    profiles = [profile_of(d) for d in detectors]
    assert [p.tier for p in profiles] == sorted(p.tier for p in profiles)
    assert [p.cost for p in profiles] == [Cost.CHEAP, Cost.CHEAP, Cost.EXPENSIVE]
