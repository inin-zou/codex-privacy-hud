"""The detector contract: what a `Finding` is, and what a `Detector` must
declare about itself before the engine will schedule it.

Why a detector declares its own tier and cost
---------------------------------------------
`Engine._scan()` does not treat all detectors alike. Some are microseconds
of compiled regex and run on every observation; one is ~430-540ms of model
inference and is therefore gated three ways (never on a local read, never on
B3/B4, never above `engine.MAX_TIER3_CHARS`, and serialized on
`engine._TIER3_LOCK`). That is a real scheduling decision, and the engine
used to *guess* it: it asked `hasattr(detector, "available")` and treated a
yes as "this is the expensive model tier", because at the time the model
detector was the only thing that tracked whether its weights had loaded.

That guess conflated three facts that are genuinely independent:

  tier         — what the detector is, in this project's own taxonomy
                 (tier 0 paths, tier 1 secrets, tier 3 the NER model).
  cost         — what one `scan()` call costs, and therefore whether the
                 engine may run it unconditionally or must gate it.
  availability — whether it can do its job *right now*: weights present,
                 optional ruleset compiled, config file readable.

Collapsing them was silently wrong in both directions. A cheap detector that
loads an optional ruleset — an entirely ordinary thing to write — grew an
`available` flag and was thereby reclassified as tier 3: it stopped running
on local destinations and on B3/B4 and was skipped past the size cap, with
no error anywhere. And a second *expensive* detector that never fails to
load has no `available` flag to sniff, so it ran unconditionally on every
observation with no cap and no serialization — precisely the synchronous
latency risk Ruling 4 exists to bound.

Detection is the part of this codebase most likely to change (the model has
already been updated once, and its label taxonomy shifted under us — see
`model.LABEL_MAP`), so the seam on that axis is the one that has to be
explicit. Hence `DetectorProfile`: the detector states its tier and its
cost, the engine reads the statement, and nothing is inferred from the
shape of the object.

Why `cost` is a separate field from `tier` rather than derived from it
---------------------------------------------------------------------
"Tier 3" and "expensive" are the same thing *today*, and deriving one from
the other would bake that coincidence in as an invariant. It is not one: a
tier-3-class semantic detector could arrive as a cheap compiled ruleset, and
a cheap-looking tier could acquire an out-of-process call. The engine
schedules on `cost` alone and never on the number, because cost is the
question it is actually asking. `tier` stays in the profile because it is
this project's shared vocabulary for the stack (docs, doctor output, and
every module docstring in this package say "tier 0"/"tier 3"), so a detector
that declares a cost but no tier would be undescribable in the terms
everyone here reasons in.

Why availability is *not* in the profile
----------------------------------------
A profile is a static property of a detector class — the same for every
instance, known without constructing anything (`ModelDetector.profile` is
readable without loading 1.5B parameters). Availability is per-instance
runtime state that can be false on one machine and true on another, and it
belongs to the detector, not to its schedule. Keeping it out of the profile
is what stops the two from being conflated again. `is_available()` below is
how the engine reads it, and its default is deliberately permissive.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


@dataclass(frozen=True)
class Finding:
    data_type: str
    value: str
    start: int
    end: int


class Cost(Enum):
    """What one `scan()` call costs the engine, in scheduling terms.

    An `Enum` rather than an `expensive: bool` because these are names the
    engine branches on and the report copy quotes, and because the axis has
    room to grow a middle value (something worth gating by size but not by
    boundary) without every call site having to be re-read to work out what
    `expensive=False` was supposed to mean for it.
    """

    #: Microseconds to low milliseconds, pure and stateless. The engine runs
    #: these on every observation, at every boundary, at any payload size.
    CHEAP = "cheap"

    #: Hundreds of milliseconds, and/or a shared non-reentrant resource. The
    #: engine gates these: skipped for local destinations and for B3/B4,
    #: skipped (not truncated) above `engine.MAX_TIER3_CHARS`, serialized on
    #: `engine._TIER3_LOCK`, and reported via `Decision.degraded` whenever a
    #: scan that should have run did not.
    EXPENSIVE = "expensive"


@dataclass(frozen=True)
class DetectorProfile:
    """A detector's declaration of what it is and what it costs.

    Frozen because it is read on every scan off a detector list shared
    process-wide across every session (see `dispatch.new_state`): a mutable
    profile would let one session silently re-schedule every other one.
    """

    tier: int
    cost: Cost

    def __post_init__(self) -> None:
        if not isinstance(self.tier, int) or isinstance(self.tier, bool):
            raise TypeError(f"DetectorProfile.tier must be an int, got {self.tier!r}")
        if self.tier < 0:
            raise ValueError(f"DetectorProfile.tier must be >= 0, got {self.tier}")
        if not isinstance(self.cost, Cost):
            raise TypeError(
                f"DetectorProfile.cost must be a Cost, got {self.cost!r}")


class Detector(Protocol):
    """A detector: something that says what is in a piece of text.

    `profile` is part of the contract, not an optional extra. Declare it as
    a class attribute so it is readable without constructing the detector::

        class MyDetector:
            profile = DetectorProfile(tier=2, cost=Cost.CHEAP)

            def scan(self, text: str, ctx: dict) -> list[Finding]: ...

    Optionally also expose `available: bool` when the detector can be
    non-functional at runtime (missing weights, an unreadable optional
    ruleset). Doing so says nothing about the detector's tier or cost — see
    this module's docstring for why that separation is the point.

    Note what is deliberately *not* a `Detector`: `detect/shell.py`. Its
    `destination_hosts`/`extract_destinations` are free functions answering
    "where is this going", not "what is in this", and they have no `scan`.
    The docs' uniform "tiers 0-3" framing reads as if shell parsing were a
    fourth detector in this list; it is not, and it has no profile.
    """

    profile: DetectorProfile

    def scan(self, text: str, ctx: dict) -> list[Finding]: ...


class UndeclaredDetector(TypeError):
    """Raised when a detector does not declare a valid `DetectorProfile`.

    A `TypeError` because that is what it is — an object that does not
    satisfy the `Detector` contract was passed where one was required. It is
    raised at wiring time (`Engine.__init__`) rather than tolerated with a
    default, because every possible default is a silent misclassification:
    defaulting to cheap runs a model on every local read, and defaulting to
    expensive makes a regex tier stop seeing local reads. Neither shows up as
    an error, and both are exactly the failure this contract exists to
    prevent.
    """


def profile_of(detector: object) -> DetectorProfile:
    """Return `detector`'s declared profile, or raise `UndeclaredDetector`.

    This is the one place in the codebase that reflects on a detector's
    attributes, and it reflects on the *contract field* rather than sniffing
    for an unrelated one. `isinstance` and not duck typing: accepting
    anything with a `.cost` attribute would move the guessing up one level
    instead of removing it.
    """
    profile = getattr(detector, "profile", None)
    if not isinstance(profile, DetectorProfile):
        raise UndeclaredDetector(
            f"{type(detector).__name__} does not declare a DetectorProfile. "
            "Every detector must state its own tier and cost so the engine "
            "does not have to guess how to schedule it — add a class "
            "attribute, e.g. "
            "`profile = DetectorProfile(tier=2, cost=Cost.CHEAP)`. "
            f"Got profile={profile!r}."
        )
    return profile


def is_available(detector: object) -> bool:
    """Whether `detector` can currently do its job.

    Defaults to True when the detector declares nothing: not declaring
    `available` is the normal case (a compiled regex is always usable) and
    means "no reason to think otherwise", so the permissive default is the
    honest one. A detector that *can* be non-functional is expected to say
    so — `ModelDetector.available` is False when the weights are absent, and
    the engine then reports the scan degraded rather than pretending tier 3
    ran.

    Unlike `profile_of`, this is optional-by-design, which is why the two are
    separate functions: a missing profile is a bug in the detector, a missing
    `available` is just a detector that never breaks.
    """
    return bool(getattr(detector, "available", True))
