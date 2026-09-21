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

import sys
import threading
import time

import pytest

from privacy_hud import engine
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


class _SlowStub(StubModelDetector):
    """`StubModelDetector` that takes measurable time inside `scan()`.

    Egress uses a requested timeout based on the remaining budget and an
    inclusive completion cutoff; neither guarantees elapsed time. See
    `engine.TIER3_EGRESS_BUDGET`. Only a detector that is slow *while
    holding the model* can tell a deadline that applies to the result from
    one that only applies to the lock wait, which is the distinction the
    first version of this change got wrong."""

    def __init__(self, delay, findings):
        super().__init__(findings)
        self.delay = delay

    def scan(self, text, ctx):
        time.sleep(self.delay)
        return super().scan(text, ctx)


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
    ("mcp_tool", "B3"),
    ("external_net", "B4"),
])
def test_tier3_runs_for_b3_and_b4_egress(tmp_path, destination, boundary):
    """`architecture.md` §4: "Tier 3 runs ... when the payload crosses
    B3/B4". The engine excluded exactly that boundary until #47 item 1, and
    the exclusion was not a small one: `email`, `person`, `address`, `phone`
    and `account` are tier-3-only, so no outbound call could ever produce a
    finding of any of them. The README's own `support.log → GitHub MCP`
    illustration could not be recorded at its last hop, and a `mask` rule on
    `email` had nothing to intersect and so could never fire."""
    scan = _full_stack(tmp_path).scan(_obs(destination=destination))
    assert scan.boundary == boundary
    assert TIER3_TYPE in _types(scan)
    assert scan.degraded is False


def test_tier3_runs_on_a_pretooluse_egress_the_shape_that_actually_ships(tmp_path):
    """The parametrized test above keeps this file's default `PostToolUse`
    shape so it isolates one variable. This one is the shape `dispatch`
    really builds for B3/B4 — the only event that can be egress, and the
    only one whose reply carries a decision."""
    scan = _full_stack(tmp_path).scan(
        _obs(hook_event="PreToolUse", direction="egress",
             destination="mcp_tool", source="github", tool_name="mcp__github"))
    assert scan.boundary == "B3"
    assert TIER3_TYPE in _types(scan)


def test_tier3_is_skipped_for_a_local_read(tmp_path):
    scan = _full_stack(tmp_path).scan(_obs(destination="local"))
    assert scan.boundary == "B0"
    assert TIER3_TYPE not in _types(scan)


def test_skipping_tier3_by_schedule_does_not_mark_the_scan_degraded(tmp_path):
    """`degraded` marks a scan gap: an applicable deep scan supplied no
    accepted result. An out-of-scope scan has no gap. A local read is *out
    of the deep scan's domain by design*, so surfacing design.md §5's
    "fast-path results only" banner for it would tell the user the tool is
    impaired when it is behaving exactly as specified.

    B3/B4 used to be listed here alongside `local`. It no longer is, and the
    difference is the whole of #47 item 1: an egress that does not get the
    deep scan has now genuinely lost something, and says so."""
    scan = _full_stack(tmp_path).scan(_obs(destination="local"))
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
    """An oversized *local* read is not degraded: the deep scan is out of
    scope there, and an out-of-scope scan has no scan gap."""
    scan = _full_stack(tmp_path).scan(
        _obs(destination="local", text=TEXT + ("x" * MAX_TIER3_CHARS)))
    assert scan.degraded is False


def test_an_oversized_egress_degrades_now_that_the_deep_scan_applies_there(tmp_path):
    """The mirror of the test above, and the reason the two cannot share a
    parametrize: `local` is out of scope, B3/B4 is in scope and capped. An
    oversize payload is a scan gap: inference is not attempted."""
    scan = _full_stack(tmp_path).scan(
        _obs(destination="mcp_tool", text=TEXT + ("x" * MAX_TIER3_CHARS)))
    assert scan.degraded is True
    assert TIER3_TYPE not in _types(scan)
    assert CHEAP_TYPES <= _types(scan)


# ---------------------------------------------------------------------------
# Egress uses a deadline; ingress does not use the egress deadline.
# ---------------------------------------------------------------------------
#
# Why the two differ, in one paragraph, because it is the only genuinely
# subtle thing in this file. `hooks/handler.py`'s client timeout is 2.0s and
# I6 makes an egress timeout DENY. Tier 3 is a serial resource
# (`_TIER3_LOCK`), so before this change `daemon.Daemon`'s docstring could
# measure an egress `PreToolUse` taking 3060ms behind six in-flight ingress
# scans — and a benign `curl .../health` was denied because an unrelated
# session was busy. Putting tier 3 on the egress path re-opens that queue.
# Egress uses a requested timeout based on the remaining budget and an
# inclusive completion cutoff; neither guarantees elapsed time. See
# `engine.TIER3_EGRESS_BUDGET`. Ingress does not use the egress deadline:
# its reply is `{}` either way (Ruling 3), so it blocks.

def test_an_egress_whose_budget_expires_reports_a_timeout_gap(tmp_path,
                                                              monkeypatch):
    """The deadline applies to the result, not just the wait for the lock.

    The first version of this change took the lock with a timeout and then
    ran the scan with no deadline at all — a slow forward pass could still
    run past the hook client's 2.0s and be denied by I6. A slow
    detector with the lock free is exactly the case that version let
    through."""
    monkeypatch.setattr(engine, "TIER3_EGRESS_BUDGET", 0.05)
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(),
                             _SlowStub(0.6, [EMAIL_FINDING])])
    started = time.monotonic()
    scan = eng.scan(_obs(destination="mcp_tool"))
    elapsed = time.monotonic() - started

    assert TIER3_TYPE not in _types(scan)
    assert scan.degraded_reason == engine.GAP_TIMEOUT
    assert CHEAP_TYPES <= _types(scan), "the cheap tiers still ran"
    # Fixture-specific: 0.05s budget against a 0.6s detector.
    assert elapsed < 0.5, f"this fixture's egress took {elapsed:.2f}s"


def test_a_second_egress_is_refused_admission_rather_than_queued(tmp_path,
                                                                 monkeypatch):
    """Admission control, and the reason it is not just a nicety.

    At most one egress scan worker is admitted at a time. Admission is
    nonblocking; the worker retains its slot until it exits, including after
    caller abandonment. Without it, a burst of outbound calls whose callers
    abandoned their results would leave workers queued for the model, and
    later egress scans would queue behind work nobody will use. In this
    fixture the second call comes back fast and says `busy`."""
    monkeypatch.setattr(engine, "TIER3_EGRESS_BUDGET", 0.05)
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(),
                             _SlowStub(0.5, [EMAIL_FINDING])])
    first = eng.scan(_obs(destination="mcp_tool"))
    assert first.degraded_reason == engine.GAP_TIMEOUT

    started = time.monotonic()
    second = eng.scan(_obs(destination="external_net"))
    elapsed = time.monotonic() - started

    assert second.degraded_reason == engine.GAP_BUSY
    assert elapsed < 0.2, "a refused egress must not wait for the slot"
    assert CHEAP_TYPES <= _types(second)


def test_the_admission_slot_comes_back_when_the_abandoned_scan_finishes(
        tmp_path, monkeypatch):
    """The worker retains its slot until it exits, including after caller
    abandonment.

    If the caller released it on giving up, the next egress would be
    admitted while the model was still busy with the last one — which is the
    queue admission control exists to prevent. If nobody released it, egress
    would degrade forever after the first timeout. This pins the third
    behaviour: released, but only once the work is actually done."""
    monkeypatch.setattr(engine, "TIER3_EGRESS_BUDGET", 0.05)
    slow = _SlowStub(0.3, [EMAIL_FINDING])
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(), slow])
    assert eng.scan(_obs(destination="mcp_tool")).degraded_reason == \
        engine.GAP_TIMEOUT

    # Wait for the abandoned worker on the slot itself, rather than sleeping
    # a guessed interval: this is the handoff under test.
    assert engine._TIER3_EGRESS_SLOT.acquire(timeout=5)
    engine._TIER3_EGRESS_SLOT.release()

    slow.delay = 0.0
    monkeypatch.setattr(engine, "TIER3_EGRESS_BUDGET", 1.0)
    scan = eng.scan(_obs(destination="mcp_tool"))
    assert scan.degraded_reason is None, "the slot never came back"
    assert TIER3_TYPE in _types(scan)


def test_a_late_result_is_dropped_rather_than_merged(tmp_path, monkeypatch):
    """A result the caller did not accept must change nothing.

    Findings are used only under the acceptance condition stated at
    `engine.TIER3_EGRESS_BUDGET`, and the worker writes only to its own
    task. So the email this worker records after its caller's wait returned
    False never appears in the returned `ScanResult`, and so never reaches
    a ledger row or a block ruling built from it."""
    monkeypatch.setattr(engine, "TIER3_EGRESS_BUDGET", 0.05)
    slow = _SlowStub(0.4, [EMAIL_FINDING])
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(), slow])
    scan = eng.scan(_obs(destination="mcp_tool"))
    assert TIER3_TYPE not in _types(scan)

    time.sleep(0.6)                                     # the worker lands
    assert TIER3_TYPE not in _types(scan), "a late result mutated the result"
    assert scan.degraded_reason == engine.GAP_TIMEOUT


def test_a_contended_ingress_waits_for_the_model_instead_of_degrading(tmp_path):
    eng = _full_stack(tmp_path)
    engine._TIER3_LOCK.acquire()
    releaser = threading.Timer(0.3, engine._TIER3_LOCK.release)
    releaser.start()
    scan = eng.scan(_obs())           # ingress, B1
    releaser.join()

    # Ingress does not use the egress deadline.
    assert TIER3_TYPE in _types(scan), "ingress must block for the model"
    assert scan.degraded is False


# ---------------------------------------------------------------------------
# Availability: the unavailable history requires that no expensive detector
# supplies a successful available result.
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


# ---------------------------------------------------------------------------
# What the worker must not swallow, and what it must not accept late.
# ---------------------------------------------------------------------------

class _CrashingStub(StubModelDetector):
    def scan(self, text, ctx):
        raise RuntimeError("inference blew up")


def test_a_detector_crash_on_egress_reaches_the_caller(tmp_path):
    """I6, and the reason the worker catches `BaseException` for the caller to
    re-raise after a true wait return.

    Before the deep scan moved to a worker thread, a detector exception on
    the egress path left `Engine.scan`, left `dispatch()`, and landed on the
    daemon's exception boundary, where I6 denies. On a worker thread it
    would instead hit `threading.excepthook` — which prints it, and a
    detector's exception text can quote the payload it was scanning — while
    the caller read the task's initial `timeout` and **allowed** the call. In
    this fixture, the wait returns True, so the worker error is re-raised
    rather than converted into an ordinary gap."""
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(), _CrashingStub([])])
    with pytest.raises(RuntimeError, match="inference blew up"):
        eng.scan(_obs(destination="mcp_tool"))


def test_an_ingress_detector_crash_still_reaches_the_caller(tmp_path):
    """The path that never changed, pinned beside it so the two agree."""
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(), _CrashingStub([])])
    with pytest.raises(RuntimeError, match="inference blew up"):
        eng.scan(_obs())


class _GilHog(StubModelDetector):
    """Busy-loops instead of sleeping, so the CALLER cannot run either.

    `_SlowStub` sleeps, which releases the GIL — the caller wakes on time,
    `wait()` returns False, and the timeout path is what gets tested. To
    reach `_in_time`, the wait must return True with no worker error and
    a successful worker outcome. The late-worker fixture holds the GIL so
    the worker finishes after the deadline while the caller is descheduled;
    timely successful completion also reaches `_in_time`.
    """

    def __init__(self, hold, findings):
        super().__init__(findings)
        self.hold = hold

    def scan(self, text, ctx):
        end = time.monotonic() + self.hold
        while time.monotonic() < end:
            pass
        return super().scan(text, ctx)


def _scan_with_a_late_worker(tmp_path, monkeypatch, hold=0.25):
    """Run one egress scan whose worker finishes after the deadline, with
    the caller genuinely descheduled for the whole of it.

    `sys.setswitchinterval` is what makes this real. A Python busy loop
    still yields at the normal switch interval (5 ms here), so the caller
    wakes on time, `Event.wait()` returns False, and the TIMEOUT path is
    what produces the result — `_in_time` is never even called. Raising the
    interval past the worker's hold keeps the caller off the CPU until the
    worker has finished and set `done`. In this fixture, `wait()` returns
    True with no worker error and a successful worker outcome, so the
    completion-time check is reached after the deadline.
    """
    monkeypatch.setattr(engine, "TIER3_EGRESS_BUDGET", 0.02)
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(),
                             _GilHog(hold, [EMAIL_FINDING])])
    previous = sys.getswitchinterval()
    sys.setswitchinterval(hold * 20)
    try:
        return eng.scan(_obs(destination="mcp_tool"))
    finally:
        sys.setswitchinterval(previous)


def test_a_result_that_finished_after_the_deadline_is_not_accepted(tmp_path,
                                                                   monkeypatch):
    """`done` being set says the worker completed, not that the result is
    accepted. Completion at or before the deadline is necessary but not
    sufficient for accepting the result; see `engine.TIER3_EGRESS_BUDGET`.
    Here the wait returns True and the completion is after the deadline, so
    the result is rejected and the outcome is `GAP_TIMEOUT`.
    """
    scan = _scan_with_a_late_worker(tmp_path, monkeypatch)
    assert TIER3_TYPE not in _types(scan), (
        "a scan that finished after its deadline was accepted")
    assert scan.degraded_reason == engine.GAP_TIMEOUT
    assert CHEAP_TYPES <= _types(scan)


def test_that_test_fails_when_the_completion_check_is_bypassed(tmp_path,
                                                               monkeypatch):
    """The discriminator, and the reason this file has three tests for one
    branch instead of two.

    Two earlier versions of the test above passed without ever exercising
    `_in_time`: the first replaced the function with a constant `False` and
    described itself as moving the deadline into the past, and the second
    used a busy loop that still yielded, so `Event.wait()` timed out and the
    timeout path produced the same outcome. Review caught the second by
    replacing `_in_time` with an unconditional `True` and watching the test
    pass anyway. So that mutation is a test now.

    It asserts lateness itself rather than trusting the setup to produce
    it — review's next round pointed out that an earlier version of this
    also passed with an on-time worker, which would have made it agree with
    the test above for the wrong reason.
    """
    seen: list[tuple[float | None, float]] = []
    real = engine._in_time

    def always_in_time(finished_at, deadline):
        seen.append((finished_at, deadline))
        real(finished_at, deadline)          # exercised, result discarded
        return True

    monkeypatch.setattr(engine, "_in_time", always_in_time)
    scan = _scan_with_a_late_worker(tmp_path, monkeypatch)

    assert seen, "`_in_time` was never consulted, so this proves nothing"
    finished_at, deadline = seen[-1]
    assert finished_at is not None and finished_at > deadline, (
        f"the worker finished {deadline - (finished_at or 0):.3f}s EARLY, so "
        "this run never produced the late-completion state it claims to test")
    assert TIER3_TYPE in _types(scan), (
        "the late result was rejected by something other than `_in_time`, so "
        "the test above would pass with the check removed")


def test_the_same_scan_inside_its_budget_is_accepted(tmp_path, monkeypatch):
    """The control: `_in_time` must not reject everything."""
    monkeypatch.setattr(engine, "TIER3_EGRESS_BUDGET", 5.0)
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(),
                             _GilHog(0.05, [EMAIL_FINDING])])
    scan = eng.scan(_obs(destination="mcp_tool"))
    assert TIER3_TYPE in _types(scan)
    assert scan.degraded_reason is None


class _FailingModel(StubModelDetector):
    """A detector that discovers mid-scan that it cannot work, and says so
    the way `ModelDetector.scan` does."""

    def scan(self, text, ctx):
        self.available = False
        return []


def test_a_detector_that_fails_mid_scan_degrades_rather_than_reading_clean(
        tmp_path):
    """The failure that used to report as a clean scan.

    `ModelDetector.scan` caught inference exceptions and returned `[]`. The
    engine had already checked availability before the call, so `ran_any`
    went True, `degraded` came out False, and a session whose every deep
    scan crashed read as fully verified with nothing found — #47 item 6 one
    layer below where it was filed. In this ingress fixture, the only
    expensive detector becomes unavailable during inference, so the scan
    reports `GAP_UNAVAILABLE`. An accepted empty result is a clean scan,
    not a scan gap, and this is not one."""
    eng = _engine(tmp_path, [PathDetector(), SecretDetector(), _FailingModel([])])
    scan = eng.scan(_obs())
    assert scan.degraded_reason == engine.GAP_UNAVAILABLE
    assert CHEAP_TYPES <= _types(scan)
