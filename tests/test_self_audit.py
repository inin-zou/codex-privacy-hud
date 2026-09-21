# tests/test_self_audit.py
"""I7's corpus: the clean half must be silent, the planted half must be found.

I7 used to say "running Privacy HUD on this repo's own development session
must produce zero exposures". That was false — three read-only source
reviews measured 88%, 100% and 100% of budget — and it was false for
sixteen days after the measurement, because the measurement lived in a
commit message and nothing here could reach it.

The replacement is narrower on purpose. "Zero on a development session" is
not falsifiable: sessions differ, and a session that reads a file holding a
real address *should* record an exposure. So the claim is about **stated
inputs**, and the inputs are committed next to this file:

  `clean.json`    ordinary development text with no personal data, no
                  credential and no sensitive path. Correct answer: nothing.
                  Every finding is a false positive, with no judgement call
                  about whether it "sort of counts".
  `planted.json`  synthetic values planted on purpose, each labelled with
                  the tier expected to find it. Correct answer: all of them.

Two directions of failure, and this file cares about both. A detector that
stops seeing planted credentials has failed at the only job that matters. A
detector that fires on `SELECT COUNT(*) FROM events` has failed differently
and more insidiously: an inflated budget is a number users learn to ignore,
and then the real one arrives and they ignore that too.

**What this is not.** It is not the session-level run. It exercises the
detector stack directly, so it says nothing about hooks, the daemon, the
ledger's accounting, or what a live Codex session does — which is where the
88% came from. Closing that gap needs the accounting work in #43/#44/#47,
and until then the honest reading of a green run here is "the detectors
behave on these inputs", not "the tool is clean".
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from privacy_hud.detect.paths import PathDetector
from privacy_hud.detect.secrets import SecretDetector

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "self_audit"

#: How many clean entries are allowed to produce a finding. Zero, and it
#: stays zero: this is the corpus where the right answer is unambiguous, so
#: a baseline above zero would be a way to keep a known false positive
#: without deciding anything about it. If a change makes this fail, either
#: the detector regressed or the entry was not as clean as it looked —
#: both are worth stopping for.
CLEAN_FALSE_POSITIVE_BUDGET = 0


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))["entries"]


def _planted(tiers: tuple[int, ...]) -> list:
    """Planted entries for `tiers`, with `known_gap` ones marked xfail.

    `strict=True` is the whole value of the mechanism: when a gap is closed
    the test goes RED on an unexpected pass, so the entry has to be promoted
    and the note removed. A non-strict xfail would let a fixed detector sit
    behind a stale "we do not catch this" comment indefinitely, which is the
    documentation drift this repository keeps finding in other forms.
    """
    out = []
    for entry in _load("planted.json"):
        if entry["tier"] not in tiers:
            continue
        marks = []
        if entry.get("known_gap"):
            marks.append(pytest.mark.xfail(strict=True,
                                           reason=entry["known_gap"]))
        out.append(pytest.param(entry, marks=marks, id=entry["id"]))
    return out


def _cheap_stack() -> list:
    """Tiers 0 and 1, which need no weights and run everywhere CI does."""
    return [PathDetector(), SecretDetector()]


def _model_detector():
    """The real tier 3, or None when its weights are not on this machine."""
    from privacy_hud.detect.model import ModelDetector

    detector = ModelDetector()
    return detector if getattr(detector, "available", False) else None


def _scan(detectors, text: str) -> list:
    found = []
    for d in detectors:
        found.extend(d.scan(text, {"source": "self-audit"}))
    return found


# ---------------------------------------------------------------------------
# The negative control: ordinary development text is not a disclosure.
# ---------------------------------------------------------------------------

def _clean_params() -> list:
    """Clean entries, with the ones the MODEL fires on marked xfail.

    The cheap tiers are silent on all 20, so the cheap test below takes them
    unmarked. The model is not silent, and the first version of this file
    never asked it — a false-positive corpus that did not run the detector
    producing the false positives, reporting green while two of its own
    entries failed the property it advertised. Review found it by running
    the model itself.
    """
    out = []
    for entry in _load("clean.json"):
        marks = []
        fp = entry.get("known_false_positive")
        if fp:
            marks.append(pytest.mark.xfail(
                strict=True,
                reason=f"model reports {fp['data_type']} {fp['value']!r}: "
                       f"{fp['why']}"))
        out.append(pytest.param(entry, marks=marks, id=entry["id"]))
    return out


@pytest.mark.parametrize("entry", _load("clean.json"), ids=lambda e: e["id"])
def test_a_clean_development_string_produces_no_cheap_finding(entry):
    found = _scan(_cheap_stack(), entry["text"])
    assert found == [], (
        f"{entry['id']} ({entry['kind']}) is ordinary {entry['kind']} with "
        f"nothing sensitive in it, and produced {[f.data_type for f in found]}"
    )


def test_the_clean_corpus_is_silent_as_a_whole():
    """The same check as a single number, because that is the number
    `docs/self-audit.md` quotes and a per-entry failure does not say how
    widespread a regression is."""
    detectors = _cheap_stack()
    noisy = [e["id"] for e in _load("clean.json")
             if _scan(detectors, e["text"])]
    assert len(noisy) <= CLEAN_FALSE_POSITIVE_BUDGET, (
        f"{len(noisy)} of {len(_load('clean.json'))} clean entries fired: "
        f"{noisy}")


@pytest.mark.parametrize("entry", _clean_params())
def test_a_clean_development_string_produces_no_deep_finding(entry):
    """The check the first version of this file was missing.

    Known limit 7 measured 9 of 61 clean strings producing a finding, all of
    them the model's confident output. A corpus that asserts "ordinary
    development text is not a disclosure" and then only runs regex is not
    checking that claim at all."""
    model = _model_detector()
    if model is None:
        pytest.skip("tier 3 weights are not on this machine")
    found = _scan([model], entry["text"])
    assert found == [], (
        f"{entry['id']} ({entry['kind']}) is ordinary {entry['kind']} with "
        f"nothing sensitive in it, and the model reported "
        f"{[(f.data_type, f.value) for f in found]}")


def test_the_clean_corpus_records_every_model_false_positive_it_has():
    """No unmarked entry may fire on the model, and no marked one may be
    clean. The first half stops a new false positive arriving unrecorded;
    the second stops a stale marker outliving the behaviour it describes —
    the same job `strict=True` does per entry, checked in one place so the
    fixture and the model cannot drift apart quietly."""
    model = _model_detector()
    if model is None:
        pytest.skip("tier 3 weights are not on this machine")
    for entry in _load("clean.json"):
        fires = bool(_scan([model], entry["text"]))
        recorded = bool(entry.get("known_false_positive"))
        assert fires == recorded, (
            f"{entry['id']}: model fires={fires}, fixture records={recorded}")


# ---------------------------------------------------------------------------
# The positive control: what is planted must be found.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("entry", _planted((0, 1)))
def test_a_planted_cheap_tier_value_is_found(entry):
    found = _scan(_cheap_stack(), entry["text"])
    for expected in entry["expect"]:
        assert any(f.data_type == expected["data_type"]
                   and expected["value"] in f.value
                   for f in found), (
            f"{entry['id']}: expected {expected['data_type']} "
            f"{expected['value']!r}, got "
            f"{[(f.data_type, f.value) for f in found]}")


@pytest.mark.parametrize("entry", _planted((3,)))
def test_a_planted_deep_tier_value_is_found(entry):
    model = _model_detector()
    if model is None:
        pytest.skip("tier 3 weights are not on this machine")
    found = _scan([model], entry["text"])
    for expected in entry["expect"]:
        # The VALUE, not just the type. A first version of this compared
        # data-type sets, and `address-03` — where the model splits one
        # street line into `42`, `Rue de Rivoli` and `75001` — passed it:
        # three `address` findings satisfy "an address was found" while no
        # single finding carries the address. Task 12 masks on these
        # offsets, so a fragmented span is a masking hole, and a check that
        # cannot see it is a check that would have let the fragmentation
        # bug in `detect/model.py`'s own docstring through again.
        assert any(f.data_type == expected["data_type"]
                   and expected["value"] in f.value
                   for f in found), (
            f"{entry['id']}: expected {expected['data_type']} "
            f"{expected['value']!r}, got "
            f"{[(f.data_type, f.value) for f in found]}")


# ---------------------------------------------------------------------------
# The corpus itself has to stay honest.
# ---------------------------------------------------------------------------

def test_no_planted_value_appears_in_the_clean_half():
    """A planted value leaking into the clean corpus would turn a true
    positive into a recorded 'false positive' and quietly raise the
    tolerance for real ones."""
    planted = [e["value"] for entry in _load("planted.json")
               for e in entry["expect"]]
    for entry in _load("clean.json"):
        for value in planted:
            assert value not in entry["text"], (
                f"{entry['id']} contains the planted value {value!r}")


def test_every_planted_entry_declares_what_it_expects():
    for entry in _load("planted.json"):
        assert entry["expect"], f"{entry['id']} plants nothing"
        assert entry["tier"] in (0, 1, 3), entry["id"]


def test_the_documented_corpus_sizes_match_the_files():
    """`docs/self-audit.md` quotes both counts. A corpus that grew while the
    document did not is the drift this whole repository keeps finding."""
    doc = (FIXTURES.parents[2] / "docs" / "self-audit.md").read_text(
        encoding="utf-8")
    assert f"{len(_load('clean.json'))} clean entries" in doc
    assert f"{len(_load('planted.json'))} planted entries" in doc
