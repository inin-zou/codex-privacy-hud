# tests/test_self_audit.py
"""I7's corpus: the clean half must be silent, the planted half must be found.

I7 used to say "running Privacy HUD on this repo's own development session
must produce zero exposures". Three read-only source reviews measured 88%,
100% and 100% of budget, so the invariant was contradicted by the tool's own
output. What it was not is unfalsifiable — one counterexample disproves it,
and one arrived. It was an **invalid requirement**: sessions differ, and a
session that reads a file holding a real address *should* record an
exposure, so the rule asked a correct tool to fail.

(Both retracted phrasings — "not falsifiable", and a claim that the
measurement went unexamined for sixteen days — were corrected in
`CLAUDE.md` and `docs/self-audit.md` one commit before they were corrected
here, which is why this paragraph exists as a separate act of maintenance
rather than as part of that one.)

So the claim is about **stated inputs**, and the inputs are committed next
to this file:

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

**What a green run means**, stated here in the same words as
`docs/self-audit.md` because the two drifting apart is how this file's
earlier readings got weaker than the document's: **no unrecorded regression
appeared in the cases this corpus covers.** Not "the detectors behave on
these inputs" — an earlier version of this docstring said that, and the
audit page had already retracted it. Four known violations pass as expected
failures, every model check skips where the weights are absent (which is
CI, so CI's green covers the cheap tiers only), and nothing here calls
`is_sensitive_path`, so disabling the path guard entirely still passes.

It is also not the session-level run: it exercises detectors directly, so
it says nothing about hooks, the daemon, the ledger's accounting, or a live
Codex session — which is where the 88% came from.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from privacy_hud.detect.base import is_available
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


class ModelUnavailable(RuntimeError):
    """The model stopped working during a scan.

    Deliberately not an `AssertionError`: the expected-failure markers in
    this file are pinned to that type, so this one cannot be mistaken for
    the detector miss it is recorded next to.
    """


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
            marks.append(pytest.mark.xfail(
                strict=True, raises=AssertionError,
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


def _scan_deeply(model, text: str) -> list:
    """Scan with the model, and refuse to report a result it did not produce.

    `ModelDetector.scan` catches an inference exception, marks itself
    unavailable and returns `[]` — which is the honest thing for a detector
    to do and a trap for a caller that reads "no findings" as "nothing
    here". Checking availability only *before* the scan leaves exactly that
    hole: one failed inference and every later clean entry is certified
    clean by a model that never examined it. Review demonstrated it —
    inference failed on `log-02` and the aggregate test passed anyway,
    having silently stopped testing five entries.

    So availability is read again afterwards, and a detector that went
    unavailable during its own scan fails the test rather than passing it.
    This is the same defect `engine._run_expensive` was fixed for in #47
    item 6, one layer up, written by the same person on the same day.
    """
    found = model.scan(text, {"source": "self-audit"})
    if not is_available(model):
        # NOT an assertion. Every `known_gap` entry is an xfail, and an
        # xfail marker swallows whatever exception the test raises — so an
        # assertion here would be reported as "expected detector miss,
        # fragmented into three spans" for a run where inference crashed
        # and produced no spans at all. A distinct type, with the markers
        # pinned to `raises=AssertionError`, makes a broken model an ERROR
        # and keeps it out of the one bucket labelled "we know about this".
        raise ModelUnavailable(
            "the model marked itself unavailable during this scan, so its "
            "empty result is a failure to examine the input, not a reading")
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
                strict=True, raises=AssertionError,
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
    found = _scan_deeply(model, entry["text"])
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
        found = _scan_deeply(model, entry["text"])
        # Compare what was found, not merely whether anything was. A
        # boolean lets the recorded type and value drift away from the
        # model's actual output while the test stays green — a marker that
        # no longer describes the behaviour it excuses.
        actual = sorted((f.data_type, f.value) for f in found)
        fp = entry.get("known_false_positive")
        expected = sorted([(fp["data_type"], fp["value"])] if fp else [])
        assert actual == expected, (
            f"{entry['id']}: model reports {actual}, fixture records "
            f"{expected}")


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
    found = _scan_deeply(model, entry["text"])
    for expected in entry["expect"]:
        # The VALUE, not just the type. A first version of this compared
        # data-type sets, and `address-03` — where the model splits one
        # street line into `42`, `Rue de Rivoli` and `75001` — passed it:
        # three `address` findings satisfy "an address was found" while no
        # single finding carries the address. What is lost is the reported
        # value; masking is NOT broken by it, because `minimize_text`
        # replaces all three fragments (an earlier version of this comment
        # claimed otherwise without checking). A check that cannot see
        # fragmentation would still have let the bug in `detect/model.py`'s
        # own docstring through a second time.
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
