"""Tier 3 — openai/privacy-filter token classification.

Loads from the local HuggingFace cache only (Global Constraint I2: no network
calls). If the weights are absent the detector reports unavailable and the
engine degrades to tiers 0-2 with a visible warning, rather than crashing or
falling back to any remote service.

Why this module does its own span assembly
------------------------------------------
It used to ask `transformers` for `aggregation_strategy="simple"` and turn
every returned span into a `Finding`. Both halves of that were wrong, and the
first one is a bug rather than a tuning question:

`simple` aggregation only understands **BIO** tags. This model's taxonomy is
**BIOES** (`config.json`'s id2label runs `B-`/`I-`/`E-`/`S-` for all eight
categories). `TokenClassificationPipeline.get_tag` treats anything that is not
`B-...`/`I-...` as a continuation *of a differently-named tag* — for `E-`
labels the tag it derives is the literal string `"E-private_person"`, which
never equals the open group's `"private_person"` — so `group_entities` breaks
the group at every `E-` token, i.e. at the end of **every** entity. One name
comes back as two spans, and `group_sub_entities` strips the prefix on the way
out so both are labelled `private_person` and nothing looks wrong.

Measured on 94 synthetic development-session strings (61 with no personal data
in them, 33 containing real personal data), the split roughly doubles the span
count for identical detections: 56 → 38 spurious spans over the clean 61, and
102 → 53 true spans over the other 33, with the set of data types found per
string unchanged in all 94. The consequences were all downstream of that
doubling:

  * Volume inflation. `Ledger.record` dedupes on `value_hash`, so two halves
    of one name are two distinct rows, each scoring a full
    `severity x volume x boundary` (I4 makes that permanent).
  * Unreadable exemplars. `/Users/<user>/...` produced `person` rows masked
    `/y•••g` and `••••` — the two halves of one username, which reads to a
    user like two separate findings of nothing recognizable.
  * A masking hole. Task 12 rewrites outbound payloads by slicing on these
    offsets, so masking the first half of an entity left the second half
    ("...zou") in the text that went upstream.

`aggregation_strategy="none"` plus `spans_from_tokens` below assembles the
spans with the prefixes the model actually emits, which is why the pipeline is
constructed with `"none"` here and never asked to group anything.

Why there is a confidence floor, and why it is only a floor
-----------------------------------------------------------
The pipeline returns a per-token `score`; this module used to ignore it. Over
the same corpus, the mean token score of an assembled span separates part of
the noise cleanly. At `MIN_SCORE` = 0.85 the spurious span count over the clean
61 drops 38 → 13, the strings that produce any finding at all drop 16/61 →
9/61, and their summed severity weight drops 400 → 118. The measured cost is 2
true spans out of 53, which takes 2 of the 33 strings from detected to
undetected: a bare first name in prose ("Ask Marcus about the migration",
0.62) and the partial span the model puts on a bare 10-digit phone number
(0.61, and labelled `account` rather than `phone`).

The whole recall cost sits in one step of the sweep — nothing true is lost
between 0.0 and 0.60, both of those cases go between 0.60 and 0.65, and then
nothing more until 0.95, where a real database password (0.949) goes. So the
alternative worth knowing about is `MIN_SCORE` = 0.60: 38 → 28 spurious spans
at zero measured recall cost. 0.85 is the more aggressive of the two defensible
choices, taken because a budget inflated by noise is a number users stop
reading; if that judgement is ever revisited, revisit it downward. Above 0.9 is
not a judgement call but a regression — the password at 0.949 is the reason
`tests/detect/test_model.py` pins the ceiling.

It is a floor and nothing more, because the residual false positives are the
model's confident beliefs and no threshold reaches them without costing real
recall first. From the same run:

  * a local username inside a home-directory path scores 0.998-1.000 as
    `person`, and so does `"Bash"` appearing as a JSON string value;
  * a log/DB timestamp scores 1.000 as `date`, indistinguishable from a real
    date of birth in the same `YYYY-MM-DD` shape (also 1.000);
  * a UUID scores 0.978 as `secret` while a genuine database password scores
    0.949 — so any threshold high enough to drop the UUID drops the password
    first, which is the direction that actually matters.

Shape rules for those were tried and rejected on measurement, not taste:
requiring whitespace in a `person` span (i.e. "a real name has two parts")
would have dropped `Kowalczyk` (0.9999), `Madonna`, `Pele`, `Aisling` and the
handles `@kowalczyk`/`@dvolkov`, all real disclosures; dropping spans whose
edges cut a word in half removed nothing that `MIN_SCORE` did not already
remove and cost one more true span. Suppressing entity spans that sit inside a
filesystem path would silence the username noise and also
`/Users/<name>/Downloads/patient-intake-2026.csv`, which is exactly the kind of
row this product exists to show. Those four residual classes are documented in
README's known limits instead.
"""
from __future__ import annotations

import os
from typing import Any

from .base import Cost, DetectorProfile, Finding

# Keys are the model's real entity_group values, uppercased (verified against
# the shipped config.json's id2label — the model's BIOES taxonomy uses a
# "private_"-prefixed scheme, e.g. "private_email", not a flat "EMAIL").
LABEL_MAP = {
    "PRIVATE_PERSON": "person",
    "PRIVATE_ADDRESS": "address",
    "PRIVATE_EMAIL": "email",
    "PRIVATE_PHONE": "phone",
    "PRIVATE_URL": "url",
    "PRIVATE_DATE": "date",
    "ACCOUNT_NUMBER": "account",
    "SECRET": "credential",
}

#: Minimum mean per-token confidence for an assembled span to become a
#: `Finding`. See this module's docstring for the measurement behind 0.85 and
#: for why it is deliberately low: an inflated privacy budget teaches users to
#: ignore the number, but a detector that stops seeing real disclosures has
#: failed outright, so this is set below every true positive observed rather
#: than at the point that maximizes precision.
MIN_SCORE = 0.85

#: Characters trimmed off both ends of an assembled span. The model regularly
#: swallows the delimiter in front of a value (`,Nadia Farouk`, `' mlinwei`)
#: because that delimiter is part of the same wordpiece token, and the offsets
#: are what Task 12 masks on — so a span must not claim the comma or the quote
#: next to the value it found. Deliberately narrow: `.` can end a hostname,
#: `=` is base64 padding, `/` ends a URL path and `@` starts a handle, so none
#: of those are trimmed.
_TRIM = " \t\r\n,;'\"`"


def split_label(label: str) -> tuple[str, str]:
    """Split a token label into (prefix, tag).

    Understands BIOES and BIO. A label with no prefix this function recognizes
    keeps its whole text as the tag and is reported as `"I"` — a continuation —
    because that is the reading that merges rather than splits, and an
    over-merged span is one honest finding while an over-split one is several
    fabricated ones. (`transformers`' own `get_tag` makes the same choice and
    is where this project's fragmentation bug came from: it does that to `E-`
    and `S-`, which it does not recognize, so the tag it derives carries the
    prefix and never matches the open group's.)
    """
    if len(label) > 2 and label[1] == "-" and label[0] in "BIES":
        return label[0], label[2:]
    return "I", label


def _trim(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start] in _TRIM:
        start += 1
    while end > start and text[end - 1] in _TRIM:
        end -= 1
    return start, end


def spans_from_tokens(text: str, tokens: list[dict], *,
                      min_score: float = MIN_SCORE) -> list[Finding]:
    """Assemble BIOES-tagged tokens into `Finding`s over `text`.

    Pure, and separated from `ModelDetector.scan` on purpose: this is the part
    that was wrong, it is the part with the offset invariant Task 12 depends
    on, and it is the part CI can test on a machine with no model weights.

    `tokens` is `transformers`' `aggregation_strategy="none"` output: dicts
    with `entity`, `score`, `start`, `end`, and `index` (the token's position
    in the encoded sequence). `"O"` tokens may be absent — the pipeline drops
    them by default — so adjacency is decided on `index`, not on list order: a
    gap in the indices means something unlabelled sat between the two tokens
    and they are not one entity. Without that check "Marcus Delacroix and
    Nadia Farouk" would come back as a single person span covering the "and".

    Grouping follows the tags the model emits: `B` opens, `I` extends, `E`
    extends and closes, `S` stands alone. An `I` or `E` with nothing open (the
    model does this for long base64 runs, which come back as one unbroken
    `I-secret` sequence) opens a group rather than being discarded.
    """
    groups: list[dict] = []
    cur: dict | None = None
    prev_index: int | None = None
    for tok in tokens:
        label = str(tok.get("entity", "O"))
        if label == "O":
            cur = None
            prev_index = None
            continue
        prefix, tag = split_label(label)
        index = tok.get("index")
        if index is None:
            # No positional information: assume adjacency, which only ever
            # merges. See `split_label` for why that is the safe default.
            index = (prev_index + 1) if prev_index is not None else 0
        index = int(index)
        contiguous = (cur is not None and cur["tag"] == tag
                      and prev_index is not None and index == prev_index + 1)
        # `cur is None` already makes `contiguous` false; spelled out so the
        # else branch is visibly working on a group that exists.
        if prefix in ("B", "S") or not contiguous or cur is None:
            cur = {"tag": tag, "start": int(tok["start"]), "end": int(tok["end"]),
                   "scores": [float(tok["score"])]}
            groups.append(cur)
        else:
            cur["end"] = int(tok["end"])
            cur["scores"].append(float(tok["score"]))
        prev_index = index
        if prefix in ("E", "S"):
            cur = None

    out = []
    for g in groups:
        data_type = LABEL_MAP.get(g["tag"].upper())
        if data_type is None:
            continue
        score = sum(g["scores"]) / len(g["scores"])
        if score < min_score:
            continue
        start, end = _trim(text, g["start"], g["end"])
        if end <= start:
            continue
        # Trust the offsets over the pipeline's own `word`: aggregation can
        # normalize whitespace/casing so `word` is not always byte-identical
        # to the source slice, and Task 12 rewrites outbound payloads by
        # slicing on these offsets. A value that doesn't match text[start:end]
        # would corrupt that rewrite.
        out.append(Finding(data_type, text[start:end], start, end))
    return out


class StubModelDetector:
    """Test double: yields fixed findings without loading 1.5B parameters.

    Only yields a finding when `text[start:end] == value` genuinely holds
    for the `text` being scanned — the same offset invariant every real
    detector must satisfy (Task 12 slices outbound payloads on these
    offsets). Engine._scan() now runs tier 3 unconditionally on every
    qualifying observation (no shape pre-filter), so a stub that returned
    its configured findings regardless of input would fire on totally
    unrelated text in every test using this fixture — exactly the kind of
    fixture unrealism this project has hit before with offset bugs.

    Declares the *same* profile as `ModelDetector`, deliberately: a stand-in
    the engine schedules differently from the thing it stands in for would
    make every test that uses it a fiction. If tier 3's cost class ever
    changes, both must change together."""

    profile = DetectorProfile(tier=3, cost=Cost.EXPENSIVE)

    def __init__(self, findings: list[tuple[str, str, int, int]]):
        self._findings = findings
        self.available = True

    def scan(self, text: str, ctx: dict) -> list[Finding]:
        return [Finding(t, v, s, e) for t, v, s, e in self._findings
                if text[s:e] == v]


class ModelDetector:
    # The one expensive detector in the stack: ~430-540ms per scan on the
    # development machine, over a `transformers` pipeline that is not safe to
    # call concurrently. `Cost.EXPENSIVE` is what buys it the engine's
    # boundary gate, the MAX_TIER3_CHARS cap and `_TIER3_LOCK` — and it is
    # declared here rather than inferred from `self.available` below, because
    # those are different claims: this one says "one scan is costly", that
    # one says "the weights loaded on this machine". A tier-3 detector whose
    # weights are present is still expensive, and an unavailable one is still
    # tier 3.
    profile = DetectorProfile(tier=3, cost=Cost.EXPENSIVE)

    def __init__(self, model_id: str = "openai/privacy-filter",
                 min_score: float = MIN_SCORE):
        self.model_id = model_id
        self.min_score = min_score
        # A transformers pipeline once `_load` succeeds; transformers is an
        # optional dependency, so there is no type to name here.
        self._pipe: Any = None
        self.available = self._load()

    def _load(self) -> bool:
        try:
            # I2: never reach the network. `pipeline()`'s own
            # `local_files_only` kwarg was removed upstream (it now raises
            # TypeError from _sanitize_parameters); HF_HUB_OFFLINE is the
            # current supported way to force the whole huggingface_hub /
            # transformers stack offline. Set it here rather than requiring
            # every caller to export it, and never override an operator's
            # own choice if they already set it to something.
            os.environ.setdefault("HF_HUB_OFFLINE", "1")

            from transformers import pipeline

            # `"none"`: the library's own aggregation cannot read this
            # model's BIOES tags and splits every entity at its last token.
            # `spans_from_tokens` does the grouping instead — see the module
            # docstring.
            self._pipe = pipeline(
                "token-classification",
                model=self.model_id,
                aggregation_strategy="none",
            )
            return True
        except Exception:
            return False

    def scan(self, text: str, ctx: dict) -> list[Finding]:
        if not self.available or not text.strip():
            return []
        try:
            tokens = self._pipe(text)
        except Exception:
            # An inference failure is not a clean scan (an accepted empty
            # result is a clean scan, not a scan gap), and returning `[]`
            # here with `available` still true said it was: the engine counted the detector as having
            # run, the observation came out `degraded=False`, and a session
            # whose every deep scan crashed read as a fully verified 0%.
            # That is the exact shape of #47 item 6 — a flag computed and
            # discarded — one layer further down than where it was filed.
            #
            # `available` goes false rather than the exception propagating.
            # On egress, a false wait return yields `GAP_TIMEOUT`; after a
            # true return, a worker error is re-raised and I6 denies the call.
            # Unavailable is the state this class already has for "cannot do
            # its job". The unavailable history requires that no expensive
            # detector supplies a successful available result, including a
            # detector becoming unavailable during inference.
            # `privacy-hud-doctor` already asks about availability.
            self.available = False
            return []
        return spans_from_tokens(text, tokens, min_score=self.min_score)
