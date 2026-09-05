"""Tier 3 — openai/privacy-filter token classification.

Loads from the local HuggingFace cache only (Global Constraint I2: no network
calls). If the weights are absent the detector reports unavailable and the
engine degrades to tiers 0-2 with a visible warning, rather than crashing or
falling back to any remote service.
"""
from __future__ import annotations

import os

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

    def __init__(self, model_id: str = "openai/privacy-filter"):
        self.model_id = model_id
        self._pipe = None
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

            self._pipe = pipeline(
                "token-classification",
                model=self.model_id,
                aggregation_strategy="simple",
            )
            return True
        except Exception:
            return False

    def scan(self, text: str, ctx: dict) -> list[Finding]:
        if not self.available or not text.strip():
            return []
        try:
            spans = self._pipe(text)
        except Exception:
            return []
        out = []
        for s in spans:
            data_type = LABEL_MAP.get(str(s.get("entity_group", "")).upper())
            if data_type is None:
                continue
            start, end = int(s["start"]), int(s["end"])
            # Trust the offsets over the pipeline's own `word`: aggregation
            # can normalize whitespace/casing so `word` is not always
            # byte-identical to the source slice, and Task 12 rewrites
            # outbound payloads by slicing on these offsets. A value that
            # doesn't match text[start:end] would corrupt that rewrite.
            value = text[start:end]
            out.append(Finding(data_type, value, start, end))
        return out
