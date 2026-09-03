"""Tier 3 — openai/privacy-filter token classification.

Loads from the local HuggingFace cache only (Global Constraint I2: no network
calls). If the weights are absent the detector reports unavailable and the
engine degrades to tiers 0-2 with a visible warning, rather than crashing or
falling back to any remote service.
"""
from __future__ import annotations

from .base import Finding

LABEL_MAP = {
    "NAME": "person",
    "ADDRESS": "address",
    "EMAIL": "email",
    "PHONE": "phone",
    "URL": "url",
    "DATE": "date",
    "ACCOUNT": "account",
    "SECRET": "credential",
}


class StubModelDetector:
    """Test double: yields fixed findings without loading 1.5B parameters."""

    def __init__(self, findings: list[tuple[str, str, int, int]]):
        self._findings = findings
        self.available = True

    def scan(self, text: str, ctx: dict) -> list[Finding]:
        return [Finding(t, v, s, e) for t, v, s, e in self._findings]


class ModelDetector:
    def __init__(self, model_id: str = "openai/privacy-filter"):
        self.model_id = model_id
        self._pipe = None
        self.available = self._load()

    def _load(self) -> bool:
        try:
            from transformers import pipeline

            self._pipe = pipeline(
                "token-classification",
                model=self.model_id,
                aggregation_strategy="simple",
                local_files_only=True,  # I2: never reach the network
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
