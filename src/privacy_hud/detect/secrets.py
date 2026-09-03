"""Tier 1 — credential regex plus a Shannon-entropy backstop for keys that
have no recognizable prefix."""
from __future__ import annotations

import math
import re
from collections import Counter

from .base import Finding

KEY_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b(?:postgres|mysql|mongodb)(?:\+\w+)?://[^\s\"']+:[^\s\"'@]+@[^\s\"']+"),
]

ASSIGNMENT = re.compile(
    r"""(?ix)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9+/_\-]{16,})["']?"""
)

PLACEHOLDERS = re.compile(
    r"(?i)^(?:your|my|the)?[-_ ]?(?:api[-_ ]?key|secret|token|password)?[-_ ]?(?:here|goes[-_ ]?here|xxx+|placeholder|example|changeme|todo|\.{3})$"
)

ENTROPY_THRESHOLD = 3.5


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class SecretDetector:
    def scan(self, text: str, ctx: dict) -> list[Finding]:
        out: list[Finding] = []
        for pat in KEY_PATTERNS:
            for m in pat.finditer(text):
                out.append(Finding("credential", m.group(0), m.start(), m.end()))
        for m in ASSIGNMENT.finditer(text):
            candidate = m.group(1)
            if PLACEHOLDERS.match(candidate) or "-here" in candidate.lower():
                continue
            if shannon(candidate) < ENTROPY_THRESHOLD:
                continue
            if any(f.start <= m.start(1) < f.end for f in out):
                continue
            out.append(Finding("credential", candidate, m.start(1), m.end(1)))
        return out
