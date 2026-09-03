"""Tier 0 — sensitive path rules. ~0.1 ms, always runs."""
from __future__ import annotations

import re

from .base import Detector, Finding

# Every pattern below captures the path itself in group 1, and only group 1.
# Offsets and value are read from that one group so there is a single source
# of truth for both — no separate stripping step that can drift out of sync
# with the reported span (see task-5-report.md, fix round 1, Finding 1).
PATTERNS = [
    re.compile(r"(?:^|[\s/=\"'])(\.env(?:\.[\w-]+)?)\b"),
    re.compile(r"\b(id_rsa|id_ed25519|id_ecdsa)\b"),
    re.compile(r"(\.(?:pem|p12|pfx|keystore))\b"),
    re.compile(r"(\.aws/credentials)\b"),
    re.compile(r"\b(credentials\.json)\b"),
    re.compile(r"(\.ssh/config)\b"),
]


class PathDetector:
    def scan(self, text: str, ctx: dict) -> list[Finding]:
        out = []
        for pat in PATTERNS:
            for m in pat.finditer(text):
                out.append(Finding("path", m.group(1), m.start(1), m.end(1)))
        return out
