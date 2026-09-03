"""Tier 0 — sensitive path rules. ~0.1 ms, always runs."""
from __future__ import annotations

import re

from .base import Detector, Finding

PATTERNS = [
    re.compile(r"(?:^|[\s/=\"'])(\.env(?:\.[\w-]+)?)\b"),
    re.compile(r"\b(id_rsa|id_ed25519|id_ecdsa)\b"),
    re.compile(r"\.(pem|p12|pfx|keystore)\b"),
    re.compile(r"\.aws/credentials\b"),
    re.compile(r"\bcredentials\.json\b"),
    re.compile(r"\.ssh/config\b"),
]


class PathDetector:
    def scan(self, text: str, ctx: dict) -> list[Finding]:
        out = []
        for pat in PATTERNS:
            for m in pat.finditer(text):
                out.append(Finding("path", m.group(0).strip(), m.start(), m.end()))
        return out
