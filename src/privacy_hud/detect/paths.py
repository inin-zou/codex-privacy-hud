"""Tier 0 — sensitive path rules. ~0.1 ms, always runs."""
from __future__ import annotations

import re

from .base import Cost, DetectorProfile, Finding

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
    # Cheap by declaration, not by inference: compiled regex over the
    # payload, ~0.1ms, nothing to load and nothing that can be missing. It
    # runs on every observation at every boundary, and the engine is told so
    # here rather than deducing it from the absence of an attribute.
    profile = DetectorProfile(tier=0, cost=Cost.CHEAP)

    def scan(self, text: str, ctx: dict) -> list[Finding]:
        out = []
        for pat in PATTERNS:
            for m in pat.finditer(text):
                out.append(Finding("path", m.group(1), m.start(1), m.end(1)))
        return out


#: Suffixes that make a path a template rather than the file it stands in
#: for: `.env.example` is committed to the repository precisely so it can be
#: read. `PATTERNS` matches them (`\.env(\.[\w-]+)?` covers `.env.example`),
#: and for DETECTION that is right -- a template that really does hold a key
#: should still be noticed, and noticing costs 2.0 budget points. Blocking
#: one costs a command that does not run and a user whose only escape is
#: turning the guard off, so the guard is narrower than the detector here.
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")


def is_sensitive_path(path: str) -> bool:
    """Whether reading `path` is worth stopping (`#36`'s deny list).

    Narrower than `PathDetector.scan`, and deliberately so -- see
    `TEMPLATE_SUFFIXES`. Takes one path, not a blob of text: the caller has
    already resolved which file a tool call would read (`origin.py`), so
    this does not go looking for paths inside a string.
    """
    if not path:
        return False
    if path.endswith(TEMPLATE_SUFFIXES):
        return False
    return any(pattern.search(path) for pattern in PATTERNS)
