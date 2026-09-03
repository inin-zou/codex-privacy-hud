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
    # PEM-style private key headers: RSA, OpenSSH, EC, DSA, generic PKCS8,
    # and the PGP armor header. A raw key block pasted into text (not just a
    # filename reference) must be caught here.
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        r"|-----BEGIN PGP PRIVATE KEY BLOCK-----"
    ),
]

# Keyword-gated: a recognizable secret-ish name immediately left of the
# value. Quotes optional — this also covers unquoted shell/env-style
# assignment (KEY=value). Floor: 16 chars.
ASSIGNMENT = re.compile(
    r"""(?ix)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9+/_\-]{16,})["']?"""
)

# Name-agnostic: any quoted literal long and random enough to be a
# credential, regardless of what (if anything) precedes it. This is what
# makes the entropy backstop reachable for a key assigned to an
# unrecognized variable name — gating the backstop on ASSIGNMENT's fixed
# keyword list defeated its own purpose (fix round 1, Finding 2). The floor
# is raised to 20 (vs. 16 for ASSIGNMENT) because there is no keyword signal
# narrowing the search space here; the extra length cuts down on shorter,
# more ordinary tokens crossing the entropy bar by chance. Quotes are
# required (not optional) to keep this from firing on arbitrary unquoted
# `name=value` pairs (env/config lines, path variables, etc.), which would
# be a much larger false-positive surface than quoted string literals.
GENERIC_QUOTED = re.compile(r"""["']([A-Za-z0-9+/_\-]{20,})["']""")

PLACEHOLDERS = re.compile(
    r"(?i)^(?:your|my|the)?[-_ ]?(?:api[-_ ]?key|secret|token|password)?[-_ ]?(?:here|goes[-_ ]?here|xxx+|placeholder|example|changeme|todo|\.{3})$"
)

ENTROPY_THRESHOLD = 3.5

# Exact digest lengths for common hash functions (md5, sha1, sha256, sha512).
# A pure-hex string at one of these lengths is treated as a checksum/git SHA,
# not a credential, but ONLY when found by GENERIC_QUOTED — the name-agnostic,
# no-context path. ASSIGNMENT (an explicit api_key/secret/token/... keyword
# immediately to the left) is NOT exempted: an explicit keyword is stronger
# evidence than shape, so `api_key = "<40 hex chars>"` still flags. See
# task-5-report.md, fix round 2, for the length-allowlist-vs-variety-rule
# reasoning.
HEX_DIGEST_LENGTHS = {32, 40, 64, 128}
_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_placeholder(candidate: str) -> bool:
    return bool(PLACEHOLDERS.match(candidate)) or "-here" in candidate.lower()


def _is_hex_digest(candidate: str) -> bool:
    return len(candidate) in HEX_DIGEST_LENGTHS and bool(_HEX_ONLY.match(candidate))


def _overlaps_existing(out: list[Finding], start: int, end: int) -> bool:
    return any(f.start <= start < f.end for f in out)


class SecretDetector:
    def scan(self, text: str, ctx: dict) -> list[Finding]:
        out: list[Finding] = []
        for pat in KEY_PATTERNS:
            for m in pat.finditer(text):
                out.append(Finding("credential", m.group(0), m.start(), m.end()))
        for pat in (ASSIGNMENT, GENERIC_QUOTED):
            for m in pat.finditer(text):
                candidate = m.group(1)
                if _is_placeholder(candidate):
                    continue
                if pat is GENERIC_QUOTED and _is_hex_digest(candidate):
                    continue
                if shannon(candidate) < ENTROPY_THRESHOLD:
                    continue
                if _overlaps_existing(out, m.start(1), m.end(1)):
                    continue
                out.append(Finding("credential", candidate, m.start(1), m.end(1)))
        return out
