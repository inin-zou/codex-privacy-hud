# src/privacy_hud/mask.py
"""Value identity and human-readable exemplars without storing raw values.

The salt lives in daemon memory for one session and is destroyed at
SessionEnd, so hashes are useless across sessions and cannot be reversed
without it.
"""
from __future__ import annotations

import hmac
import os
from hashlib import sha256

_DOT = "•"


def new_salt() -> bytes:
    return os.urandom(32)


def value_hash(salt: bytes, value: str) -> bytes:
    return hmac.new(salt, value.strip().lower().encode(), sha256).digest()[:16]


def mask(data_type: str, value: str) -> str | None:
    """Return a masked exemplar, or None when nothing may be shown.

    Credentials get no exemplar at all: even a prefix narrows the keyspace.
    """
    if data_type == "credential":
        return None
    if data_type == "email" and "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:2]}{_DOT * 3}@{domain}"
    if len(value) <= 4:
        return _DOT * len(value)
    return f"{value[:2]}{_DOT * 3}{value[-1]}"


def pseudonym(salt: bytes, data_type: str, value: str) -> str:
    """Stable per-session replacement, so the agent's cross-references survive
    minimization."""
    token = value_hash(salt, value).hex()[:8]
    if data_type == "email":
        return f"user_{token}@example.invalid"
    return f"{data_type}_{token}"
