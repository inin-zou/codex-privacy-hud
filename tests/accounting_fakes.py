"""Test-only builders for synthetic version-2 accounting (#54 Phase 3).

Nothing under `src/` may import this module. It creates version-2 sessions
through the ledger's private constructor, which no production path calls,
and builds valid observation and event records that a test then varies.
"""
from __future__ import annotations

import dataclasses
import secrets
import sqlite3
from pathlib import Path

from privacy_hud.accounting import (
    Evidence, EventRecord, ObservationRecord, RecipientInput, ScoringProfile,
    SubjectInput,
)
from privacy_hud.identity import recipient_identity, value_identity
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix

M = load_matrix()
PROFILE = ScoringProfile.from_matrix(M)
KEY = bytes(range(32))

#: Tables a version-2 write may touch, plus the ones it must not.
TABLES = ("sessions", "coverage", "scoring_profiles", "observations",
          "subjects", "recipients", "events", "disclosures", "scan_gaps",
          "policy")


def hex_id() -> str:
    return secrets.token_hex(16)


def prepared_ledger(path: Path) -> Ledger:
    """A ledger at generation 5401, prepared by a genuine legacy boundary."""
    led = Ledger(path, M)
    with led._write_transaction():
        led.prepare_session_boundary("legacy-boundary")
        led.start_session("legacy-boundary", cwd="", model="")
    return led


def start_v2(led: Ledger, session_id: str | None = None,
             profile: ScoringProfile = PROFILE) -> str:
    session_id = session_id or f"v2-{hex_id()}"
    with led._write_transaction():
        led._start_v2_session(session_id, cwd="", model="", profile=profile)
    return session_id


def profile_with(**changes) -> ScoringProfile:
    """`PROFILE` with some top-level fields or map entries replaced."""
    fields = {
        "format_version": 1,
        "matrix_version": PROFILE.matrix_version,
        "budget_cap": PROFILE.budget_cap,
        "severity": dict(PROFILE.severity),
        "boundary_multiplier": dict(PROFILE.boundary_multiplier),
        "destination_boundary": dict(PROFILE.destination_boundary),
        "bands": PROFILE.bands,
        "charged_type_rule": PROFILE.charged_type_rule,
    }
    for name, value in changes.items():
        if isinstance(value, dict):
            fields[name].update(value)
        else:
            fields[name] = value
    return ScoringProfile(**fields)


def value_subject(text: str) -> SubjectInput:
    return SubjectInput(subject_kind="value",
                        identity_hash=value_identity(KEY, text))


def unresolved_subject(token: str | None = None) -> SubjectInput:
    return SubjectInput(subject_kind="value", identity_hash=None,
                        unresolved_token=token)


def recipient(kind: str = "mcp_tool", name: str = "server-a") -> RecipientInput:
    return RecipientInput(destination_kind=kind,  # type: ignore[arg-type]
                          identity_hash=recipient_identity(KEY, kind, name))  # type: ignore[arg-type]


def unresolved_recipient(kind: str = "mcp_tool",
                         token: str | None = None) -> RecipientInput:
    return RecipientInput(destination_kind=kind,  # type: ignore[arg-type]
                          identity_hash=None, unresolved_token=token)


def observation(session_id: str, **changes) -> ObservationRecord:
    """A permitted PreToolUse at B3 whose crossing is confirmed."""
    values = {
        "session_id": session_id,
        "delivery_key": hex_id(),
        "action_id": hex_id(),
        "turn_id": None,
        "ts": 1_700_000_000,
        "hook_event": "PreToolUse",
        "phase": "pre",
        "action_kind": "tool",
        "boundary": "B3",
        "decision": "allow",
        "evidence": (Evidence.PERMISSION_ISSUED | Evidence.CROSSING_CONFIRMED
                     | Evidence.LOCAL_DETECTION | Evidence.HOOK_OBSERVED),
        "resolution_scope": "none",
        "potential_crossing": True,
        "scan_gap": None,
    }
    values.update(changes)
    return ObservationRecord(**values)


def event(subject: SubjectInput | None = None,
          to: RecipientInput | None = None, **changes) -> EventRecord:
    """A confirmed B3 email exposure to MCP server-a."""
    values = {
        "subject": subject or value_subject("alice@example.com"),
        "recipient": to or recipient(),
        "kind": "exposed",
        "evidence": Evidence.CROSSING_CONFIRMED,
        "data_type": "email",
        "rule_id": None,
        "occurrences": 1,
        "source_label": "tool input",
        "boundary": "B3",
        "masked_example": "al•••m",
    }
    values.update(changes)
    return EventRecord(**values)


def replace(record, **changes):
    return dataclasses.replace(record, **changes)


def snapshot(conn: sqlite3.Connection) -> dict[str, list[tuple]]:
    """Every row of every accounting-relevant table."""
    present = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    return {table: [tuple(r) for r in conn.execute(
        f"SELECT * FROM {table} ORDER BY rowid")]
        for table in TABLES if table in present}


def count(conn: sqlite3.Connection, table: str, session_id: str | None = None
          ) -> int:
    if session_id is None:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE session_id=?",
                        (session_id,)).fetchone()[0]


def score(conn: sqlite3.Connection, session_id: str) -> float:
    return conn.execute("SELECT budget_score FROM sessions WHERE session_id=?",
                        (session_id,)).fetchone()[0]
