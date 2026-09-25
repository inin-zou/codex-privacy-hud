"""Session-local matching and append-only guard-decision metadata.

The HMAC lookup never leaves daemon memory. Persisted IDs describe the
evaluated representation, not a filesystem object or execution subject.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3

from . import ledger_schema
from .accounting import GuardTarget, ObservationRecord, RecordResult

_DOMAIN = b"privacy-hud:guard-target:evaluated-path-v1\x00"


class GuardTargetIndex:
    """One engine's successful-record correlation window."""

    def __init__(self) -> None:
        self._seen: dict[bytes, tuple[str, int]] = {}

    def prepare(
        self, key: bytes, evaluated: str, rule_id: str,
    ) -> tuple[bytes, GuardTarget]:
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("invalid guard-target key")
        if not isinstance(evaluated, str):
            raise ValueError("invalid guard-target representation")
        digest = hmac.new(
            key,
            _DOMAIN + evaluated.encode("utf-8", errors="surrogatepass"),
            hashlib.sha256,
        ).digest()
        prior = self._seen.get(digest)
        target = GuardTarget(
            target_id=prior[0] if prior else secrets.token_hex(16),
            rule_id=rule_id,
            same_as_event_id=prior[1] if prior else None,
        )
        return digest, target

    def remember(
        self, digest: bytes, target: GuardTarget, event_id: int,
    ) -> None:
        # Called only after a successful outermost ledger commit.
        self._seen.setdefault(digest, (target.target_id, event_id))

    def clear(self) -> None:
        self._seen.clear()


def record_target(
    conn: sqlite3.Connection,
    observation: ObservationRecord,
    result: RecordResult,
) -> int:
    """Append inside Ledger's existing observation transaction.

    Validation failure rolls back the observation, events and metadata.
    No exception includes the candidate or command.
    """
    target = observation.guard_target
    if not isinstance(target, GuardTarget) or not conn.in_transaction:
        raise ValueError("invalid guard-target recording")
    if (
        observation.hook_event != "PreToolUse"
        or observation.phase != "pre"
        or observation.action_kind != "read"
        or observation.boundary != "B0"
        or observation.decision != "deny"
    ):
        raise ValueError("invalid guard-target observation")

    found = conn.execute(
        "SELECT e.id FROM events e"
        " JOIN subjects s ON s.session_id=e.session_id"
        " AND s.subject_id=e.subject_id"
        " WHERE e.session_id=? AND e.observation_id=?"
        " AND e.kind='prevented' AND e.data_type='path'"
        " AND e.source_label='local file' AND e.boundary='B0'"
        " AND e.rule_id=? AND (e.evidence & 2)<>0"
        " AND s.subject_kind='file' AND s.resolution='unresolved'"
        " AND s.identity_hash IS NULL",
        (
            observation.session_id,
            result.observation_id,
            target.rule_id,
        ),
    ).fetchall()
    if len(found) != 1:
        raise ValueError("invalid guard-target event")
    event_id = int(found[0][0])

    if not ledger_schema.guard_target_schema_present(conn):
        for statement in ledger_schema.guard_target_statements():
            conn.execute(statement)
    ledger_schema.validate_guard_target_schema(conn)
    conn.execute(
        "INSERT INTO guard_targets"
        "(event_id,session_id,target_id,rule_id,basis,same_as_event_id)"
        " VALUES(?,?,?,?,?,?)",
        (
            event_id,
            observation.session_id,
            target.target_id,
            target.rule_id,
            target.basis,
            target.same_as_event_id,
        ),
    )
    return event_id


def read_target(
    conn: sqlite3.Connection, session_id: str, event_id: int,
) -> GuardTarget | None:
    """Read optional metadata without initializing or changing storage."""
    if not ledger_schema.guard_target_schema_present(conn):
        return None
    row = conn.execute(
        "SELECT target_id,rule_id,same_as_event_id,basis"
        " FROM guard_targets WHERE session_id=? AND event_id=?",
        (session_id, event_id),
    ).fetchone()
    if row is None:
        return None
    return GuardTarget(
        target_id=row[0],
        rule_id=row[1],
        same_as_event_id=row[2],
        basis=row[3],
    )
