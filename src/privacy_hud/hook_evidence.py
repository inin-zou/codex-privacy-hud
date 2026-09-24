"""Hook evidence: what one delivered hook establishes, and nothing more
(#54 Phase 4).

The daemon normalizes every protocol-2 event into a `HookEvidence` before
any accounting write. Normalization is conservative by construction: the
current adapter records that a hook was observed, names the action, turn
and intended recipient where they can be identified exactly, and claims no
terminal outcome. A payload cannot supply evidence, receipts, identities,
evaluated paths or internal IDs: every accounting field here is derived by
the daemon, never read from a similarly named payload field.

Pure: no filesystem, environment, DNS or network access.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn, Protocol

from .accounting import (
    ActionKind,
    Boundary,
    EventRecord,
    Evidence,
    HookEvent,
    Phase,
    RecipientInput,
    ResolutionScope,
)
from .ledger_schema import UnsupportedAccounting


def _scaffold() -> NoReturn:
    # P4-C1 contract scaffolding: the operation is declared, not implemented.
    raise UnsupportedAccounting("hook evidence is not implemented")


#: Passed to `normalize_delivery_key` when the envelope carried no
#: `delivery_key` field at all. A JSON `null` is a supplied value, not this.
DELIVERY_KEY_ABSENT: object = object()


@dataclass(frozen=True, kw_only=True)
class HookEvidence:
    delivery_key: str
    action_id: str
    turn_id: str | None
    hook_event: HookEvent
    phase: Phase
    action_kind: ActionKind
    boundary: Boundary
    recipient: RecipientInput
    evidence: Evidence
    resolution_scope: ResolutionScope
    potential_crossing: bool
    receipt_events: tuple[EventRecord, ...] = ()


class HookEvidenceAdapter(Protocol):
    def normalize(
        self,
        *,
        payload: dict,
        delivery_key: str,
        accounting_key: bytes | None,
    ) -> HookEvidence: ...


class CurrentHookAdapter:
    def normalize(
        self,
        *,
        payload: dict,
        delivery_key: str,
        accounting_key: bytes | None,
    ) -> HookEvidence:
        _scaffold()


def normalize_delivery_key(value: object) -> str:
    _scaffold()
