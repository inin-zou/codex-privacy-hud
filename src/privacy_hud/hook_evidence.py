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

import os
import re
from dataclasses import dataclass
from typing import Protocol, cast

from . import codex
from .accounting import (
    ActionKind,
    Boundary,
    DestinationKind,
    EventKind,
    EventRecord,
    Evidence,
    HookEvent,
    Phase,
    RecipientInput,
    ResolutionScope,
)
from .detect.shell import extract_destinations, intended_network_recipient
from .identity import action_identity, recipient_identity, turn_identity
from .origin import OriginKind, extract_origin

INVALID_DELIVERY_KEY = "invalid hook delivery key"
INVALID_HOOK_EVIDENCE = "invalid hook accounting evidence"

_DELIVERY_KEY = re.compile(r"[0-9a-f]{32}\Z")

#: The phase each hook event's observation carries; pinned against the
#: ledger's own table by `tests/test_hook_evidence.py`.
_PHASE: dict[str, Phase] = {
    "PreToolUse": "pre",
    "UserPromptSubmit": "pre",
    "PostToolUse": "post",
    "SessionStart": "lifecycle",
    "SessionEnd": "lifecycle",
    "SubagentStart": "lifecycle",
    "SubagentStop": "lifecycle",
    "PreCompact": "lifecycle",
}

#: The matrix's `destination_boundary`, restated so normalization reads no
#: file; `tests/test_hook_evidence.py` pins the two together.
_DESTINATION_BOUNDARY: dict[DestinationKind, Boundary] = {
    "local": "B0",
    "model_context": "B1",
    "subagent": "B2",
    "mcp_tool": "B3",
    "external_net": "B4",
}

#: Hooks whose payload carries the host's ID for one tool action.
_TOOL_HOOKS = frozenset({"PreToolUse", "PostToolUse"})


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


def _is_delivery_key(value: object) -> bool:
    return isinstance(value, str) and _DELIVERY_KEY.match(value) is not None


def normalize_delivery_key(value: object) -> str:
    """The delivery key for one protocol-2 event.

    `DELIVERY_KEY_ABSENT` -- the envelope had no such field -- gets a fresh
    request-local key. A supplied value must be 32 lowercase hex
    characters; anything else, JSON `null` included, is refused rather
    than silently replaced."""
    if value is DELIVERY_KEY_ABSENT:
        return os.urandom(16).hex()
    if _is_delivery_key(value):
        return cast(str, value)
    raise ValueError(INVALID_DELIVERY_KEY)


def _tool_input(payload: dict) -> dict:
    tool_input = payload.get("tool_input")
    return tool_input if isinstance(tool_input, dict) else {}


def _command(tool_input: dict) -> str:
    command = tool_input.get("command")
    return command if isinstance(command, str) else ""


def _recognized_read(tool_name: object, tool_input: dict) -> bool:
    """A shell command the read guard would evaluate as a local file read.
    One predicate for both hooks, so a read's action kind cannot differ
    between its pre and post observations."""
    if tool_name != codex.SHELL_TOOL:
        return False
    if extract_destinations(_command(tool_input)) != ["local"]:
        return False
    origin = extract_origin(codex.SHELL_TOOL, tool_input)
    return origin is not None and origin.kind is OriginKind.PATH


def _classify(event: str, payload: dict
              ) -> tuple[ActionKind, DestinationKind, bool]:
    """(action kind, intended destination, potential crossing)."""
    if event in ("SessionStart", "SessionEnd", "PreCompact"):
        return "lifecycle", "local", False
    if event == "SubagentStop":
        return "subagent", "subagent", False
    if event == "SubagentStart":
        return "subagent", "subagent", True
    if event == "UserPromptSubmit":
        return "prompt", "model_context", True
    tool_name = payload.get("tool_name")
    tool_input = _tool_input(payload)
    read = _recognized_read(tool_name, tool_input)
    if event == "PostToolUse":
        # One action keeps one kind: a delegation's result shares its
        # pre-hook's `tool_use_id`, so it stays a subagent action. The
        # result itself is still ingress to the parent's model context.
        if isinstance(tool_name, str) and tool_name in codex.SUBAGENT_TOOLS:
            return "subagent", "model_context", True
        return ("read" if read else "tool"), "model_context", True
    # PreToolUse
    if codex.is_b2_delegation(payload):
        return "subagent", "subagent", True
    if read:
        return "read", "local", False
    if isinstance(tool_name, str) and codex.is_mcp_tool(tool_name):
        return "tool", "mcp_tool", True
    if (tool_name == codex.SHELL_TOOL
            and extract_destinations(_command(tool_input)) != ["local"]):
        return "tool", "external_net", True
    return "tool", "local", False


def _recipient(destination: DestinationKind, payload: dict,
               key: bytes | None) -> RecipientInput:
    """The intended recipient, resolved only when it is known exactly and
    the session key is available. Subagents stay unresolved: no child
    identity is guessed from parent IDs or names."""
    concrete: str | None = None
    if key is not None:
        if destination in ("local", "model_context"):
            concrete = destination
        elif destination == "mcp_tool":
            tool_name = payload.get("tool_name")
            if isinstance(tool_name, str):
                concrete = codex.mcp_server_namespace(tool_name)
        elif destination == "external_net":
            concrete = intended_network_recipient(
                _command(_tool_input(payload)))
    if key is None or concrete is None:
        return RecipientInput(destination_kind=destination,
                              identity_hash=None)
    return RecipientInput(
        destination_kind=destination,
        identity_hash=recipient_identity(key, destination, concrete))


def _correlated(identify, key: bytes | None, host_id: object) -> str | None:
    if key is None:
        return None
    try:
        return cast(str, identify(key, host_id))
    except ValueError:
        return None  # not a usable host ID: no correlation is claimed


class CurrentHookAdapter:
    """The production adapter. It records that a hook was observed and
    nothing more: `HOOK_OBSERVED`, scope `none`, no receipt events, and
    never crossing, enforcement, rejection, persistence or execution
    evidence. Policy and detection bits are added by the engine after it
    has actually issued a decision or found a value."""

    def normalize(
        self,
        *,
        payload: dict,
        delivery_key: str,
        accounting_key: bytes | None,
    ) -> HookEvidence:
        if (not isinstance(payload, dict) or not _is_delivery_key(delivery_key)
                or (accounting_key is not None
                    and (type(accounting_key) is not bytes
                         or len(accounting_key) != 32))):
            raise ValueError(INVALID_HOOK_EVIDENCE)
        event = payload.get("hook_event_name")
        if not isinstance(event, str) or event not in _PHASE:
            raise ValueError(INVALID_HOOK_EVIDENCE)
        action_kind, destination, potential = _classify(event, payload)
        action_id = None
        if event in _TOOL_HOOKS:
            action_id = _correlated(action_identity, accounting_key,
                                    payload.get("tool_use_id"))
        return HookEvidence(
            delivery_key=delivery_key,
            action_id=action_id or os.urandom(16).hex(),
            turn_id=_correlated(turn_identity, accounting_key,
                                payload.get("turn_id")),
            hook_event=cast(HookEvent, event),
            phase=_PHASE[event],
            action_kind=action_kind,
            boundary=_DESTINATION_BOUNDARY[destination],
            recipient=_recipient(destination, payload, accounting_key),
            evidence=Evidence.HOOK_OBSERVED,
            resolution_scope="none",
            potential_crossing=potential,
        )


def classify_evidence(
    *,
    boundary: Boundary,
    evidence: Evidence,
) -> tuple[EventKind, ...]:
    """The event kinds one finding event's own evidence supports.

    Terminal kinds first, every one that applies, in the stable order
    prevented, exposed, local_access, retention: a denial issued or
    enforced, a rejection before crossing or an applied rewrite is
    `prevented`; a confirmed crossing of a non-B0 boundary is `exposed`;
    observed execution at B0 is `local_access`; observed persistence is
    `retention`. Only when none applies: an issued permission is
    `permitted`, otherwise a local detection is `detected`, otherwise
    nothing. An issued rewrite alone is neither prevention nor an applied
    rewrite. The evidence is the event's, never another pair's."""
    kinds: list[EventKind] = []
    if evidence & (Evidence.DENY_ISSUED | Evidence.DENY_ENFORCED
                   | Evidence.REJECTED_BEFORE_CROSSING
                   | Evidence.REWRITE_ENFORCED):
        kinds.append("prevented")
    if Evidence.CROSSING_CONFIRMED in evidence and boundary != "B0":
        kinds.append("exposed")
    if Evidence.EXECUTION_OBSERVED in evidence and boundary == "B0":
        kinds.append("local_access")
    if Evidence.PERSISTENCE_OBSERVED in evidence:
        kinds.append("retention")
    if kinds:
        return tuple(kinds)
    if Evidence.PERMISSION_ISSUED in evidence:
        return ("permitted",)
    if Evidence.LOCAL_DETECTION in evidence:
        return ("detected",)
    return ()
