# src/privacy_hud/mcp_tools.py
"""Public Python API retained for existing privacy tool callers.

Shared implementations live below the runtime adapters: policy validation,
writes and confirmation conditions in `policy_services`, and session
resolution, audit reads and local session controls in `session_services`.
The internal allow_once primitive remains here; no shipped MCP tool exposes
it.
"""
from __future__ import annotations

from .matrix.loader import HARD_BLOCKED_DATA_TYPES as HARD_BLOCKED_DATA_TYPES
from .minimize import mint_token
from .policy_services import (
    CHEAP_DATA_TYPES as CHEAP_DATA_TYPES,
    apply_policy as apply_policy,
    rule_enforcement_note as rule_enforcement_note,
    validate_policy_rule as validate_policy_rule,
)
from .session_services import (
    CONCURRENT_WITHIN as CONCURRENT_WITHIN,
    AuditReading as AuditReading,
    ResolvedSession as ResolvedSession,
    get_exposure_detail as get_exposure_detail,
    get_session_coverage as get_session_coverage,
    get_session_summary as get_session_summary,
    hud_set_hidden as hud_set_hidden,
    hud_status as hud_status,
    list_exposures as list_exposures,
    read_audit as read_audit,
    read_guard_set as read_guard_set,
    read_guard_status as read_guard_status,
    resolve_audit_session as resolve_audit_session,
)


def allow_once(ledger, session_id: str, *, tool_name: str, tool_input,
               reviewed: bool) -> None:
    """Mint a single-use consent token for exactly `(tool_name,
    tool_input)` (design.md §8 / architecture.md §8's token binding),
    consumed by `Engine.observe` -> `minimize.consume_token` the next time
    Codex retries that exact call.

    `reviewed` must be truthy or this raises `PermissionError` and mints
    nothing. This encodes design.md §8's rule verbatim: `Allow once`
    requires the user to have seen the L3 detail first -- "consent
    without information is not consent." The caller (the UI / skill) is
    responsible for setting `reviewed=True` only after the user has
    actually opened `get_exposure_detail` for the flow in question; this
    function has no way to verify that itself, since a `Ledger` alone
    carries no view-history state, so it enforces the one part of the
    rule it CAN enforce coercively: no token is minted at all without an
    explicit, affirmative claim that the review happened.
    """
    if not reviewed:
        raise PermissionError(
            "allow_once requires reviewed=True: the exposure detail must "
            "be shown before a one-shot allowance can be granted "
            "(design.md §8 -- consent without information is not consent).")
    mint_token(ledger, session_id, tool_name, tool_input, mode="allow_once")
