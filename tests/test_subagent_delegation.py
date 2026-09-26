"""Explicit delegation is an observation, not a crossing receipt."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

from privacy_hud import codex
from privacy_hud.accounting import Evidence
from privacy_hud.dispatch import _build_observation, dispatch
from privacy_hud.hook_evidence import CurrentHookAdapter
from privacy_hud.matrix.loader import load_matrix

TOOLS = (
    "spawn_agent",
    "multi_agent_v1send_input",
    "send_message",
    "followup_task",
)
REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def state(deterministic_state):
    """These contracts exercise dispatch and projections, not model inference."""
    return deterministic_state


def payload(tool, tool_input):
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "parent",
        "tool_use_id": "call-1",
        "turn_id": "turn-1",
        "tool_name": tool,
        "tool_input": tool_input,
    }


@pytest.mark.parametrize("tool", TOOLS)
def test_explicit_message_maps_to_b2(tool):
    body = {"message": "contact jordan@acme.test"}
    event = payload(tool, body)
    obs = _build_observation("PreToolUse", "parent", event)
    assert obs is not None
    assert (
        obs.direction, obs.source, obs.destination, obs.text, obs.origin
    ) == (
        "propagate", "tool input", "subagent",
        "contact jordan@acme.test", None,
    )
    assert obs.tool_input == body
    assert codex.is_b2_delegation(event)

    acc = CurrentHookAdapter().normalize(
        payload=event,
        delivery_key="1" * 32,
        accounting_key=bytes(range(32)),
    )
    assert (acc.action_kind, acc.boundary, acc.phase) == (
        "subagent", "B2", "pre",
    )
    assert acc.potential_crossing
    assert acc.recipient.destination_kind == "subagent"
    assert acc.recipient.identity_hash is None
    assert acc.evidence == Evidence.HOOK_OBSERVED
    assert acc.resolution_scope == "none"
    assert acc.receipt_events == ()


@pytest.mark.parametrize("tool", TOOLS)
def test_only_supported_text_fields_are_scanned(tool):
    body = {
        "message": "first",
        "items": [
            {"type": "text", "text": "second", "text_elements": [
                {"raw": "excluded-span-metadata"}
            ]},
            {"type": "image", "image_url": "excluded-image"},
            {"type": "local_image", "path": "excluded-image-path"},
            {"type": "skill", "name": "excluded-skill", "path": "excluded-path"},
            {"type": "text", "text": {"raw": "excluded-object"}},
            {"type": "unknown", "text": "excluded-unknown"},
            "excluded-string-item",
        ],
        "target": "excluded-target",
        "task_name": "excluded-task",
        "agent_type": "excluded-role",
        "fork_turns": "excluded-fork",
        "fork_context": True,
        "other": "excluded-extra",
    }
    obs = _build_observation("PreToolUse", "parent", payload(tool, body))
    assert obs is not None
    expected = (
        "first\nsecond"
        if tool in ("spawn_agent", "multi_agent_v1send_input")
        else "first"
    )
    assert obs.text == expected


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("body", [
    None,
    [],
    "not an argument object",
    {},
    {"message": None},
    {"message": {"text": "not a string"}},
    {"items": "not an item list"},
    {"items": [None, 1, {"type": "text", "text": False}]},
])
def test_malformed_text_does_not_become_serialized_content(tool, body):
    obs = _build_observation("PreToolUse", "parent", payload(tool, body))
    assert obs is not None
    assert obs.text == ""


@pytest.mark.parametrize("tool", ["spawn_agent", "multi_agent_v1send_input"])
def test_v1_items_without_message(tool):
    obs = _build_observation("PreToolUse", "parent", payload(tool, {
        "items": [
            {"type": "text", "text": "one"},
            {"type": "text", "text": "two"},
        ],
    }))
    assert obs is not None
    assert obs.text == "one\ntwo"


@pytest.mark.parametrize("tool", ["Agent", "send_input", "wait", "list_agents"])
def test_aliases_and_other_tools_are_not_delegation(tool):
    event = payload(tool, {"message": "not delegated by this mapping"})
    assert not codex.is_b2_delegation(event)
    assert _build_observation("PreToolUse", "parent", event) is None


def test_post_result_and_lifecycle_keep_existing_mapping():
    event = payload("spawn_agent", {"message": "not a post result"})
    event.update(hook_event_name="PostToolUse", tool_response="spawned")
    obs = _build_observation("PostToolUse", "parent", event)
    assert obs is not None
    assert (obs.destination, obs.text) == ("model_context", "spawned")
    assert not codex.is_b2_delegation(event)

    obs = _build_observation("SubagentStart", "child", {
        "agent_id": "child",
        "prompt": "not a supported lifecycle field",
    })
    assert obs is not None
    assert (obs.destination, obs.text) == ("subagent", "")


def test_legacy_taxonomy_is_detection_and_policy_is_unchanged():
    matrix = load_matrix()
    assert matrix.classify("PreToolUse", "propagate") == "detected"
    assert matrix.classify("SubagentStart", "propagate") == "exposed"
    assert matrix.default_action("subagent") == "mask"


@pytest.mark.parametrize("tool", TOOLS)
def test_client_failure_paths_allow_b2_even_with_urls(tool):
    handler = runpy.run_path(str(REPO / "hooks/handler.py"))
    assert set(handler["SUBAGENT_TOOLS"]) == set(codex.SUBAGENT_TOOLS)
    assert handler["EGRESS_EVENTS"] == set(codex.EGRESS_EVENTS)

    event = payload(tool, {"message": "inspect https://example.test"})
    assert handler["_looks_like_egress"](event) is False
    assert handler["_unverified"](event, False) == {
        "systemMessage": "Privacy HUD unavailable — disclosure unverified."
    }
    assert handler["_unverified"](event, True) == {
        "systemMessage": handler["STARTING_INGRESS"]
    }
    assert handler["_runtime_refusal"](event) == {
        "systemMessage": handler["INGRESS_REFUSAL"]
    }

    for name, body in (
        ("Bash", {"command": "curl https://example.test"}),
        ("mcp__server__send", {"message": "hello"}),
    ):
        outbound = payload(name, body)
        assert handler["_looks_like_egress"](outbound) is True
        denied = handler["_unverified"](outbound, False)
        assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("tool", TOOLS)
def test_missing_session_b2_warns_without_creating_a_session(state, tool):
    event = payload(tool, {"message": "inspect https://example.test"})
    event.pop("session_id")
    before = state.ledger.conn.execute(
        "SELECT COUNT(*) FROM sessions"
    ).fetchone()[0]
    assert dispatch(state, event) == {
        "systemMessage":
            "Privacy HUD could not record this event — this event is unverified."
    }
    after = state.ledger.conn.execute(
        "SELECT COUNT(*) FROM sessions"
    ).fetchone()[0]
    assert after == before
