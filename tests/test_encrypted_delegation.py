"""Synthetic contracts for opaque delegation; no live Codex state."""

from __future__ import annotations

import base64
import hashlib
import json
import runpy
from pathlib import Path

import pytest

from privacy_hud import codex
from privacy_hud.detect.secrets import SecretDetector
from privacy_hud.dispatch import _build_observation, dispatch

TOOLS = (
    "spawn_agent",
    "send_message",
    "followup_task",
    "collaborationspawn_agent",
    "collaborationsend_message",
    "collaborationfollowup_task",
)
NOTICE = (
    "Privacy HUD: encrypted delegation message is unobservable; "
    "coverage is incomplete."
)
REPO = Path(__file__).resolve().parents[1]


def fake_token(ciphertext_size=48):
    """Fernet format only: no key, encryption, or authenticating MAC."""
    ciphertext = hashlib.shake_256(
        b"synthetic ciphertext; not encryption"
    ).digest(ciphertext_size)
    raw = (
        b"\x80"
        + (1700000000).to_bytes(8, "big")
        + bytes(range(16))
        + ciphertext
        + bytes(range(32))
    )
    return base64.urlsafe_b64encode(raw).decode("ascii")


def envelope(tool, message):
    if tool.endswith("spawn_agent"):
        return {
            "task_name": "filename_check",
            "fork_turns": "none",
            "message": message,
        }
    return {"target": "/root/worker", "message": message}


def pre(tool, body, sid="parent"):
    return {
        "hook_event_name": "PreToolUse",
        "session_id": sid,
        "tool_use_id": "synthetic-call",
        "tool_name": tool,
        "tool_input": body,
    }


def start(state, sid="parent"):
    dispatch(
        state,
        {"hook_event_name": "SessionStart", "session_id": sid},
        delivery_key="1" * 32,
    )


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("ciphertext_size", [16, 32, 48, 256])
def test_recognized_message_is_excluded_by_field(tool, ciphertext_size):
    token = fake_token(ciphertext_size)
    body = envelope(tool, token)
    before = json.loads(json.dumps(body))

    assert codex.encrypted_delegation_fields(tool, body) == ("message",)
    assert codex.delegated_text(tool, body) == ""
    assert body == before

    event = pre(tool, body)
    assert codex.is_b2_delegation(event)
    obs = _build_observation("PreToolUse", "parent", event)
    assert obs is not None
    assert obs.text == ""
    assert obs.delegation_unobservable


@pytest.mark.parametrize(
    "message",
    [
        "gAAAAAB",
        "gAAAAAB...",
        fake_token() + "\n",
        fake_token() + " additional plaintext",
        '"' + fake_token() + '"',
        base64.urlsafe_b64encode(b"\x80" + bytes(70)).decode("ascii"),
        base64.urlsafe_b64encode(b"\x81" + bytes(72)).decode("ascii"),
        None,
        {"text": "not a string"},
    ],
)
def test_malformed_or_plaintext_values_are_not_excluded(message):
    body = envelope("spawn_agent", message)
    assert codex.encrypted_delegation_fields("spawn_agent", body) == ()
    expected = message if isinstance(message, str) else ""
    assert codex.delegated_text("spawn_agent", body) == expected


@pytest.mark.parametrize(
    "tool",
    ["multi_agent_v1send_input", "mcp__demo__send", "Bash", "assign_task"],
)
def test_other_tools_do_not_gain_a_ciphertext_exemption(tool):
    body = envelope("send_message", fake_token())
    assert codex.encrypted_delegation_fields(tool, body) == ()


def test_spawn_requires_v2_envelope_metadata():
    token = fake_token()
    body = {"message": token}
    assert codex.encrypted_delegation_fields("spawn_agent", body) == ()
    assert codex.delegated_text("spawn_agent", body) == token


@pytest.mark.parametrize(
    "credential",
    [
        "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2",
        "AKIA" + "0123456789ABCDEF",
        "eyJabcdefghijk.abcdefghijklm.nopqrstuvwxyz",
        "postgres://demo:synthetic-password@db.example.test/app",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_real_credential_formats_remain_detectable_in_plaintext(credential):
    detector = SecretDetector()
    assert detector.scan(credential, {})

    for tool in (*TOOLS, "multi_agent_v1send_input"):
        body = envelope(tool, credential)
        assert codex.encrypted_delegation_fields(tool, body) == ()
        assert any(
            finding.data_type == "credential"
            for finding in detector.scan(codex.delegated_text(tool, body), {})
        )

    body = envelope("spawn_agent", fake_token())
    body["items"] = [{"type": "text", "text": credential}]
    text = codex.delegated_text("spawn_agent", body)
    assert text == credential
    assert any(
        finding.data_type == "credential"
        for finding in detector.scan(text, {})
    )


def test_detector_characterization_does_not_add_global_exemptions():
    detector = SecretDetector()
    for size in (16, 32, 48):
        token = fake_token(size)
        assert detector.scan(token, {}) == []
        matches = detector.scan_labeled(json.dumps({"message": token}), {})
        assert [match.kind for match in matches] == (
            ["High-entropy quoted string"] if size == 48 else []
        )

    matches = detector.scan_labeled(
        json.dumps({"task_name": "/root/filename_check"}), {}
    )
    assert [match.kind for match in matches] == ["High-entropy quoted string"]
    assert matches[0].finding.value == "/root/filename_check"


@pytest.mark.parametrize("tool", TOOLS)
def test_encrypted_pre_records_gap_without_findings(
        deterministic_state, tmp_path, tool):
    state = deterministic_state
    seen = []

    class RecordingDetector(SecretDetector):
        def scan(self, text, ctx):
            seen.append(text)
            return super().scan(text, ctx)

    state.detectors = [RecordingDetector()]
    start(state)
    token = fake_token()
    event = pre(tool, envelope(tool, token))

    assert dispatch(state, event, delivery_key="2" * 32) == {
        "systemMessage": NOTICE
    }
    assert seen
    assert all(token not in text for text in seen)

    row = state.ledger.conn.execute(
        "SELECT boundary, decision, scan_gap FROM observations "
        "WHERE session_id=? AND hook_event=?",
        ("parent", "PreToolUse"),
    ).fetchone()
    assert tuple(row) == ("B2", "allow", "unavailable")

    for table in ("events", "subjects", "recipients", "disclosures"):
        assert state.ledger.conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE session_id=?",
            ("parent",),
        ).fetchone()[0] == 0

    summary = state.ledger.summary("parent")
    assert summary.confirmed_points == 0
    assert summary.unresolved_actions == 1
    assert summary.percent is None
    assert "coverage_incomplete" in summary.percentage_unavailable_reasons
    assert state.ledger.coverage("parent").shallow_scans == 1

    # Protocol-2 retry does not append another observation or scan gap.
    assert dispatch(state, event, delivery_key="2" * 32) == {
        "systemMessage": NOTICE
    }
    assert state.ledger.scan_gaps("parent") == 1

    dump = "\n".join(state.ledger.conn.iterdump())
    assert token not in dump
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert token.encode("ascii") not in path.read_bytes()


def test_legacy_encrypted_pre_records_gap_without_a_finding(
        deterministic_state):
    state = deterministic_state
    start(state, "other-session")
    token = fake_token()

    result = dispatch(
        state,
        pre("spawn_agent", envelope("spawn_agent", token), "late-parent"),
        delivery_key="3" * 32,
    )
    assert result == {"systemMessage": NOTICE}

    session = state.ledger.conn.execute(
        "SELECT accounting_version, budget_score FROM sessions "
        "WHERE session_id=?",
        ("late-parent",),
    ).fetchone()
    assert tuple(session) == (1, 0)
    assert state.ledger.scan_gaps("late-parent") == 1
    assert state.ledger.conn.execute(
        "SELECT COUNT(*) FROM events_legacy_v1 WHERE session_id=?",
        ("late-parent",),
    ).fetchone()[0] == 0
    assert token not in "\n".join(state.ledger.conn.iterdump())


def test_post_scans_result_and_does_not_scan_echoed_input():
    token = fake_token()
    event = pre("spawn_agent", envelope("spawn_agent", token))
    event.update(
        hook_event_name="PostToolUse",
        tool_response='{"task_name":"/root/worker"}',
    )
    obs = _build_observation("PostToolUse", "parent", event)
    assert obs is not None
    assert token not in obs.text
    assert not obs.delegation_unobservable
    assert SecretDetector().scan(obs.text, {}) == []

    # An arbitrary result is not entitled to the input-field exemption.
    event["tool_response"] = {"message": token}
    obs = _build_observation("PostToolUse", "parent", event)
    assert obs is not None
    assert SecretDetector().scan(obs.text, {})


@pytest.mark.parametrize("tool", TOOLS)
def test_client_keeps_supported_delegation_fail_open(tool):
    handler = runpy.run_path(str(REPO / "hooks/handler.py"))
    assert set(handler["SUBAGENT_TOOLS"]) == set(codex.SUBAGENT_TOOLS)
    event = pre(tool, envelope(tool, "inspect https://example.test"))
    assert handler["_looks_like_egress"](event) is False
    assert handler["_unverified"](event, False) == {
        "systemMessage": "Privacy HUD unavailable — disclosure unverified."
    }
