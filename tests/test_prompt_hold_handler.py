from __future__ import annotations

import importlib.util
import io
import json
import types
from pathlib import Path

import pytest

from privacy_hud import dispatch as dispatch_mod
from privacy_hud.detect.model import StubModelDetector
from runtime_helpers import close_writer, writer_state
from test_prompt_hold import A, CONFIRMED, HELD, Clock


HANDLER = Path(__file__).resolve().parents[1] / "hooks" / "handler.py"


@pytest.fixture
def handler():
    spec = importlib.util.spec_from_file_location("prompt_test_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Socket:
    def __init__(self, handler, output):
        self.handler = handler
        self.output = output
        self.reply = b""

    def connect(self, path):
        pass

    def settimeout(self, timeout):
        pass

    def close(self):
        pass

    def sendall(self, data):
        frame = json.loads(data)
        if frame["op"] == "hello":
            reply = {
                "v": self.handler.PROTOCOL_VERSION,
                "op": "hello",
                "ok": True,
                "release": "0.9.2",
                "build_id": "a" * 64,
                "activation_epoch": "b" * 32,
                "storage_generation": self.handler.STORAGE_GENERATION,
                "schema_version": 5402,
                "ready": True,
            }
        else:
            reply = {
                "v": self.handler.PROTOCOL_VERSION,
                "op": "event",
                "ok": True,
                "output": self.output(frame),
            }
        self.reply = (json.dumps(reply) + "\n").encode()

    def recv(self, size):
        result, self.reply = self.reply[:size], self.reply[size:]
        return result


def configure(handler, monkeypatch, tmp_path, payload):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    monkeypatch.setenv("PRIVACY_HUD_NO_SPAWN", "1")
    monkeypatch.setattr(handler, "_selection", lambda root: (
        "ok", ("a" * 64, "b" * 32)
    ))
    monkeypatch.setattr(
        handler, "time", types.SimpleNamespace(monotonic=lambda: 100.0)
    )
    monkeypatch.setattr(handler.sys, "stdin", io.StringIO(json.dumps(payload)))


def test_stdout_is_exact_hold_then_confirmation_through_real_dispatch(
    handler, monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(
        dispatch_mod, "ModelDetector", lambda: StubModelDetector([])
    )
    state = writer_state(tmp_path)
    clock = Clock()
    state.prompt_clock = clock
    dispatch_mod.dispatch(
        state, {"hook_event_name": "SessionStart", "session_id": "s"}
    )

    def output(frame):
        return dispatch_mod.dispatch(
            state, frame["payload"], delivery_key=frame["delivery_key"]
        )

    try:
        for text, expected in [
            (A, {"decision": "block", "reason": HELD}),
            ("edited " + A, {"systemMessage": CONFIRMED}),
        ]:
            payload = {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "s",
                "prompt": text,
            }
            configure(handler, monkeypatch, tmp_path, payload)
            monkeypatch.setattr(
                handler.socket, "socket", lambda *a, **k: Socket(handler, output)
            )
            assert handler.cli() == 0
            captured = capsys.readouterr()
            assert captured.err == ""
            assert captured.out == json.dumps(expected)
            assert A not in captured.out
            clock.now += 2
    finally:
        close_writer(state.ledger)


@pytest.mark.parametrize("starting", [False, True])
def test_no_daemon_and_cold_start_still_fail_open(
    handler, monkeypatch, tmp_path, capsys, starting
):
    payload = {
        "hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": A
    }
    configure(handler, monkeypatch, tmp_path, payload)

    class Missing(Socket):
        def connect(self, path):
            raise OSError("synthetic")

    monkeypatch.setattr(
        handler.socket, "socket", lambda *a, **k: Missing(handler, None)
    )
    monkeypatch.setattr(handler, "_spawn_daemon", lambda root: starting)
    assert handler.cli() == 0
    output = json.loads(capsys.readouterr().out)
    assert set(output) == {"systemMessage"}
    assert "decision" not in output
    assert A not in json.dumps(output)


def test_client_crash_has_empty_stdout(
    handler, monkeypatch, tmp_path, capsys
):
    configure(handler, monkeypatch, tmp_path, {})

    def crash():
        raise RuntimeError(A)

    monkeypatch.setattr(handler, "main", crash)
    assert handler.cli() == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_lost_reply_remains_unverified_and_is_not_replayed(
    handler, monkeypatch, tmp_path, capsys
):
    configure(handler, monkeypatch, tmp_path, {
        "hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": A
    })
    delivered = []

    class LostReply(Socket):
        def sendall(self, data):
            frame = json.loads(data)
            if frame["op"] == "event":
                delivered.append(frame)
                self.reply = b""
            else:
                super().sendall(data)

        def recv(self, size):
            if delivered:
                raise handler.socket.timeout()
            return super().recv(size)

    monkeypatch.setattr(
        handler.socket, "socket", lambda *a, **k: LostReply(handler, None)
    )
    assert handler.cli() == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"systemMessage"}
    assert len(delivered) == 1
