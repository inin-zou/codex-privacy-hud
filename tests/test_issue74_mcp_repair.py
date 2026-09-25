"""Issue 74: synthetic MCP identities only; no real process inspection."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shlex
import signal
from pathlib import Path
from types import SimpleNamespace

import pytest

from privacy_hud import runtime_messages as messages
from privacy_hud import runtime_repair as repair
from privacy_hud import runtime_storage as storage


@pytest.fixture
def fake_runtime(tmp_path, monkeypatch):
    data = tmp_path / "data"
    bundle = tmp_path / "bundle"
    python = tmp_path / "venv" / "bin" / "python"
    data.mkdir()
    python.parent.mkdir(parents=True)
    python.touch()

    def identity(pid, command="mcp"):
        return {
            "pid": pid,
            "uid": str(os.getuid()),
            "start": "synthetic-start",
            "executable": str(python.resolve()),
            "argv": [
                str(python), "-I",
                str(bundle / "scripts" / "runtime.py"),
                "--plugin-data", str(data), command,
            ],
            "launcher": None,
        }

    processes = {424242: identity(424242)}
    sent = []
    progress = []
    state = SimpleNamespace(
        data=data,
        bundle=bundle,
        python=python,
        identity=identity,
        processes=processes,
        sent=sent,
        progress=progress,
        exits=True,
        respawn=False,
    )

    def send(pid, sig):
        sent.append((pid, sig))
        if state.exits:
            processes.pop(pid, None)
            if state.respawn:
                processes[424244] = identity(424244)

    def forbidden(*args, **kwargs):
        pytest.fail("real process inspection or signalling was attempted")

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setenv("PLUGIN_DATA", str(data))
    monkeypatch.setattr(repair, "_ps_identity", forbidden)
    monkeypatch.setattr(repair, "_process_image", forbidden)
    monkeypatch.setattr(repair, "_signal", send)
    monkeypatch.setattr(repair, "process_identity", processes.get)
    monkeypatch.setattr(
        repair, "_recorded_interpreter", lambda root: python)
    monkeypatch.setattr(repair, "_selected_bundle", lambda root: bundle)
    monkeypatch.setattr(
        storage, "open_holders", lambda root: sorted(processes))
    return state


@pytest.mark.parametrize("framework", [False, True])
def test_exact_mcp_identity_is_recognized(fake_runtime, framework):
    f = fake_runtime
    identity = f.identity(424242)
    interpreter = f.python

    if framework:
        base = f.data.parent / "Python.framework" / "Versions" / "3.12"
        recorded = base / "bin" / "python3"
        app = base / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
        identity["argv"][0] = str(app)
        identity["executable"] = str(app)
        identity["launcher"] = str(recorded)
        interpreter = recorded

    alias = f.data.parent / "data-alias"
    alias.symlink_to(f.data, target_is_directory=True)
    identity["argv"][4] = str(alias)

    assert repair.classify_holder(
        identity, f.data, f.bundle, interpreter=interpreter) == "mcp"
    assert f.sent == []


@pytest.mark.parametrize("case, check, reason", [
    ("user", "unverified", "user"),
    ("image", "identity", "uninspectable"),
    ("extra", "unverified", "launch_form"),
    ("not_isolated", "unverified", "launch_form"),
    ("other_bundle", "unverified", "launch_form"),
    ("other_command", "unverified", "launch_form"),
    ("no_interpreter", "unverified", "installation"),
    ("other_interpreter", "unverified", "interpreter"),
    ("other_executable", "unverified", "interpreter"),
    ("other_data", "unverified", "data_dir"),
])
def test_mcp_ownership_is_not_relaxed(fake_runtime, case, check, reason):
    f = fake_runtime
    identity = f.identity(424242)
    interpreter = f.python

    if case == "user":
        identity["uid"] = str(os.getuid() + 1)
    elif case == "image":
        identity["argv"] = None
    elif case == "extra":
        identity["argv"].append("--unexpected")
    elif case == "not_isolated":
        identity["argv"][1] = "-B"
    elif case == "other_bundle":
        identity["argv"][2] = str(f.data / "other" / "scripts" / "runtime.py")
    elif case == "other_command":
        identity["argv"][5] = "ambient"
    elif case == "no_interpreter":
        interpreter = None
    elif case == "other_interpreter":
        identity["argv"][0] = str(f.data / "other-python")
    elif case == "other_executable":
        identity["executable"] = str(f.data / "other-python")
    else:
        identity["argv"][4] = str(f.data / "other-data")

    with pytest.raises(storage.QuiescenceRefusal) as caught:
        repair.classify_holder(
            identity, f.data, f.bundle, interpreter=interpreter)

    assert (caught.value.check, caught.value.reason) == (check, reason)
    assert f.sent == []


def test_mixed_unknown_holder_prevents_all_signals(fake_runtime):
    f = fake_runtime
    f.processes[424243] = f.identity(424243, "ambient")

    with pytest.raises(storage.QuiescenceRefusal):
        repair._quiesce(f.data, f.bundle, progress=f.progress.append)

    assert f.sent == []
    assert f.progress == []


def test_mcp_identity_change_prevents_signal(fake_runtime, monkeypatch):
    f = fake_runtime
    original = f.identity(424242)
    changed = dict(original, start="replacement-start")
    reads = iter([original, changed])
    monkeypatch.setattr(repair, "process_identity", lambda pid: next(reads))

    with pytest.raises(storage.QuiescenceRefusal) as caught:
        repair._quiesce(f.data, f.bundle, progress=f.progress.append)

    assert caught.value.reason == "changed"
    assert f.sent == []
    assert f.progress == []


def test_mcp_exiting_before_revalidation_is_not_signalled(
        fake_runtime, monkeypatch):
    f = fake_runtime
    identity = f.identity(424242)
    reads = iter([identity, None])
    holders = iter([[424242], [], []])
    monkeypatch.setattr(repair, "process_identity", lambda pid: next(reads))
    monkeypatch.setattr(storage, "open_holders", lambda root: next(holders))

    assert repair._quiesce(
        f.data, f.bundle, progress=f.progress.append) is False
    assert f.sent == []
    assert f.progress == []


def test_mcp_is_announced_before_one_sigterm(fake_runtime, monkeypatch):
    f = fake_runtime
    send = repair._signal

    def announced_send(pid, sig):
        assert f.progress == [messages.MCP_STOPPING]
        send(pid, sig)

    monkeypatch.setattr(repair, "_signal", announced_send)

    assert repair._quiesce(
        f.data, f.bundle, progress=f.progress.append) is True
    assert f.sent == [(424242, signal.SIGTERM)]
    assert f.progress == [messages.MCP_STOPPING, messages.MCP_STOPPED]


def test_mcp_timeout_never_escalates(fake_runtime, monkeypatch):
    f = fake_runtime
    f.exits = False
    ticks = iter([0.0, repair.QUIESCE_TIMEOUT])
    monkeypatch.setattr(repair.time, "monotonic", lambda: next(ticks))

    with pytest.raises(storage.QuiescenceRefusal) as caught:
        repair._quiesce(f.data, f.bundle, progress=f.progress.append)

    assert caught.value.check == "stop_timeout"
    assert caught.value.signalled is True
    assert f.sent == [(424242, signal.SIGTERM)]
    assert f.progress == [messages.MCP_STOPPING]
    assert repair.refusal_message(caught.value) == messages.HOLDER_STOP_TIMEOUT


@pytest.mark.parametrize("respawn", [False, True])
def test_stop_only_uses_the_same_mcp_rules(fake_runtime, respawn):
    f = fake_runtime
    f.respawn = respawn

    assert repair.stop_selected_runtime(f.data) is (not respawn)
    assert f.sent == [(424242, signal.SIGTERM)]


def test_respawn_refuses_with_allowlisted_diagnostic(fake_runtime, monkeypatch):
    f = fake_runtime
    f.respawn = True

    def run(bundle, data, **kwargs):
        repair._quiesce(data, bundle, progress=kwargs["progress"])
        pytest.fail("respawn must prevent repair success")

    monkeypatch.setattr(repair, "repair_runtime", run)
    out, err = io.StringIO(), io.StringIO()

    assert repair.main([
        "--bundle-root", str(f.bundle), "--plugin-data", str(f.data),
    ], out=out, err=err) == 1

    assert f.sent == [(424242, signal.SIGTERM)]
    command = repair.format_repair_command(f.bundle, f.data)
    assert messages.QUIESCENCE_AFTER_STOP.format(
        repair_command=command) in out.getvalue()
    assert "No stop signal was sent." not in out.getvalue()

    diagnostic = json.loads(err.getvalue())
    assert set(diagnostic) == {
        "diagnostic", "release", "time", "check", "reason",
        "pids", "errno", "heartbeat_age", "signalled",
    }
    assert diagnostic["check"] == "holders"
    assert diagnostic["pids"] == [424244]
    assert diagnostic["signalled"] is True
    assert str(f.data) not in err.getvalue()
    assert str(f.python) not in err.getvalue()


def test_transition_recheck_catches_late_mcp_holder(
        fake_runtime, monkeypatch):
    f = fake_runtime
    calls = 0

    def holders(root):
        nonlocal calls
        calls += 1
        # Discovery, pre-signal revalidation, post-stop check,
        # then prepare_storage's check.
        if calls == 4:
            f.processes[424244] = f.identity(424244)
        return sorted(f.processes)

    def forbidden(*args, **kwargs):
        pytest.fail("repair advanced past the late holder")

    monkeypatch.setattr(storage, "open_holders", holders)
    monkeypatch.setattr(
        repair, "load_identity",
        lambda bundle: SimpleNamespace(
            storage_generation=repair.STORAGE_GENERATION))
    monkeypatch.setattr(repair, "classify_receipt", lambda root: "absent")
    monkeypatch.setattr(
        repair, "_candidate_python", lambda *args: f.python)
    monkeypatch.setattr(
        repair, "_probe",
        lambda *args: {"transformers": "present", "torch": "present"})
    monkeypatch.setattr(
        repair, "acquire_writer",
        lambda *args, **kwargs: contextlib.nullcontext(
            SimpleNamespace(activation=None)))
    monkeypatch.setattr(storage, "_require_ownership", lambda root: None)
    monkeypatch.setattr(storage, "_validate", lambda *args: None)
    monkeypatch.setattr(storage, "validate_existing_ledger", lambda root: 0)
    monkeypatch.setattr(storage, "_record", lambda *args: None)
    monkeypatch.setattr(repair, "_retire_snapshots", forbidden)
    monkeypatch.setattr(repair, "_write_receipt", forbidden)
    monkeypatch.setattr(repair, "_start_daemon", forbidden)

    with pytest.raises(storage.QuiescenceRefusal) as caught:
        repair.repair_runtime(f.bundle, f.data)

    assert calls == 4
    assert caught.value.check == "holders"
    assert caught.value.pids == (424244,)
    assert caught.value.signalled is True
    assert f.sent == [(424242, signal.SIGTERM)]


def test_unknown_holder_copy_formats_the_actual_repair_command(fake_runtime):
    f = fake_runtime
    refusal = storage.QuiescenceRefusal(
        "unverified", pids=(424242,), reason="launch_form")
    command = repair.format_repair_command(f.bundle, f.data)
    text = repair.refusal_message(refusal).format(repair_command=command)

    assert "operating system's process viewer" in text
    assert "only after identifying it" in text
    assert command in text
    assert shlex.split(command) == [
        "sh", str(f.bundle / "install.sh"),
        "--repair-runtime", "--plugin-data", str(f.data), "--yes",
    ]
    assert "this installation's Privacy HUD MCP server" not in text
