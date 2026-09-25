"""Issue 74 upgrade ownership: synthetic processes and temporary files only."""

from __future__ import annotations

import json
import os
import shutil
import signal
from types import SimpleNamespace

import pytest

from privacy_hud import codex
from privacy_hud import runtime_contract as contract
from privacy_hud import runtime_messages as messages
from privacy_hud import runtime_repair as repair
from privacy_hud import runtime_storage as storage


@pytest.fixture
def upgrade_runtime(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(root / "home"))
    monkeypatch.setenv("CODEX_HOME", str(root / "codex"))

    data = root / "data"
    data.mkdir()
    monkeypatch.setenv("PLUGIN_DATA", str(data))

    parent = codex.plugin_cache_root() / "market" / codex.PLUGIN_NAME
    selected = parent / "0.9.3"
    older = parent / "0.8.2"
    for bundle in (selected, older):
        bootstrap = bundle / "scripts" / "runtime.py"
        bootstrap.parent.mkdir(parents=True)
        bootstrap.touch()

    python = root / "environment" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.touch()

    def write_receipt(version=2, recorded=None):
        document = {
            "v": version,
            "python": str(python if recorded is None else recorded),
        }
        if version == 2:
            document.update({
                "env": {},
                "dependency_probe": {},
                "selected_bundle_root": str(selected),
                "selected_build_id": "a" * 64,
                "activation_epoch": "b" * 32,
                "storage_generation": contract.STORAGE_GENERATION,
                "recorded_at": 0.0,
            })
        path = data / contract.RECEIPT_NAME
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o600)

    def identity(pid, bundle=older, command="mcp"):
        return {
            "pid": pid,
            "uid": str(os.getuid()),
            "started": "synthetic-start",
            "args": "synthetic",
            "executable": str(python),
            "argv": [
                str(python), "-I", str(bundle / "scripts" / "runtime.py"),
                "--plugin-data", str(data), command,
            ],
            "launcher": None,
        }

    state = SimpleNamespace(
        root=root, data=data, parent=parent, selected=selected,
        older=older, python=python, identity=identity,
        write_receipt=write_receipt, processes={}, sent=[], progress=[],
        exits=True, respawn=False,
    )
    state.processes[424242] = identity(424242)

    def forbidden(*args, **kwargs):
        pytest.fail("real process inspection or signalling was attempted")

    def send(pid, sig):
        state.sent.append((pid, sig))
        if state.exits:
            state.processes.pop(pid, None)
            if state.respawn:
                state.processes[424244] = identity(424244)

    monkeypatch.setattr(repair, "_ps_identity", forbidden)
    monkeypatch.setattr(repair, "_process_image", forbidden)
    monkeypatch.setattr(repair, "_signal", send)
    monkeypatch.setattr(repair, "process_identity", state.processes.get)
    monkeypatch.setattr(
        storage, "open_holders", lambda data_dir: sorted(state.processes))
    write_receipt()
    return state


@pytest.mark.parametrize("receipt_version", [1, 2])
@pytest.mark.parametrize("framework", [False, True])
def test_sibling_mcp_uses_the_surviving_receipt(
        upgrade_runtime, receipt_version, framework):
    f = upgrade_runtime
    identity = f.identity(424242)
    recorded = f.python
    if framework:
        base = f.root / "Python.framework" / "Versions" / "3.12"
        recorded = base / "bin" / "python3"
        app = base / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
        identity["argv"][0] = str(app)
        identity["executable"] = str(app)
        identity["launcher"] = str(recorded)
    f.write_receipt(receipt_version, recorded)

    alias = f.root / "data-alias"
    alias.symlink_to(f.data, target_is_directory=True)
    identity["argv"][4] = str(alias)

    assert repair._recorded_interpreter(f.data) == recorded
    assert repair.classify_holder(
        identity, f.data, f.selected,
        interpreter=repair._recorded_interpreter(f.data)) == "mcp"
    assert f.sent == []


@pytest.mark.parametrize("version", ["0.7.0", "0.8.2", "0.9.4", "1.0.0"])
def test_sibling_ownership_does_not_depend_on_version_order(
        upgrade_runtime, version):
    f = upgrade_runtime
    bundle = f.parent / version
    bootstrap = bundle / "scripts" / "runtime.py"
    bootstrap.parent.mkdir(parents=True, exist_ok=True)
    bootstrap.touch()
    assert repair.classify_holder(
        f.identity(424242, bundle), f.data, f.selected,
        interpreter=f.python) == "mcp"


@pytest.mark.parametrize("case", [
    "outside", "marketplace", "plugin", "nested", "version_prefix",
    "version_suffix", "version_short", "version_zero", "dotdot",
    "dot", "deleted", "missing_bootstrap", "version_symlink",
    "scripts_symlink", "bootstrap_symlink", "development_selection",
])
def test_sibling_cache_boundary_refuses_path_spoofing(upgrade_runtime, case):
    f = upgrade_runtime
    bundle = f.older
    selected = f.selected
    raw = None

    if case == "outside":
        bundle = f.root / "lookalike" / "market" / codex.PLUGIN_NAME / "0.8.2"
    elif case == "marketplace":
        bundle = codex.plugin_cache_root() / "other" / codex.PLUGIN_NAME / "0.8.2"
    elif case == "plugin":
        bundle = f.parent.parent / (codex.PLUGIN_NAME + "-other") / "0.8.2"
    elif case == "nested":
        bundle = f.parent / "extra" / "0.8.2"
    elif case.startswith("version_") and case != "version_symlink":
        names = {
            "version_prefix": "v0.8.2",
            "version_suffix": "0.8.2-dev",
            "version_short": "0.8",
            "version_zero": "00.8.2",
        }
        bundle = f.parent / names[case]
    elif case == "dotdot":
        raw = str(f.older / ".." / f.older.name / "scripts" / "runtime.py")
    elif case == "dot":
        raw = str(f.older) + "/./scripts/runtime.py"
    elif case == "deleted":
        shutil.rmtree(f.older)
    elif case == "missing_bootstrap":
        (f.older / "scripts" / "runtime.py").unlink()
    elif case == "version_symlink":
        outside = f.root / "moved-version"
        f.older.rename(outside)
        f.older.symlink_to(outside, target_is_directory=True)
    elif case == "scripts_symlink":
        outside = f.root / "moved-scripts"
        (f.older / "scripts").rename(outside)
        (f.older / "scripts").symlink_to(outside, target_is_directory=True)
    elif case == "bootstrap_symlink":
        outside = f.root / "moved-bootstrap.py"
        (f.older / "scripts" / "runtime.py").rename(outside)
        (f.older / "scripts" / "runtime.py").symlink_to(outside)
    elif case == "development_selection":
        selected = f.root / "checkout"
        (selected / "scripts").mkdir(parents=True)
        (selected / "scripts" / "runtime.py").touch()

    if bundle != f.older:
        bootstrap = bundle / "scripts" / "runtime.py"
        bootstrap.parent.mkdir(parents=True)
        bootstrap.touch()
    identity = f.identity(424242, bundle)
    if raw is not None:
        identity["argv"][2] = raw

    with pytest.raises(storage.QuiescenceRefusal) as caught:
        repair.classify_holder(
            identity, f.data, selected, interpreter=f.python)

    assert caught.value.reason == "launch_form"
    assert repair.refusal_message(caught.value) == messages.HOLDER_UNVERIFIED
    assert f.sent == []


@pytest.mark.parametrize("case, reason", [
    ("uid", "user"),
    ("extra", "launch_form"),
    ("isolation", "launch_form"),
    ("daemon", "launch_form"),
    ("ambient", "launch_form"),
    ("python", "interpreter"),
    ("executable", "interpreter"),
    ("data", "data_dir"),
    ("no_receipt", "installation"),
    ("changed_receipt", "interpreter"),
])
def test_sibling_mcp_retains_all_ownership_gates(
        upgrade_runtime, case, reason):
    f = upgrade_runtime
    identity = f.identity(424242)
    if case == "uid":
        identity["uid"] = str(os.getuid() + 1)
    elif case == "extra":
        identity["argv"].append("--extra")
    elif case == "isolation":
        identity["argv"][1] = "-B"
    elif case in ("daemon", "ambient"):
        identity["argv"][5] = case
    elif case == "python":
        identity["argv"][0] = str(f.root / "another-python")
    elif case == "executable":
        identity["executable"] = str(f.root / "another-python")
    elif case == "data":
        identity["argv"][4] = str(f.root / "another-data")
    elif case == "no_receipt":
        (f.data / contract.RECEIPT_NAME).unlink()
    elif case == "changed_receipt":
        f.write_receipt(recorded=f.root / "another-python")

    with pytest.raises(storage.QuiescenceRefusal) as caught:
        repair.classify_holder(
            identity, f.data, f.selected,
            interpreter=repair._recorded_interpreter(f.data))

    assert caught.value.reason == reason
    assert f.sent == []


@pytest.mark.parametrize("stop_only", [False, True])
@pytest.mark.parametrize("respawn", [False, True])
def test_sibling_mcp_stop_and_replacement_holder(upgrade_runtime, stop_only, respawn):
    f = upgrade_runtime
    f.respawn = respawn
    if stop_only:
        assert repair.stop_selected_runtime(f.data) is (not respawn)
    elif respawn:
        with pytest.raises(storage.QuiescenceRefusal) as caught:
            repair._quiesce(f.data, f.selected, progress=f.progress.append)
        assert caught.value.check == "holders"
        assert caught.value.signalled is True
        assert repair.refusal_message(caught.value) == messages.QUIESCENCE_AFTER_STOP
    else:
        assert repair._quiesce(
            f.data, f.selected, progress=f.progress.append) is True

    assert f.sent == [(424242, signal.SIGTERM)]
    if not stop_only:
        assert f.progress == [messages.MCP_STOPPING, messages.MCP_STOPPED]


@pytest.mark.parametrize("case", ["unknown", "changed", "departed", "timeout"])
def test_sibling_stop_revalidation_and_announcements(
        upgrade_runtime, monkeypatch, case):
    f = upgrade_runtime
    if case == "unknown":
        f.processes[424243] = f.identity(424243, command="ambient")
    elif case == "changed":
        original = f.processes[424242]
        reads = iter([original, dict(original, started="replacement")])
        monkeypatch.setattr(repair, "process_identity", lambda pid: next(reads))
    elif case == "departed":
        original = f.processes[424242]
        reads = iter([original, None])
        holders = iter([[424242], [], []])
        monkeypatch.setattr(repair, "process_identity", lambda pid: next(reads))
        monkeypatch.setattr(storage, "open_holders", lambda root: next(holders))
    else:
        f.exits = False
        ticks = iter([0.0, repair.QUIESCE_TIMEOUT])
        monkeypatch.setattr(repair.time, "monotonic", lambda: next(ticks))

    if case == "departed":
        assert repair._quiesce(
            f.data, f.selected, progress=f.progress.append) is False
    else:
        with pytest.raises(storage.QuiescenceRefusal) as caught:
            repair._quiesce(f.data, f.selected, progress=f.progress.append)
        if case == "timeout":
            assert caught.value.check == "stop_timeout"
            assert caught.value.signalled is True

    assert f.sent == (
        [(424242, signal.SIGTERM)] if case == "timeout" else [])
    assert f.progress == ([messages.MCP_STOPPING] if case == "timeout" else [])


def test_selected_and_legacy_forms_remain_accepted(upgrade_runtime):
    f = upgrade_runtime
    for command, expected in (("daemon", "current"), ("mcp", "mcp")):
        identity = f.identity(424242, f.selected, command)
        assert repair.classify_holder(
            identity, f.data, f.selected, interpreter=f.python) == expected
    legacy = f.identity(424242)
    legacy["argv"] = [str(f.python), *repair.LEGACY_DAEMON_ARGS]
    assert repair.classify_holder(
        legacy, f.data, f.selected, interpreter=f.python) == "legacy"
    assert f.sent == []
