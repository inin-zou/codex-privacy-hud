# tests/test_runtime_messages.py
"""#66's fixed runtime copy, and the stdlib-only copies of it.

`scripts/runtime.py` must print refusals when the package cannot be
imported, so it restates the strings it uses. This pins every restated copy
to `privacy_hud.runtime_messages`, and the literals themselves to the text
the #66 contract specifies.
"""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import pytest

from privacy_hud import runtime_messages, runtime_repair

REPO = Path(__file__).resolve().parent.parent
BOOTSTRAP = REPO / "scripts" / "runtime.py"


def _literals(path: Path) -> dict:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                pass
    return out


@pytest.mark.parametrize("name", [
    "RUNTIME_SETUP_FAIL", "REPAIR_COMMAND_OUTPUT", "MCP_BOOTSTRAP_REFUSAL",
    "DAEMON_STARTUP_REFUSAL", "AMBIENT_RUNTIME_MISMATCH",
])
def test_bootstrap_restates_runtime_messages(name):
    assert _literals(BOOTSTRAP)[name] == getattr(runtime_messages, name)


def test_runtime_message_literals():
    assert runtime_messages.RUNTIME_SETUP_FAIL.format(repair_command="CMD") == (
        "[FAIL] Runtime setup\n"
        "No usable Privacy HUD runtime is configured.\n"
        "Run this command in another terminal:\n"
        "  CMD\n"
        "Installation may download dependencies and model weights.")
    assert runtime_messages.REPAIR_COMMAND_OUTPUT.format(
        repair_command="CMD") == (
        "Run this command in another terminal:\n"
        "  CMD\n"
        "This command may download dependencies and model weights.\n"
        "It does not install or replace a patched Codex binary.")
    assert runtime_messages.MCP_BOOTSTRAP_REFUSAL.format(
        repair_command="CMD") == (
        "privacy-hud mcp: runtime setup is incompatible; no ledger was "
        "opened.\n"
        "Run in another terminal:\n"
        "  CMD")
    assert runtime_messages.DAEMON_STARTUP_REFUSAL == (
        "privacy-hud daemon: runtime identity or ledger compatibility check "
        "failed; no writable ledger was opened.\n"
        "Run the repair command reported by the current plugin's doctor.")
    assert runtime_messages.AMBIENT_RUNTIME_MISMATCH == \
        "Privacy — runtime mismatch"


def test_bootstrap_repair_command_matches_the_package():
    spec = importlib.util.spec_from_file_location("_bootstrap_under_test",
                                                  BOOTSTRAP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for bundle, data in ((Path("/b"), Path("/d")),
                         (Path("/a b/c'd"), Path("/x/$(touch y)/`z`"))):
        assert module.format_repair_command(bundle, data) == \
            runtime_repair.format_repair_command(bundle, data)
    assert runtime_repair.format_repair_command(Path("/a b"), Path("/d")) == (
        "sh '/a b/install.sh' --repair-runtime --plugin-data /d --yes")
