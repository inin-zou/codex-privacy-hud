"""`privacy_hud.offline`: the one owner of I2's forced-offline environment.

These pin the policy itself and the copies of it that cannot import it:
`hooks/handler.py` is stdlib-only (CLAUDE.md §4) and `mcp/server.py`'s
launcher half runs before the package is importable, so each carries the
same assignments inline. A copy that drifts from the policy is how an
offline guarantee quietly becomes a partial one.
"""
from __future__ import annotations

import ast
import sys
import types
from pathlib import Path

import pytest

from privacy_hud import offline

REPO = Path(__file__).resolve().parents[1]


def test_forced_values_are_all_on():
    assert offline.FORCED_ENV["HF_HUB_OFFLINE"] == "1"
    assert offline.FORCED_ENV["TRANSFORMERS_OFFLINE"] == "1"
    assert set(offline.FORCED_ENV.values()) == {"1"}


@pytest.mark.parametrize("inherited", ["0", "false", "", "no"])
def test_force_overrides_inherited_values(inherited):
    env = {name: inherited for name in offline.FORCED_ENV}
    env["HF_HOME"] = "/keep/me"
    out = offline.force_offline(env)
    assert out is env
    assert {k: env[k] for k in offline.FORCED_ENV} == offline.FORCED_ENV
    assert env["HF_HOME"] == "/keep/me", "cache locations are preserved"


def test_prepare_process_overrides_the_live_environment(monkeypatch):
    for name in offline.FORCED_ENV:
        monkeypatch.setenv(name, "0")
    monkeypatch.setattr(offline, "loaded_stack_is_offline", lambda: True)
    assert offline.prepare_process() is True
    import os
    assert {k: os.environ[k] for k in offline.FORCED_ENV} == offline.FORCED_ENV


def _fake_hub(monkeypatch, offline_value):
    hub = types.ModuleType("huggingface_hub.constants")
    hub.HF_HUB_OFFLINE = offline_value
    monkeypatch.setitem(sys.modules, "huggingface_hub.constants", hub)


def test_a_stack_not_yet_imported_is_safe(monkeypatch):
    for name in ("huggingface_hub.constants", "transformers",
                 "transformers.utils.hub"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    assert offline.loaded_stack_is_offline() is True


def test_a_hub_imported_online_is_unsafe(monkeypatch):
    _fake_hub(monkeypatch, False)
    assert offline.loaded_stack_is_offline() is False


def test_a_hub_imported_offline_is_safe(monkeypatch):
    _fake_hub(monkeypatch, True)
    monkeypatch.delitem(sys.modules, "transformers.utils.hub", raising=False)
    assert offline.loaded_stack_is_offline() is True


def test_transformers_without_a_readable_hub_state_is_unsafe(monkeypatch):
    monkeypatch.delitem(sys.modules, "huggingface_hub.constants", raising=False)
    monkeypatch.setitem(sys.modules, "transformers",
                        types.ModuleType("transformers"))
    assert offline.loaded_stack_is_offline() is False


def test_legacy_transformers_cached_online_mode_is_unsafe(monkeypatch):
    _fake_hub(monkeypatch, True)
    legacy = types.ModuleType("transformers.utils.hub")
    legacy._is_offline_mode = False
    monkeypatch.setitem(sys.modules, "transformers.utils.hub", legacy)
    assert offline.loaded_stack_is_offline() is False


def test_prepare_process_reports_an_unsafe_preloaded_stack(monkeypatch):
    _fake_hub(monkeypatch, False)
    assert offline.prepare_process() is False


# --------------------------------------------------------------------- #
# the inline copies
# --------------------------------------------------------------------- #

def _inline_dict(path: Path, name: str) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name
                        for t in node.targets)):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{path.name} has no {name} assignment")


@pytest.mark.parametrize("path", [REPO / "hooks" / "handler.py",
                                  REPO / "scripts" / "runtime.py"])
def test_launcher_flags_match_shared_policy(path):
    assert _inline_dict(path, "OFFLINE_ENV") == offline.FORCED_ENV


def test_download_override_is_command_scoped():
    """The weights download is the one place the offline flags are off, and
    only for that command: every copy of the recipe prefixes the command
    itself, so neither the installer's shell nor the user's is changed."""
    prefix = offline.download_env_prefix()
    for name in offline.DOWNLOAD_OVERRIDE:
        assert f"{name}=0" in prefix
    assert "HF_HUB_DISABLE_TELEMETRY=1" in prefix
    install = (REPO / "install.sh").read_text(encoding="utf-8")
    assert f'{prefix} "$SHARE/venv/bin/python" - <<\'PY\'' in install
    by_hand = (REPO / "docs" / "installing-by-hand.md").read_text(
        encoding="utf-8")
    assert f'{prefix} python3 -c "' in by_hand
    for text in (install, by_hand):
        for name in offline.DOWNLOAD_OVERRIDE:
            assert f"export {name}" not in text
