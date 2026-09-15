# tests/test_no_tmp_fallback.py
"""Spec §6: without a Codex-assigned data directory, nothing is written
anywhere. The old default of `/tmp` put a ledger in a shared directory the
moment anyone ran a component by hand; the 2026-09-03 stray ledger.db beside
this repo is that failure. Each entry point is exercised with PLUGIN_DATA
unset and with the runtime resolver returning nothing, and the assertion is
on the filesystem, not on return values.

`_snapshot` checks only this plugin's own artifact names rather than
diffing all of `/tmp`: other processes on the box write to `/tmp`
concurrently, and a full directory diff would be flaky for reasons that
have nothing to do with this plugin.
"""
from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

from privacy_hud import daemon, local_ui_server, runtime

HANDLER = Path(__file__).parents[1] / "hooks" / "handler.py"

# This plugin's own artifact names -- the daemon's socket/lock, the ledger
# and its WAL/SHM siblings, the setup receipt, the spawn-attempt latch, and
# the UI's static-asset directory. Anything else appearing in `/tmp` or the
# cwd during a test is another process's business, not this plugin's.
_ARTIFACT_NAMES = {
    "ledger.db",
    "ledger.db-wal",
    "ledger.db-shm",
    "daemon.sock",
    "daemon.sock.lock",
    "runtime.json",
    "daemon.spawn-attempt",
    "hud",
}


def _snapshot(paths):
    return {p: (set(os.listdir(p)) & _ARTIFACT_NAMES)
            for p in paths if os.path.isdir(p)}


@pytest.fixture
def unset(monkeypatch, tmp_path):
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    monkeypatch.chdir(tmp_path)
    # No Codex install to resolve against either.
    monkeypatch.setattr(runtime, "resolve_data_dir",
                        lambda explicit=None: (None, ["no codex"], []))
    before = _snapshot(["/tmp", str(tmp_path)])
    yield tmp_path
    after = _snapshot(["/tmp", str(tmp_path)])
    new = {k: after[k] - before.get(k, set()) for k in after}
    assert not any(v for v in new.values()), new


def test_daemon_refuses_to_start(unset, capsys):
    assert daemon.main() == daemon.EXIT_FAILURE
    assert "PLUGIN_DATA" in capsys.readouterr().err


def test_handler_is_a_no_op(unset, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("handler", HANDLER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        {"hook_event_name": "UserPromptSubmit", "session_id": "x", "prompt": "hi"})))
    assert mod.main() == {}


def test_ledger_path_is_none(unset):
    assert local_ui_server.resolve_data_dir() is None
    assert local_ui_server._ledger_path() is None


def test_resolver_is_used_when_env_is_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    monkeypatch.setattr(runtime, "resolve_data_dir",
                        lambda explicit=None: (tmp_path, [], [tmp_path]))
    assert local_ui_server.resolve_data_dir() == tmp_path


def test_env_wins_when_set(monkeypatch, tmp_path):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    assert local_ui_server.resolve_data_dir() == tmp_path
