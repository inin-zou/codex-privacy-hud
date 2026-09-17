# tests/test_mcp_launcher.py
"""`mcp/server.py` has to get itself into the plugin's own interpreter.

Codex will not run `${PLUGIN_ROOT}/...` as an MCP `command` -- the manifest
may name a bare executable on the host PATH or a `./` path inside the plugin
root, and the venv is neither. So Codex launches host `python3`, which has
neither `privacy_hud` nor `mcp` importable, and this file re-executes itself
under the interpreter `privacy-hud-setup` recorded in `runtime.json`.

`hooks/handler.py` already does this to spawn the daemon. The checks are
restated rather than imported (they are inlined in `_spawn_daemon`, on the
path every tool call runs); `test_the_receipt_checks_match_the_hook_client`
is what keeps the two copies honest.

Everything here runs the real file in a subprocess, because what is being
tested is what `execve` does to a process, which cannot be observed in-process.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SERVER = REPO / "mcp" / "server.py"
MARKER = "PRIVACY_HUD_MCP_REEXEC"


def _fake_interpreter(tmp_path: Path) -> Path:
    """An executable that reports how it was invoked and exits, standing in
    for the venv python. It prints to STDOUT on purpose: reaching it is the
    success signal, and on the real path stdout is where JSON-RPC goes."""
    path = tmp_path / "fake-python"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "print(json.dumps({'argv': sys.argv[1:],\n"
        "                  'pythonpath': os.environ.get('PYTHONPATH', ''),\n"
        "                  'marker': os.environ.get('PRIVACY_HUD_MCP_REEXEC', '')}))\n",
        encoding="utf-8")
    path.chmod(0o755)
    return path


def _receipt(tmp_path: Path, python: Path, *, pythonpath="/pinned/site-packages",
             version=1, mode=0o600) -> Path:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    receipt = data / "runtime.json"
    receipt.write_text(json.dumps({
        "v": version, "python": str(python), "pythonpath": pythonpath,
        "plugin_data": str(data), "env": {}}), encoding="utf-8")
    receipt.chmod(mode)
    return data


def _run(data_dir, *, env_extra=None):
    env = {k: v for k, v in os.environ.items() if k != MARKER}
    env["PLUGIN_DATA"] = str(data_dir) if data_dir is not None else ""
    if data_dir is None:
        del env["PLUGIN_DATA"]
    env.pop("PYTHONPATH", None)
    env.update(env_extra or {})
    return subprocess.run([sys.executable, str(SERVER)], env=env,
                          capture_output=True, text=True, timeout=60)


def test_it_re_execs_under_the_recorded_interpreter(tmp_path):
    data = _receipt(tmp_path, _fake_interpreter(tmp_path))
    result = _run(data)
    payload = json.loads(result.stdout)
    assert payload["argv"] == [str(SERVER)]
    assert payload["marker"] == "1", "the guard must be set before execve"


def test_the_recorded_pythonpath_is_prepended(tmp_path):
    data = _receipt(tmp_path, _fake_interpreter(tmp_path))
    result = _run(data, env_extra={"PYTHONPATH": "/already/here"})
    payload = json.loads(result.stdout)
    assert payload["pythonpath"].split(os.pathsep) == [
        "/pinned/site-packages", "/already/here"]


def test_it_does_not_re_exec_twice(tmp_path):
    """The marker is the only thing standing between a receipt that names
    this very file and an execve loop.

    Asserting the fake interpreter's payload is absent, NOT that stdout is
    empty: with the marker set the launcher correctly falls through to
    `main()`, which starts the real server — and stdout is that server's
    JSON-RPC channel, so an empty-stdout assertion would be asserting that
    the server does not work.
    """
    data = _receipt(tmp_path, _fake_interpreter(tmp_path))
    result = _run(data, env_extra={MARKER: "1"})
    assert "pythonpath" not in result.stdout, \
        "the fake interpreter ran: the re-exec guard did not hold"


@pytest.mark.parametrize("break_it, expected", [
    ("no_plugin_data", "PLUGIN_DATA"),
    ("no_receipt", "runtime.json"),
    ("wrong_version", "runtime.json"),
    ("world_writable", "writable"),
    ("not_executable", "executable"),
])
def test_every_failure_is_quiet_on_stdout_and_loud_on_stderr(
        tmp_path, break_it, expected):
    """stdout is the JSON-RPC channel. A single stray byte there
    desynchronises the protocol, so a failure that prints to stdout is worse
    than the failure it reports."""
    fake = _fake_interpreter(tmp_path)
    if break_it == "no_plugin_data":
        data = None
    elif break_it == "no_receipt":
        data = tmp_path / "empty"
        data.mkdir()
    elif break_it == "wrong_version":
        data = _receipt(tmp_path, fake, version=99)
    elif break_it == "world_writable":
        data = _receipt(tmp_path, fake, mode=0o666)
    else:
        notexec = tmp_path / "not-exec"
        notexec.write_text("", encoding="utf-8")
        notexec.chmod(0o644)
        data = _receipt(tmp_path, notexec)
    result = _run(data)
    assert result.returncode != 0
    assert result.stdout == "", f"wrote to stdout: {result.stdout!r}"
    assert expected in result.stderr


def test_the_receipt_checks_match_the_hook_client():
    """Two stdlib-only readers of the same file. The repo's precedent for
    that (EGRESS_EVENTS, the socket name) is to restate and pin, so this is
    the pin: the constants, and the fact that both refuse a receipt another
    user can write -- the check that makes `runtime.json` not an
    arbitrary-exec hole."""
    server = SERVER.read_text(encoding="utf-8")
    handler = (REPO / "hooks" / "handler.py").read_text(encoding="utf-8")
    for source in (server, handler):
        assert 'RECEIPT_NAME = "runtime.json"' in source
        assert "RECEIPT_VERSION = 1" in source
        assert re.search(r"st_uid\s*!=\s*os\.getuid\(\)", source)
        assert "0o022" in source
