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
        "                  'plugin_data': os.environ.get('PLUGIN_DATA', ''),\n"
        "                  'marker': os.environ.get('PRIVACY_HUD_MCP_REEXEC', ''),\n"
        "                  'env': dict(os.environ)}))\n",
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


def _codex_home_with_receipt(tmp_path: Path, python: Path) -> tuple[Path, Path]:
    """A `$CODEX_HOME` shaped like a real one: the plugin-data directory Codex
    assigns this plugin, with a receipt in it. Returns `(codex_home, data)`."""
    data = (tmp_path / "codex-home" / "plugins" / "data"
            / "codex-privacy-hud-codex-privacy-hud")
    data.mkdir(parents=True)
    receipt = data / "runtime.json"
    receipt.write_text(json.dumps({
        "v": 1, "python": str(python), "pythonpath": "/pinned/site-packages",
        "plugin_data": str(data), "env": {}}), encoding="utf-8")
    receipt.chmod(0o600)
    return tmp_path / "codex-home", data


def _run(data_dir, *, env_extra=None, codex_home="/nonexistent/codex-home"):
    env = {k: v for k, v in os.environ.items() if k != MARKER}
    env["PLUGIN_DATA"] = str(data_dir) if data_dir is not None else ""
    if data_dir is None:
        del env["PLUGIN_DATA"]
    # Never the developer's real `~/.codex`: since the launcher falls back to
    # the directory Codex assigns when `PLUGIN_DATA` is unset, a machine with
    # the plugin installed would otherwise resolve a real receipt and start a
    # real server in the middle of the suite.
    env["CODEX_HOME"] = str(codex_home)
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


def test_reexec_forces_offline_flags(tmp_path):
    """The server half never loads the model today, but it runs under the
    pinned interpreter that can; an inherited "0" must not reach it. The
    launcher cannot import the package before the re-exec, so it carries its
    own copy of the policy (`OFFLINE_ENV`), pinned by `tests/test_offline.py`."""
    from privacy_hud import offline
    data = _receipt(tmp_path, _fake_interpreter(tmp_path))
    result = _run(data, env_extra={name: "0" for name in offline.FORCED_ENV})
    env = json.loads(result.stdout)["env"]
    assert {k: env.get(k) for k in offline.FORCED_ENV} == offline.FORCED_ENV


def test_the_recorded_pythonpath_is_prepended(tmp_path):
    data = _receipt(tmp_path, _fake_interpreter(tmp_path))
    result = _run(data, env_extra={"PYTHONPATH": "/already/here"})
    payload = json.loads(result.stdout)
    assert payload["pythonpath"].split(os.pathsep) == [
        "/pinned/site-packages", "/already/here"]


def test_it_falls_back_to_the_directory_codex_assigns(tmp_path):
    """With no `PLUGIN_DATA`, resolve the directory instead of refusing.

    The spec asserts Codex injects `PLUGIN_DATA` into an MCP server's
    environment and cites nothing for it, and `doctor.check_mcp_server` sets
    the variable itself before spawning — so a green doctor was compatible
    with a server that died at every real Codex launch. `_ledger_path`, in
    this same file, has always resolved the directory without the variable.
    The strict half just ran first.
    """
    fake = _fake_interpreter(tmp_path)
    codex_home, data = _codex_home_with_receipt(tmp_path, fake)
    result = _run(None, codex_home=codex_home)
    payload = json.loads(result.stdout)
    assert payload["argv"] == [str(SERVER)]
    assert payload["plugin_data"] == str(data), \
        "the child must be told which directory this resolved to"


def test_the_data_dir_fallback_matches_codex(tmp_path, monkeypatch):
    """The second pin of a restated fact, alongside the receipt checks.

    `codex.codex_data_candidates()` is where this project's knowledge of
    Codex's layout lives, and the launcher cannot import it — everything
    before the `execve` runs under host `python3`. So it mirrors it, and this
    runs both against the same tree and compares the answers, rather than
    comparing source text and hoping the two mean the same thing.
    """
    import server

    from privacy_hud import codex

    root = tmp_path / "plugins" / "data"
    root.mkdir(parents=True)
    for name in ("codex-privacy-hud-codex-privacy-hud",
                 "someone-else-codex-privacy-hud",
                 # Close enough to match a *shortened* plugin name and not
                 # the real one, so a drift in the restated literal shows up
                 # here rather than as a server reading someone else's data.
                 "privacy-hud-lookalike",
                 "unrelated-plugin"):
        (root / name).mkdir()
    (root / "codex-privacy-hud-notadir").write_text("", encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))

    assert server._codex_data_candidates() == [
        str(p) for p in codex.codex_data_candidates()]
    assert len(server._codex_data_candidates()) == 2

    # And the choice the launcher makes on top of them: one candidate is an
    # answer, two are not — the same rule `runtime.resolve_data_dir` applies.
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    assert server._resolved_data_dir() is None
    (root / "someone-else-codex-privacy-hud").rmdir()
    (root / "privacy-hud-lookalike").rmdir()
    (root / "unrelated-plugin").rmdir()
    assert server._resolved_data_dir() == str(
        root / "codex-privacy-hud-codex-privacy-hud")


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
