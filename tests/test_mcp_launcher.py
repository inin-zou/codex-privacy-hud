# tests/test_mcp_launcher.py
"""`mcp/server.py` has to get itself into the plugin's own interpreter.

Codex will not run `${PLUGIN_ROOT}/...` as an MCP `command` -- the manifest
may name a bare executable on the host PATH or a `./` path inside the plugin
root, and the venv is neither. So Codex launches host `python3`, which has
neither `privacy_hud` nor `mcp` importable. The launcher checks the receipt,
then hands over to the bundled bootstrap (`scripts/runtime.py`, #66), which
re-executes the interpreter receipt v2 records, in isolated mode, on this
bundle.

`hooks/handler.py` makes the same receipt checks to spawn the daemon. They
are restated rather than imported;
`test_the_receipt_checks_match_the_hook_client` keeps the two copies honest.

Everything here runs the real file in a subprocess, from a temporary copy of
the bundle with its own manifest, because what is being tested is what
`execve` does to a process, which cannot be observed in-process.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from runtime_helpers import make_bundle, write_receipt_v1, write_receipt_v2

REPO = Path(__file__).resolve().parent.parent
SERVER = REPO / "mcp" / "server.py"
MARKER = "PRIVACY_HUD_BOOTSTRAP_REEXEC"


@pytest.fixture
def bundle(tmp_path) -> Path:
    return make_bundle(tmp_path / "bundle")


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
        "                  'marker': os.environ.get(%r, ''),\n"
        "                  'env': dict(os.environ)}))\n" % MARKER,
        encoding="utf-8")
    path.chmod(0o755)
    return path


def _receipt(tmp_path: Path, bundle: Path, python: Path, *,
             mode=0o600, **overrides) -> Path:
    data = tmp_path / "data"
    write_receipt_v2(data, bundle=bundle, python=python, mode=mode,
                     **overrides)
    return data


def _codex_home_with_receipt(tmp_path: Path, bundle: Path,
                             python: Path) -> tuple[Path, Path]:
    """A `$CODEX_HOME` shaped like a real one: the plugin-data directory Codex
    assigns this plugin, with a receipt in it. Returns `(codex_home, data)`."""
    data = (tmp_path / "codex-home" / "plugins" / "data"
            / "codex-privacy-hud-codex-privacy-hud")
    data.mkdir(parents=True)
    write_receipt_v2(data, bundle=bundle, python=python)
    return tmp_path / "codex-home", data


def _run(bundle: Path, data_dir, *, env_extra=None,
         codex_home="/nonexistent/codex-home"):
    env = {k: v for k, v in os.environ.items()
           if k not in (MARKER, "PRIVACY_HUD_MCP_REEXEC")}
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
    return subprocess.run([sys.executable, str(bundle / "mcp" / "server.py")],
                          env=env, capture_output=True, text=True, timeout=60)


def _expected_argv(bundle: Path, data: Path) -> list[str]:
    return ["-I", str(bundle.resolve() / "scripts" / "runtime.py"),
            "--plugin-data", str(data), "mcp"]


def test_it_re_execs_under_the_recorded_interpreter(tmp_path, bundle):
    data = _receipt(tmp_path, bundle, _fake_interpreter(tmp_path))
    result = _run(bundle, data)
    payload = json.loads(result.stdout)
    assert payload["argv"] == _expected_argv(bundle, data)
    assert payload["marker"] == "1", "the guard must be set before execve"


def test_reexec_forces_offline_flags(tmp_path, bundle):
    """The server half never loads the model today, but it runs under the
    pinned interpreter that can; an inherited "0" must not reach it. The
    bootstrap carries its own copy of the policy (`OFFLINE_ENV`), pinned by
    `tests/test_offline.py`."""
    from privacy_hud import offline
    data = _receipt(tmp_path, bundle, _fake_interpreter(tmp_path))
    result = _run(bundle, data,
                  env_extra={name: "0" for name in offline.FORCED_ENV})
    env = json.loads(result.stdout)["env"]
    assert {k: env.get(k) for k in offline.FORCED_ENV} == offline.FORCED_ENV


def test_inherited_pythonpath_is_removed(tmp_path, bundle):
    """#66: the old launcher prepended the receipt's `pythonpath` to the
    inherited one. Neither may select first-party code now."""
    data = _receipt(tmp_path, bundle, _fake_interpreter(tmp_path))
    result = _run(bundle, data, env_extra={"PYTHONPATH": "/already/here"})
    payload = json.loads(result.stdout)
    assert payload["pythonpath"] == ""
    assert payload["env"]["PYTHONNOUSERSITE"] == "1"


def test_it_falls_back_to_the_directory_codex_assigns(tmp_path, bundle):
    """With no `PLUGIN_DATA`, resolve the directory instead of refusing.

    The spec asserts Codex injects `PLUGIN_DATA` into an MCP server's
    environment and cites nothing for it, and `doctor.check_mcp_server` sets
    the variable itself before spawning — so a green doctor was compatible
    with a server that died at every real Codex launch. `_ledger_path`, in
    this same file, has always resolved the directory without the variable.
    The strict half just ran first.
    """
    fake = _fake_interpreter(tmp_path)
    codex_home, data = _codex_home_with_receipt(tmp_path, bundle, fake)
    result = _run(bundle, None, codex_home=codex_home)
    payload = json.loads(result.stdout)
    assert payload["argv"] == _expected_argv(bundle, data)
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


def test_a_forged_marker_is_refused_quietly(tmp_path, bundle):
    """The marker only guards against an exec loop. Inherited by a process
    that is not the selected interpreter, it is refused -- with nothing on
    stdout -- rather than treated as "already re-executed"."""
    data = _receipt(tmp_path, bundle, _fake_interpreter(tmp_path))
    result = _run(bundle, data, env_extra={MARKER: "1"})
    assert result.returncode == 1
    assert result.stdout == ""
    assert "runtime setup is incompatible" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("break_it, expected", [
    ("no_plugin_data", "PLUGIN_DATA"),
    ("no_receipt", "runtime.json"),
    ("wrong_version", "runtime.json"),
    ("receipt_v1", "runtime.json"),
    ("world_writable", "writable"),
    ("not_executable", "executable"),
    ("modified_bundle", "runtime setup is incompatible; no ledger was opened"),
    ("other_build", "runtime setup is incompatible; no ledger was opened"),
])
def test_every_failure_is_quiet_on_stdout_and_loud_on_stderr(
        tmp_path, bundle, break_it, expected):
    """stdout is the JSON-RPC channel. A single stray byte there
    desynchronises the protocol, so a failure that prints to stdout is worse
    than the failure it reports. No traceback either: a bootstrap failure is
    reported with fixed text."""
    fake = _fake_interpreter(tmp_path)
    if break_it == "no_plugin_data":
        data = None
    elif break_it == "no_receipt":
        data = tmp_path / "empty"
        data.mkdir()
    elif break_it == "wrong_version":
        data = _receipt(tmp_path, bundle, fake, v=99)
    elif break_it == "receipt_v1":
        data = tmp_path / "data"
        write_receipt_v1(data, python=fake, pythonpath=str(REPO / "src"))
    elif break_it == "world_writable":
        data = _receipt(tmp_path, bundle, fake, mode=0o666)
    elif break_it == "modified_bundle":
        data = _receipt(tmp_path, bundle, fake)
        target = bundle / "src" / "privacy_hud" / "codex.py"
        target.write_text(target.read_text(encoding="utf-8") + "# edit\n",
                          encoding="utf-8")
    elif break_it == "other_build":
        data = _receipt(tmp_path, bundle, fake, selected_build_id="c" * 64)
    else:
        notexec = tmp_path / "not-exec"
        notexec.write_text("", encoding="utf-8")
        notexec.chmod(0o644)
        data = _receipt(tmp_path, bundle, notexec)
    result = _run(bundle, data)
    assert result.returncode != 0
    assert result.stdout == "", f"wrote to stdout: {result.stdout!r}"
    assert expected in result.stderr
    assert "Traceback" not in result.stderr


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
        assert "RECEIPT_VERSION = 2" in source
        assert 'BOOTSTRAP = ("scripts", "runtime.py")' in source
        assert re.search(r"st_uid\s*!=\s*os\.getuid\(\)", source)
        assert "0o022" in source
