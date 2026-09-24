# tests/test_runtime_bootstrap.py
"""#66 Pair 1: the bundled bootstrap and build identity.

`scripts/runtime.py` is the one way first-party code is started. It derives
the bundle from its own location, re-executes the receipt's interpreter in
isolated mode, imports `privacy_hud` only from that bundle's `src`, and
refuses when the bundle's files no longer match its build id.

Every test builds its own bundle, virtual environment and data directory
under `tmp_path`. The virtual environment carries an old `privacy_hud`
distribution whose import writes a sentinel file, standing in for the
`privacy-hud 0.7.1` still installed in real dependency environments; the
decisive assertion throughout is that the sentinel is never written.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from runtime_helpers import (
    make_bundle,
    make_venv,
    plant_old_distribution,
    site_packages,
    write_receipt_v1,
    write_receipt_v2,
)

MARKERS = ("PRIVACY_HUD_BOOTSTRAP_REEXEC", "PRIVACY_HUD_MCP_REEXEC")
SETUP_REFUSAL = "No usable Privacy HUD runtime is configured."


@pytest.fixture
def world(tmp_path):
    bundle = make_bundle(tmp_path / "bundle")
    venv_python = make_venv(tmp_path / "venv")
    sentinel = tmp_path / "OLD-PRIVACY-HUD-IMPORTED"
    plant_old_distribution(site_packages(venv_python), sentinel)
    data = tmp_path / "data"
    data.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    return SimpleNamespace(tmp=tmp_path, bundle=bundle, python=venv_python,
                           sentinel=sentinel, data=data, home=home)


def _env(world, extra: dict | None = None) -> dict:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(world.home),
           "CODEX_HOME": str(world.tmp / "no-codex-home")}
    env.update(extra or {})
    return env


def run_bootstrap(world, *args, python=None, flags=(), env=None):
    cmd = [str(python or sys.executable), *flags,
           str(world.bundle / "scripts" / "runtime.py"),
           "--plugin-data", str(world.data), *args]
    return subprocess.run(cmd, env=_env(world, env), capture_output=True,
                          text=True, timeout=120)


def _probe_json(result) -> dict:
    assert result.returncode == 0, (result.returncode, result.stderr)
    return json.loads(result.stdout)


def _assert_refused(world, result) -> None:
    assert result.returncode == 1, (result.returncode, result.stdout,
                                    result.stderr)
    assert result.stdout == ""
    assert SETUP_REFUSAL in result.stderr
    assert "Traceback" not in result.stderr
    assert not world.sentinel.exists(), "the old distribution was imported"


def _bundle_package(world) -> str:
    return str((world.bundle / "src" / "privacy_hud").resolve())


def test_receipt_v1_site_packages_cannot_shadow_bundle(world):
    # Receipt v1 names the dependency environment and its `pythonpath`, the
    # directory holding the old package. It is repair input only.
    write_receipt_v1(world.data, python=world.python,
                     pythonpath=str(site_packages(world.python)))
    _assert_refused(world, run_bootstrap(world, "probe"))

    # The hook client does not start a daemon from a v1 receipt either.
    subprocess.run([sys.executable, str(world.bundle / "hooks" / "handler.py")],
                   input=json.dumps({"hook_event_name": "PostToolUse",
                                     "session_id": "s1"}),
                   env=_env(world, {"PLUGIN_DATA": str(world.data)}),
                   capture_output=True, text=True, timeout=30)
    deadline = time.monotonic() + 3.0
    while not world.sentinel.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not world.sentinel.exists(), "a v1 receipt started old code"

    # The same environment selected through receipt v2 supplies only
    # dependencies: application code comes from the bundle.
    write_receipt_v2(world.data, bundle=world.bundle, python=world.python)
    probe = _probe_json(run_bootstrap(world, "probe"))
    assert probe["first_party_origin"] == _bundle_package(world)
    assert not world.sentinel.exists()


def test_inherited_pythonpath_cannot_shadow_bundle(world):
    hostile = world.tmp / "hostile"
    hostile_sentinel = world.tmp / "HOSTILE-IMPORTED"
    plant_old_distribution(hostile, hostile_sentinel)
    write_receipt_v2(world.data, bundle=world.bundle, python=world.python)

    probe = _probe_json(run_bootstrap(
        world, "probe", env={"PYTHONPATH": str(hostile),
                             "PYTHONUSERBASE": str(hostile)}))
    assert probe["first_party_origin"] == _bundle_package(world)
    assert not hostile_sentinel.exists()
    assert not world.sentinel.exists()
    assert str(hostile) not in probe["sys_path"]
    assert probe["isolated"] is True


def test_reexec_marker_does_not_bypass_identity_check(world):
    write_receipt_v2(world.data, bundle=world.bundle, python=world.python)
    forged = {name: "1" for name in MARKERS}

    # A forged marker in a process that is not the selected, isolated
    # interpreter is refused rather than trusted.
    _assert_refused(world, run_bootstrap(world, "probe", python=world.python,
                                         env=forged))

    # And it does not skip the digest check either.
    target = world.bundle / "src" / "privacy_hud" / "codex.py"
    target.write_text(target.read_text(encoding="utf-8") + "# edited\n",
                      encoding="utf-8")
    _assert_refused(world, run_bootstrap(world, "probe", python=world.python,
                                         flags=("-I",), env=forged))


@pytest.mark.parametrize("change", ["edit", "extra_source", "missing_source"])
def test_same_release_modified_source_is_refused(world, change):
    write_receipt_v2(world.data, bundle=world.bundle, python=world.python)
    package = world.bundle / "src" / "privacy_hud"
    if change == "edit":
        target = package / "codex.py"
        target.write_text(target.read_text(encoding="utf-8") + "# edited\n",
                          encoding="utf-8")
    elif change == "extra_source":
        (package / "sitecustomize.py").write_text("x = 1\n", encoding="utf-8")
    else:
        (package / "mask.py").unlink()
    manifest = json.loads((world.bundle / "runtime-build.json").read_text(
        encoding="utf-8"))
    assert manifest["release"] == "0.8.2"
    _assert_refused(world, run_bootstrap(world, "probe"))


@pytest.mark.parametrize("missing", ["package", "selected_root"])
def test_missing_bundle_never_falls_back_to_distribution(world, missing):
    if missing == "package":
        write_receipt_v2(world.data, bundle=world.bundle, python=world.python)
        shutil.rmtree(world.bundle / "src" / "privacy_hud")
    else:
        gone = world.tmp / "pruned-cache" / "0.8.0"
        write_receipt_v2(world.data, bundle=gone, python=world.python,
                         build_id="b" * 64)
    _assert_refused(world, run_bootstrap(world, "probe"))


def test_print_repair_command_needs_no_receipt(tmp_path):
    bundle = make_bundle(tmp_path / "bundle")
    data = tmp_path / "plugin data $(touch pwned)"
    # `-I -S`: no site-packages at all, so nothing third-party can load.
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(bundle / "scripts" / "runtime.py"),
         "--plugin-data", str(data), "repair", "--print-command"],
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        capture_output=True, text=True, timeout=60)
    argv = ["sh", str(bundle.resolve() / "install.sh"), "--repair-runtime",
            "--plugin-data", str(data), "--yes"]
    command = shlex.join(argv)
    assert result.returncode == 0, result.stderr
    assert result.stdout == (
        "Run this command in another terminal:\n"
        f"  {command}\n"
        "This command may download dependencies and model weights.\n"
        "It does not install or replace a patched Codex binary.\n")
    assert shlex.split(command) == argv
    assert not data.exists()
    assert not (tmp_path / "pwned").exists()
    assert result.stderr == ""
    assert os.listdir(tmp_path) == ["bundle"]
