"""Piped installer preflight and installed-bundle selection.

No inherited user environment, real Codex, package index, launchd, or
network access is used. Runtime setup and receipt selection are real.
"""
from __future__ import annotations

import hashlib
import io
import json
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from privacy_hud import codex, runtime_contract
from forwarder_helpers import bounded_run
from runtime_helpers import make_bundle, write_manifest
from test_install_wrapper_contract import _executable

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "install.sh"
RELEASE = runtime_contract.RELEASE

pytestmark = pytest.mark.skipif(
    sys.platform not in ("darwin", "linux"),
    reason="runtime process inspection requires macOS or Linux",
)


def _snapshot(root: Path) -> dict[str, bytes | None]:
    return {
        p.relative_to(root).as_posix():
        p.read_bytes() if p.is_file() else None
        for p in sorted(root.rglob("*"))
    }


def _publish(case, fault: str = "") -> None:
    release_dir = case.root / "releases" / f"v{RELEASE}"
    release_dir.mkdir(parents=True, exist_ok=True)
    archive = release_dir / f"codex-privacy-hud-{RELEASE}.tar.gz"
    prefix = f"codex-privacy-hud-{RELEASE}"

    if fault == "version":
        project = case.source / "pyproject.toml"
        project.write_text(
            project.read_text().replace(
                f'version = "{RELEASE}"', 'version = "999.0.0"', 1
            )
        )
    elif fault == "incomplete":
        (case.source / "scripts" / "runtime.py").unlink()

    with tarfile.open(archive, "w:gz") as handle:
        handle.add(case.source, arcname=prefix)
        if fault == "traversal":
            member = tarfile.TarInfo(f"{prefix}/../escaped")
            member.size = 1
            handle.addfile(member, io.BytesIO(b"x"))
        elif fault == "symlink":
            member = tarfile.TarInfo(f"{prefix}/escape-link")
            member.type = tarfile.SYMTYPE
            member.linkname = str(case.home)
            handle.addfile(member)

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sidecar = archive.with_name(archive.name + ".sha256")
    sidecar.write_text(f"{digest}  {archive.name}\n")

    if fault == "unavailable":
        archive.unlink()
    elif fault == "checksum":
        sidecar.write_text(f"{'0' * 64}  {archive.name}\n")
    elif fault == "missing-checksum":
        sidecar.unlink()


@pytest.fixture
def case():
    # Real setup may start a daemon; keep its Unix socket path short.
    with tempfile.TemporaryDirectory(prefix="php", dir="/tmp") as temp:
        root = Path(temp).resolve()
        home = root / "h"
        commands = root / "bin"
        cwd = root / "empty"
        scratch = root / "tmp"
        for path in (home, commands, cwd, scratch):
            path.mkdir()

        source = make_bundle(root / "source bundle")
        # make_bundle copies runtime-covered files only. These files are
        # also needed to represent a distributable plugin bundle.
        for name in (".agents", "skills"):
            shutil.copytree(REPO / name, source / name)

        codex_home = home / ".codex"
        installed = (
            codex_home / "plugins" / "cache"
            / codex.MARKETPLACE_NAME / codex.PLUGIN_NAME / RELEASE
        )
        data = (
            codex_home / "plugins" / "data" / codex.PLUGIN_DATA_DIRNAME
        )
        share = home / ".local" / "share" / "codex-privacy-hud"
        env = {
            "HOME": str(home),
            "CODEX_HOME": str(codex_home),
            "PATH": f"{commands}:/usr/bin:/bin:/usr/sbin:/sbin",
            "SHELL": "/bin/sh",
            "TMPDIR": str(scratch),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "HF_HOME": str(home / ".cache" / "huggingface"),
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "HF_DATASETS_OFFLINE": "1",
            "HF_HUB_DISABLE_TELEMETRY": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_NO_INDEX": "1",
            "PIP_CONFIG_FILE": "/dev/null",
            "PRIVACY_HUD_TARGET": "aarch64-apple-darwin",
            "PRIVACY_HUD_RELEASE_BASE_URL":
                (root / "releases").as_uri(),
            "TEST_SOURCE": str(source),
            "TEST_INSTALLED": str(installed),
            "TEST_CODEX_LOG": str(root / "codex.log"),
            "TEST_PIP_LOG": str(root / "pip.log"),
            "TEST_CURL_LOG": str(root / "curl.log"),
            "TEST_LAUNCHCTL_LOG": str(root / "launchctl.log"),
        }

        real_python = shlex.quote(sys.executable)
        host_body = (
            'if [ "$#" -eq 3 ] && [ "$1" = "-m" ] '
            '&& [ "$2" = "venv" ]; then\n'
            f'  {real_python} -I -B -m venv --without-pip "$3"\n'
            '  cat > "$3/bin/pip" <<\'PIP\'\n'
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$TEST_PIP_LOG"\n'
            "PIP\n"
            '  chmod +x "$3/bin/pip"\n'
            "  exit 0\n"
            "fi\n"
            f'exec {real_python} -I -B "$@"\n'
        )
        for name in (
            "python3.14", "python3.13", "python3.12",
            "python3.11", "python3",
        ):
            _executable(commands / name, host_body)

        _executable(
            commands / "codex",
            'printf "%s\\n" "$*" >> "$TEST_CODEX_LOG"\n'
            'case "$*" in\n'
            '  --version) echo "codex-cli 0.154.0" ;;\n'
            '  "plugin marketplace add inin-zou/codex-privacy-hud") '
            "exit 0 ;;\n"
            '  "plugin marketplace upgrade codex-privacy-hud") '
            "exit 0 ;;\n"
            '  "plugin add codex-privacy-hud@codex-privacy-hud")\n'
            '    mkdir -p "$(dirname "$TEST_INSTALLED")"\n'
            '    cp -R "$TEST_SOURCE" "$TEST_INSTALLED"\n'
            '    if [ "${TEST_INSTALLED_SKEW:-0}" = 1 ]; then\n'
            '      printf "\\n# changed cache copy\\n" >> '
            '"$TEST_INSTALLED/pyproject.toml"\n'
            "    fi\n"
            "    ;;\n"
            "  *) exit 64 ;;\n"
            "esac\n",
        )
        _executable(
            commands / "curl",
            'printf "%s\\n" "$*" >> "$TEST_CURL_LOG"\n'
            '[ "$#" -eq 4 ] && [ "$1" = "-fsSL" ] '
            '&& [ "$3" = "-o" ] || exit 64\n'
            'case "$2" in\n'
            '  file://*) cp "${2#file://}" "$4" ;;\n'
            "  *) exit 97 ;;\n"
            "esac\n",
        )
        _executable(
            commands / "launchctl",
            'printf "%s\\n" "$*" >> "$TEST_LAUNCHCTL_LOG"\n'
            "exit 99\n",
        )

        value = SimpleNamespace(
            root=root, home=home, cwd=cwd, scratch=scratch,
            source=source, installed=installed, data=data,
            share=share, env=env,
        )
        yield value

        # Stop only a runtime that this synthetic test selected.
        if (data / runtime_contract.RECEIPT_NAME).exists():
            result = subprocess.run(
                [
                    sys.executable, "-I", "-B",
                    str(source / "scripts" / "runtime.py"),
                    "--plugin-data", str(data),
                    "repair", "--stop-runtime",
                ],
                cwd=cwd, env=env, capture_output=True,
                text=True, timeout=120,
            )
            assert result.returncode == 0, result.stdout + result.stderr


def _pipe(case, *args: str):
    assert list(case.cwd.iterdir()) == []
    env = dict(case.env, TEST_INSTALLER=str(INSTALL))
    marked = env.get("TEST_FORWARDER")
    forwarders = (Path(marked),) if marked else ()
    return bounded_run(
        case.root,
        [
            "/bin/sh",
            "-c",
            'cat "$TEST_INSTALLER" | /bin/sh -s -- "$@"',
            "installer-pipe",
            *args,
        ],
        env,
        forwarders=forwarders,
        cwd=case.cwd,
        timeout=120,
    )


def _output(result) -> str:
    return result.stdout + result.stderr


def test_only_installer_bytes_can_install_from_empty_cwd(case):
    _publish(case)
    result = _pipe(case, "--yes", "--no-model")
    output = _output(result)
    assert result.returncode == 0, output
    assert "step 2/9:" in output
    assert "step 5/9:" in output
    assert "[ OK ] Runtime source" in output
    assert Path(case.env["TEST_PIP_LOG"]).read_text()

    receipt = json.loads(
        (case.data / runtime_contract.RECEIPT_NAME).read_text()
    )
    assert receipt["selected_bundle_root"] == str(case.installed)
    assert receipt["python"] == str(case.share / "venv/bin/python")
    assert str(case.scratch) not in receipt["selected_bundle_root"]

    for name in ("doctor", "ambient", "ui", "mcp", "daemon"):
        wrapper = case.share / "bin" / f"privacy-hud-{name}"
        assert f'"{case.installed}/scripts/runtime.py"' in wrapper.read_text()

    assert not (case.home / ".profile").exists()
    assert not (case.home / ".codex/config.toml").exists()
    assert not Path(case.env["TEST_LAUNCHCTL_LOG"]).exists()
    assert not list(case.scratch.glob("privacy-hud-bundle.*"))
    assert not list(case.scratch.glob("privacy-hud-codex.*"))


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("unavailable", "release bundle unavailable"),
        ("checksum", "release bundle checksum mismatch"),
        ("missing-checksum", "release bundle checksum unavailable"),
        ("version", "release bundle version mismatch"),
        ("incomplete", "release bundle incomplete"),
        ("traversal", "unsafe release archive"),
        ("symlink", "unsafe release archive"),
    ],
)
def test_preflight_failure_leaves_no_partial_install(case, fault, message):
    _publish(case, fault)
    before = _snapshot(case.home)
    result = _pipe(case, "--yes", "--no-model")
    output = _output(result)
    assert result.returncode != 0, output
    assert message in output
    assert _snapshot(case.home) == before
    assert not case.share.exists()  # Includes manifest, venv, wrappers.
    assert not case.installed.exists()
    assert not (case.data / runtime_contract.RECEIPT_NAME).exists()
    assert not Path(case.env["TEST_PIP_LOG"]).exists()
    calls = Path(case.env["TEST_CODEX_LOG"])
    assert not calls.exists() or "plugin " not in calls.read_text()
    assert not list(case.scratch.glob("privacy-hud-bundle.*"))


@pytest.mark.parametrize("fake", ["0", "1"])
@pytest.mark.parametrize("operation", ["--repair-runtime", "--uninstall"])
def test_piped_maintenance_refuses_without_mutating_state(
    case, fake, operation
):
    case.env["PRIVACY_HUD_FAKE"] = fake
    case.data.mkdir(parents=True)
    (case.data / "keep").write_bytes(b"synthetic")
    case.share.mkdir(parents=True)
    (case.share / "manifest.json").write_text(
        json.dumps({"plugin_data": str(case.data)})
    )
    before = _snapshot(case.home)
    args = [operation]
    if operation == "--repair-runtime":
        args.extend(["--plugin-data", str(case.data), "--yes"])

    result = _pipe(case, *args)
    output = _output(result)
    assert result.returncode != 0, output
    assert f"{operation} requires the installer from an existing plugin bundle" in output
    assert 'sh "$PRIVACY_HUD_BUNDLE/install.sh"' in output
    assert _snapshot(case.home) == before
    assert not Path(case.env["TEST_CURL_LOG"]).exists()
    assert not Path(case.env["TEST_CODEX_LOG"]).exists()


def test_installed_cache_skew_never_selects_or_wraps_that_code(case):
    _publish(case)
    case.env["TEST_INSTALLED_SKEW"] = "1"
    result = _pipe(case, "--yes", "--no-model")
    output = _output(result)
    assert result.returncode != 0, output
    assert f"install.sh: {_build_failure()}\n" in result.stderr
    assert "run: codex plugin list" not in output
    assert not (case.share / "bin").exists()
    assert not (case.data / runtime_contract.RECEIPT_NAME).exists()
    # This failure occurs after preflight and steps 2/4.
    assert (case.share / "manifest.json").exists()
    assert (case.share / "venv").exists()
    assert case.installed.exists()


OLD_RELEASE = "0.10.6"
MARKETPLACE_ADD = "plugin marketplace add inin-zou/codex-privacy-hud"
MARKETPLACE_UPGRADE = "plugin marketplace upgrade codex-privacy-hud"
PLUGIN_ADD = "plugin add codex-privacy-hud@codex-privacy-hud"

UPGRADE_REMEDY = (
    "Run 'codex plugin marketplace upgrade codex-privacy-hud', then "
    "rerun the README installer one-liner. If 'codex' selects an old "
    "Privacy HUD forwarder, use your official Codex binary's absolute "
    "path for the refresh command."
)
ADD_FAILURE = (
    "could not configure the codex-privacy-hud marketplace; "
    "plugin installation was not attempted. Correct the Codex error "
    "above, then rerun the README installer one-liner. "
    "The installer manifest and dependency environment were preserved."
)
REFRESH_FAILURE = (
    "could not refresh the codex-privacy-hud Git marketplace; "
    "plugin installation was not attempted. Correct the Codex error "
    "above. "
    + UPGRADE_REMEDY
    + " For a local-path marketplace, follow the local-checkout "
    "instructions in docs/installing-by-hand.md; this installer "
    "requires a Git marketplace. The installer manifest and "
    "dependency environment were preserved."
)


def _selection_failure() -> str:
    return (
        "could not find exactly one installed plugin bundle for release "
        f"{RELEASE}; no runtime was selected by this run. "
        + UPGRADE_REMEDY
        + " If this persists, the installed bundle may be missing or "
        "ambiguous; report this error without deleting plugin data."
    )


def _build_failure() -> str:
    return (
        f"installed plugin bundle does not match release {RELEASE}; "
        "no runtime was selected by this run. "
        + UPGRADE_REMEDY
        + " If this persists, report the release mismatch without "
        "deleting plugin data."
    )


def _marketplace(
    case, *, configured: bool = True, mode: str = "refresh",
    add_fails: bool = False,
) -> Path:
    old_source = case.root / "old source"
    shutil.copytree(case.source, old_source)

    # Represent an older release consistently, including its build digest.
    for relative in (
        "install.sh",
        "pyproject.toml",
        ".codex-plugin/plugin.json",
        ".agents/plugins/marketplace.json",
        "src/privacy_hud/runtime_contract.py",
    ):
        path = old_source / relative
        source = path.read_text(encoding="utf-8")
        assert RELEASE in source, relative
        path.write_text(
            source.replace(RELEASE, OLD_RELEASE),
            encoding="utf-8",
        )
    with patch.object(runtime_contract, "RELEASE", OLD_RELEASE):
        write_manifest(old_source)

    old_installed = case.installed.parent / OLD_RELEASE
    snapshot = case.root / "marketplace-snapshot"
    if configured:
        old_installed.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(old_source, old_installed)
        snapshot.write_text(str(old_source) + "\n", encoding="utf-8")

    case.env.update({
        "TEST_SNAPSHOT": str(snapshot),
        "TEST_OLD_SOURCE": str(old_source),
        "TEST_OLD_INSTALLED": str(old_installed),
        "TEST_REFRESH_MODE": mode,
        "TEST_ADD_FAILS": "1" if add_fails else "0",
    })
    commands = Path(case.env["PATH"].split(":")[0])
    _executable(
        commands / "codex",
        r'''
printf "%s\n" "$*" >> "$TEST_CODEX_LOG"
case "$*" in
  --version)
    echo "codex-cli 0.154.0"
    ;;
  "plugin marketplace add inin-zou/codex-privacy-hud")
    if [ "$TEST_ADD_FAILS" = 1 ]; then
      echo "synthetic marketplace add failure" >&2
      exit 1
    fi
    if [ -f "$TEST_SNAPSHOT" ]; then
      echo "Marketplace codex-privacy-hud is already added"
    else
      printf "%s\n" "$TEST_SOURCE" > "$TEST_SNAPSHOT"
    fi
    ;;
  "plugin marketplace upgrade codex-privacy-hud")
    [ -f "$TEST_SNAPSHOT" ] || exit 65
    case "$TEST_REFRESH_MODE" in
      refresh)
        printf "%s\n" "$TEST_SOURCE" > "$TEST_SNAPSHOT"
        ;;
      noop)
        ;;
      offline)
        echo "synthetic git ls-remote connection failure" >&2
        exit 1
        ;;
      local)
        echo "synthetic marketplace is not configured as a Git marketplace" >&2
        exit 1
        ;;
      *)
        exit 64
        ;;
    esac
    ;;
  "plugin add codex-privacy-hud@codex-privacy-hud")
    selected=$(cat "$TEST_SNAPSHOT")
    if [ "$selected" = "$TEST_SOURCE" ]; then
      destination=$TEST_INSTALLED
    elif [ "$selected" = "$TEST_OLD_SOURCE" ]; then
      destination=$TEST_OLD_INSTALLED
    else
      exit 66
    fi
    if [ ! -d "$destination" ]; then
      mkdir -p "$(dirname "$destination")"
      cp -R "$selected" "$destination"
    fi
    ;;
  *)
    exit 64
    ;;
esac
''',
    )
    return old_installed


def _plugin_calls(case) -> list[str]:
    log = Path(case.env["TEST_CODEX_LOG"])
    if not log.exists():
        return []
    return [
        line for line in log.read_text(encoding="utf-8").splitlines()
        if line.startswith("plugin ")
    ]


def _assert_unselected(case) -> None:
    assert not (case.data / runtime_contract.RECEIPT_NAME).exists()
    assert not (case.share / "bin").exists()
    assert (case.share / "manifest.json").is_file()
    assert (case.share / "venv").is_dir()


@pytest.mark.parametrize("configured", [True, False])
def test_marketplace_refresh_precedes_install_and_selects_release(
    case, configured,
):
    old_installed = _marketplace(case, configured=configured)
    old_before = _snapshot(old_installed) if configured else None
    _publish(case)

    result = _pipe(case, "--yes", "--no-model")
    output = _output(result)

    assert result.returncode == 0, output
    assert _plugin_calls(case) == [
        MARKETPLACE_ADD, MARKETPLACE_UPGRADE, PLUGIN_ADD,
    ]
    assert Path(case.env["TEST_SNAPSHOT"]).read_text().strip() == (
        str(case.source)
    )
    assert case.installed.is_dir()
    receipt = json.loads(
        (case.data / runtime_contract.RECEIPT_NAME).read_text()
    )
    assert receipt["selected_bundle_root"] == str(case.installed)
    manifest = json.loads(
        (case.installed / runtime_contract.MANIFEST_NAME).read_text()
    )
    assert manifest["release"] == RELEASE
    assert receipt["selected_build_id"] == manifest["build_id"]
    assert "[ OK ] Runtime source" in output
    if configured:
        assert _snapshot(old_installed) == old_before
    else:
        assert not old_installed.exists()


@pytest.mark.parametrize(
    ("mode", "cli_error"),
    [
        ("offline", "synthetic git ls-remote connection failure"),
        (
            "local",
            "synthetic marketplace is not configured as a Git marketplace",
        ),
    ],
)
def test_marketplace_refresh_failure_stops_before_plugin_add(
    case, mode, cli_error,
):
    old_installed = _marketplace(case, mode=mode)
    old_before = _snapshot(old_installed)
    snapshot = Path(case.env["TEST_SNAPSHOT"])
    snapshot_before = snapshot.read_bytes()
    _publish(case)

    result = _pipe(case, "--yes", "--no-model")
    output = _output(result)

    assert result.returncode != 0, output
    assert _plugin_calls(case) == [MARKETPLACE_ADD, MARKETPLACE_UPGRADE]
    assert cli_error in result.stderr
    assert f"install.sh: {REFRESH_FAILURE}\n" in result.stderr
    assert "step 5/9:" not in output
    assert "could not find exactly one installed plugin bundle" not in output
    assert snapshot.read_bytes() == snapshot_before
    assert _snapshot(old_installed) == old_before
    assert not case.installed.exists()
    _assert_unselected(case)


def test_marketplace_add_failure_is_not_swallowed(case):
    old_installed = _marketplace(case, add_fails=True)
    old_before = _snapshot(old_installed)
    _publish(case)

    result = _pipe(case, "--yes", "--no-model")
    output = _output(result)

    assert result.returncode != 0, output
    assert _plugin_calls(case) == [MARKETPLACE_ADD]
    assert "synthetic marketplace add failure" in result.stderr
    assert f"install.sh: {ADD_FAILURE}\n" in result.stderr
    assert "step 5/9:" not in output
    assert _snapshot(old_installed) == old_before
    assert not case.installed.exists()
    _assert_unselected(case)


def test_successful_but_ineffective_refresh_names_actual_remedy(case):
    old_installed = _marketplace(case, mode="noop")
    old_before = _snapshot(old_installed)
    _publish(case)

    result = _pipe(case, "--yes", "--no-model")
    output = _output(result)

    assert result.returncode != 0, output
    assert _plugin_calls(case) == [
        MARKETPLACE_ADD, MARKETPLACE_UPGRADE, PLUGIN_ADD,
    ]
    assert "step 5/9:" in output
    assert f"install.sh: {_selection_failure()}\n" in result.stderr
    assert "run: codex plugin list" not in output
    assert not case.installed.exists()
    assert _snapshot(old_installed) == old_before
    _assert_unselected(case)


def test_refresh_does_not_relax_ambiguous_bundle_refusal(case):
    _marketplace(case)
    other = (
        Path(case.env["CODEX_HOME"]) / "plugins/cache"
        / "synthetic-other-marketplace" / codex.PLUGIN_NAME / RELEASE
    )
    other.parent.mkdir(parents=True)
    shutil.copytree(case.source, other)
    _publish(case)

    result = _pipe(case, "--yes", "--no-model")
    output = _output(result)

    assert result.returncode != 0, output
    assert _plugin_calls(case) == [
        MARKETPLACE_ADD, MARKETPLACE_UPGRADE, PLUGIN_ADD,
    ]
    assert f"install.sh: {_selection_failure()}\n" in result.stderr
    assert case.installed.exists()
    assert other.exists()
    _assert_unselected(case)


def test_marketplace_operations_bypass_a_marked_old_forwarder(case):
    _marketplace(case)
    marked = case.root / "old-forwarder-bin" / "codex"
    marked.parent.mkdir()
    marked.write_text(
        "#!/bin/sh\n"
        "# codex-privacy-hud forwarder\n"
        'printf "%s\\n" "synthetic old forwarder executed" >&2\n'
        "exit 91\n",
        encoding="utf-8",
    )
    marked.chmod(0o755)
    case.env["PATH"] = f"{marked.parent}:{case.env['PATH']}"
    case.env["TEST_FORWARDER"] = str(marked)
    _publish(case)

    result = _pipe(case, "--yes", "--no-model")
    output = _output(result)

    assert result.returncode == 0, output
    assert "synthetic old forwarder executed" not in output
    assert _plugin_calls(case) == [
        MARKETPLACE_ADD, MARKETPLACE_UPGRADE, PLUGIN_ADD,
    ]


def test_fake_install_does_not_refresh_or_install_marketplace(case):
    _marketplace(case, mode="offline")
    snapshot = Path(case.env["TEST_SNAPSHOT"])
    before = snapshot.read_bytes()
    case.env["PRIVACY_HUD_FAKE"] = "1"
    _publish(case)

    result = _pipe(case, "--yes", "--no-model")
    output = _output(result)

    assert result.returncode == 0, output
    assert _plugin_calls(case) == []
    assert snapshot.read_bytes() == before
    assert "step 4/9:" not in output
    assert not case.installed.exists()
    assert not (case.data / runtime_contract.RECEIPT_NAME).exists()


@pytest.mark.parametrize("fake", ["0", "1"])
def test_runtime_repair_never_calls_codex_marketplace(case, fake):
    _marketplace(case, mode="offline")
    snapshot = Path(case.env["TEST_SNAPSHOT"])
    before = snapshot.read_bytes()
    case.env["PRIVACY_HUD_FAKE"] = fake
    case.data.mkdir(parents=True)

    result = bounded_run(
        case.root,
        [
            "/bin/sh",
            str(case.source / "install.sh"),
            "--repair-runtime",
            "--plugin-data",
            str(case.data),
            "--yes",
            "--no-model",
        ],
        case.env,
        cwd=case.cwd,
        timeout=120,
    )
    output = _output(result)

    assert result.returncode == 0, output
    assert not Path(case.env["TEST_CODEX_LOG"]).exists()
    assert not Path(case.env["TEST_CURL_LOG"]).exists()
    assert snapshot.read_bytes() == before
    receipt = json.loads(
        (case.data / runtime_contract.RECEIPT_NAME).read_text()
    )
    assert receipt["selected_bundle_root"] == str(case.source)
    assert not case.installed.exists()
    assert "step 4/9:" not in output
