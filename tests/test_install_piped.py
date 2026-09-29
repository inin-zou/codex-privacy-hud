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

import pytest

from privacy_hud import codex, runtime_contract
from runtime_helpers import make_bundle
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
    # executable selects /bin/sh; argv[0] makes $0 exactly "sh".
    return subprocess.run(
        ["sh", "-s", "--", *args],
        executable="/bin/sh",
        input=INSTALL.read_bytes(),
        cwd=case.cwd,
        env=case.env,
        capture_output=True,
        timeout=120,
    )


def _output(result) -> str:
    return (result.stdout + result.stderr).decode(errors="replace")


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
    assert "installed plugin bundle does not match release" in output
    assert not (case.share / "bin").exists()
    assert not (case.data / runtime_contract.RECEIPT_NAME).exists()
    # This failure occurs after preflight and steps 2/4.
    assert (case.share / "manifest.json").exists()
    assert (case.share / "venv").exists()
    assert case.installed.exists()
