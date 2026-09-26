"""Complete installer contract with distinct source and installed bundles.

All state lives in a short temporary tree. External installation commands
are local doubles; setup, selection, bootstrap, daemon, and wrappers are real.
"""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from privacy_hud import codex, runtime_contract
from runtime_helpers import make_bundle

pytestmark = pytest.mark.skipif(
    sys.platform not in ("darwin", "linux"),
    reason="runtime process inspection requires macOS or Linux",
)


def _executable(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _run(env: dict[str, str], cwd: Path, *argv: str):
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_complete_install_dispatches_to_selected_bundle():
    # A short root is required for the real daemon's Unix socket on macOS.
    with tempfile.TemporaryDirectory(prefix="phi", dir="/tmp") as temp:
        root = Path(temp).resolve()
        home = root / "h"
        home.mkdir()
        commands = root / "bin"
        commands.mkdir()
        scratch = root / "tmp"
        scratch.mkdir()

        source = make_bundle(root / "installer source")
        codex_home = home / ".codex"
        installed = (
            codex_home
            / "plugins"
            / "cache"
            / codex.MARKETPLACE_NAME
            / codex.PLUGIN_NAME
            / runtime_contract.RELEASE
        )
        data = codex_home / "plugins" / "data" / codex.PLUGIN_DATA_DIRNAME
        share = home / ".local" / "share" / "codex-privacy-hud"
        python = share / "venv" / "bin" / "python"

        codex_home.mkdir()
        config = codex_home / "config.toml"
        config.write_text('model = "synthetic"\n', encoding="utf-8")
        rc = home / ".profile"
        rc.write_text("# synthetic shell configuration\n", encoding="utf-8")
        before_config = config.read_bytes()
        before_rc = rc.read_bytes()

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
            "PRIVACY_HUD_RELEASE_BASE_URL": (root / "releases").as_uri(),
            "TEST_SOURCE": str(source),
            "TEST_INSTALLED": str(installed),
            "TEST_CODEX_LOG": str(root / "codex.log"),
            "TEST_PIP_LOG": str(root / "pip.log"),
            "TEST_LAUNCHCTL_LOG": str(root / "launchctl.log"),
        }

        # Intercept only environment creation. Every other invocation uses
        # the suite's real interpreter. The created runtime is a bare venv.
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
            "    ;;\n"
            "  *) exit 64 ;;\n"
            "esac\n",
        )
        _executable(commands / "curl", "exit 22\n")
        _executable(
            commands / "launchctl",
            'printf "%s\\n" "$*" >> "$TEST_LAUNCHCTL_LOG"\nexit 99\n',
        )

        bootstrap = source / "scripts" / "runtime.py"
        try:
            result = _run(
                env, root, "/bin/sh", str(source / "install.sh"),
                "--yes", "--no-model",
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert source.resolve() != installed.resolve()

            calls = Path(env["TEST_CODEX_LOG"]).read_text().splitlines()
            assert "plugin marketplace add inin-zou/codex-privacy-hud" in calls
            assert "plugin add codex-privacy-hud@codex-privacy-hud" in calls
            assert Path(env["TEST_PIP_LOG"]).read_text()

            receipt = json.loads(
                (data / runtime_contract.RECEIPT_NAME).read_text()
            )
            assert receipt["selected_bundle_root"] == str(installed)
            assert receipt["python"] == str(python)

            # Equal bundle contents do not authorize another bundle path.
            refused = _run(
                env, root, str(python), str(bootstrap),
                "--plugin-data", str(data), "probe",
            )
            assert refused.returncode == 1, refused.stdout + refused.stderr

            # Execute the generated wrapper before inspecting its text.
            # This is the RED assertion on the current installer.
            doctor = _run(
                env, root, str(share / "bin" / "privacy-hud-doctor"),
            )
            assert "[ OK ] Runtime source" in doctor.stdout, (
                doctor.stdout + doctor.stderr
            )
            shown_bundle = "~/" + installed.relative_to(home).as_posix()
            assert f"Bundle: {shown_bundle}" in doctor.stdout
            assert doctor.returncode in (0, 1)

            # Step 9 must also have reached the actual doctor implementation.
            assert "[ OK ] Runtime source" in result.stdout

            ambient = _run(
                env, root, str(share / "bin" / "privacy-hud-ambient"),
                "--once",
            )
            assert ambient.returncode == 0, ambient.stdout + ambient.stderr
            assert "runtime mismatch" not in ambient.stdout.lower()

            for name in ("doctor", "ambient", "ui", "mcp", "daemon"):
                wrapper = share / "bin" / f"privacy-hud-{name}"
                expected = (
                    f'exec "{python}" "{installed}/scripts/runtime.py" '
                    f'--plugin-data "{data}" {name} "$@"'
                )
                assert expected in wrapper.read_text()

            assert config.read_bytes() == before_config
            assert rc.read_bytes() == before_rc
            assert not Path(env["TEST_LAUNCHCTL_LOG"]).exists()
        finally:
            # Also exercises stop-only from the distinct installer source.
            # It must not require the caller's bundle to be selected.
            stopped = _run(
                env, root, sys.executable, "-I", "-B", str(bootstrap),
                "--plugin-data", str(data), "repair", "--stop-runtime",
            )
            assert stopped.returncode == 0, stopped.stdout + stopped.stderr
