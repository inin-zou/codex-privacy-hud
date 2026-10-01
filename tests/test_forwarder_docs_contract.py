"""Forwarder documentation and copyable PATH remedy contracts for #98."""

from pathlib import Path
import subprocess

import pytest


REPO = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("name", "required", "stale"),
    [
        (
            "README.md",
            (
                "`$0`",
                "skips marked Privacy HUD forwarders",
                "guards the version probe",
                "after other PATH assignments",
                "different `HOME`",
            ),
            ("ten-line shell script", "first in your shell rc file"),
        ),
        (
            "README.zh-CN.md",
            (
                "从 `$0` 解析自身位置",
                "跳过带有 Privacy HUD 标记的转发脚本",
                "版本探测期间阻止递归进入转发脚本",
                "放在其他 PATH 赋值语句之后",
                "即使新 shell 的 `HOME` 不同",
            ),
            ("十行的 shell 脚本", "shell rc 文件最前面"),
        ),
        (
            "docs/known-limits.md",
            (
                "resolves its own location from `$0`",
                "skips marked Privacy HUD forwarders",
                "guards the version probe",
                "independently of the caller's `HOME`",
            ),
            ("chooses between two binaries by version match, nothing more",),
        ),
    ],
)
def test_forwarder_docs_describe_identity_and_path_remedy(name, required, stale):
    text = " ".join((REPO / name).read_text(encoding="utf-8").split())
    for phrase in required:
        assert phrase in text, (name, phrase)
    for phrase in stale:
        assert phrase not in text, (name, phrase)


@pytest.mark.parametrize(
    "installation_bin",
    [
        "/synthetic/install-home/.local/bin",
        "/synthetic/a b'c\"$HOME`printf WRONG`$(printf WRONG)\\d/.local/bin",
    ],
)
def test_path_hint_targets_installation_when_login_home_differs(installation_bin):
    lines = (REPO / "install.sh").read_text(encoding="utf-8").splitlines()
    starts = [
        index for index, line in enumerate(lines)
        if line.startswith("    PATH_BIN=")
    ]
    assert len(starts) == 1
    start = starts[0]
    assert lines[start + 1].startswith('    log "export PATH=')
    renderer = (
        "log() { printf '%s\\n' \"$*\"; }\n"
        + "\n".join(lines[start:start + 2])
    )
    env = {
        "HOME": "/synthetic/login-home",
        "PATH": "/usr/bin:/bin",
        "BIN": installation_bin,
    }
    rendered = subprocess.run(
        ["/bin/sh", "-c", renderer],
        env=env,
        capture_output=True,
        text=True,
        timeout=3,
    )
    assert rendered.returncode == 0, rendered.stderr
    assert rendered.stderr == ""
    assert len(rendered.stdout.splitlines()) == 1
    assert rendered.stdout.startswith('export PATH="')
    assert rendered.stdout.endswith(':$PATH"\n')

    applied = subprocess.run(
        ["/bin/sh", "-c", rendered.stdout + 'printf \'%s\\n\' "$PATH"'],
        env=env,
        capture_output=True,
        text=True,
        timeout=3,
    )
    assert applied.returncode == 0, applied.stderr
    assert applied.stderr == ""
    assert applied.stdout == f"{installation_bin}:{env['PATH']}\n"
