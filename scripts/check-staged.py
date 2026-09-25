#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

RUFF_VERSION = "0.16.7"


def git_output(root, *args):
    return subprocess.check_output(["git", *args], cwd=root)


def main():
    root = Path(
        os.fsdecode(git_output(Path.cwd(), "rev-parse", "--show-toplevel")).strip()
    )
    version = subprocess.run(
        [sys.executable, "-m", "ruff", "--version"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    if version.returncode or version.stdout.strip() != f"ruff {RUFF_VERSION}":
        raise SystemExit(
            "pre-commit: require Ruff 0.16.7 in the hook's Python environment; "
            "run python3 -m pip install ruff==0.16.7"
        )

    changed = [
        os.fsdecode(name)
        for name in git_output(
            root, "diff", "--cached", "--name-only",
            "--diff-filter=ACMR", "-z",
        ).split(b"\0")
        if name
    ]
    config_paths = [
        os.fsdecode(name)
        for name in git_output(
            root, "diff", "--cached", "--name-only", "--no-renames", "-z",
        ).split(b"\0")
        if name
    ]
    config_changed = any(
        Path(name).name in {"pyproject.toml", "ruff.toml", ".ruff.toml"}
        for name in config_paths
    )
    targets = ["."] if config_changed else [
        name for name in changed
        if Path(name).suffix in {".py", ".pyi", ".ipynb"}
    ]

    with tempfile.TemporaryDirectory(prefix="privacy-hud-index-") as temporary:
        snapshot = Path(temporary)
        subprocess.run(
            [
                "git", "checkout-index", "--all", "--force",
                f"--prefix={snapshot}{os.sep}",
            ],
            cwd=root, check=True,
        )
        if targets:
            subprocess.run(
                [
                    sys.executable, "-m", "ruff", "check", "--no-cache",
                    "--", *targets,
                ],
                cwd=snapshot, check=True,
            )
        subprocess.run(["sh", "-n", "install.sh"], cwd=snapshot, check=True)
        subprocess.run(
            [
                sys.executable, "-B",
                "scripts/build-runtime-manifest.py", "--check",
            ],
            cwd=snapshot, check=True,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"pre-commit: staged checks failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
