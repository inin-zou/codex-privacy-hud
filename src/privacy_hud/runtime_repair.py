# src/privacy_hud/runtime_repair.py
"""Runtime repair (#66).

Only the command a user is told to run lives here so far. The command is
built with `shlex.join` from the exact bundle and data directory, so a path
containing spaces or shell metacharacters is one argument, never a command
substitution.
"""
from __future__ import annotations

import shlex
from pathlib import Path


def format_repair_command(bundle_root: Path, data_dir: Path) -> str:
    return shlex.join([
        "sh", str(Path(bundle_root) / "install.sh"),
        "--repair-runtime", "--plugin-data", str(data_dir), "--yes",
    ])
