# src/privacy_hud/runtime_repair.py
"""Explicit runtime repair (#66, Pair 5).

Repair is the one operation that changes which runtime is selected. It is
never automatic: a hook may start an already-selected, compatible runtime,
but only an explicit repair may quiesce the old one, relocate the ledger
and publish a new activation.

Scaffolding only at this commit: the tests in `tests/test_runtime_repair.py`
name the contract, and the state machine lands in the GREEN commit.
"""
from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path

from .runtime_contract import Activation, RuntimeRefusal
from .runtime_owner import unselected_activation

__all__ = [
    "RepairResult", "format_repair_command", "main", "process_identity",
    "repair_runtime", "resolve_installed_bundle", "stop_holders",
]


@dataclass(frozen=True)
class RepairResult:
    activation: Activation
    preserved_existing: bool
    degraded: bool


def format_repair_command(bundle_root: Path, data_dir: Path) -> str:
    """The exact command a user is told to run, shell-quoted.

    `shlex.join` over a fixed argv, so a path containing spaces or shell
    metacharacters is one argument and never a command substitution.
    """
    return shlex.join([
        "sh", str(Path(bundle_root) / "install.sh"),
        "--repair-runtime", "--plugin-data", str(data_dir), "--yes",
    ])


def _signal(pid: int, sig: int) -> None:
    """The one place a signal is sent. Named so a test can watch it, and
    so nothing else in this module can reach `os.kill` directly."""
    os.kill(pid, sig)


def process_identity(pid: int) -> dict | None:
    """The facts that make a pid the same process later: user, start
    identity, executable and arguments. `None` when it cannot be read."""
    return None


def stop_holders(data_dir, holders: dict, *, deadline: float) -> None:
    """Ask each recognized holder to exit, revalidating its identity first
    and waiting for it, bounded by `deadline`."""
    raise RuntimeRefusal("holder_unknown")


def resolve_installed_bundle(release: str) -> Path:
    """The single installed plugin bundle for `release`, from Codex's own
    plugin cache. More than one match is an error, not a choice."""
    return Path(os.devnull)


def repair_runtime(bundle_root: Path, data_dir: Path, *,
                   python: Path | None = None,
                   allow_degraded: bool = False) -> RepairResult:
    """Select `bundle_root`, move the ledger behind the fence, and start a
    matching daemon."""
    return RepairResult(activation=unselected_activation(),
                        preserved_existing=False, degraded=False)


def main(argv: list[str] | None = None, *, out=None) -> int:
    """`runtime.py --plugin-data DIR setup` and `install.sh
    --repair-runtime` both land here."""
    return 1
