# src/privacy_hud/runtime_commands.py
"""The commands every Privacy HUD surface runs (#66, Pair 6).

Scaffolding only at this commit: `tests/test_runtime_surfaces.py` names
the contract, and the implementation lands in the GREEN commit.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .mcp_tools import ResolvedSession
from .runtime_contract import Activation, JSONObject


class PolicyOutcomeUnknown(RuntimeError):
    """The request was transmitted and no reply came back. Whether the
    rule was saved is unknown, and saying otherwise would be a guess."""


@dataclass(frozen=True)
class AuditResult:
    resolved: ResolvedSession
    text: str
    banner: str
    runtime_mismatch: bool


def update_policy(data_dir: Path, *, activation: Activation,
                  session_id: str, rule_type: str, selector: str
                  ) -> JSONObject:
    """Ask the selected daemon to save a policy rule."""
    return {}


def audit(data_dir: Path, *, activation: Activation,
          session_id: str | None = None, tab: str = "Exposed") -> AuditResult:
    """Resolve the session once and render its audit."""
    return AuditResult(resolved=ResolvedSession(None, "none"), text="",
                       banner="", runtime_mismatch=False)
