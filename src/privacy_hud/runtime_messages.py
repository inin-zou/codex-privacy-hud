# src/privacy_hud/runtime_messages.py
"""Fixed user-facing text for runtime failures (#66).

Every string here is copied from the #66 contract. Nothing here is built
from an exception message, a path the plugin did not choose, or hook
content; the only substitutions are a release string and a repair command
from `runtime_repair.format_repair_command`.

`scripts/runtime.py` and `hooks/handler.py` must be able to print these
when the package cannot be imported, so they restate the ones they use and
`tests/test_runtime_messages.py` pins the copies to this module.
"""
from __future__ import annotations

#: Doctor, and any bootstrap command that finds no usable selected runtime.
RUNTIME_SETUP_FAIL = (
    "[FAIL] Runtime setup\n"
    "No usable Privacy HUD runtime is configured.\n"
    "Run this command in another terminal:\n"
    "  {repair_command}\n"
    "Installation may download dependencies and model weights."
)

#: `repair --print-command`, and `$privacy repair`.
REPAIR_COMMAND_OUTPUT = (
    "Run this command in another terminal:\n"
    "  {repair_command}\n"
    "This command may download dependencies and model weights.\n"
    "It does not install or replace a patched Codex binary."
)

#: MCP bootstrap failure: stderr only, exit 1, stdout left empty.
MCP_BOOTSTRAP_REFUSAL = (
    "privacy-hud mcp: runtime setup is incompatible; no ledger was opened.\n"
    "Run in another terminal:\n"
    "  {repair_command}"
)

#: Daemon refusal before any writable ledger open.
DAEMON_STARTUP_REFUSAL = (
    "privacy-hud daemon: runtime identity or ledger compatibility check "
    "failed; no writable ledger was opened.\n"
    "Run the repair command reported by the current plugin's doctor."
)

#: Ambient launcher, in place of a percentage.
AMBIENT_RUNTIME_MISMATCH = "Privacy — runtime mismatch"
