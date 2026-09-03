#!/usr/bin/env python3
# mcp/server.py
"""Thin stdio MCP wrapper around `privacy_hud.mcp_tools` (Task 13).

Exposes the six tools architecture.md §9 names -- `privacy.get_session_summary`,
`privacy.list_exposures`, `privacy.get_exposure_detail`, `privacy.update_policy`,
`privacy.allow_once`, `privacy.start_clean_session` -- each a direct call into
the corresponding pure function in `src/privacy_hud/mcp_tools.py`. All the
real logic (I1's no-raw-value guarantee, the consent rule, the policy-table
write) lives there and is unit-tested in `tests/test_mcp.py` without going
through this file at all; this module's only job is the MCP transport.

**Dependency note (read before deploying).** The `mcp` package (the official
Model Context Protocol SDK, https://pypi.org/project/mcp/) is NOT declared in
`pyproject.toml`'s `[project] dependencies` -- that list is intentionally
`[]`. It happened to already be importable in the environment this file was
written in, but a fresh clone of this repo has no guarantee of that. Rather
than silently add a new hard dependency to the whole package (paid by every
consumer of `privacy_hud`, including the hook client's stdlib-only path and
every test that never touches MCP), this file:

  1. Imports `mcp` lazily, inside `main()`, not at module import time -- so
     `import privacy_hud.mcp_tools` and the rest of the test suite never pay
     an import cost or failure risk for a dependency this ONE file needs.
  2. Fails with a clear, actionable message (not a bare traceback) if `mcp`
     is missing, naming the exact install command.
  3. Is declared as an optional extra in `pyproject.toml`
     (`pip install privacy-hud[mcp]`) rather than a hard dependency -- see
     that file's `[project.optional-dependencies]` table. The tradeoff: this
     server cannot run out of the box; it can only run once that extra is
     installed. That tradeoff was chosen deliberately, not by omission --
     forcing the MCP SDK onto a hook client that must stay stdlib-only
     (CLAUDE.md's convention) was judged worse than a one-line extra install
     for the one process that actually needs it.

**Naming note.** This file lives at `mcp/server.py` (the path the task
specifies), which is NOT a Python package (no `mcp/__init__.py` is created
here on purpose) -- a package literally named `mcp` sitting at the repo root
would collide with the real `mcp` PyPI distribution on `sys.path` the moment
the repo root is importable as a namespace package. Run this file as a
script (`python3 mcp/server.py`, or an absolute path), never as
`python3 -m mcp.server` from the repo root.

**Ledger identity.** Reads `PLUGIN_DATA` exactly as `dispatch.new_state` and
`hooks/handler.py` do (`$PLUGIN_DATA/ledger.db`, `$PLUGIN_DATA/daemon.sock`'s
sibling) -- see dispatch.py's `new_state()`. Opening a `Ledger` against that
same path means this process reads the SAME on-disk database the daemon is
writing to (SQLite WAL mode makes that safe for a second, mostly-reading
connection); it does not open a second, divergent ledger.

**Enforcement, repeated where a deployer will actually see it:** see
`mcp_tools.py`'s module docstring. `privacy.update_policy` writes a real,
durable rule, and `Engine.observe` reads the `policy` table (ahead of its
own matrix defaults) on every subsequent egress call -- "Block this
source" / "Protect future occurrences" are genuinely enforced on the
*next* matching call. This does not apply retroactively: data already
disclosed before the rule was written stays disclosed (design.md P4).
"""
from __future__ import annotations

import os
from pathlib import Path

from privacy_hud import mcp_tools
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix


def _ledger_path() -> Path:
    """Same convention as `dispatch.new_state()` / `hooks/handler.py`:
    `$PLUGIN_DATA/ledger.db`, defaulting to `/tmp` exactly like the daemon
    does, so a locally-run MCP server with no environment configured still
    finds the same database a locally-run daemon would."""
    data_dir = Path(os.environ.get("PLUGIN_DATA", "/tmp"))
    return data_dir / "ledger.db"


def _open_ledger() -> Ledger:
    matrix = load_matrix()
    return Ledger(_ledger_path(), matrix)


def build_app():
    """Construct the FastMCP app and register the six `privacy.*` tools.
    Imports `mcp` here (not at module scope) -- see this file's docstring."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised only when the
        # optional extra genuinely isn't installed; covering this branch in
        # a test would require uninstalling `mcp` mid-suite.
        raise SystemExit(
            "mcp/server.py requires the 'mcp' package, which is an optional "
            "extra (not a hard dependency of privacy-hud). Install it with:\n"
            "    pip install 'privacy-hud[mcp]'\n"
            "or, from a source checkout:\n"
            "    pip install mcp\n"
            f"(original ImportError: {exc})"
        ) from exc

    app = FastMCP("privacy-hud")
    ledger = _open_ledger()

    @app.tool(name="privacy.get_session_summary")
    def get_session_summary(session_id: str) -> dict:
        """The four L2 tiles: disclosure percent, exposed items,
        destinations, prevented (design.md §5)."""
        return mcp_tools.get_session_summary(ledger, session_id)

    @app.tool(name="privacy.list_exposures")
    def list_exposures(session_id: str, tab: str) -> list[dict]:
        """Rows for one of the L2 tabs: "Exposed", "Prevented", or
        "All events" (design.md §5)."""
        return mcp_tools.list_exposures(ledger, session_id, tab)

    @app.tool(name="privacy.get_exposure_detail")
    def get_exposure_detail(session_id: str, event_id: int) -> dict:
        """The L3 detail payload for one flow, keyed by its `events` row
        id (design.md §6)."""
        return mcp_tools.get_exposure_detail(ledger, session_id, event_id)

    @app.tool(name="privacy.update_policy")
    def update_policy(session_id: str, rule_type: str, selector: str) -> dict:
        """Write a "Protect future occurrences" (`rule_type="mask"`) or
        "Block this source" (`rule_type="block_source"`) rule (design.md
        §6). See this file's module docstring: `Engine.observe` enforces
        this rule starting with the next matching call, not retroactively."""
        mcp_tools.apply_policy(ledger, session_id, rule_type=rule_type,
                                selector=selector)
        return {"applied": True, "rule_type": rule_type, "selector": selector}

    @app.tool(name="privacy.allow_once")
    def allow_once(session_id: str, tool_name: str, tool_input: dict,
                   reviewed: bool) -> dict:
        """Mint a single-use, 120s consent token for exactly this call
        (design.md §8). Raises if `reviewed` is not true -- the L3 detail
        must have been shown first."""
        mcp_tools.allow_once(ledger, session_id, tool_name=tool_name,
                              tool_input=tool_input, reviewed=reviewed)
        return {"minted": True}

    @app.tool(name="privacy.start_clean_session")
    def start_clean_session(session_id: str) -> dict:
        """Design.md §6's red-band "Start a clean session" action. Returns
        the new session_id the caller should use going forward."""
        new_id = mcp_tools.start_clean_session(ledger, session_id)
        return {"session_id": new_id}

    return app


def main() -> int:
    app = build_app()
    app.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
