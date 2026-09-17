#!/usr/bin/env python3
# mcp/server.py
"""Thin stdio MCP wrapper around `privacy_hud.mcp_tools` (Task 13).

Exposes eight tools: five of those architecture.md §9 names --
`privacy.get_session_summary`, `privacy.list_exposures`,
`privacy.get_exposure_detail`, `privacy.update_policy`, `privacy.allow_once` --
plus `privacy.hud_toggle`, added later for the status-line item, and
`privacy.read_guard_status` / `privacy.read_guard_set`, added later still for
the read-guard toggle (#36 Task 2). §9's sixth,
`privacy.start_clean_session`, was removed (#23): it opened a ledger row under
an id Codex never sends, so nothing was ever recorded against it. Each is a direct call into the corresponding
function in `src/privacy_hud/mcp_tools.py`. All the
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

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import-time cost is the whole point of not importing these
    from privacy_hud.ledger import Ledger

#: `$PLUGIN_DATA/runtime.json` — written by `privacy-hud-setup`, read by
#: `hooks/handler.py` to launch the daemon and by this file to launch itself.
#: Restated rather than imported: `handler.py` inlines these checks inside
#: `_spawn_daemon`, on the path every tool call runs, and extracting them to
#: share would change the hook client for this file's benefit. The repo's
#: precedent for a fact two stdlib-only ends must share is to restate it and
#: pin both copies with one test —
#: `tests/test_mcp_launcher.py::test_the_receipt_checks_match_the_hook_client`.
RECEIPT_NAME = "runtime.json"
RECEIPT_VERSION = 1

#: Set in the child's environment before `execve`, so an entry that finds it
#: already set does not exec again. Without it, a receipt naming an
#: interpreter that re-enters this file loops until the process table gives up.
REEXEC_MARKER = "PRIVACY_HUD_MCP_REEXEC"


def _fail(message: str):
    """One line to stderr, non-zero exit, nothing on stdout.

    stdout is the JSON-RPC channel for stdio MCP: a single stray byte there
    desynchronises the framing, so an error printed to stdout is worse than
    the error it reports. I1: `message` names a cause, never a payload.
    """
    print(f"privacy-hud mcp: {message}", file=sys.stderr)
    raise SystemExit(1)


def _reexec_under_pinned_interpreter() -> None:
    """Replace this process with the interpreter `runtime.json` records.

    Codex constrains an MCP `command` to a bare executable on the host PATH
    or a `./` path inside the plugin root, and rejects `${PLUGIN_ROOT}` there
    — unlike `hooks.json`, where `$PLUGIN_ROOT` expands. The plugin's venv is
    neither, so the manifest launches host `python3` and this is how the
    process reaches an interpreter that can import `privacy_hud` and `mcp`.

    Re-exec, not `sys.path`: `mcp` depends on `pydantic`, whose core is a
    compiled extension built for one interpreter version. Borrowing the
    venv's `site-packages` from a different host `python3` is a binary
    mismatch waiting for the two versions to differ.

    Returns only when already running under the pinned interpreter. Otherwise
    `execve` replaces the process and this never returns.
    """
    if os.environ.get(REEXEC_MARKER):
        return
    data_dir = os.environ.get("PLUGIN_DATA")
    if not data_dir:
        _fail("PLUGIN_DATA is not set; Codex did not launch this, or the "
              "plugin is not installed")
    try:
        with open(os.path.join(data_dir, RECEIPT_NAME)) as handle:
            # This file names a program about to be executed, so who can
            # write it matters — `handler.py` carries the same check and the
            # same reasoning. `fstat` on the open handle, not `stat` on the
            # path: the check must describe the bytes actually read.
            info = os.fstat(handle.fileno())
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                _fail(f"{RECEIPT_NAME} is writable by others; refusing to "
                      "execute the interpreter it names")
            receipt = json.load(handle)
        if not isinstance(receipt, dict) or receipt.get("v") != RECEIPT_VERSION:
            raise ValueError("unusable receipt")
        python = receipt["python"]
        if not isinstance(python, str) or not python:
            raise ValueError("unusable receipt")
    except (OSError, ValueError, KeyError) as exc:
        _fail(f"no usable {RECEIPT_NAME} ({type(exc).__name__}); "
              "run privacy-hud-setup")
    if not os.access(python, os.X_OK) or os.path.isdir(python):
        _fail("the recorded interpreter is not executable; run privacy-hud-setup")

    env = dict(os.environ)
    env[REEXEC_MARKER] = "1"
    pythonpath = receipt.get("pythonpath")
    if isinstance(pythonpath, str) and pythonpath:
        parts = [pythonpath] + [p for p in env.get("PYTHONPATH", "").split(
            os.pathsep) if p]
        seen, ordered = set(), []
        for part in parts:
            if part not in seen:
                seen.add(part)
                ordered.append(part)
        env["PYTHONPATH"] = os.pathsep.join(ordered)
    os.execve(python, [python, os.path.abspath(__file__)], env)


def _ledger_path() -> Path:
    """`$PLUGIN_DATA/ledger.db`, resolved the same way every other reader
    does (`local_ui_server.resolve_data_dir`). No `/tmp` default (spec §6):
    a server with nowhere to read from exits with a message rather than
    inventing an empty ledger in a shared directory."""
    from privacy_hud.local_ui_server import resolve_data_dir
    data_dir = resolve_data_dir()
    if data_dir is None:
        raise SystemExit("privacy-hud mcp: PLUGIN_DATA is not set and no "
                          "Codex plugin-data directory was found")
    return data_dir / "ledger.db"


def _open_ledger() -> "Ledger":
    from privacy_hud.ledger import Ledger
    from privacy_hud.matrix.loader import load_matrix
    return Ledger(_ledger_path(), load_matrix())


def build_app():
    """Construct the FastMCP app and register the eight `privacy.*` tools.
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

    from privacy_hud import mcp_tools

    app = FastMCP("privacy-hud")
    ledger = _open_ledger()

    # The three read tools below end in `.as_dict()`. `mcp_tools` returns
    # `ledger.py`'s `SessionSummary`/`ExposureRow` dataclasses, and this is the
    # wire boundary: `ledger._EXPOSURE_JSON_FIELDS` pins which keys an MCP
    # client sees and in what order, so the read tools' published
    # shape is a decision recorded in one place rather than whatever a
    # dataclass happens to declare. Do not drop these calls -- a dataclass
    # handed to the MCP transport is not serializable.

    @app.tool(name="privacy.get_session_summary")
    def get_session_summary(session_id: str) -> dict:
        """The four L2 tiles: disclosure percent, exposed items,
        destinations, prevented (design.md §5)."""
        return mcp_tools.get_session_summary(ledger, session_id).as_dict()

    @app.tool(name="privacy.list_exposures")
    def list_exposures(session_id: str, tab: str) -> list[dict]:
        """Rows for one of the L2 tabs: "Exposed", "Prevented", or
        "All events" (design.md §5)."""
        return [r.as_dict()
                for r in mcp_tools.list_exposures(ledger, session_id, tab)]

    @app.tool(name="privacy.get_exposure_detail")
    def get_exposure_detail(session_id: str, event_id: int) -> dict:
        """The L3 detail payload for one flow, keyed by its `events` row
        id (design.md §6)."""
        return mcp_tools.get_exposure_detail(
            ledger, session_id, event_id).as_dict()

    @app.tool(name="privacy.update_policy")
    def update_policy(session_id: str, rule_type: str, selector: str) -> dict:
        """Write a "Protect future occurrences" (`rule_type="mask"`) rule, or
        a source rule -- `rule_type="block_path"` or `"block_command"` --
        that blocks later outbound calls carrying a value from that exact
        origin (design.md §6, #40). See this file's module docstring:
        `Engine.observe` enforces any of these starting with the next
        matching call, not retroactively, and matches only byte-identical
        values. `rule_type="block_source"` is refused (#38): it named a
        label, not a source, and `block_path`/`block_command` are the
        replacement rather than a revival of it."""
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

    @app.tool(name="privacy.hud_toggle")
    def hud_toggle(session_id: str, hidden: bool) -> dict:
        """Hide or show this session's line in the Codex status bar."""
        return mcp_tools.hud_set_hidden(_ledger_path().parent, session_id, hidden)

    @app.tool(name="privacy.read_guard_status")
    def read_guard_status() -> dict:
        """Whether reads of known-sensitive paths are currently blocked
        (`#36`). The toggle lives in `$PLUGIN_DATA/settings.json`, not
        Codex's own config, so this is how a caller finds out what it
        says."""
        return mcp_tools.read_guard_status(_ledger_path().parent)

    @app.tool(name="privacy.read_guard_set")
    def read_guard_set(enabled: bool) -> dict:
        """Turn the read guard on or off. Takes effect for the running
        daemon immediately -- no restart required (`settings.py`'s
        mtime cache)."""
        return mcp_tools.read_guard_set(_ledger_path().parent, enabled)

    return app


def main() -> int:
    _reexec_under_pinned_interpreter()
    app = build_app()
    app.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
