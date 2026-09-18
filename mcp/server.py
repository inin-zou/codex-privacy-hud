#!/usr/bin/env python3
# mcp/server.py
"""Thin stdio MCP wrapper around `privacy_hud.mcp_tools` (Task 13).

Exposes exactly the five tools named in `EXPOSED_TOOLS`, below: the four
reads (`privacy.get_session_summary`, `privacy.list_exposures`,
`privacy.get_exposure_detail`, `privacy.read_guard_status`) plus
`privacy.update_policy`, the one write, which can only tighten enforcement
because `mcp_tools.apply_policy` refuses the one rule that would loosen it
-- a `mask` rule on a data type the engine hard-blocks, which would replace
that block with an executed, masked call. See `_MASK_WOULD_DOWNGRADE` there,
and the behaviour test in `tests/test_mcp_surface.py`:
`test_no_exposed_tool_can_turn_a_deny_into_an_allow`.
`privacy.allow_once`, `privacy.hud_toggle` and
`privacy.read_guard_set` are withheld because each could loosen what the
plugin enforces if the model called it, and an MCP tool is called by the
model -- see `EXPOSED_TOOLS`'s docstring and
`tests/test_mcp_surface.py`. `privacy.start_clean_session` was removed
(#23): it opened a ledger row under an id Codex never sends, so nothing was
ever recorded against it. Each is a direct call into the corresponding
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


#: Codex's own name for this plugin's data directory is
#: `<marketplace>-<plugin>`, and `codex.PLUGIN_NAME` is the substring both
#: halves share. Restated here for the same reason the receipt checks are:
#: this half of the file runs under host `python3`, before the re-exec, where
#: `privacy_hud` is not importable at all. `_codex_data_candidates` below
#: mirrors `codex.codex_data_candidates()` line for line, and
#: `tests/test_mcp_launcher.py::test_the_data_dir_fallback_matches_codex`
#: runs both against the same tree and compares the answers.
PLUGIN_NAME = "codex-privacy-hud"


def _fail(message: str):
    """One line to stderr, non-zero exit, nothing on stdout.

    stdout is the JSON-RPC channel for stdio MCP: a single stray byte there
    desynchronises the framing, so an error printed to stdout is worse than
    the error it reports. I1: `message` names a cause, never a payload.
    """
    print(f"privacy-hud mcp: {message}", file=sys.stderr)
    raise SystemExit(1)


def _codex_data_candidates() -> list[str]:
    """Directories under `$CODEX_HOME/plugins/data/` that look like ours.

    A stdlib mirror of `privacy_hud.codex.codex_data_candidates()`, which is
    where this project's knowledge of Codex's layout lives. It cannot be
    imported here: everything above the `execve` runs under host `python3`,
    which has no `privacy_hud` on its path — that is the whole reason the
    re-exec exists. The repo's precedent for a fact two stdlib-only ends must
    share is to restate it and pin the copies with one test (`EGRESS_EVENTS`,
    the socket name, the receipt checks above), and that is what this is.
    """
    home = os.environ.get("CODEX_HOME")
    root = (Path(home).expanduser() if home else Path.home() / ".codex")
    try:
        entries = sorted((root / "plugins" / "data").iterdir())
    except OSError:
        return []
    return [str(p) for p in entries if p.is_dir() and PLUGIN_NAME in p.name]


def _resolved_data_dir() -> str | None:
    """`$PLUGIN_DATA`, or the directory Codex assigns this plugin.

    The spec asserts Codex injects `PLUGIN_DATA` into an MCP server's
    environment, with no source for the claim — and `doctor.check_mcp_server`
    sets that variable itself before spawning the server, so a green doctor
    is compatible with a server that dies at every real Codex launch. Rather
    than leave the assumption load-bearing, resolve the directory the way
    every other reader in this project does when the variable is absent
    (`runtime.plugin_data_dir` -> `codex.codex_data_candidates`), so the
    assumption stops mattering either way.

    One candidate only. Several means "which of these is Codex's?" has no
    answer here, and `runtime.resolve_data_dir` refuses that case too rather
    than guessing; `None` sends the caller to `_fail`, which is loud.
    """
    env = os.environ.get("PLUGIN_DATA")
    if env:
        return env
    candidates = _codex_data_candidates()
    return candidates[0] if len(candidates) == 1 else None


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
    data_dir = _resolved_data_dir()
    if not data_dir:
        _fail("PLUGIN_DATA is not set and no Codex plugin-data directory for "
              "this plugin could be resolved; the plugin is not installed, or "
              "several candidates matched — run privacy-hud-setup")
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
    # Hand the child the directory this half resolved, so the two halves
    # cannot disagree about which ledger this server is for. When
    # `PLUGIN_DATA` was set this is a no-op; when it was not, it is the
    # resolution above, made explicit rather than re-derived after the exec.
    env["PLUGIN_DATA"] = data_dir
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


#: The tools the model may call, sorted. A tool belongs here only if calling
#: it cannot weaken what the plugin enforces:
#:
#:   * the four reads answer questions and change nothing;
#:   * `update_policy` only tightens, and here is why rather than the bare
#:     claim. Its rule types are `mask`, `block_path` and `block_command`
#:     (since #38). `block_path`/`block_command` set a deny outright.
#:     `mask` forces a rewrite of a call that would otherwise have been
#:     allowed -- except on a data type the engine hard-blocks, where it
#:     would instead replace that block with an executed, masked call,
#:     because `Engine.observe` applies a mask rule ahead of its own matrix
#:     defaults and the default deny only runs while the action is still
#:     "allow". That one combination is refused by
#:     `mcp_tools.apply_policy` (`_MASK_WOULD_DOWNGRADE`), keyed off the
#:     same `HARD_BLOCKED_DATA_TYPES` the engine gates the block on, so the
#:     two cannot drift. With it refused, nothing this tool can write
#:     loosens anything. Its selectors are a data type, a path or a program
#:     name, never a value, so the call carries no secret, and no path
#:     removes a rule once written (known limit 13) -- which is also why
#:     the refusal matters: a downgrade written here would last the session.
#:
#: Withheld, and not by oversight: `privacy.allow_once` (mints a token that
#: unblocks the call it names), `privacy.read_guard_set` (can turn the read
#: guard off) and `privacy.hud_toggle` (can hide the indicator). The last two
#: stay reachable through `$privacy read|hud on|off`, which a user types.
#: `allow_once` keeps no surface at all: see
#: `tests/test_mcp_surface.py::test_allow_once_would_block_itself`.
#:
#: `privacy-hud-doctor` compares the running server's tools against its own
#: copy of this list, so a regression fails a check a user runs.
EXPOSED_TOOLS = (
    "privacy.get_exposure_detail",
    "privacy.get_session_summary",
    "privacy.list_exposures",
    "privacy.read_guard_status",
    "privacy.update_policy",
)


def build_app():
    """Construct the FastMCP app and register the five `privacy.*` tools in
    `EXPOSED_TOOLS`. Imports `mcp` here (not at module scope) -- see this
    file's docstring."""
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
        replacement rather than a revival of it. A `mask` rule on a data
        type the engine hard-blocks (`credential`) is refused as well: that
        rule would take effect ahead of the block and replace it with an
        executed, masked call, which is the only way this tool could ever
        loosen enforcement."""
        mcp_tools.apply_policy(ledger, session_id, rule_type=rule_type,
                                selector=selector)
        return {"applied": True, "rule_type": rule_type, "selector": selector}

    @app.tool(name="privacy.read_guard_status")
    def read_guard_status() -> dict:
        """Whether reads of known-sensitive paths are currently blocked
        (`#36`). The toggle lives in `$PLUGIN_DATA/settings.json`, not
        Codex's own config, so this is how a caller finds out what it
        says."""
        return mcp_tools.read_guard_status(_ledger_path().parent)

    return app


def main() -> int:
    _reexec_under_pinned_interpreter()
    app = build_app()
    app.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
