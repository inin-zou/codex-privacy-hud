#!/usr/bin/env python3
# mcp/server.py
"""Thin stdio MCP wrapper around `privacy_hud.mcp_tools` (Task 13).

Exposes exactly the five tools named in `EXPOSED_TOOLS`, below: the four
reads (`privacy.get_session_summary`, `privacy.list_exposures`,
`privacy.get_exposure_detail`, `privacy.read_guard_status`) plus
`privacy.update_policy`, the one write, which can only tighten enforcement
because `Engine.observe` never lets a user `mask` rule decide an observation
that carries a hard-blocked data type: the mask branch is skipped and the
matrix default -- the deny -- stands. That is a property of the engine, not
of the rules this tool is allowed to write; a rule whose selector is
innocuous can still land on a call that carries a credential, which is the
case a mint-site refusal cannot see. `mcp_tools.apply_policy` additionally
refuses a `mask` rule on a hard-blocked selector, now because such a rule is
inert (see `_MASK_WOULD_DOWNGRADE` there). The behaviour test is
`tests/test_mcp_surface.py::test_no_exposed_tool_can_turn_a_deny_into_an_allow`,
whose payload carries a second, co-occurring finding for exactly that reason.
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

**Saving a rule and enforcing it are separate.** `privacy.update_policy`
writes a session policy rule and returns `saved: true`,
`enforcement: "conditional"`, and the conditions from
`mcp_tools.rule_enforcement_note`. A saved rule can match only findings
produced on later outbound calls this plugin checks. Mask rules also
yield to an outright block. Origin rules require the value to be detected
on ingress and again on egress. Detection can miss values, and hosted
tools never reach this plugin. Data already disclosed stays disclosed.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import-time cost is the whole point of not importing these
    from privacy_hud.ledger import Ledger

#: `$PLUGIN_DATA/runtime.json` (receipt v2), read by `hooks/handler.py` to
#: launch the daemon and checked here before this file hands over to the
#: bundled bootstrap. Restated rather than imported: `handler.py` inlines
#: these checks on the path every tool call runs. The repo's precedent for a
#: fact two stdlib-only ends must share is to restate it and pin both copies
#: with one test —
#: `tests/test_mcp_launcher.py::test_the_receipt_checks_match_the_hook_client`.
RECEIPT_NAME = "runtime.json"
RECEIPT_VERSION = 2

#: The bundled bootstrap, relative to this plugin bundle (#66).
BOOTSTRAP = ("scripts", "runtime.py")

#: What a ledger-backed tool reports when sqlite fails. Fixed text: the
#: exception's own message could carry anything, and the tool must never
#: return an empty summary or `saved: true` in its place.
LEDGER_ERROR = ("Privacy HUD ledger operation failed; no successful result "
                "is available.")


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


def _bundle_root() -> Path:
    """This plugin bundle: the directory above `mcp/`."""
    return Path(__file__).resolve().parent.parent


def _launch_through_bootstrap() -> int:
    """Hand this process to the bundled bootstrap (#66).

    Codex constrains an MCP `command` to a bare executable on the host PATH
    or a `./` path inside the plugin root, and rejects `${PLUGIN_ROOT}` there
    — unlike `hooks.json`, where `$PLUGIN_ROOT` expands. So the manifest
    launches host `python3`, which can import neither `privacy_hud` nor
    `mcp`, and this is how the process reaches the selected interpreter.

    The checks below run first so the cheap, common failures keep their
    fixed one-line diagnostics. The bootstrap then does the rest: it
    verifies the selected build, re-executes the receipt's interpreter in
    isolated mode (`python -I`, so no inherited `PYTHONPATH` can supply
    first-party code), imports `privacy_hud` only from this bundle, and
    calls `serve()` below. Nothing on this path writes to stdout: it is the
    JSON-RPC channel.

    Re-exec rather than borrowing `sys.path`: `mcp` depends on `pydantic`,
    whose core is a compiled extension built for one interpreter version.
    """
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
        if (not isinstance(receipt, dict)
                or isinstance(receipt.get("v"), bool)
                or receipt.get("v") != RECEIPT_VERSION):
            raise ValueError("unusable receipt")
        python = receipt["python"]
        if not isinstance(python, str) or not python:
            raise ValueError("unusable receipt")
    except (OSError, ValueError, KeyError) as exc:
        _fail(f"no usable {RECEIPT_NAME} ({type(exc).__name__}); "
              "run privacy-hud-setup")
    if not os.access(python, os.X_OK) or os.path.isdir(python):
        _fail("the recorded interpreter is not executable; run privacy-hud-setup")

    import importlib.util
    path = _bundle_root().joinpath(*BOOTSTRAP)
    spec = importlib.util.spec_from_file_location(
        "_privacy_hud_bootstrap", path)
    if spec is None or spec.loader is None:  # pragma: no cover - a bundle
        # without its bootstrap is refused by the digest check anyway
        raise SystemExit(1)
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    return bootstrap.main(["--plugin-data", data_dir, "mcp"])


def _data_dir() -> Path:
    """`$PLUGIN_DATA`, resolved the same way every other reader does
    (`local_ui_server.resolve_data_dir`). No `/tmp` default (spec §6): a
    server with nowhere to read from exits with a message rather than
    inventing an empty ledger in a shared directory."""
    from privacy_hud.local_ui_server import resolve_data_dir
    data_dir = resolve_data_dir()
    if data_dir is None:
        raise SystemExit("privacy-hud mcp: PLUGIN_DATA is not set and no "
                          "Codex plugin-data directory was found")
    return data_dir


def _ledger_path() -> Path:
    """`$PLUGIN_DATA/ledger.db`."""
    return _data_dir() / "ledger.db"


def _open_ledger() -> "Ledger":
    """The server's one ledger connection, with thread affinity off.

    MCP SDK 2.x runs a synchronous tool on a worker thread, so the thread
    that opens this connection is not the one that uses it. `build_app`
    serializes every use and the close under one lock, which is the
    condition `Ledger` states for turning affinity off. With affinity on,
    every ledger-backed tool failed with `sqlite3.ProgrammingError` (0.7.4
    and earlier).

    A reader's open (`initialize=False`): the server never applies the
    schema or migrates, so it cannot change the structure of the ledger the
    daemon writes, and a missing ledger fails to open instead of being
    created empty."""
    from privacy_hud.ledger import Ledger
    from privacy_hud.matrix.loader import load_matrix
    return Ledger(_ledger_path(), load_matrix(), check_same_thread=False,
                  initialize=False)


#: The tools the model may call, sorted. A tool belongs here only if calling
#: it cannot weaken what the plugin enforces:
#:
#:   * the four reads answer questions and change nothing;
#:   * `update_policy` only tightens, and here is why rather than the bare
#:     claim. Its rule types are `mask`, `block_path` and `block_command`
#:     (since #38). `block_path`/`block_command` set a deny outright.
#:     `mask` forces a rewrite of a call that would otherwise have been
#:     allowed -- and only of such a call: `Engine.observe` skips its mask
#:     branch entirely on any observation carrying a finding of a
#:     `HARD_BLOCKED_DATA_TYPES` type, so the matrix default decides that
#:     one and the deny stands. No rule this tool can write, with any
#:     selector, changes that. The guard is in the engine rather than in
#:     what this tool accepts because it has to be: the branch matched on
#:     every finding of the observation, so a mask rule on an innocuous type
#:     that co-occurred with a credential skipped the block, and a refusal
#:     keyed on the selector cannot see that call. `mcp_tools.apply_policy`
#:     does still refuse `mask` on a hard-blocked selector
#:     (`_MASK_WOULD_DOWNGRADE`), keyed off the same
#:     `HARD_BLOCKED_DATA_TYPES` the engine gates the block on so the two
#:     cannot drift -- now because such a rule would be inert, and as
#:     defence in depth. Its selectors are a data type, a path or a program
#:     name, never a value, so the call carries no secret, and no path
#:     removes a rule once written (known limit 13).
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
    """Construct the MCP app and register the five `privacy.*` tools in
    `EXPOSED_TOOLS`. Imports `mcp` here (not at module scope) -- see this
    file's docstring.

    `MCPServer` is the SDK 2.x name for what 1.x called `FastMCP`. The rename
    is why `pyproject.toml` bounds the extra at `mcp>=2` rather than leaving
    it bare: with no bound, which side of the rename an install lands on
    depends on the day it ran. A venv built 2026-09-15 got 1.x and started; the
    same `install.sh` on 2026-09-20 got 2.2.0, `mcp.server.fastmcp` raised, the
    server never started, and -- in the doctor's words -- "Codex reports
    nothing when this happens: the plugin loads, and the tools are simply
    absent."
    """
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError as exc:  # pragma: no cover - exercised only when the
        # optional extra genuinely isn't installed; covering this branch in
        # a test would require uninstalling `mcp` mid-suite.
        raise SystemExit(
            "mcp/server.py requires the 'mcp' package (>= 2), which is an "
            "optional extra (not a hard dependency of privacy-hud). Install "
            "it with:\n"
            "    pip install 'privacy-hud[mcp]'\n"
            "or, from a source checkout:\n"
            "    pip install 'mcp>=2'\n"
            f"(original ImportError: {exc})"
        ) from exc

    import asyncio
    import contextlib
    import sqlite3
    import threading

    from mcp.server.mcpserver.exceptions import ToolError

    from privacy_hud import mcp_tools

    # The connection is opened with a reader's open, which cannot create a
    # missing ledger. The daemon creates it on the first SessionStart, and
    # Codex can start this server before that: so it is opened now when the
    # file exists, and otherwise on the first tool call that needs it. A
    # call made before any ledger exists fails with `LEDGER_ERROR` rather
    # than reporting an empty session.
    opened: list = []

    def ledger():
        if not opened:
            opened.append(_open_ledger())
        return opened[0]

    if _ledger_path().exists():
        ledger()
    # One lock for the connection: every ledger access in a tool, including
    # the `.as_dict()` that materializes a read's result, the lazy open, and
    # the close at shutdown.
    # It serializes this process's use of the connection whatever thread the
    # SDK runs a tool on. It does not coordinate with the daemon, which is
    # another process: sqlite arbitrates between processes.
    lock = threading.Lock()

    @contextlib.contextmanager
    def tool_access():
        with lock:
            try:
                yield
            except sqlite3.Error:
                # A fixed message, never the sqlite text (I1: an exception
                # message is a string this plugin did not choose). No retry:
                # a write that may have failed is reported as failed, never
                # as `saved: true`.
                raise ToolError(LEDGER_ERROR) from None

    def close_ledger() -> None:
        with lock:
            if opened:
                opened[0].conn.close()

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        try:
            yield {}
        finally:
            # Waits for a tool that holds the connection, off the event loop.
            await asyncio.to_thread(close_ledger)

    app = MCPServer("privacy-hud", lifespan=lifespan)

    # The three read tools below end in `.as_dict()`. `mcp_tools` returns
    # `ledger.py`'s summary variants and `LegacyExposureRow`, and this is the
    # wire boundary: `ledger._EXPOSURE_JSON_FIELDS` pins which keys an MCP
    # client sees and in what order, so the read tools' published
    # shape is a decision recorded in one place rather than whatever a
    # dataclass happens to declare. Do not drop these calls -- a dataclass
    # handed to the MCP transport is not serializable.

    @app.tool(name="privacy.get_session_summary")
    def get_session_summary(session_id: str) -> dict:
        """Read the selected session's accounting summary.

        accounting_version=1 returns legacy_score, legacy_cap, legacy_percent,
        legacy_permitted_crossing_rows, legacy_boundary_kinds,
        legacy_prevented_rows, score_label, and accounting_note.
        legacy_percent is the existing score divided by its stored cap,
        rounded and capped at 100. It is not a probability or a fraction of
        data disclosed. Row counts are not call counts, and boundary kinds are
        not concrete recipients. Historical accounting includes permitted
        crossings and may collapse different outcomes. It does not establish
        confirmed disclosure.

        accounting_version=0 returns percent=null, score_label="No session on
        record", and accounting_note. No numeric score, cap, or counts are
        available for that session.

        Report score_label and accounting_note with the result. Do not replace
        null with zero. The old percent, exposed_items, destinations, and
        prevented fields are not returned for legacy summaries.
        """
        with tool_access():
            return mcp_tools.get_session_summary(
                ledger(), session_id).as_dict()

    @app.tool(name="privacy.list_exposures")
    def list_exposures(session_id: str, tab: str) -> list[dict]:
        """Read public legacy event rows for the selected session. Accepted tab
        values are "Exposed", "Prevented", and "All events"; they select
        stored legacy classifications.

        Each returned row has accounting_version=1. "Exposed" selects legacy
        permitted-crossing rows, not confirmed deliveries. "Prevented" selects
        legacy prevented rows, not confirmed host-enforced interventions.
        count is the stored legacy repetition count, not a distinct-value or
        call count. Different outcomes may have collapsed into one row.

        An unrecorded session returns an empty list. That is not evidence that
        no events occurred. Raw values and identity hashes are not returned.
        """
        with tool_access():
            return [r.as_dict()
                    for r in mcp_tools.list_exposures(ledger(), session_id,
                                                      tab)]

    @app.tool(name="privacy.get_exposure_detail")
    def get_exposure_detail(session_id: str, event_id: int) -> dict:
        """Read one public legacy event row by session_id and event_id. The
        lookup is scoped to both identifiers and returns accounting_version=1.

        The stored classification, intervention label, repetition count, and
        budget contribution retain legacy meanings. They do not establish
        delivery, host enforcement, or a multi-hop flow. first_seen and
        budget_cap are included when available.

        An unknown event or an event outside the selected session is an error.
        An unrecorded session has no event detail. This tool reads metadata;
        it does not save a policy rule.
        """
        with tool_access():
            return mcp_tools.get_exposure_detail(
                ledger(), session_id, event_id).as_dict()

    @app.tool(name="privacy.update_policy")
    def update_policy(session_id: str, rule_type: str, selector: str) -> dict:
        """Save a policy rule for the selected session: mask selects a data type;
        block_path and block_command select a recorded origin.

        Success returns saved=true and enforcement="conditional". Report the
        returned conditions to the user. Saving a rule does not establish that
        a later call will match it or that the host will apply a denial or
        rewritten input.

        Mask rules can cause Privacy HUD to return rewritten input for
        matching findings on later outbound calls this plugin checks. A deny
        takes precedence. Types other than path and credential require an
        accepted deep-scan result.

        Origin rules require detection on ingress and again on egress. They
        match the whole value normalized using value.strip().lower();
        summaries and partial quotations may not match. Scan gaps and detector
        misses can prevent matching, and hosted tools bypass these hooks.

        block_source and allow_dest are refused. A mask rule selecting a
        hard-blocked data type is also refused. Data already disclosed stays
        disclosed.
        """
        from privacy_hud.ledger import writer_connection
        from privacy_hud.matrix.loader import load_matrix
        from privacy_hud.runtime_contract import RuntimeRefusal
        from privacy_hud.runtime_messages import POLICY_PREFLIGHT_REFUSAL

        with tool_access():
            # The server's own connection is `mode=ro` (#66): the daemon
            # owns ledger writes, and this process is not it. A rule is
            # written under a lease taken for this one mutation, inside the
            # same `tool_access()` lock as every other ledger use here, so
            # the worker-thread serialization this server depends on is
            # unchanged.
            try:
                with writer_connection(_ledger_path(), load_matrix(),
                                       data_dir=_data_dir(),
                                       check_same_thread=False) as writable:
                    mcp_tools.apply_policy(writable, session_id,
                                           rule_type=rule_type,
                                           selector=selector)
            except RuntimeRefusal:
                # Refused before the write. Nothing was saved, and saying so
                # is a fact rather than a guess (§D).
                raise ToolError(POLICY_PREFLIGHT_REFUSAL) from None
        # `saved`, not `applied`. The rule is in the policy table; whether it
        # ever fires depends on a later call producing a finding it matches.
        # For every type outside `mcp_tools.CHEAP_DATA_TYPES`, matching
        # requires an accepted deep-scan result (#49 item 2, known limit 21). Report what happened, not what the
        # user hopes will happen.
        return {"saved": True, "enforcement": "conditional",
                "rule_type": rule_type, "selector": selector,
                "conditions": mcp_tools.rule_enforcement_note(
                    rule_type, selector).strip()}

    @app.tool(name="privacy.read_guard_status")
    def read_guard_status() -> dict:
        """Read whether the known-sensitive-path read guard is enabled in Privacy
        HUD's settings.json. deny_read=true means the plugin is configured to
        issue denials for recognized matching reads. It does not confirm host
        enforcement. This tool does not change the setting.
        """
        return mcp_tools.read_guard_status(_ledger_path().parent)

    return app


def serve() -> int:
    """Run the stdio server. Called by the bootstrap, in the selected
    interpreter, after the runtime identity checks."""
    app = build_app()
    app.run(transport="stdio")
    return 0


def main() -> int:
    return _launch_through_bootstrap()


if __name__ == "__main__":
    raise SystemExit(main())
