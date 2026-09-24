# tests/test_codex_facts.py
"""`privacy_hud/codex.py` — the one module that knows Codex the platform.

Two properties are defended here, and they are the two the module exists for.

**It stays a leaf.** Every other module imports it — `dispatch`, `daemon`,
`doctor`, `runtime`, `local_ui_server` — precisely so they stop importing each
other's privates for these facts. The moment it imports one of them back, the
cycle those deferred imports were dodging is available again, so the
no-package-imports rule is asserted by AST rather than left to review, the
same way `tests/test_network_isolation.py` asserts the dependency allowlist.

**Its event set is Codex's, not ours.** `hooks/hooks.json` is what decides
which events arrive; an event registered there that `codex.KNOWN_EVENTS` does
not list is a silent gap (it reaches the daemon and falls through to an empty
allow), and one listed here but not registered is a fact about a Codex that
is no longer running. The two are compared instead of trusted.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

from privacy_hud import codex

REPO = Path(__file__).resolve().parents[1]
CODEX_PY = REPO / "src" / "privacy_hud" / "codex.py"
HOOKS_JSON = REPO / "hooks" / "hooks.json"


def _imported_modules(path: Path) -> set[str]:
    """Every module name imported anywhere in `path`, including inside a
    function body — a deferred import is still an import, and a deferred
    import of a sibling is exactly the thing this module exists to delete."""
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            # `from . import x` / `from .x import y` have level > 0 and a
            # module of None or "x"; either way it is a package import.
            if node.level:
                names.add("." * node.level + (node.module or ""))
            elif node.module:
                names.add(node.module)
    return names


def test_codex_module_imports_nothing_from_the_package():
    """`codex.py` is stdlib-only and imports nothing from `privacy_hud`.

    That is what makes it importable from anywhere. `doctor` -> `runtime` ->
    `doctor` and `doctor` -> `local_ui_server` -> `runtime` -> `doctor` were
    both real cycles, broken only by deferred imports that each carried a
    comment explaining why; the facts they were reaching for live here now,
    and a leaf with no package imports cannot take part in a cycle at all.
    """
    offenders = sorted(name for name in _imported_modules(CODEX_PY)
                       if name.startswith(".")
                       or name.split(".")[0] == "privacy_hud")
    assert not offenders, (
        "codex.py must import nothing from privacy_hud -- every module in "
        "the package imports it, so an import back is a cycle: "
        + ", ".join(offenders))


def test_codex_module_imports_only_the_stdlib():
    import sys

    offenders = sorted(name for name in _imported_modules(CODEX_PY)
                       if not name.startswith(".")
                       and name.split(".")[0] not in sys.stdlib_module_names)
    assert not offenders, offenders


def test_known_events_are_exactly_the_events_hooks_json_registers():
    """`hooks/hooks.json` is the registration; `codex.KNOWN_EVENTS` is what
    the package believes about it.

    A Codex release that renames an event, or a hook we add and forget to
    write down, is otherwise invisible: an unregistered event simply never
    arrives, and an unknown one that does falls through `dispatch.dispatch`
    to an empty allow with nothing recorded and nothing said.
    """
    registered = set(json.loads(HOOKS_JSON.read_text())["hooks"])
    assert set(codex.KNOWN_EVENTS) == registered


def test_the_event_subsets_are_subsets():
    """Each named subset must name events Codex actually sends. A typo here
    would be silent in both directions — an egress event that never matches
    fails *open* on the one path I6 says must fail closed."""
    assert codex.OBSERVED_EVENTS <= codex.KNOWN_EVENTS
    assert codex.EGRESS_EVENTS <= codex.KNOWN_EVENTS
    assert codex.PROBE_EVENT in codex.KNOWN_EVENTS


def test_the_probe_event_has_no_observation_mapping():
    """`doctor`'s round trip must not be able to record anything. It sends
    `PROBE_EVENT` precisely because `dispatch` has no `Observation` for it, so
    `dispatch()` returns an empty allow before it touches the ledger, creates
    a session, builds an `Engine` or runs a detector. Keeping the probe out of
    `OBSERVED_EVENTS` is what makes that true; `tests/test_doctor.py` asserts
    the other half (it is not a lifecycle event either)."""
    assert codex.PROBE_EVENT not in codex.OBSERVED_EVENTS


def test_dispatch_and_doctor_use_the_same_objects():
    """The aliases are aliases, not copies. `dispatch._KNOWN_EVENTS` and
    `doctor`'s four re-exports keep their old names because tests and prose
    all over the tree name them there; what must not come back is a second
    definition drifting from this one."""
    from privacy_hud import dispatch, doctor

    assert dispatch._KNOWN_EVENTS is codex.OBSERVED_EVENTS
    assert doctor.SOCKET_NAME is codex.SOCKET_NAME
    assert doctor.PLUGIN_NAME is codex.PLUGIN_NAME
    assert doctor.PROBE_EVENT is codex.PROBE_EVENT
    assert doctor._codex_home is codex.codex_home
    assert doctor._codex_data_candidates is codex.codex_data_candidates


def test_the_tool_name_facts_have_one_definition():
    """`minimize` and `origin` branch on Codex's tool names; before this
    they each held their own literal. A fact about Codex belongs here (§2),
    and a second copy is how `block_source` drifted into never matching."""
    from privacy_hud import minimize, origin

    assert minimize._STRING_COMMAND_TOOLS is codex.STRING_COMMAND_TOOLS
    assert codex.SHELL_TOOL in codex.STRING_COMMAND_TOOLS
    assert codex.PATCH_TOOL in codex.STRING_COMMAND_TOOLS
    # `origin` reads a command only out of the shell tool; anything else
    # falls to PATH_KEYS or to no origin at all.
    assert origin.extract_origin(codex.SHELL_TOOL, {"command": "cat .env"}) \
        is not None
    assert origin.extract_origin("NotAShell", {"command": "cat .env"}) is None


def test_the_patch_tool_yields_no_path_origin():
    """Codex's only native writer takes a string payload, not a path key --
    which is the whole reason the read guard cannot mistake a patch for a
    read. If Codex ever gives `apply_patch` a `file_path`, this fails, and
    known limit 14's reasoning has to be revisited rather than discovered
    by a user whose write was refused under "blocked a read"."""
    from privacy_hud import origin

    assert origin.extract_origin(
        codex.PATCH_TOOL,
        {"input": "*** Begin Patch\n*** Update File: .env\n"}) is None


def test_the_manifest_declares_the_mcp_server_in_the_shape_codex_parses():
    """Codex warns and IGNORES an `mcpServers` value it cannot use, leaving
    the plugin loaded with hooks and skills intact — the same silent shape as
    the hooks trust gate. A typo here is invisible from inside Codex, so the
    shape is pinned here and proved live by `privacy-hud-doctor`.

    The field set comes from the 0.154.0 binary's `AgentPluginMcpServer`
    parser: a stdio server takes `command`, `args`, `env` and `cwd`, and
    nothing else. `command` must be a bare executable name or a contained
    `./` path — `${PLUGIN_ROOT}` is rejected there, which is why this runs
    host `python3` and `mcp/server.py` re-execs itself (see that file).
    """
    import json
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    manifest = json.loads(
        (repo / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    servers = manifest["mcpServers"]
    assert set(servers) == {"privacy-hud"}
    entry = servers["privacy-hud"]
    assert entry == {"command": "python3", "args": ["./mcp/server.py"],
                     "cwd": "."}
    assert (repo / "mcp" / "server.py").is_file()


# --- #54 Phase 4: MCP server namespace -----------------------------------

def test_ambiguous_mcp_name_is_unresolved():
    from privacy_hud import codex
    assert codex.mcp_server_namespace("mcp__vault__read") == "vault"
    assert codex.mcp_server_namespace("mcp__Git-Hub__pr.list_v2") == \
        "Git-Hub"
    for name in ("mcp", "mcp__", "mcp__vault", "mcp__vault__",
                 "mcp____read", "mcp__a__b__c", "mcp__a_b__c",
                 "mcpvault__read", "mcp_vault__read", "mcp__va ult__read",
                 "mcp__vault__re/ad", "MCP__vault__read",
                 "mcp__vault__read\n", "mcp__vault__réad", ""):
        assert codex.mcp_server_namespace(name) is None, name
        # The broad egress predicate is unchanged by this narrower one.
    assert codex.is_mcp_tool("mcp__a__b__c")
