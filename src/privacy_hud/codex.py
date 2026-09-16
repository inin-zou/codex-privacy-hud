# src/privacy_hud/codex.py
"""Everything this package knows about Codex *the platform*, in one file.

**What this defends.** Codex changes underneath this plugin, and it is the
one axis of change the maintainer does not control: a release that renames a
hook event, adds one, moves the plugin cache, or changes how `$PLUGIN_DATA`
is named breaks us silently — an unknown event falls through
`dispatch.dispatch` to `_allow()`, a directory that no longer exists resolves
to nothing, and every hook in the session is answered "unverified" while
every component reports itself healthy. Before this module those facts were
spread over five files as executable literals (`dispatch._KNOWN_EVENTS` and
its `if event ==` chain, `daemon`'s fail-closed gate, `doctor.PROBE_EVENT`,
`doctor._codex_home`/`_codex_data_candidates`, `handler._looks_like_egress`'s
twin in `dispatch`), so "Codex changed" meant reading five files and hoping.
It is one file now: when Codex moves, this is the file to read.

**Stdlib only, and it imports nothing from this package.** That is what makes
it importable from anywhere — `dispatch`, `daemon`, `doctor`, `runtime`,
`local_ui_server` all need these facts, and before this module they reached
for each other's privates through deferred imports that existed purely to
dodge a `doctor` -> `runtime` -> `doctor` cycle. A leaf with no package
imports cannot take part in a cycle at all;
`tests/test_codex_facts.py::test_codex_module_imports_nothing_from_the_package`
asserts that by AST, the same way `tests/test_network_isolation.py` asserts
the dependency allowlist.

**What belongs here and what does not.** A fact about Codex — the name of an
event Codex sends, the directory Codex assigns, the file name both ends of
our own wire protocol must agree on — belongs here. A *policy* of this
plugin's — which events are worth scoring, what a `PreToolUse` on a local
command means, what the doctor says about a missing directory — belongs in
the module that owns the policy. The line matters: this file must stay
readable as "what Codex does", not as a second copy of the daemon.

**I1.** Nothing here touches session content. Names, paths and event labels.
"""
from __future__ import annotations

import os
from pathlib import Path

# --------------------------------------------------------------------- #
# Identity: the two manifests, and the directory name Codex derives
# --------------------------------------------------------------------- #

#: The plugin's name in `.codex-plugin/plugin.json`, which is also the
#: directory name Codex uses under `plugins/cache/<marketplace>/`.
PLUGIN_NAME = "codex-privacy-hud"

#: The marketplace's name in `.agents/plugins/marketplace.json`.
MARKETPLACE_NAME = "codex-privacy-hud"

#: `<marketplace>-<plugin>`: the directory Codex creates under
#: `$CODEX_HOME/plugins/data/` and hands the plugin as `$PLUGIN_DATA`.
#:
#: Derived here from the two names above rather than read from the manifests
#: at import time, deliberately: the runtime cannot rely on the repo checkout
#: existing at all (Codex runs a *copy* out of its own cache, and a wheel
#: install has no manifests beside it), so a resolver that parsed them would
#: fail exactly where it is most needed. The duplication is checked rather
#: than trusted — `tests/test_hud_contract.py` parses both manifests and
#: asserts these three constants, the Rust status-line item's
#: `PLUGIN_DATA_DIRNAME` and `install.sh`'s literal all agree with them.
PLUGIN_DATA_DIRNAME = f"{MARKETPLACE_NAME}-{PLUGIN_NAME}"

# --------------------------------------------------------------------- #
# Files inside `$PLUGIN_DATA`
# --------------------------------------------------------------------- #

#: The daemon's unix socket. `hooks/handler.py` restates this literal because
#: it is stdlib-only and never imports this package;
#: `tests/test_daemon.py::test_the_socket_name_is_the_same_in_all_three_places`
#: compares the copies, so the duplication is checked rather than trusted.
#: Drift is silent and total: the client connects to a path nothing listens
#: on and every hook in the session is answered unverified.
SOCKET_NAME = "daemon.sock"

#: The ledger. `$PLUGIN_DATA/ledger.db` is the one file every reader in this
#: project — daemon, `$privacy` UI, MCP server, doctor — must agree on.
LEDGER_NAME = "ledger.db"

# --------------------------------------------------------------------- #
# Hook events
# --------------------------------------------------------------------- #

#: Every event Codex can send us: exactly the events `hooks/hooks.json`
#: registers, which is the only thing that decides what arrives.
#: `tests/test_codex_facts.py` parses that JSON and asserts this set equals
#: its keys — the pin that makes "Codex renamed an event" a test failure here
#: instead of a silent gap in a user's session.
KNOWN_EVENTS = frozenset({
    "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
    "SubagentStart", "SubagentStop", "PreCompact", "SessionEnd",
})

#: The subset with a pinned `Observation` mapping (`dispatch`'s table).
#: Everything else that reaches the daemon is allowed and recorded nowhere,
#: rather than guessed at. Which events are *worth scoring* is this plugin's
#: policy, but the policy is expressed in Codex's vocabulary, so the names
#: live here with the rest of them; `dispatch._KNOWN_EVENTS` is an alias.
OBSERVED_EVENTS = frozenset({
    "SessionStart", "SessionEnd", "UserPromptSubmit", "PostToolUse",
    "PreToolUse", "SubagentStart",
})

#: The only event that can ever carry egress, and therefore the only one a
#: failure must fail *closed* on (I6: fail open on ingress, fail closed on
#: egress). `hooks/handler.py` restates this set as a literal for the same
#: stdlib-only reason the socket name is restated, and `tests/test_runtime.py`
#: compares the two.
EGRESS_EVENTS = frozenset({"PreToolUse"})

#: The harmless probe: the event the doctor's round trip sends because it
#: cannot record or change anything. It is in `KNOWN_EVENTS` (Codex sends it)
#: and not in `OBSERVED_EVENTS` (no `Observation` is defined for it), so
#: `dispatch()` returns an empty allow before it touches the ledger, creates
#: a session, builds an `Engine` or runs a detector. See `doctor`'s module
#: docstring for the full argument.
PROBE_EVENT = "PreCompact"

# --------------------------------------------------------------------- #
# Tool names                                                            #
# --------------------------------------------------------------------- #
#
# Codex does not send the tool name the model called. It maps its internal
# tool identity through `codex_core::tools::hook_names::HookToolName` to a
# hook-facing name, which is why the shell tool — internally `exec_command`
# / `unified_exec` — arrives here as `Bash`. Only the two below are
# evidenced; the full mapping is not recoverable from a stripped build, so
# treat this as "the names we have seen", never as "the names that exist".
#
# Evidence, so a later reader can re-check rather than re-guess:
#   * real hook payloads recorded in a ledger — `Bash` and `apply_patch`
#     are the only non-null `events.tool_name` values written by live
#     sessions (`Read` appears twice, uncorroborated; see below)
#   * the patched Codex 0.154.0 binary's symbol table:
#     `codex_core::tools::handlers::*` is `apply_patch`, `shell_spec`,
#     `unified_exec`, `view_image`, `plan`, `mcp`, … — with **no
#     read/view/edit/write file tool of any kind**
#   * Codex's own trace log (`$CODEX_HOME/logs_2.sqlite`) records
#     `tool_name` as `exec_command` / `exec` and nothing file-shaped

#: Codex's shell tool as hooks see it. Codex has no native file-read tool:
#: the model reads a file by shelling out (`cat`, `sed -n`), so a read
#: reaches us as this name with the command in `tool_input["command"]`.
#: That is what confines `origin.extract_origin`'s command parsing — and
#: the #36 read guard built on it — to this one tool.
SHELL_TOOL = "Bash"

#: Codex's only native writer. Its `tool_input` is a string payload, not a
#: path key, so `origin.extract_origin` yields no PATH origin for it and
#: the read guard cannot mistake a patch for a read. If that shape ever
#: changes, `tests/test_codex_facts.py` is where it must be noticed.
PATCH_TOOL = "apply_patch"

#: Tool names whose `updatedInput` Codex requires to be a plain string
#: `command` rather than a dict, per architecture.md §8's "Rewrite path".
STRING_COMMAND_TOOLS = frozenset({SHELL_TOOL, PATCH_TOOL})


def is_mcp_tool(tool_name: str) -> bool:
    """Is `tool_name` one of Codex's MCP tool calls?

    `startswith("mcp")`, not `"mcp__"` — Codex's own spelling, and the
    predicate `hooks/handler.py._looks_like_egress` applies on the client
    side. The two ends must agree or the daemon's classification of a call
    disagrees with the client's fail-closed gate for the same call; that is
    why there is one definition and the stdlib-only client's copy is pinned.
    """
    return tool_name.startswith("mcp")


# --------------------------------------------------------------------- #
# Codex's directories
# --------------------------------------------------------------------- #

def codex_home() -> Path:
    """Codex's state directory. `CODEX_HOME` wins, as it does for Codex."""
    override = os.environ.get("CODEX_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".codex"


def plugin_data_root() -> Path:
    """`$CODEX_HOME/plugins/data/` — where Codex puts every plugin's
    `$PLUGIN_DATA` directory."""
    return codex_home() / "plugins" / "data"


def plugin_cache_root() -> Path:
    """`$CODEX_HOME/plugins/cache/` — where Codex keeps the *copy* of each
    plugin it actually executes (`<marketplace>/<plugin>/<version>/`), which
    is why an edited file in a checkout is not what runs."""
    return codex_home() / "plugins" / "cache"


def codex_data_candidates() -> list[Path]:
    """Directories under `$CODEX_HOME/plugins/data/` that look like ours.

    This is the answer to the single most expensive misconfiguration this
    project has hit: `PLUGIN_DATA` is assigned by Codex, and a daemon started
    against a different value listens on a socket no hook will ever connect
    to. Reading the real value off disk is what README tells the user to do
    (`ls ~/.codex/plugins/data/`); this does the same `ls` so a remedy line
    can name the exact directory instead of describing how to find it.

    Matched on `PLUGIN_NAME` being *in* the name rather than on
    `PLUGIN_DATA_DIRNAME` exactly: a directory installed from a differently
    named marketplace is still ours, and reporting "Codex assigns you this
    one" is more useful than reporting nothing at all.
    """
    try:
        entries = sorted(plugin_data_root().iterdir())
    except OSError:
        return []
    return [p for p in entries if p.is_dir() and PLUGIN_NAME in p.name]


def ledger_path(data_dir) -> Path:
    """`$PLUGIN_DATA/ledger.db`. The one derivation; `runtime.ledger_path`
    is the resolver that decides *which* `$PLUGIN_DATA` first."""
    return Path(data_dir) / LEDGER_NAME


def socket_path(data_dir) -> Path:
    """`$PLUGIN_DATA/daemon.sock`, given an already-resolved data directory.

    `daemon._default_socket_path` stays the canonical helper for the daemon
    itself (it is what `daemon.main` calls, and `doctor` prefers it when
    `daemon` imports); this is the same derivation for callers that must not
    depend on `daemon` importing at all.
    """
    return Path(data_dir) / SOCKET_NAME
