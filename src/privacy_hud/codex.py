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

**I1.** Delegation helpers inspect transient arguments without persisting
content. Other platform facts are names, paths and event labels.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import time
import tomllib
from pathlib import Path
from typing import NamedTuple

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

#: The historical ledger pathname. A database before #66's transition, and
#: the directory fence afterwards. `ledger_path()` below is what every
#: reader in this project — daemon, `$privacy` UI, MCP server, doctor —
#: must agree on; this constant is only the name of the old place.
LEDGER_NAME = "ledger.db"

#: Storage generation 1: `$PLUGIN_DATA/ledger/active.db`, the database the
#: fence exists to keep historical entry points away from.
#: `runtime_storage` owns the transition that creates it and repeats these
#: two names; `tests/test_codex_facts.py` keeps the copies honest.
ACTIVE_DIR_NAME = "ledger"
ACTIVE_DB_NAME = "active.db"

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

#: Events that can carry B3/B4 egress. This is a candidate set, not proof
#: that every matching payload is outbound. Supported B2 delegation
#: pre-hooks are explicitly exempted by is_b2_delegation.
#: The stdlib-only hook client restates the event and tool-name sets;
#: tests pin both copies.
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


# Hook-facing names verified in Codex 0.154.0, 0.155.0 and 0.155.1:
# core/src/tools/handlers/multi_agents/{spawn,send_input}.rs,
# core/src/tools/handlers/multi_agents_v2/{spawn,message_tool}.rs,
# core/src/tools/{hook_names,mod}.rs.
# Codex 0.154.0 and 0.159.3 also flatten the collaboration namespace by
# concatenating it with the tool name. V2 message encryption is declared in
# multi_agents_spec.rs; hook argument parsing does not decrypt it.
# Agent is a matcher alias, not a serialized tool name.
SUBAGENT_TOOLS = frozenset({
    "spawn_agent",
    "multi_agent_v1send_input",
    "send_message",
    "followup_task",
    "collaborationspawn_agent",
    "collaborationsend_message",
    "collaborationfollowup_task",
})


def is_b2_delegation(payload: dict) -> bool:
    """A supported explicit-delegation pre-hook, not a crossing receipt."""
    name = payload.get("tool_name")
    return (
        payload.get("hook_event_name") == "PreToolUse"
        and isinstance(name, str)
        and name in SUBAGENT_TOOLS
    )


def encrypted_delegation_fields(tool_name: str, tool_input: dict) -> tuple[str, ...]:
    """Recognize an opaque V2 message by tool, envelope and complete format.

    This checks a Fernet-shaped transport value, not its authenticity or
    plaintext. Never apply this exemption to arbitrary detector input.
    V1 text items and other fields remain outside the exemption.
    """
    if tool_name in ("spawn_agent", "collaborationspawn_agent"):
        if not isinstance(tool_input.get("task_name"), str):
            return ()
    elif tool_name in (
        "send_message", "followup_task",
        "collaborationsend_message", "collaborationfollowup_task",
    ):
        if not isinstance(tool_input.get("target"), str):
            return ()
    else:
        return ()

    message = tool_input.get("message")
    if not isinstance(message, str):
        return ()
    if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", message) is None:
        return ()
    try:
        raw = base64.b64decode(message, altchars=b"-_", validate=True)
    except binascii.Error:
        return ()
    # Version + timestamp + IV + at least one ciphertext block + HMAC.
    if len(raw) < 73 or raw[0] != 0x80 or (len(raw) - 57) % 16:
        return ()
    if base64.urlsafe_b64encode(raw).decode("ascii") != message:
        return ()
    return ("message",)


def delegated_text(tool_name: str, tool_input: dict) -> str:
    """Extract visible delegated text, excluding recognized opaque messages.

    V1 supports message or UserInput text items. V2 supports message.
    A recognized encrypted message is unavailable to every detector.
    Recognition does not authenticate the token or establish delivery.
    Other metadata is never serialized into delegated text.
    """
    parts: list[str] = []
    excluded = encrypted_delegation_fields(tool_name, tool_input)
    message = tool_input.get("message")
    if isinstance(message, str) and "message" not in excluded:
        parts.append(message)
    if tool_name in ("spawn_agent", "multi_agent_v1send_input"):
        items = tool_input.get("items")
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict) or item.get("type") != "text":
                    continue
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
    return "\n".join(parts)


def is_mcp_tool(tool_name: str) -> bool:
    """Is `tool_name` one of Codex's MCP tool calls?

    `startswith("mcp")`, not `"mcp__"` — Codex's own spelling, and the
    predicate `hooks/handler.py._looks_like_egress` applies on the client
    side. The two ends must agree or the daemon's classification of a call
    disagrees with the client's fail-closed gate for the same call; that is
    why there is one definition and the stdlib-only client's copy is pinned.
    """
    return tool_name.startswith("mcp")


#: `mcp__<server>__<tool>`, the one flattened MCP spelling whose server
#: can be read back unambiguously (#54 Phase 4). ASCII classes only, and
#: `\Z` rather than `$`, so a trailing newline is not accepted.
_MCP_TOOL_NAME = re.compile(
    r"mcp__(?P<server>[A-Za-z0-9-]+)__(?P<tool>[A-Za-z0-9_.-]+)\Z")


def mcp_server_namespace(tool_name: str) -> str | None:
    """The MCP server an `mcp__<server>__<tool>` name addresses, or None.

    Deliberately narrower than `is_mcp_tool`: that predicate decides which
    calls are egress, and stays broad; this one names a recipient, and
    answers only when the flattened name cannot be read two ways. Neither
    captured component may contain `__`, and the server's case is kept.
    Anything else -- a missing separator, a doubled one inside the tool
    name, a character outside the two classes -- is None: unresolved, never
    guessed."""
    if not isinstance(tool_name, str):
        return None
    match = _MCP_TOOL_NAME.match(tool_name)
    if match is None or "__" in match.group("tool"):
        return None
    return match.group("server")


# --------------------------------------------------------------------- #
# Codex's directories
# --------------------------------------------------------------------- #

def codex_home() -> Path:
    """Codex's state directory. `CODEX_HOME` wins, as it does for Codex."""
    override = os.environ.get("CODEX_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".codex"


CONFIG_FILENAME = "config.toml"
PLUGIN_HOOKS_FILE = "hooks/hooks.json"

HOOK_EVENT_LABELS = {
    "SessionStart": "session_start",
    "UserPromptSubmit": "user_prompt_submit",
    "PreToolUse": "pre_tool_use",
    "PostToolUse": "post_tool_use",
    "SubagentStart": "subagent_start",
    "SubagentStop": "subagent_stop",
    "PreCompact": "pre_compact",
    "SessionEnd": "session_end",
}


def user_config_path() -> Path:
    """The default user config; invocation-specific layers are not resolved."""
    return codex_home() / CONFIG_FILENAME


def _normalized_command_identity(
        event: str, group: dict, handler: dict) -> dict:
    """Codex 0.155.1 and 0.164.0 identity for the command schema we ship.

    Only 0.164.0 is admitted by the doctor's version-to-scheme table.
    See hooks/src/engine/discovery.rs and config/src/fingerprint.rs.
    Unsupported schema is refused, never approximated.
    """
    if set(group) - {"matcher", "hooks"}:
        raise ValueError("unsupported hook group")
    allowed = {"type", "command", "timeout", "async", "statusMessage"}
    if set(handler) - allowed or handler.get("type") != "command":
        raise ValueError("unsupported hook handler")

    command = handler.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("invalid hook command")

    timeout = handler.get("timeout")
    if timeout is not None and (
        type(timeout) is not int or not 0 <= timeout <= 2**63 - 1
    ):
        raise ValueError("invalid hook timeout")
    if event == "SessionEnd":
        timeout = min(3, max(1, 1 if timeout is None else timeout))
    else:
        timeout = max(1, 600 if timeout is None else timeout)

    asynchronous = handler.get("async", False)
    if type(asynchronous) is not bool:
        raise ValueError("invalid hook async field")
    status = handler.get("statusMessage")
    if status is not None and not isinstance(status, str):
        raise ValueError("invalid hook status message")

    matcher = group.get("matcher")
    if matcher is not None and not isinstance(matcher, str):
        raise ValueError("invalid hook matcher")
    if event == "UserPromptSubmit":
        matcher = None
    elif matcher not in (None, ".*"):
        raise ValueError("unsupported hook matcher")

    normalized = {
        "type": "command",
        "command": command,
        "timeout": timeout,
        "async": asynchronous,
    }
    if status is not None:
        normalized["statusMessage"] = status
    identity = {
        "event_name": HOOK_EVENT_LABELS[event],
        "hooks": [normalized],
    }
    if matcher is not None:
        identity["matcher"] = matcher
    return identity


def plugin_hook_hashes(bundle: Path, marketplace: str) -> dict[str, str]:
    """Expected persisted keys and exact hashes for one installed bundle.

    This deliberately supports our command-hook schema, not arbitrary Codex
    hooks. Empty, incomplete and unsupported bundles cannot pass doctor.
    Nothing is executed and no command or digest is logged.
    """
    with (bundle / PLUGIN_HOOKS_FILE).open(
            "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError("invalid hook document")
    if set(document) - {"description", "hooks"}:
        raise ValueError("unsupported hook document")
    if (
        document.get("description") is not None
        and not isinstance(document["description"], str)
    ):
        raise ValueError("invalid hook description")
    events = document.get("hooks")
    if not isinstance(events, dict) or set(events) != KNOWN_EVENTS:
        raise ValueError("incomplete hook event set")

    expected: dict[str, str] = {}
    source = f"{PLUGIN_NAME}@{marketplace}:{PLUGIN_HOOKS_FILE}"
    for event, groups in events.items():
        if not isinstance(groups, list) or not groups:
            raise ValueError("invalid hook groups")
        for group_index, group in enumerate(groups):
            if not isinstance(group, dict):
                raise ValueError("invalid hook group")
            handlers = group.get("hooks")
            if not isinstance(handlers, list) or not handlers:
                raise ValueError("invalid hook handlers")
            for handler_index, handler in enumerate(handlers):
                if not isinstance(handler, dict):
                    raise ValueError("invalid hook handler")
                identity = _normalized_command_identity(event, group, handler)
                canonical = json.dumps(
                    identity,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                key = (
                    f"{source}:{HOOK_EVENT_LABELS[event]}:"
                    f"{group_index}:{handler_index}"
                )
                expected[key] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return expected


# Exact verified release, not a compatibility range.
HOOK_TRUST_SCHEMES = {
    "0.164.0": "declaration-and-content-v1",
}

CODEX_VERSION_TIMEOUT = 2.0
PLUGIN_FINGERPRINT_BUDGET = 5.0
FORWARDER_MARKER = b"# codex-privacy-hud forwarder"


def hook_trust_scheme(version: str | None) -> str | None:
    if os.name != "posix":
        return None
    return HOOK_TRUST_SCHEMES.get(version or "")


def _official_codex_candidate() -> Path | None:
    seen: set[Path] = set()
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory or ".") / "codex"
        try:
            resolved = candidate.resolve(strict=True)
            if resolved in seen:
                continue
            seen.add(resolved)

            # Known installer-owned patched binary layout.
            parts = resolved.parts
            if any(
                parts[index:index + 2] == ("share", PLUGIN_NAME)
                for index in range(len(parts) - 1)
            ):
                continue
            if not os.access(resolved, os.X_OK):
                continue

            fd = os.open(
                resolved,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
            )
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    continue
                header = os.read(fd, 512)
            finally:
                os.close(fd)
            if any(
                line.startswith(FORWARDER_MARKER)
                for line in header.splitlines()[:2]
            ):
                continue
            return resolved
        except (OSError, RuntimeError, ValueError):
            continue
    return None


def _probe_official_codex_version() -> str | None:
    if os.name != "posix":
        return None
    executable = _official_codex_candidate()
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [str(executable), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=CODEX_VERSION_TIMEOUT,
            check=False,
            cwd="/",
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": "/dev/null",
                "CODEX_HOME": "/dev/null",
                "LC_ALL": "C",
                "LANG": "C",
            },
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or len(result.stdout) > 256:
        return None
    match = re.fullmatch(
        rb"codex-cli ((?:0|[1-9][0-9]*)\."
        rb"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))\r?\n?",
        result.stdout,
    )
    return match.group(1).decode("ascii") if match else None


def official_codex_version() -> str | None:
    """Probe the selected non-forwarder executable; never cache across runs."""
    return _probe_official_codex_version()


def trust_config_path() -> Path:
    """Match 0.164's default user-layer identity, without resolving the file."""
    override = os.environ.get("CODEX_HOME")
    if override:
        # Codex checks the literal override; it does not expand '~' here.
        directory = Path(override).resolve(strict=True)
        if not directory.is_dir():
            raise ValueError("invalid Codex home")
    else:
        directory = Path(os.path.abspath(Path.home() / ".codex"))
    return directory / CONFIG_FILENAME


def legacy_trust_path(config_file: Path, plugin_id: str) -> Path:
    if os.name != "posix" or not config_file.is_absolute():
        raise ValueError("unsupported config path identity")
    digest = hashlib.sha256()
    for part in (
        os.fsencode(str(config_file)),
        plugin_id.encode("utf-8"),
    ):
        digest.update(len(part).to_bytes(8, "little"))
        digest.update(part)
    return config_file.parent / ".hook-trust" / digest.hexdigest()


def read_legacy_baseline(config_file: Path, plugin_id: str) -> str | None:
    path = legacy_trust_path(config_file, plugin_id)
    try:
        with path.open("rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return None
    # Rust read_to_string is strict UTF-8 and does not strip whitespace.
    return raw.decode("utf-8")


def _excluded_bundle_name(name: str) -> bool:
    try:
        text = os.fsencode(name).decode("utf-8")
    except UnicodeDecodeError:
        return False
    return (
        text in {"__pycache__", ".venv"}
        or text.endswith(".pyc")
        or text.endswith(".egg-info")
    )


def plugin_content_hash(
    root: Path, *, budget: float = PLUGIN_FINGERPRINT_BUDGET,
) -> str:
    """Codex 0.164 POSIX fingerprint; cancellation is cooperative."""
    if os.name != "posix":
        raise ValueError("unsupported path encoding")

    deadline = time.monotonic() + budget

    def check_deadline() -> None:
        if time.monotonic() >= deadline:
            raise TimeoutError("bundle fingerprint budget exceeded")

    check_deadline()
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("plugin root is not a directory")

    digest = hashlib.sha256(b"codex-plugin-bundle-v1")
    pending = [root]
    while pending:
        check_deadline()
        path = pending.pop()
        relative = path.relative_to(root)
        if relative.parts and _excluded_bundle_name(path.name):
            continue

        name = b"" if path == root else os.fsencode(str(relative))
        digest.update(len(name).to_bytes(8, "little"))
        digest.update(name)
        metadata = path.lstat()

        if stat.S_ISDIR(metadata.st_mode):
            digest.update(b"directory")
            entries = []
            with os.scandir(path) as iterator:
                for entry in iterator:
                    check_deadline()
                    entries.append(Path(entry.path))
            entries.sort(key=lambda entry: os.fsencode(entry.name))
            pending.extend(reversed(entries))
        elif stat.S_ISREG(metadata.st_mode):
            digest.update(b"file")
            length = metadata.st_size
            digest.update(length.to_bytes(8, "little"))
            check_deadline()
            fd = os.open(
                path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
            )
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode):
                    raise ValueError("unsupported plugin entry")
                remaining = length + 1
                total = 0
                while remaining:
                    check_deadline()
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        break
                    total += len(chunk)
                    remaining -= len(chunk)
                    digest.update(chunk)
                if total != length:
                    raise ValueError("plugin file changed while fingerprinting")
            finally:
                os.close(fd)
        else:
            raise ValueError("unsupported plugin entry")

    check_deadline()
    return "sha256:" + digest.hexdigest()


class HookState(NamedTuple):
    trusted_hash: str | None = None
    trusted_content_hash: str | None = None
    enabled: bool | None = None


def read_hook_states(
    expected_keys: set[str],
) -> dict[str, HookState]:
    """Project only this plugin's exact expected keys; never return raw TOML."""
    try:
        with trust_config_path().open("rb") as handle:
            document = tomllib.load(handle)
    except FileNotFoundError:
        return {}

    hooks = document.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("invalid hook state")
    states = hooks.get("state", {})
    if not isinstance(states, dict):
        raise ValueError("invalid hook state")

    selected: dict[str, HookState] = {}
    for key in expected_keys:
        entry = states.get(key)
        if entry is None:
            continue
        if not isinstance(entry, dict):
            raise ValueError("invalid hook state")
        declaration = entry.get("trusted_hash")
        content = entry.get("trusted_content_hash")
        enabled = entry.get("enabled")
        if declaration is not None and not isinstance(declaration, str):
            raise ValueError("invalid hook state")
        if content is not None and not isinstance(content, str):
            raise ValueError("invalid hook state")
        if enabled is not None and type(enabled) is not bool:
            raise ValueError("invalid hook state")
        selected[key] = HookState(declaration, content, enabled)
    return selected


def plugin_data_root() -> Path:
    """`$CODEX_HOME/plugins/data/` — where Codex puts every plugin's
    `$PLUGIN_DATA` directory."""
    return codex_home() / "plugins" / "data"


def plugin_cache_root() -> Path:
    """`$CODEX_HOME/plugins/cache/` — where Codex keeps the *copy* of each
    plugin it actually executes (`<marketplace>/<plugin>/<version>/`), which
    is why an edited file in a checkout is not what runs."""
    return codex_home() / "plugins" / "cache"


def cached_plugin_parent(
        bundle: Path, *, allow_missing: bool = False) -> Path | None:
    """The canonical cache parent of a release bundle, or None.

    Version names are three ASCII nonnegative integers separated by dots,
    with no leading zeros except zero itself. Existing bundles require a
    canonical bundled bootstrap. For holder recognition, allow_missing
    also accepts any absent version directory of that form beneath an
    existing canonical plugin parent, even if it never existed or was
    installed. No installation or selection history is checked. An
    incomplete existing bundle or a symlink is not an absent version
    directory.

    This describes cache placement, not authentication of same-user code.
    The configured cache root may itself resolve through a user alias.
    """
    try:
        root = plugin_cache_root().resolve(strict=True)
        path = Path(bundle)
        if not path.is_absolute() or path.resolve(strict=False) != path:
            return None
        relative = path.relative_to(root)
        if len(relative.parts) != 3:
            return None
        _marketplace, plugin, version = relative.parts
        if plugin != PLUGIN_NAME:
            return None
        if re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\."
                        r"(0|[1-9][0-9]*)", version) is None:
            return None
        if path.parent.resolve(strict=True) != path.parent:
            return None
        try:
            path.lstat()
        except FileNotFoundError:
            return path.parent if allow_missing else None
        bootstrap = path / "scripts" / "runtime.py"
        if (not bootstrap.is_file()
                or bootstrap.resolve(strict=True) != bootstrap):
            return None
        return path.parent
    except (OSError, RuntimeError, ValueError):
        return None


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
    """The ledger every surface opens, given an already-resolved
    `$PLUGIN_DATA`. `runtime.ledger_path` is the resolver that decides
    *which* `$PLUGIN_DATA` first.

    Two answers, because a machine can be in two states (#66). Once the
    historical pathname is the directory fence, the ledger is the active
    store beside it; until then it is still where it always was. The two
    never coexist -- `runtime_storage.prepare_storage` retires one as it
    publishes the other -- so this is a question about which state the
    installation is in, not a search.

    A file at `ledger.db` is therefore never ignored, and no empty
    `ledger/active.db` is ever conjured beside one: inventing a database
    nobody wrote is how a surface comes to report a clean session that
    never happened.
    """
    root = Path(data_dir)
    fence = root / LEDGER_NAME
    if fence.is_dir() and not fence.is_symlink():
        return root / ACTIVE_DIR_NAME / ACTIVE_DB_NAME
    return fence


def socket_path(data_dir) -> Path:
    """`$PLUGIN_DATA/daemon.sock`, given an already-resolved data directory.

    The one derivation: `daemon.main`, `doctor` and the session-query client
    (`session_services`, via `runtime_client.query_active_sessions`) all call
    this, so none of them depends on `daemon` importing.
    """
    return Path(data_dir) / SOCKET_NAME
