"""Where a value entered the session from.

`events.source` used to hold a fixed label -- `tool input` on every
outbound call, the tool name or `user prompt` on the way in -- so a rule
could not name a source at all (#38). This module is the one place that
reads a real origin out of a tool call, and `#36`'s read-blocking will
share it rather than grow a second parser that drifts from this one.

**Arguments are never part of an origin (I1).** `events.source` is
persisted, rendered in the audit and served to the browser UI, and command
lines routinely carry credentials (`curl -u admin:hunter2`, `psql
postgres://u:pw@h`). A program name carries none, so that is all this
module ever takes from a command it cannot read a path out of.

Pure and stdlib-only, like `budget.py`: no ledger, no engine, no I/O. It
answers one question and holds no state.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass
from enum import Enum

#: Programs whose first non-flag argument is a file they read. A command
#: that writes (`cp`, `tee`, `install`) is deliberately absent: its output
#: is not that file's contents, so the file is not where the data came from.
READ_VERBS = frozenset({
    "cat", "head", "tail", "less", "more", "bat", "grep", "egrep", "rg",
    "strings", "xxd", "od", "jq", "yq",
})

#: The subset of `READ_VERBS` whose first non-flag token is a pattern or
#: filter expression, not the file (`grep PATTERN FILE`, `jq FILTER FILE`).
#: For these, the path is the *second* non-flag token.
PATTERN_THEN_PATH_VERBS = frozenset({"grep", "egrep", "rg", "jq", "yq"})

#: Programs whose first non-flag token is a subcommand worth keeping: `git
#: log` and `git status` are different origins, while `git` alone says
#: little. The subcommand is a fixed verb, never a path or a value.
SUBCOMMAND_PROGRAMS = frozenset({
    "git", "gh", "docker", "kubectl", "npm", "pnpm", "yarn", "pip", "cargo",
    "brew", "aws", "gcloud", "terraform", "systemctl",
})

#: Tool-input keys that name a file a tool read, in the order they are tried.
PATH_KEYS = ("file_path", "path", "notebook_path")


class OriginKind(Enum):
    """Which kind of origin a value came from.

    An `Enum` for `Cost`'s reason: the engine branches on it, the ledger
    persists its `value`, and the UI decides whether a row can be blocked
    from it. There is deliberately no `TOOL` member -- when neither a path
    nor a command can be read, `extract_origin` returns `None`, because "no
    origin" and "an origin that happens to be a tool name" are different
    facts and must not render as the same thing.
    """

    PATH = "path"
    COMMAND = "command"


@dataclass(frozen=True)
class Origin:
    """Where a value entered the session from.

    Frozen for `DetectorProfile`'s reason: an `Origin` is stored as a value
    in the engine's per-session taint map and read back later, and a mutable
    one could stop being what was recorded.
    """

    value: str
    kind: OriginKind


def _tokens(command: str) -> list[str] | None:
    """Split `command`, or `None` when it cannot be split.

    `shlex.split` raises `ValueError` on unbalanced quotes. That one
    exception is caught here, where it is raised, and becomes "no origin" --
    never a guess. `detect/shell.py::_tokens` falls back to `command.split()`
    for the same input because a missed destination there fails open on a
    boundary decision; here a wrong origin would be attributed to a file the
    data never came from, so this returns nothing instead.
    """
    try:
        return shlex.split(command)
    except ValueError:
        return None


def _first_non_flag(tokens: list[str], skip: int = 0) -> str | None:
    """The first non-flag token in `tokens`, skipping the first `skip` of them.

    `skip` exists for `grep`/`jq`-family verbs: their first non-flag token is
    a pattern or filter expression, not a file, so the path is the one after.
    """
    seen = 0
    for token in tokens:
        if token.startswith("-"):
            continue
        if seen < skip:
            seen += 1
            continue
        return token
    return None


def extract_origin(tool_name: str, tool_input: dict) -> Origin | None:
    """The origin of whatever this tool call produced, or `None`.

    `None` means "this call's output has no origin we can name", and the
    caller keeps the tool name in `source` and offers no rule for the row.
    """
    if not isinstance(tool_input, dict):
        return None

    for key in PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return Origin(value=value, kind=OriginKind.PATH)

    if tool_name != "Bash":
        return None

    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None

    tokens = _tokens(command)
    if not tokens:
        return None

    program = tokens[0].rsplit("/", 1)[-1]
    rest = tokens[1:]

    if program in READ_VERBS:
        skip = 1 if program in PATTERN_THEN_PATH_VERBS else 0
        path = _first_non_flag(rest, skip=skip)
        if path is not None:
            return Origin(value=path, kind=OriginKind.PATH)

    if program in SUBCOMMAND_PROGRAMS:
        subcommand = _first_non_flag(rest)
        if subcommand is not None:
            return Origin(value=f"{program} {subcommand}",
                          kind=OriginKind.COMMAND)

    return Origin(value=program, kind=OriginKind.COMMAND)
