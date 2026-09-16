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

That holds only if the path it reads out is really a path, and the first
version of this module read "does not start with `-`" as "positional" --
so `grep -A 3 sk-proj-… .env` returned the key as the origin and wrote it
to `events.source`. Two defences now stand between an argument and the
ledger, because either alone has a gap: `VALUE_OPTIONS` knows which
options take a separated value (precise, but a table can go stale against
a real command line), and `_looks_like_a_path` rejects a candidate that is
not shaped like a file (blunt, but it does not need to have heard of the
option). A candidate either defence doubts is not a path, and the call
falls through to the program name -- the spec's "never guess" rule, whose
safe answer is a COMMAND origin, never a wrong PATH one.

Pure and stdlib-only, like `budget.py`: no ledger, no engine, no I/O. It
answers one question and holds no state.
"""
from __future__ import annotations

import re
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

#: Options that take their value as a SEPARATE token, per program, with how
#: many tokens each swallows (`jq --arg NAME VALUE` takes two).
#:
#: Without this, `grep -A 3 <secret> .env` reads `3` as the pattern and the
#: secret as the file, and `head -n 5 f` reads `5` as the file -- an
#: argument, and possibly a credential, straight into `events.source`
#: (I1). Attached forms (`-n5`, `--lines=5`) carry their value inside the
#: token and swallow nothing, so they are not listed and need not be.
#:
#: The table errs towards listing: marking a boolean flag as value-taking
#: loses a path (the origin degrades to the program name), while missing a
#: value-taking one could surface its value. `_looks_like_a_path` is the
#: second line of defence for whatever a real command line adds that this
#: table has not heard of.
_GREP_VALUE_OPTIONS = {
    "-A": 1, "-B": 1, "-C": 1, "-m": 1, "-e": 1, "-f": 1, "-d": 1, "-D": 1,
    "--after-context": 1, "--before-context": 1, "--context": 1,
    "--max-count": 1, "--regexp": 1, "--file": 1, "--devices": 1,
    "--directories": 1, "--binary-files": 1, "--color": 1, "--colour": 1,
    "--label": 1, "--include": 1, "--exclude": 1, "--exclude-dir": 1,
    "--exclude-from": 1, "--group-separator": 1,
}
_HEAD_TAIL_VALUE_OPTIONS = {
    "-n": 1, "-c": 1, "-s": 1, "--lines": 1, "--bytes": 1, "--sleep-interval": 1,
    "--pid": 1, "--max-unchanged-stats": 1,
}
VALUE_OPTIONS: dict[str, dict[str, int]] = {
    "grep": _GREP_VALUE_OPTIONS,
    "egrep": _GREP_VALUE_OPTIONS,
    "rg": {
        **_GREP_VALUE_OPTIONS,
        "-g": 1, "--glob": 1, "--iglob": 1, "-t": 1, "--type": 1, "-T": 1,
        "--type-not": 1, "-r": 1, "--replace": 1, "-j": 1, "--threads": 1,
        "-M": 1, "--max-columns": 1, "--max-depth": 1, "--max-filesize": 1,
        "-E": 1, "--encoding": 1, "--pre": 1, "--sort": 1, "--sortr": 1,
        "--colors": 1, "--engine": 1, "--ignore-file": 1, "--path-separator": 1,
    },
    "head": _HEAD_TAIL_VALUE_OPTIONS,
    "tail": _HEAD_TAIL_VALUE_OPTIONS,
    "jq": {
        "--arg": 2, "--argjson": 2, "--slurpfile": 2, "--rawfile": 2,
        "-f": 1, "--from-file": 1, "--indent": 1, "--jsonargs": 0,
    },
    "yq": {
        "-o": 1, "--output-format": 1, "-I": 1, "--indent": 1, "-p": 1,
        "--input-format": 1, "-f": 1, "--from-file": 1, "--split-exp": 1,
    },
    "bat": {
        "-l": 1, "--language": 1, "--theme": 1, "--style": 1, "-r": 1,
        "--line-range": 1, "-H": 1, "--highlight-line": 1, "--paging": 1,
        "--pager": 1, "--wrap": 1, "--terminal-width": 1, "--tabs": 1,
        "-m": 1, "--map-syntax": 1,
    },
    "strings": {"-n": 1, "-t": 1, "-e": 1, "-T": 1, "--bytes": 1,
                "--radix": 1, "--encoding": 1, "--target": 1},
    "xxd": {"-c": 1, "-g": 1, "-l": 1, "-s": 1, "-o": 1},
    "od": {"-A": 1, "-j": 1, "-N": 1, "-t": 1, "-w": 1, "-S": 1,
           "--address-radix": 1, "--skip-bytes": 1, "--read-bytes": 1,
           "--format": 1, "--width": 1, "--strings": 1},
    "less": {"-x": 1, "-j": 1, "-k": 1, "-o": 1, "-O": 1, "-P": 1, "-b": 1,
             "-h": 1, "-y": 1, "-z": 1, "-#": 1, "-T": 1},
    "more": {"-n": 1},
    # Subcommand programs: the same shift, one window earlier. `git -C
    # /srv/repo log` must not record "/srv/repo" as the subcommand, and
    # `kubectl -n prod get` must not record the namespace.
    "git": {"-C": 1, "-c": 1, "--git-dir": 1, "--work-tree": 1,
            "--namespace": 1, "--exec-path": 1},
    "gh": {"-R": 1, "--repo": 1},
    "docker": {"-H": 1, "--host": 1, "--context": 1, "--config": 1,
               "--log-level": 1},
    "kubectl": {"-n": 1, "--namespace": 1, "--context": 1, "--cluster": 1,
                "--kubeconfig": 1, "--user": 1, "-s": 1, "--server": 1,
                "--token": 1, "--as": 1},
    "npm": {"--prefix": 1, "--registry": 1, "-w": 1, "--workspace": 1},
    "pnpm": {"--prefix": 1, "--registry": 1, "-w": 1, "--workspace": 1,
             "-C": 1, "--dir": 1},
    "yarn": {"--cwd": 1, "--registry": 1},
    "pip": {"--index-url": 1, "-i": 1, "--extra-index-url": 1, "--cache-dir": 1,
            "--proxy": 1},
    "cargo": {"-Z": 1, "--config": 1, "--color": 1, "--manifest-path": 1},
    "brew": {},
    "aws": {"--profile": 1, "--region": 1, "--endpoint-url": 1,
            "--ca-bundle": 1, "--cli-read-timeout": 1, "--output": 1},
    "gcloud": {"--project": 1, "--account": 1, "--configuration": 1,
               "--format": 1},
    "terraform": {"-chdir": 1},
    "systemctl": {"-H": 1, "--host": 1, "-M": 1, "--machine": 1, "-t": 1,
                  "--type": 1, "--state": 1},
}

#: Options through which a pattern verb takes its pattern. With one of these
#: present the pattern is no longer the first positional, so the file is
#: (`grep -e KEY .env`), and the usual one-token skip must not apply.
PATTERN_OPTIONS = frozenset({"-e", "--regexp", "-f", "--file", "--from-file"})

#: A subcommand is a fixed lowercase verb (`log`, `pr`, `s3`). Anything else
#: -- a path, a URL, a namespace, a value -- is not one, and is not recorded.
_SUBCOMMAND = re.compile(r"[a-z][a-z0-9_-]*\Z")

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


def _split_arguments(tokens: list[str],
                     value_options: dict[str, int]) -> tuple[list[str], set[str]]:
    """`(positional tokens, option names seen)`.

    A token is positional only if it is neither an option nor an option's
    separated value. Reading "not starting with `-`" as "positional" was
    what let `grep -A 3 <secret> .env` return the secret: `3` took the
    pattern's place and the secret took the file's.
    """
    positionals: list[str] = []
    options: set[str] = set()
    pending = 0
    for token in tokens:
        if pending:
            pending -= 1
            continue
        if token.startswith("-"):
            name, separator, _ = token.partition("=")
            options.add(name)
            if not separator:  # `--opt=value` carries its value already
                pending = value_options.get(name, 0)
            continue
        positionals.append(token)
    return positionals, options


def _looks_like_a_path(token: str) -> bool:
    """Whether `token` is shaped like a file a command was told to read.

    The second line of defence behind `VALUE_OPTIONS`, and the one that
    holds when a real command line uses an option the table has not heard
    of. A path a user would recognise carries a separator or a dot
    (`.env`, `config/.env`, `/etc/passwd`, `a.json`); an option value that
    slipped through usually carries neither (`5`, `20`, `hunter2`,
    `sk-proj-...`). The asymmetry is deliberate: a rejected real path costs
    a `COMMAND` origin and a button the user does not get, while an
    accepted option value costs an argument -- possibly a credential -- in
    `events.source`, which is persisted, served and rendered (I1). So a
    bare `cat Makefile` yields `cat`: the spec's "never guess" rule means a
    doubtful candidate is not a path.
    """
    return token.startswith("~") or "/" in token or "." in token


def origin_phrase(value: str, kind: OriginKind) -> str:
    """How user-facing copy names an origin of each kind.

    One helper rather than a literal per call site, because the two kinds
    read differently and a hardcoded "read from" turns a command origin
    into a file that does not exist ("read from `git log`"). `render`'s
    button (`[ Block values read from .env ]`, ``[ Block values from `git
    log` output ]``) and the engine's deny message are the same sentence
    about the same fact, so they take their wording from here and cannot
    drift apart.
    """
    if kind is OriginKind.PATH:
        return f"read from {value}"
    return f"from `{value}` output"


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
    positionals, options = _split_arguments(tokens[1:],
                                            VALUE_OPTIONS.get(program, {}))

    if program in READ_VERBS:
        # `grep PATTERN FILE`: the pattern holds the first positional, so
        # the file is the next one -- unless the pattern came through
        # `-e`/`-f`, in which case the file is the first after all.
        skip = int(program in PATTERN_THEN_PATH_VERBS
                   and not (options & PATTERN_OPTIONS))
        if len(positionals) > skip and _looks_like_a_path(positionals[skip]):
            return Origin(value=positionals[skip], kind=OriginKind.PATH)

    if program in SUBCOMMAND_PROGRAMS and positionals:
        if _SUBCOMMAND.match(positionals[0]):
            return Origin(value=f"{program} {positionals[0]}",
                          kind=OriginKind.COMMAND)

    return Origin(value=program, kind=OriginKind.COMMAND)
