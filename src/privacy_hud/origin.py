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

import os
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum

from . import codex

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

#: Options that take NO value, per program. Needed for the same reason
#: `VALUE_OPTIONS` is: a token following an option is trustworthy as a
#: positional only when we know the option did not take it. Knowing an option
#: is boolean says exactly that, so `tail -f app.log` keeps its file while
#: `tail --format <secret> app.log` does not (see `_Positional.trusted`).
#: Unlisted options are treated as doubtful, which costs an origin — never a
#: leak.
BOOLEAN_OPTIONS: dict[str, frozenset[str]] = {
    "grep": frozenset({
        "-i", "-v", "-n", "-r", "-R", "-l", "-L", "-c", "-w", "-x", "-q",
        "-s", "-a", "-I", "-o", "-E", "-F", "-G", "-P", "-z", "-H", "-h",
        "--ignore-case", "--invert-match", "--line-number", "--recursive",
        "--files-with-matches", "--files-without-match", "--count",
        "--word-regexp", "--line-regexp", "--quiet", "--silent",
        "--no-filename", "--with-filename", "--only-matching",
        "--extended-regexp", "--fixed-strings", "--basic-regexp",
        "--perl-regexp", "--null-data", "--text", "--binary-files",
    }),
    "head": frozenset({"-q", "-v", "-z", "--quiet", "--silent", "--verbose",
                       "--zero-terminated"}),
    "tail": frozenset({"-f", "-F", "-q", "-v", "-z", "--follow", "--quiet",
                       "--silent", "--verbose", "--zero-terminated",
                       "--retry"}),
    "cat": frozenset({"-n", "-b", "-s", "-E", "-T", "-A", "-v", "-e", "-t",
                      "-u", "--number", "--number-nonblank",
                      "--squeeze-blank", "--show-ends", "--show-tabs",
                      "--show-all", "--show-nonprinting"}),
    "less": frozenset({"-N", "-S", "-R", "-F", "-X", "-i", "-I", "-M", "-m",
                       "-n", "-q", "-Q", "-r", "-s", "-u", "-U", "-w", "-G"}),
    "more": frozenset({"-d", "-f", "-l", "-p", "-c", "-s", "-u"}),
    "bat": frozenset({"-p", "-A", "-n", "-f", "--plain", "--show-all",
                      "--number", "--force-colorization", "--list-themes",
                      "--no-config"}),
    "jq": frozenset({"-r", "-c", "-n", "-s", "-e", "-a", "-S", "-j", "-M",
                     "-C", "--raw-output", "--compact-output", "--null-input",
                     "--slurp", "--exit-status", "--sort-keys", "--tab",
                     "--join-output", "--ascii-output", "--raw-input", "-R",
                     "--monochrome-output", "--color-output"}),
    "yq": frozenset({"-r", "-n", "-e", "-N", "-P", "-C", "-M", "-i",
                     "--raw-output", "--null-input", "--exit-status",
                     "--no-colors", "--colors", "--inplace"}),
    "strings": frozenset({"-a", "-f", "-o", "-v", "--all", "--print-file-name",
                          "--help", "--version"}),
    "xxd": frozenset({"-b", "-E", "-i", "-p", "-r", "-u"}),
    "od": frozenset({"-a", "-b", "-c", "-d", "-f", "-i", "-l", "-o", "-s",
                     "-x", "-v"}),
    "rg": frozenset({
        "-i", "-v", "-n", "-N", "-l", "-c", "-w", "-x", "-q", "-s", "-S",
        "-F", "-L", "-p", "-z", "-u", "-uu", "-uuu", "--ignore-case",
        "--invert-match", "--line-number", "--no-line-number",
        "--files-with-matches", "--count", "--word-regexp", "--line-regexp",
        "--quiet", "--case-sensitive", "--smart-case", "--fixed-strings",
        "--hidden", "--no-ignore", "--follow", "--search-zip", "--json",
    }),
    "egrep": frozenset({"-i", "-v", "-n", "-r", "-l", "-c", "-w", "-x", "-q",
                        "-o", "-H", "-h"}),
}

#: Options through which a pattern verb takes its pattern. With one of these
#: present the pattern is no longer the first positional, so the file is
#: (`grep -e KEY .env`), and the usual one-token skip must not apply.
PATTERN_OPTIONS = frozenset({"-e", "--regexp", "-f", "--file", "--from-file"})

#: A subcommand is a fixed lowercase verb (`log`, `pr`, `s3`). Anything else
#: -- a path, a URL, a namespace, a value -- is not one, and is not recorded.
_SUBCOMMAND = re.compile(r"[a-z][a-z0-9_-]*\Z")

#: Tool-input keys that name a file a tool read, in the order they are tried.
#:
#: **Inferred, not evidenced.** No Codex build is known to send any of these:
#: `codex.SHELL_TOOL` records why — Codex has no native file-read tool, and
#: its hook schema declares `tool_input` as `any`, so it pins no per-tool key
#: names at all. These three are the conventional spellings, kept because a
#: tool that does send one is read for free and the alternative is guessing
#: from an arbitrary dict. On Codex today this loop is expected to be inert;
#: `source` falling back to the bare tool name is the evidenced path.
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

    `evaluated_path` (#54 Phase 4) is the literal path operand the guard
    evaluated, before `value`'s home collapse, set only when that operand
    is the one file read with nothing left to shell interpretation. It is
    transient input to a file identity: excluded from equality and `repr`,
    so enforcement semantics and anything printed are unchanged, and never
    persisted.
    """

    value: str
    kind: OriginKind
    evaluated_path: str | None = field(default=None, compare=False,
                                       repr=False)


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


#: `--`: everything after it is positional, however it is spelled.
END_OF_OPTIONS = "--"


def _collapse_home(path: str) -> str:
    """`/Users/jordan/project/.env` -> `~/project/.env`.

    `runtime.display_path`'s reason, applied one layer deeper: an origin is
    persisted in `events.source`, served by the local UI API and printed in
    the audit and on a rule button, so the account name must not ride into
    the ledger on a path. A masked path exemplar already reads
    `/Users/•••/app.log`; an origin that kept the name verbatim would be the
    one place it survived.

    Only YOUR home collapses. `/Users/alice/Downloads/patient-intake.csv`
    stays as it is -- known limit 7 calls that exact row one you want, and
    this module does not decide what is sensitive, only what the origin is.

    `runtime.display_path` is not reused because this module is a stdlib-only
    leaf (`budget.py`'s rule) and `runtime` is not: importing it here to save
    four lines would drag the whole runtime into the detection path.
    """
    home = os.environ.get("HOME") or ""
    if not home or not path.startswith(home):
        return path
    rest = path[len(home):]
    if rest and not rest.startswith("/"):
        return path  # `/Users/jordanish/...` merely shares a prefix
    return "~" + rest


def _attached_short_value(token: str, value_options: dict[str, int]) -> bool:
    """Whether `token` is a short option carrying its value attached.

    `head -n5 config/.env` writes the `5` into the option itself, so the
    option takes nothing from the tokens after it and the file that follows
    stays trustworthy. Long options do this with `=`, which is handled where
    the token is split.
    """
    return (len(token) > 2 and token[0] == "-" and token[1] != "-"
            and token[:2] in value_options)


@dataclass(frozen=True)
class _Positional:
    """One positional token, and whether it can be trusted as one.

    `trusted` is False for a token that arrived straight after an option
    `VALUE_OPTIONS` does not know. Such a token is either a real positional
    (the option took no value) or that option's value (it did) — and nothing
    in the command line says which. `_looks_like_a_path` cannot separate them
    either: a secret carrying `/` or `.` passes it, which is how
    `tail --format wJalrXUtnFEMI/K7MDENG/... /var/log/app.log` put an AWS key
    in `events.source`. The table can never list every option of every
    program, so the doubt has to be carried rather than resolved.
    """

    value: str
    trusted: bool


def _split_arguments(tokens: list[str],
                     value_options: dict[str, int],
                     boolean_options: frozenset[str] = frozenset(),
                     ) -> tuple[list[_Positional], set[str]]:
    """`(positional tokens, option names seen)`.

    A token is positional only if it is neither an option nor an option's
    separated value. Reading "not starting with `-`" as "positional" was
    what let `grep -A 3 <secret> .env` return the secret: `3` took the
    pattern's place and the secret took the file's.
    """
    positionals: list[_Positional] = []
    options: set[str] = set()
    pending = 0
    after_unknown_option = False
    end_of_options = False
    for token in tokens:
        if pending:
            pending -= 1
            continue
        if not end_of_options and token == END_OF_OPTIONS:
            end_of_options = True
            after_unknown_option = False
            continue
        if token.startswith("-") and not end_of_options:
            name, separator, _ = token.partition("=")
            options.add(name)
            if separator:  # `--opt=value` carries its value already
                after_unknown_option = False
            elif name in value_options:
                # A known value option consumes its own value, so whatever
                # follows that value is a real positional.
                pending = value_options[name]
                after_unknown_option = False
            elif name in boolean_options or _attached_short_value(
                    name, value_options):
                # Known to take nothing (`tail -f`), or a short option
                # carrying its value attached (`head -n5`): either way the
                # next token is the command's own, not this option's.
                after_unknown_option = False
            else:
                after_unknown_option = True
            continue
        positionals.append(_Positional(token, trusted=not after_unknown_option))
        after_unknown_option = False
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


#: Text the shell or the tool would still have expanded: a path carrying
#: one of these was not the file actually evaluated.
_UNEVALUATED_PATH = re.compile(r"[$`*?\[\]{}]|^~")

#: Characters that make a shell do more than split words: expansion,
#: globbing, operators, redirection, comments, history and escapes.
_SHELL_META = frozenset(";&|<>()$`\\*?[]{}~!#")

#: Options that make a read verb evaluate further files or directories
#: beside its operand -- recursion, pattern files, include/exclude lists,
#: preprocessors. With any of them the operand is not the one file read.
_MULTI_FILE_OPTIONS = frozenset({
    "-r", "-R", "--recursive", "-d", "--directories", "-D", "--devices",
    "-f", "--file", "--from-file", "--slurpfile", "--rawfile",
    "--exclude-from", "--include", "--exclude", "--exclude-dir",
    "--ignore-file", "--pre",
})

#: Read verbs that search a directory operand recursively by default, so
#: one operand never establishes one file.
_RECURSIVE_BY_DEFAULT = frozenset({"rg"})


def _literal_path(path: str) -> str | None:
    """`path` as the literal the guard evaluated, or None when it still
    holds something a shell or tool would expand, or a control character.
    Transient: never persisted, displayed or logged (I1)."""
    if (not path or _UNEVALUATED_PATH.search(path)
            or any(ord(c) < 0x20 or ord(c) == 0x7f for c in path)):
        return None
    return path


def _one_literal_operand(command: str, program: str,
                         positionals: list[_Positional], options: set[str],
                         skip: int) -> bool:
    """Whether the read verb's path operand is the only file it evaluates,
    with nothing left to shell interpretation. Conservative: a doubt means
    False, and the file identity then stays unresolved rather than being
    claimed from the first plausible operand."""
    if (program in _RECURSIVE_BY_DEFAULT
            or any(c in _SHELL_META or ord(c) < 0x20 or ord(c) == 0x7f
                   for c in command)
            or len(positionals) != skip + 1
            or not all(p.trusted for p in positionals)):
        return False
    value_options = VALUE_OPTIONS.get(program, {})
    known = BOOLEAN_OPTIONS.get(program, frozenset()) | set(value_options)
    for name in options:
        if name in _MULTI_FILE_OPTIONS:
            return False
        if name not in known and not _attached_short_value(name,
                                                           value_options):
            return False
    return True


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
            return Origin(value=_collapse_home(value), kind=OriginKind.PATH,
                          evaluated_path=_literal_path(value))

    # Only the shell tool carries a command to parse. `codex.SHELL_TOOL`
    # holds why that is also the only tool a *read* can arrive through.
    if tool_name != codex.SHELL_TOOL:
        return None

    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None

    tokens = _tokens(command)
    if not tokens:
        return None

    program = tokens[0].rsplit("/", 1)[-1]
    positionals, options = _split_arguments(
        tokens[1:], VALUE_OPTIONS.get(program, {}),
        BOOLEAN_OPTIONS.get(program, frozenset()))

    if program in READ_VERBS:
        # `grep PATTERN FILE`: the pattern holds the first positional, so
        # the file is the next one -- unless the pattern came through
        # `-e`/`-f`, in which case the file is the first after all.
        skip = int(program in PATTERN_THEN_PATH_VERBS
                   and not (options & PATTERN_OPTIONS))
        if len(positionals) > skip:
            candidate = positionals[skip]
            if candidate.trusted and _looks_like_a_path(candidate.value):
                evaluated = None
                if _one_literal_operand(command, program, positionals,
                                        options, skip):
                    evaluated = _literal_path(candidate.value)
                return Origin(value=_collapse_home(candidate.value),
                              kind=OriginKind.PATH,
                              evaluated_path=evaluated)

    if program in SUBCOMMAND_PROGRAMS and positionals:
        if positionals[0].trusted and _SUBCOMMAND.match(positionals[0].value):
            return Origin(value=f"{program} {positionals[0].value}",
                          kind=OriginKind.COMMAND)

    return Origin(value=program, kind=OriginKind.COMMAND)
