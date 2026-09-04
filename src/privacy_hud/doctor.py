# src/privacy_hud/doctor.py
"""`privacy-hud-doctor` — one command that answers "why did nothing happen?".

**Why this exists.** This plugin has seven independent moving parts and every
one of them fails *silently*. If no daemon is running the hooks still fire,
still exit 0, and still let Codex proceed — I6's fail-open is deliberately
invisible. The hook client now starts the daemon itself, which removes the
"you forgot to start it" failure and replaces it with a quieter one: the
client can only do that from an interpreter recorded by `privacy-hud-setup`
(`runtime.py`), because hooks run against Codex's minimal `PATH` where
`python3` is typically a system interpreter with no `transformers` — and a
daemon started there comes up with tier 3 dead while every other signal says
it is healthy. `PLUGIN_DATA` is assigned by Codex, not chosen by the
operator, and the daemon and the hook client must agree on it or every call
reports `unavailable`; finding that disagreement once cost a temporary
diagnostic logger injected into `hooks/handler.py`, a plugin reinstall, and a
live Codex session (auto-spawn makes that particular disagreement
impossible — the daemon inherits the hook's own `PLUGIN_DATA` — but a
hand-started daemon can still be pointed anywhere, so the check stays).
Tier 3's weights are ~2.8 GB of optional download, and without them
`ModelDetector.available` is `False`, the engine keeps working, and person /
address / date detection just stops. `transformers < 5.16` does not recognize
the `openai_privacy_filter` architecture at all, and torch is one of
*transformers'* extras so `pip install transformers` alone leaves tier 3
silently dead. And Codex installs a *copy* of the plugin into its own cache,
so an edited `hooks/handler.py` in the checkout is not what runs.

The user sees none of that. They see "nothing happened". Every check below
exists because that failure has actually been hit on this project.

**Why every failing check must carry a fix.** A diagnostic that only says
"broken" makes the operator re-derive the remedy that this module already
knows. `Check.fixes` is not decoration; a `FAIL` or `WARN` with an empty
`fixes` list is a bug in this file.

**Where the FAIL/WARN line is drawn.** `FAIL` (exit 1) means *nothing this
plugin promises can happen*: the interpreter is too old, `PLUGIN_DATA` is
unknown or missing so the daemon and hooks cannot meet, there is no usable
runtime receipt so nothing will ever start a daemon, the daemon is
unresponsive, or Codex has no installed copy to fire hooks from. `WARN`
(exit 0) means *degraded but genuinely working*: no model weights, no torch,
an old `transformers`, a stale installed copy, an empty ledger, or no daemon
running right now in a setup that starts one on the next hook. Tiers 0-2
still catch credentials, paths and shell destinations in every one of those
states, so a non-zero exit would be a lie about the product. Degradation is
never reported as a bare "warning", though — every tier-3 warning states the
consequence in the terms the user cares about: *names and addresses will not
be detected*.

**I1 — this module prints infrastructure, never content.** Counts, versions,
booleans, timestamps, and the paths of the plugin's own machinery. No prompt,
no finding, no masked exemplar, no `cwd`, no `model`, no session id, no
`data_type` breakdown. A doctor that dumps the ledger is a privacy incident,
so the ledger is read with two `COUNT(*)`s and a `MAX(started_at)` and
nothing else. Exception *messages* are withheld for the same reason (only the
class name is printed): a diagnostic must not become an exfiltration path for
whatever string an exception happened to capture. Printed paths have `$HOME`
contracted to `~`, which keeps the account name out of the report as well.

**I5 — nothing here implies recall.** The ledger check reports that sessions
were recorded, never that anything can be withdrawn.

**Read-only.** `sqlite3.connect()` creates a missing database file — the trap
`ambient.py` documents at length — so the ledger is opened through the
`file:...?mode=ro` URI, which cannot create the file and cannot run the
`CREATE TABLE IF NOT EXISTS` DDL (or the `chmod`) that `Ledger.__init__`
would. That is a deliberate deviation from `ambient.py`'s "open a `Ledger`"
approach: ambient needs `summary()`, the doctor needs three scalars, and a
diagnostic pointed at a user's real ledger should be *incapable* of writing to
it rather than merely careful not to.

The precise claim, since an approximate one would be the kind of overclaim
CLAUDE.md §5 forbids: no file this module names is ever created or modified.
Sqlite itself may materialize its own `-shm`/`-wal` sidecars beside a
WAL-mode ledger that no other connection currently holds open — that is
sqlite's locking bookkeeping, it contains none of our writes, it does not
occur while the daemon is running (the usual case, since the daemon holds the
connection), and the next clean close removes it. The ledger's own bytes are
untouched, which `tests/test_doctor.py` asserts on size and mtime.

**No colour, and no `NO_COLOR` handling to get wrong.** Same reasoning as
`ambient.py`: rather than add a colour layer and a switch to disable it, this
module emits none, which makes `NO_COLOR` respected by construction. The
status markers are plain ASCII (`[ OK ]`, `[WARN]`, `[FAIL]`, `[SKIP]`) so
the report survives a pipe, a log file, and a terminal with no Unicode.

**Why the daemon probe sends `PreCompact`.** A socket file outlives its
process, so `sock.exists()` proves nothing; only a round trip does. The probe
speaks the protocol `hooks/handler.py` owns (`{"v":1,"op":"event","payload":
...}`, newline-delimited) and picks the one event that cannot record or
change anything: `dispatch.py`'s own mapping table names `PreCompact`
explicitly as an event with no `Observation` defined, so `dispatch()` returns
`_allow()` — an empty dict — *before* it touches the ledger, creates a
session, builds an `Engine`, or runs a detector. No `session_id` is sent
either, so there is nothing for a future mapping to attribute the probe to.
A real event would have been a diagnostic that writes to the thing it is
diagnosing.

**Why this does not shell out to `codex plugin list`.** Two reasons, one of
them an invariant. I2 says this plugin makes no network calls except
`127.0.0.1`; `codex` is an API client that does, and a diagnostic belonging to
a tool whose whole claim is "nothing leaves your machine" must not launch a
process that phones home. Second, `codex` is frequently not on `PATH` where
this command is most useful (CI, a bare checkout, a venv-only install), so a
subprocess would turn "I cannot check" into "the check crashed". The
information wanted here — is a copy installed, which version, is it enabled,
does it match the checkout — is all directly observable on disk under
`$CODEX_HOME`, so it is read from there.

Stdlib only, like `hooks/handler.py` and `local_ui_server.py`. `transformers`
and `torch` are imported only to report their versions, and only inside the
check that reports them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sqlite3
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import runtime
from .local_ui_server import _ledger_path

# `runtime` is imported at module level, unlike `daemon` (see `_socket_path`
# for why that one is deferred), because it is stdlib-only and imports nothing
# else from this package: there is no chain through it that a broken detector
# stack or a missing `transformers` could take down. It is also the module
# whose literals this file must agree with, and a deferred import would make
# that agreement conditional.

# --------------------------------------------------------------------- #
# Pinned floors
# --------------------------------------------------------------------- #

#: Must track `requires-python` in pyproject.toml. Not read from the
#: installed distribution metadata at runtime: `Requires-Python` is a PEP 440
#: specifier string, parsing it correctly needs `packaging`, and a diagnostic
#: that reports the wrong floor is worse than one with a hardcoded right one.
#: `tests/test_doctor.py` reads pyproject.toml and asserts these agree, so the
#: duplication is checked rather than trusted.
MIN_PYTHON = (3, 11)

#: pyproject's `[detectors]` extra floors, restated. Both are load-bearing and
#: both are documented in README's Prerequisites: below 5.16 `transformers`
#: fails with "does not recognize this architecture" (the
#: `openai_privacy_filter` model type was not yet known to it), and 5.16
#: itself declares torch>=2.5.
MIN_TRANSFORMERS = (5, 16)
MIN_TORCH = (2, 5)

#: The plugin's name in `.claude-plugin/plugin.json`, which is also the
#: directory name Codex uses under `plugins/cache/<marketplace>/`.
PLUGIN_NAME = "codex-privacy-hud"

#: Socket file name inside `$PLUGIN_DATA`. See `_socket_path` for why this
#: literal exists here as well as in `daemon.py`.
SOCKET_NAME = "daemon.sock"

#: The harmless probe event. See the module docstring for why this one.
PROBE_EVENT = "PreCompact"

#: Default daemon round-trip budget. Same 2.0 s `hooks/handler.py` uses, so
#: "the doctor says the daemon answers in time" means the same thing the hook
#: client means by it.
DAEMON_TIMEOUT = 2.0

#: Files Codex actually executes out of its cached copy. These are what
#: staleness is measured against — not the whole tree, which in a working
#: checkout also carries `.git`, `__pycache__`, and a test suite that Codex
#: never reads and whose divergence means nothing.
PLUGIN_FILES = (
    ".claude-plugin/plugin.json",
    "hooks/hooks.json",
    "hooks/handler.py",
)

#: Directories compared file-by-file (recursively) on top of PLUGIN_FILES.
PLUGIN_TREES = ("skills",)

#: The exact file set README pins as "verified sufficient" for the pipeline —
#: deliberately not the whole 17 GB repo, which also ships ONNX exports and a
#: duplicate `original/` checkpoint this project never touches.
MODEL_FILES = (
    "config.json",
    "model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json",
    "viterbi_calibration.json",
)

#: HuggingFace's on-disk directory name for `openai/privacy-filter`.
MODEL_CACHE_DIRNAME = "models--openai--privacy-filter"

#: Said in the user's terms, not ours, wherever tier 3 is degraded. "Tier 3
#: unavailable" is jargon; "names and addresses will not be detected" is the
#: consequence, and CLAUDE.md §5 forbids letting the softer phrasing stand in
#: for it.
TIER3_CONSEQUENCE = (
    "Consequence: names and addresses will not be detected. Tiers 0-2 "
    "(credentials, file paths, shell destinations) still run."
)

OK = "OK"
WARN = "WARN"
FAIL = "FAIL"
SKIP = "SKIP"

_MARKERS = {OK: "[ OK ]", WARN: "[WARN]", FAIL: "[FAIL]", SKIP: "[SKIP]"}

#: Label column width. Wide enough for the longest check name below, so the
#: statuses and summaries line up into scannable columns.
_LABEL_WIDTH = 20


@dataclass
class Check:
    """One diagnosis: a name, a verdict, what was observed, and what to do.

    `fixes` is mandatory in spirit for anything that is not `OK`: see the
    module docstring. `summary` is the one-line right-hand column; `details`
    are indented continuation lines for anything that does not fit there.
    """

    name: str
    status: str
    summary: str
    details: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------- #
# small shared helpers
# --------------------------------------------------------------------- #

def _display_path(path) -> str:
    """`/Users/x/.codex/...` -> `~/.codex/...`.

    Two reasons. It keeps the report narrow enough to read, and it keeps the
    account name out of a report a user is likely to paste into a bug tracker
    — a small thing, but this is a privacy tool and the shell will expand `~`
    in the remedy lines anyway, so nothing is lost.
    """
    text = str(path)
    home = str(Path.home())
    if home and text.startswith(home):
        return "~" + text[len(home):]
    return text


#: Characters that need no shell quoting inside an unquoted word.
_SHELL_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "._-/+=:@,")


def _shell_path(path) -> str:
    """A path as it should appear *inside a command the user will paste*.

    `_display_path` is for prose; this is for the `-> ` remedy lines, which
    are meant to be copied into a shell. The difference is not cosmetic: this
    very project lives in a directory whose name contains spaces, so an
    unquoted `codex plugin marketplace add <repo>` silently becomes a
    three-argument command and the remedy fails in a way that reads as the
    tool's fault.

    Quoting a home-relative path is where this gets subtle, and the obvious
    answer is wrong. `~'/Desktop/a b'` does **not** expand: POSIX tilde
    expansion applies only when no character of the tilde-prefix is quoted,
    and with no unquoted slash in the word the whole thing is the
    tilde-prefix. Verified, not assumed. So a home-relative path that needs
    quoting is emitted as `"$HOME/..."` instead, which expands inside double
    quotes, tolerates spaces, and still keeps the account name out of the
    report (see `_display_path`). A path that needs no quoting stays bare and
    readable.
    """
    text = _display_path(path)
    if text.startswith("~"):
        rest = text[1:]
        if set(rest) <= _SHELL_SAFE:
            return "~" + rest
        escaped = rest
        for char in ("\\", '"', "$", "`"):
            escaped = escaped.replace(char, "\\" + char)
        return f'"$HOME{escaped}"'
    if text and set(text) <= _SHELL_SAFE:
        return text
    return "'" + text.replace("'", "'\\''") + "'"


def _version_tuple(text: str) -> tuple[int, ...]:
    """Leading numeric components of a version string, as a tuple.

    Deliberately tolerant of everything the wheels in this stack actually
    ship: `2.14.0+cpu`, `5.16.0.dev0`, `2.5.0a1`. Stops at the first
    non-numeric component rather than guessing an ordering for it, so a
    pre-release compares equal to its release for the purpose of a floor
    check. That is the right bias here: telling somebody on `5.16.0rc1` that
    they are below the 5.16 floor would send them chasing an upgrade they
    already have.
    """
    parts: list[int] = []
    for chunk in str(text).split("."):
        digits = ""
        for char in chunk:
            if char.isdigit():
                digits += char
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
        if len(digits) != len(chunk):
            break
    return tuple(parts)


def _format_version(parts) -> str:
    return ".".join(str(p) for p in parts)


def _humanize_age(seconds: float) -> str:
    """A wall-clock age a human can act on.

    Negative ages are reported as clock skew rather than normalized away: a
    ledger row stamped in the future is a real signal (a machine that slept,
    a container with a bad clock) and silently clamping it to "just now"
    would hide it.
    """
    if seconds < -60:
        return "timestamped in the future (clock skew?)"
    if seconds < 90:
        return "just now"
    minutes = int(seconds // 60)
    if minutes < 90:
        return f"{minutes} min ago"
    hours, minutes = divmod(minutes, 60)
    if hours < 36:
        return f"{hours}h {minutes}m ago"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h ago"


def _sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def _codex_home() -> Path:
    """Codex's state directory. `CODEX_HOME` wins, as it does for Codex."""
    override = os.environ.get("CODEX_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".codex"


def _repo_root() -> Path | None:
    """The source checkout this module was imported from, or `None`.

    Same `parents[2]` convention `local_ui_server._UI_DIR` uses. Returns
    `None` when the package was installed as a wheel into site-packages,
    where there is no `hooks/` tree to compare Codex's cached copy against —
    an honest "cannot check", never a manufactured verdict.
    """
    root = Path(__file__).resolve().parents[2]
    if (root / ".claude-plugin" / "plugin.json").is_file() and \
            (root / "hooks" / "hooks.json").is_file():
        return root
    return None


def _socket_path(data_dir: Path) -> Path:
    """`$PLUGIN_DATA/daemon.sock`, via `daemon.py`'s helper when it imports.

    The lazy, guarded import is the point. `daemon.py` pulls in `dispatch`,
    `engine`, `minimize` and the detector modules; a doctor is at its most
    valuable exactly when something in that chain is broken, and a
    module-level import would make an unrelated `ImportError` there take down
    the one command that could have explained it. So: use the canonical
    helper when it is available, and otherwise fall back to the same literal
    `hooks/handler.py` already hardcodes (it is stdlib-only and never imports
    this package, so that literal is independently load-bearing regardless).
    """
    try:
        from .daemon import _default_socket_path
        return Path(_default_socket_path(data_dir))
    except Exception:
        return data_dir / SOCKET_NAME


def _codex_data_candidates() -> list[Path]:
    """Directories under `$CODEX_HOME/plugins/data/` that look like ours.

    This is the answer to the single most expensive misconfiguration this
    project has hit: `PLUGIN_DATA` is assigned by Codex, and a daemon started
    against a different value listens on a socket no hook will ever connect
    to. Reading the real value off disk is what README tells the user to do
    (`ls ~/.codex/plugins/data/`); this does the same `ls` so the remedy line
    can name the exact directory instead of describing how to find it.
    """
    root = _codex_home() / "plugins" / "data"
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return []
    return [p for p in entries if p.is_dir() and PLUGIN_NAME in p.name]


# --------------------------------------------------------------------- #
# checks
# --------------------------------------------------------------------- #

def check_python(version_info=None) -> Check:
    """Interpreter against pyproject's `requires-python` floor.

    First because it is the cheapest and because everything below it is
    meaningless if it fails: the package uses `X | None` annotations and
    `tomllib`, so on an older interpreter the failure is an import error long
    before it is a privacy problem.
    """
    info = sys.version_info if version_info is None else version_info
    # Accept a 2- or 3-tuple so tests can pin a version without inventing a
    # micro number that plays no part in the comparison below.
    current = tuple(int(part) for part in tuple(info)[:3])
    shown = _format_version(current)
    floor = _format_version(MIN_PYTHON)

    if tuple(current[:2]) >= MIN_PYTHON:
        return Check("Python", OK, f"{shown} (requires >= {floor})")

    return Check(
        "Python", FAIL, f"{shown} is below the required {floor}",
        fixes=[f"Install Python {floor} or newer and recreate the venv: "
               f"python3 -m venv .venv && source .venv/bin/activate && "
               f"pip install -e \".[detectors]\""],
    )


def check_plugin_data() -> Check:
    """`PLUGIN_DATA`: is it set, does it exist, is it the one Codex assigns?

    Unset is a `FAIL`, not a warning, and the reason is the fallback rather
    than the absence: every component in this plugin defaults to `/tmp`
    (`_ledger_path`, `daemon.main`, `hooks/handler.py`), so an unset
    `PLUGIN_DATA` does not produce an error anywhere — it produces a daemon
    listening on `/tmp/daemon.sock`, a ledger in `/tmp`, and hooks talking to
    whichever of those Codex's own value does not match. Nothing the plugin
    promises can happen in that state, and the doctor cannot verify a setup
    whose location it does not know.

    A value that exists but differs from Codex's assigned directory is a
    `WARN`, not a `FAIL`: running the daemon against a scratch directory is a
    legitimate thing to do deliberately (the tests do it), so the honest
    report is "this works, and it is not what Codex will use".
    """
    raw = os.environ.get("PLUGIN_DATA")
    data_dir = _ledger_path().parent  # one convention, imported not re-derived
    candidates = _codex_data_candidates()

    def _export_fix() -> list[str]:
        if len(candidates) == 1:
            return [f"export PLUGIN_DATA={_shell_path(candidates[0])}"]
        if candidates:
            return ["Pick the directory Codex assigned to this plugin and "
                    "export it, e.g. "
                    f"export PLUGIN_DATA={_shell_path(candidates[0])}",
                    "Candidates found: " + ", ".join(
                        _display_path(c) for c in candidates)]
        return [f"ls {_shell_path(_codex_home() / 'plugins' / 'data')} "
                "and export the entry for this plugin as PLUGIN_DATA",
                "If that directory is empty, install the plugin first: "
                "codex plugin add codex-privacy-hud@codex-privacy-hud"]

    if raw is None:
        return Check(
            "PLUGIN_DATA", FAIL,
            "not set — every component falls back to /tmp",
            details=["Codex assigns this value; the daemon and the hook "
                     "client must both use the same one or every hook "
                     "reports unavailable."],
            fixes=_export_fix(),
        )

    if not data_dir.is_dir():
        return Check(
            "PLUGIN_DATA", FAIL,
            f"{_display_path(data_dir)} does not exist",
            details=["Set but pointing at nothing: the daemon would create "
                     "this directory, but Codex's hooks would still be "
                     "talking to the directory Codex itself assigned."],
            fixes=_export_fix(),
        )

    check = Check("PLUGIN_DATA", OK, _display_path(data_dir))
    resolved = data_dir.resolve()
    if candidates and resolved not in {c.resolve() for c in candidates}:
        check.status = WARN
        check.summary = f"{_display_path(data_dir)} (not Codex's directory)"
        check.details.append(
            "Codex assigns " + ", ".join(_display_path(c) for c in candidates)
            + " to this plugin, so that is where its hooks will look.")
        check.details.append(
            "Fine if you meant to point at a scratch directory; nothing "
            "recorded here will show up for a real Codex session.")
        check.fixes = _export_fix()
    return check


def check_ledger() -> Check:
    """Ledger presence, readability, session count, most recent session age.

    Opened `mode=ro` so this cannot create or migrate it — see the module
    docstring. Three scalars are read and nothing else (I1): how many
    sessions exist, how many events exist, and when the most recent session
    started. No session id, no `cwd`, no `model`, no per-type breakdown.

    "No ledger file" is a `WARN`, not a `FAIL`: it is the correct state of a
    fresh install, and the daemon creates it on the first session. What the
    warning buys is the distinction the user actually needs — between "not
    recorded yet" and "recorded, and this is how much" — which is exactly
    what `ambient.py --once` printing nothing cannot tell them.
    """
    path = _ledger_path()
    shown = _display_path(path)
    # Prose uses `shown`; the sqlite3 remedy below is a command the user
    # pastes, so it gets the shell-quoted form. See `_shell_path`.
    quoted = _shell_path(path)

    if not path.exists():
        return Check(
            "Ledger", WARN, f"no ledger yet at {shown}",
            details=["Expected before the first Codex session runs with the "
                     "daemon up; the daemon creates it."],
            fixes=["Start the daemon (see the Daemon check), then run one "
                   "Codex turn. The ledger appears on SessionStart."],
        )

    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return Check(
            "Ledger", FAIL, f"cannot open {shown} ({type(exc).__name__})",
            fixes=[f"Check the file with: sqlite3 {quoted} "
                   "'pragma integrity_check'",
                   "The ledger holds metadata only and is recreated on the "
                   "next session, so moving it aside is safe if it is "
                   "corrupt."],
        )

    try:
        sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        latest = conn.execute(
            "SELECT MAX(started_at) FROM sessions").fetchone()[0]
    except sqlite3.Error as exc:
        return Check(
            "Ledger", FAIL,
            f"{shown} is not a readable privacy-hud ledger "
            f"({type(exc).__name__})",
            details=["The file exists but its schema does not answer; it may "
                     "be truncated, or a different database entirely."],
            fixes=[f"Check the file with: sqlite3 {quoted} "
                   "'pragma integrity_check'",
                   "The ledger holds metadata only and is recreated on the "
                   "next session, so moving it aside is safe."],
        )
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass

    if not sessions:
        return Check(
            "Ledger", WARN, "readable, 0 sessions recorded",
            details=[f"{shown} exists but nothing has been recorded into it."],
            fixes=["Confirm the daemon is running against this same "
                   "PLUGIN_DATA, then run one Codex turn."],
        )

    plural = "session" if sessions == 1 else "sessions"
    summary = f"{sessions} {plural}, {events} events recorded"
    details = []
    if latest is not None:
        details.append("Most recent session started "
                       f"{_humanize_age(time.time() - float(latest))}.")
    return Check("Ledger", OK, summary, details=details)


def _setup_fixes() -> list[str]:
    """The one remedy for every runtime-pin failure, said the same way twice
    over rather than paraphrased per branch.

    "Run it from the right environment" is the load-bearing half. Running
    `privacy-hud-setup` from a shell whose `python3` has no `transformers`
    does not silently pin a blind interpreter — the command refuses — but it
    also does not get the user any closer, so the remedy names the activation
    step first.
    """
    return [
        "Record the interpreter, from the environment that has transformers "
        "and torch installed:",
        "  source .venv/bin/activate && privacy-hud-setup",
        "  (from a bare checkout: PYTHONPATH=src <that python> -m "
        "privacy_hud.runtime)",
    ]


def _probe_pinned_interpreter(receipt: dict, timeout: float
                              ) -> tuple[dict | None, float, str]:
    """Run `runtime.probe_interpreter` for a receipt.

    A separate function for the same reason `_module_version` is one: the
    real answer depends on which interpreter happens to be pinned on the
    machine the suite runs on, and a test that asserted on "whatever is
    installed here" would pass everywhere and prove nothing. Tests substitute
    this.
    """
    return runtime.probe_interpreter(receipt["python"],
                                     receipt.get("pythonpath"),
                                     timeout=timeout)


def _auto_spawn_configured(data_dir: Path) -> bool:
    """Could a hook start the daemon right now?

    Cheap on purpose — one read and one `stat`, no subprocess. It answers the
    narrow question `check_daemon` needs ("is 'no daemon' expected to be
    self-correcting?") and deliberately not the question
    `check_runtime_pin` answers ("does that interpreter actually work?"). If
    the two disagree the report says so: the pin check fails loudly while the
    daemon check reports the absence as expected, which is exactly the pair of
    statements the situation deserves.
    """
    receipt, problem = runtime.load_receipt(data_dir)
    if receipt is None or problem:
        return False
    python = receipt["python"]
    return os.access(python, os.X_OK) and not os.path.isdir(python)


def check_runtime_pin(timeout: float = runtime.PROBE_TIMEOUT) -> Check:
    """The receipt that lets the hook client start the daemon: present, still
    pointing at a real interpreter, and that interpreter still able to import
    the stack.

    **Why this check has to exist.** Codex invokes `hooks/handler.py` through
    its `#!/usr/bin/env python3` shebang against Codex's own minimal `PATH`.
    On the machine this was developed on that is `/opt/homebrew/bin/python3`,
    which has no `transformers`; the ML stack is in a different interpreter
    entirely. A daemon spawned from the shebang interpreter would therefore
    start *blind* — `ModelDetector.available` `False`, tier 3 off, no person
    or address detection — while every other check in this report, the socket
    round trip included, said the setup was healthy. That is strictly worse
    than the "you forgot to start the daemon" it replaces, so the interpreter
    is pinned at setup time and this check is what keeps the pin honest.

    **Why absence is a `FAIL`.** Without a receipt no hook will start a
    daemon, so a session records nothing unless someone remembered to start
    one by hand — and even then the daemon idle-exits after 30 minutes with
    nothing to bring it back. Nothing this plugin promises happens in that
    state, which is this file's definition of `FAIL`.

    **Why a dead tier 3 is a `WARN`.** Same line the `Detector deps` check
    draws: tiers 0-2 still catch credentials, file paths and shell
    destinations in a daemon with no model, so exiting non-zero would
    misdescribe the product. The warning states the consequence in the user's
    terms instead.

    The probe is a real `import`, in a real subprocess, of the real pinned
    interpreter (~1.4 s). `importlib.util.find_spec` would be nearly free and
    would report this project's documented torch/torchvision ABI break —
    `operator torchvision::nms does not exist` — as a healthy setup.
    """
    data_dir = _ledger_path().parent
    receipt, problem = runtime.load_receipt(data_dir)

    if receipt is None and problem == "absent":
        return Check(
            "Runtime pin", FAIL,
            f"no {runtime.RECEIPT_NAME} in {_display_path(data_dir)}",
            details=["Codex's hooks start the daemon themselves, but only "
                     "from an interpreter recorded by the setup step — "
                     "guessing one off Codex's PATH is how tier 3 ends up "
                     "silently dead.",
                     "Until this exists, no session records anything unless "
                     "a daemon is started by hand."],
            fixes=_setup_fixes(),
        )
    if receipt is None:
        return Check(
            "Runtime pin", FAIL, f"receipt is {problem}",
            details=[f"{_display_path(runtime.receipt_path(data_dir))} exists "
                     "but cannot be used, so no hook will start a daemon.",
                     "A receipt this file does not understand is never "
                     "guessed at: spawning the wrong interpreter is the "
                     "failure this pin exists to prevent."],
            fixes=_setup_fixes(),
        )

    python = receipt["python"]
    shown = _display_path(python)
    details: list[str] = []

    # Same refusal `hooks/handler.py` makes, reported before anything else it
    # would mask: a receipt anyone can write is a program anyone can choose
    # for a hook to execute, so the client declines to spawn from one. This
    # only arises where `PLUGIN_DATA` is unset and everything falls back to
    # /tmp, which `check_plugin_data` already fails on -- but a FAIL there
    # does not stop this check, and silence here would leave the user with a
    # daemon that never starts and no line saying why.
    receipt_file = runtime.receipt_path(data_dir)
    try:
        info = receipt_file.stat()
        insecure = info.st_uid != os.getuid() or bool(info.st_mode & 0o022)
    except OSError:
        insecure = False
    if insecure:
        return Check(
            "Runtime pin", FAIL,
            f"{_display_path(receipt_file)} is writable by other users",
            details=["It names an interpreter a hook process executes, so "
                     "the hook client refuses to spawn from it and no daemon "
                     "will start.",
                     "This is what an unset PLUGIN_DATA looks like from here: "
                     "every component falls back to /tmp, where anyone can "
                     "plant one."],
            fixes=[f"chmod 600 {_shell_path(receipt_file)}"] + _setup_fixes(),
        )

    recorded_at = receipt.get("recorded_at")
    if isinstance(recorded_at, (int, float)):
        details.append(f"Recorded {_humanize_age(time.time() - recorded_at)}.")

    pinned_data = receipt.get("plugin_data")
    stale_dir = (isinstance(pinned_data, str) and pinned_data
                 and Path(pinned_data).resolve() != data_dir.resolve())

    if os.path.isdir(python) or not os.access(python, os.X_OK):
        return Check(
            "Runtime pin", FAIL, f"{shown} is gone or not executable",
            details=details + [
                "The recorded interpreter no longer runs — a deleted "
                "virtualenv, a removed conda environment, an upgraded "
                "Homebrew formula.",
                "No daemon will start, and this is reported loudly rather "
                "than quietly retried against some other python: a fallback "
                "would be a daemon with no tier 3 that looks healthy."],
            fixes=_setup_fixes(),
        )

    probed, elapsed, error = _probe_pinned_interpreter(receipt, timeout)
    if probed is None:
        return Check(
            "Runtime pin", FAIL,
            f"{shown} could not be probed ({error or 'unknown error'})",
            details=details + [
                "The interpreter exists but would not answer an import "
                "probe, so what a spawned daemon would do there is unknown."],
            fixes=_setup_fixes(),
        )

    recorded = receipt.get("recorded") or {}
    problems: list[str] = []
    package = probed.get("privacy_hud")
    transformers_version = probed.get("transformers")
    torch_version = probed.get("torch")

    if not package:
        return Check(
            "Runtime pin", FAIL,
            f"{shown} cannot import privacy_hud",
            details=details + [
                "A daemon spawned there would exit immediately with an "
                "ImportError, on every hook, forever.",
                "The recorded sys.path entry is "
                f"{_display_path(receipt.get('pythonpath') or '(none)')}."],
            fixes=["Install the package into that interpreter: "
                   "pip install -e \".[detectors]\""] + _setup_fixes(),
        )

    def _floor_problem(name: str, version, floor) -> str | None:
        if version is None:
            was = recorded.get(name)
            if was:
                return f"{name} is gone (was {was} at setup)"
            return f"{name} missing"
        parsed = _version_tuple(str(version))
        if parsed and parsed[:2] < floor:
            return f"{name} {version} < {_format_version(floor)}"
        return None

    for name, version, floor in (
            ("transformers", transformers_version, MIN_TRANSFORMERS),
            ("torch", torch_version, MIN_TORCH)):
        found = _floor_problem(name, version, floor)
        if found:
            problems.append(found)
        else:
            details.append(f"{name}: {version}")

    if stale_dir:
        problems.append("recorded for another plugin-data directory")
        details.append(
            f"The receipt says it was recorded for "
            f"{_display_path(str(pinned_data))}, not "
            f"{_display_path(data_dir)} — a copied or moved setup.")

    if problems:
        details.append(TIER3_CONSEQUENCE)
        return Check(
            "Runtime pin", WARN, "; ".join(problems),
            details=details + [
                f"The pin itself is fine: {shown} runs and can import "
                "privacy_hud, so the daemon will start.",
                "What it cannot do is tier 3, and it will not say so at "
                "runtime — which is why it is said here."],
            fixes=["Install the floors into that interpreter: "
                   "pip install -e \".[detectors]\""] + _setup_fixes(),
        )

    check = Check("Runtime pin", OK,
                  f"{shown} ({elapsed:.1f}s import probe)", details=details)
    check.details.append(
        "Codex's hooks spawn this interpreter on the first tool call of a "
        "session, inheriting PLUGIN_DATA from the hook, so the daemon and "
        "the hooks cannot disagree about where to meet.")
    check.details.append(
        "The tier 3 load takes about 7s. Hooks that fire during it are "
        "answered as unverified — the first few seconds of a session are "
        "not monitored.")
    return check


def _probe_daemon(sock_path: Path, timeout: float) -> tuple[str, float, str]:
    """One round trip over the protocol `hooks/handler.py` owns.

    Returns `(outcome, elapsed_ms, extra)`. The outcomes are the ones that
    are actually distinguishable from a client, and each maps to a different
    remedy: `responsive`, `refused` (a stale socket file that outlived its
    process — the failure this whole check exists for), `timeout` (accepted
    but wedged), `no_reply` (accepted, then closed without answering — what
    `daemon._Handler.handle()` does for a malformed request), `bad_reply`
    (something is listening on this socket, but it is not this daemon), and
    `error` for everything else, notably the `OSError` from an AF_UNIX path
    over the kernel's ~104-byte `sockaddr_un` limit.

    The payload is `PROBE_EVENT` with no `session_id`; see the module
    docstring for why that cannot record or change anything.
    """
    request = json.dumps({"v": 1, "op": "event",
                          "payload": {"hook_event_name": PROBE_EVENT}})
    started = time.perf_counter()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(sock_path))
        sock.sendall((request + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    except ConnectionRefusedError:
        return "refused", (time.perf_counter() - started) * 1000, ""
    except socket.timeout:
        return "timeout", (time.perf_counter() - started) * 1000, ""
    except OSError as exc:
        return "error", (time.perf_counter() - started) * 1000, \
            type(exc).__name__
    finally:
        try:
            sock.close()
        except OSError:
            pass

    elapsed = (time.perf_counter() - started) * 1000
    if not buf.strip():
        return "no_reply", elapsed, ""
    try:
        reply = json.loads(buf.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "bad_reply", elapsed, "reply was not JSON"
    if not isinstance(reply, dict):
        return "bad_reply", elapsed, "reply was not a JSON object"
    return "responsive", elapsed, ""


def check_daemon(timeout: float = DAEMON_TIMEOUT, *,
                 pinned: bool | None = None) -> Check:
    """Is the daemon there, and does it *answer*?

    The socket file's existence is not the check. A unix socket file outlives
    the process that bound it whenever that process dies without running
    `Daemon._close()` (`kill -9`, an OOM, a closed terminal), and in that
    state `sock.exists()` is `True`, `connect()` raises
    `ConnectionRefusedError`, and every hook falls silently through to I6's
    fail-open. So the verdict comes from a round trip, and the socket file is
    only used to tell "you never started it" apart from "it died and left its
    socket behind" — two identical-looking symptoms with different fixes.

    **Absence means different things now, and this check has to say which.**
    The hook client starts the daemon itself when nothing answers, and the
    daemon idle-exits after 30 minutes — so "no socket" between sessions is
    the *correct* state of a healthy setup, not a fault, and reporting it as
    `FAIL` would train the user to ignore this line. What decides the verdict
    is therefore whether the auto-start is configured: with a usable runtime
    receipt, absence is a `WARN` that says the next hook will fix it; with no
    receipt, nothing will ever start a daemon and it stays a `FAIL`.

    `pinned` exists so a caller (a test, mostly) can state that directly
    instead of arranging a receipt on disk; left `None` it is read from the
    same `PLUGIN_DATA` everything else here uses.
    """
    data_dir = _ledger_path().parent
    sock_path = _socket_path(data_dir)
    shown = _display_path(sock_path)
    quoted = _shell_path(sock_path)
    start_fix = [
        f"export PLUGIN_DATA={_shell_path(data_dir)}",
        "PYTHONPATH=src python3 -m privacy_hud.daemon &",
    ]
    if pinned is None:
        pinned = _auto_spawn_configured(data_dir)
    # Said wherever absence is reported: a daemon that starts itself needs
    # ~7s to load tier 3 before it binds, and the hooks that fire in that
    # window are answered without detection. CLAUDE.md §5 — the limitation
    # goes next to the good news, not in a footnote.
    autostart = ["Codex's hooks start it on the first tool call of a session "
                 "(see the Runtime pin check).",
                 "It takes about 7s to load the tier 3 model before it "
                 "listens; hooks during that window are answered as "
                 "unverified, so the start of a session is unmonitored."]
    autostart_fix = ["Nothing to fix if you are between sessions — the next "
                     "hook starts it.",
                     "To have one running right now (for privacy-hud-ambient, "
                     "say), start it by hand:"] + start_fix

    # The remedy above names the directory that was actually probed, which is
    # the only self-consistent thing it can name -- but if that is not the
    # directory Codex assigns, following it produces a perfectly healthy
    # daemon on a socket no hook will ever connect to. That is precisely the
    # misconfiguration this project burned a live Codex session discovering,
    # so it gets said here too rather than only in the PLUGIN_DATA check.
    candidates = _codex_data_candidates()
    mismatch: list[str] = []
    if candidates and data_dir.resolve() not in {c.resolve()
                                                 for c in candidates}:
        mismatch = ["PLUGIN_DATA is not the directory Codex assigns (see the "
                    "PLUGIN_DATA check above) — fix that first, or a daemon "
                    "started here will be unreachable from Codex's hooks."]

    if not sock_path.exists():
        if pinned:
            return Check(
                "Daemon", WARN, f"not running (no socket at {shown})",
                details=autostart + [
                    "Until it is up, hooks still fire but every call falls "
                    "through to fail-open on ingress and fail-closed on "
                    "egress, with no detection running."] + mismatch,
                fixes=autostart_fix,
            )
        return Check(
            "Daemon", FAIL, f"no socket at {shown}",
            details=["Nothing is running and nothing will start one: there "
                     "is no runtime receipt for the hook client to spawn "
                     "from (see the Runtime pin check).",
                     "Without a daemon, hooks still fire but every call falls "
                     "through to fail-open on ingress and fail-closed on "
                     "egress, with no detection running."] + mismatch,
            fixes=_setup_fixes() + ["Or start one by hand for this session:"]
                  + start_fix,
        )

    try:
        mode = sock_path.stat().st_mode
    except OSError as exc:
        return Check(
            "Daemon", FAIL,
            f"cannot stat {shown} ({type(exc).__name__})",
            fixes=start_fix,
        )

    if not stat.S_ISSOCK(mode):
        return Check(
            "Daemon", FAIL, f"{shown} is not a socket",
            details=["Something else is occupying the path the daemon binds; "
                     "it will fail to start until that is cleared."],
            fixes=[f"rm {quoted}"] + start_fix,
        )

    outcome, elapsed, extra = _probe_daemon(sock_path, timeout)
    took = f"{elapsed:.0f} ms"

    if outcome == "responsive":
        check = Check(
            "Daemon", OK, f"responsive ({took} round trip)",
            details=[f"Probed with a {PROBE_EVENT} event, which the daemon "
                     "answers without recording anything or touching the "
                     "ledger."],
        )
        perms = stat.S_IMODE(mode)
        if perms != 0o600:
            check.status = WARN
            check.summary = (f"responsive ({took}), but the socket is "
                             f"mode {perms:04o}")
            check.details.append(
                "The socket should be 0600. At wider permissions any local "
                "user can inject hook events into your disclosure ledger.")
            check.fixes = [f"chmod 600 {quoted}",
                           "Then restart the daemon so it rebinds cleanly."]
        return check

    if outcome == "refused":
        stale = (f"{shown} exists but the process that bound it is gone "
                 "(killed, crashed, or its terminal closed). Until something "
                 "listens again, hooks connect, fail, and fall through to the "
                 "fail-open/fail-closed default.")
        if pinned:
            return Check(
                "Daemon", WARN, "stale socket — nothing is listening",
                details=[stale,
                         "This one self-heals: the next hook's connect is "
                         "refused, it spawns a daemon, and the daemon "
                         "unlinks the dead socket file before binding its "
                         "own (it probes the path under an exclusive lock, "
                         "so it only ever removes a socket it has proved "
                         "dead)."] + autostart[1:],
                fixes=autostart_fix,
            )
        return Check(
            "Daemon", FAIL, "stale socket — nothing is listening",
            details=[stale,
                     "Nothing will clear it either: there is no runtime "
                     "receipt, so no hook will start a daemon (see the "
                     "Runtime pin check)."],
            fixes=[f"rm {quoted}"] + start_fix,
        )

    if outcome == "timeout":
        return Check(
            "Daemon", FAIL, f"connected but no reply within {timeout:g}s",
            details=["The daemon accepted the connection and did not answer "
                     f"a {PROBE_EVENT} probe, which needs no detection at "
                     "all. It is wedged. Codex's own hook timeout is 5s, so "
                     "live hooks are timing out too."],
            fixes=["Stop the daemon process and start it again:"] + start_fix,
        )

    if outcome == "no_reply":
        return Check(
            "Daemon", FAIL, "connection accepted, then closed with no reply",
            details=["Something is listening but it discarded a well-formed "
                     "request. Either the daemon is mid-restart, or it is a "
                     "version that does not speak this protocol."],
            fixes=["Stop the daemon process and start it again:"] + start_fix,
        )

    if outcome == "bad_reply":
        return Check(
            "Daemon", FAIL, f"unexpected reply — {extra}",
            details=["Something other than the privacy-hud daemon is "
                     "listening on this socket path."],
            fixes=[f"Confirm nothing else uses {quoted}, remove it, and "
                   "start the daemon:"] + start_fix,
        )

    return Check(
        "Daemon", FAIL, f"probe failed ({extra or 'unknown error'})",
        details=["If this is a path-length error, the socket path is over "
                 "the kernel's ~104-byte AF_UNIX limit; PLUGIN_DATA is "
                 "nested too deeply."],
        fixes=start_fix,
    )


def _module_version(module_name: str) -> str | None:
    """Import `module_name` and return its `__version__`, or `None`.

    A separate function purely so tests can substitute it: the real answer
    depends on the interpreter the suite happens to run in, and a test that
    asserts on "whatever is installed here" tests nothing. Returns `None`
    for both "not installed" and "installed but has no `__version__`" — the
    caller reports the first as absent and cannot usefully distinguish the
    second, which does not occur for either of these two packages.
    """
    try:
        module = __import__(module_name)
    except Exception:
        return None
    version = getattr(module, "__version__", None)
    return str(version) if version else None


def _pinned_interpreter_note() -> list[str]:
    """Whose stack the two tier 3 checks below are actually describing.

    The daemon now runs a *pinned* interpreter, and this command can be run
    from any other one — so "transformers not installed", and the consequence
    that normally follows it, are facts about the doctor's process and not
    necessarily about the daemon's. Uncaveated, that is an overclaim in both
    directions: which shell the user happened to be in would decide whether a
    healthy setup reads as blind. Placed *after* the consequence it scopes,
    and it never changes a verdict — the authoritative answer for the daemon's
    interpreter is the Runtime pin check's probe of it.
    """
    try:
        receipt, problem = runtime.load_receipt(_ledger_path().parent)
        if receipt is None or problem:
            return []
        python = receipt["python"]
        if Path(python).resolve() == Path(sys.executable).resolve():
            return []
    except Exception:  # a note is never worth failing a check over
        return []
    return [f"This describes the interpreter running privacy-hud-doctor. The "
            f"daemon runs {_display_path(python)}, so the Runtime pin check — "
            "not this one — decides whether tier 3 runs for a real session."]


def check_detector_deps() -> Check:
    """`transformers` and `torch`: present, and above their pinned floors.

    A `WARN`, never a `FAIL`, in every degraded case. The engine runs tiers
    0-2 with neither package installed and still catches credentials, paths
    and shell destinations, so a non-zero exit here would overstate the
    damage. What the warning must not do is understate it either, which is
    why `TIER3_CONSEQUENCE` is appended verbatim: "transformers not
    installed" is a fact about the environment, "names and addresses will
    not be detected" is the fact about the product.

    torch gets its own line because of the specific trap README documents:
    it is one of *transformers'* optional extras, so `pip install
    transformers` leaves you with a `transformers` that imports fine and a
    tier 3 that is silently dead. A report that only checked `transformers`
    would call that setup healthy.
    """
    transformers_version = _module_version("transformers")
    torch_version = _module_version("torch")

    details: list[str] = []
    problems: list[str] = []
    fixes: list[str] = []

    if transformers_version is None:
        details.append("transformers: not installed")
        problems.append("transformers missing")
    else:
        parsed = _version_tuple(transformers_version)
        floor = _format_version(MIN_TRANSFORMERS)
        if parsed and parsed[:2] < MIN_TRANSFORMERS:
            details.append(f"transformers: {transformers_version} "
                           f"(below the required {floor})")
            details.append("Below 5.16 the pipeline fails outright with "
                           "'does not recognize this architecture' — the "
                           "openai_privacy_filter model type was not yet "
                           "known to it.")
            problems.append(f"transformers < {floor}")
        else:
            details.append(f"transformers: {transformers_version} "
                           f"(requires >= {floor})")

    if torch_version is None:
        details.append("torch: not installed")
        details.append("torch is one of transformers' optional extras, so "
                       "installing transformers alone leaves tier 3 "
                       "silently disabled.")
        problems.append("torch missing")
    else:
        parsed = _version_tuple(torch_version)
        floor = _format_version(MIN_TORCH)
        if parsed and parsed[:2] < MIN_TORCH:
            details.append(f"torch: {torch_version} (below the "
                           f"{floor} transformers 5.16 requires)")
            problems.append(f"torch < {floor}")
        else:
            details.append(f"torch: {torch_version} (requires >= {floor})")

    if not problems:
        return Check("Detector deps", OK,
                     f"transformers {transformers_version}, "
                     f"torch {torch_version}",
                     details=details + _pinned_interpreter_note())

    details.append(TIER3_CONSEQUENCE)
    details += _pinned_interpreter_note()
    fixes.append("Install both floors together, in a dedicated virtualenv: "
                 "pip install -e \".[detectors]\"")
    fixes.append("Upgrading torch inside a shared environment breaks other "
                 "ML packages built against the old one — isolate this "
                 "install.")
    return Check("Detector deps", WARN, "; ".join(problems),
                 details=details, fixes=fixes)


def _hf_hub_cache() -> Path:
    """HuggingFace's hub cache directory, by its documented precedence.

    `HF_HUB_CACHE`, else `$HF_HOME/hub`, else `~/.cache/huggingface/hub`.
    Resolved from the environment rather than by importing `huggingface_hub`,
    because the whole point of this branch is to answer the weights question
    *without* paying an import that pulls in the ML stack — and because
    `huggingface_hub` may not be installed in exactly the broken setup this
    check is for.
    """
    hub = os.environ.get("HF_HUB_CACHE")
    if hub:
        return Path(hub).expanduser()
    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        return Path(hf_home).expanduser() / "hub"
    return Path.home() / ".cache" / "huggingface" / "hub"


def _find_model_snapshot() -> tuple[Path | None, list[str]]:
    """Locate a `openai/privacy-filter` snapshot and report missing files.

    Returns `(snapshot_dir, missing_files)`, where a `None` directory means
    no snapshot at all. `Path.exists()` is used rather than `is_file()`
    because the hub stores every snapshot entry as a symlink into `blobs/`;
    `exists()` follows those, so a dangling link (blob garbage-collected out
    from under the snapshot) correctly reads as missing rather than present.

    Only the five files README pins as "verified sufficient" are looked for.
    The full repo is ~17 GB because it also ships ONNX exports and a
    duplicate `original/` checkpoint that this project never loads, and
    reporting those as missing would send a correctly-installed user off to
    download 14 GB they do not need.
    """
    repo_dir = _hf_hub_cache() / MODEL_CACHE_DIRNAME
    snapshots = repo_dir / "snapshots"
    try:
        candidates = [p for p in sorted(snapshots.iterdir()) if p.is_dir()]
    except OSError:
        return None, list(MODEL_FILES)

    best: tuple[int, Path] | None = None
    for snapshot in candidates:
        missing = [name for name in MODEL_FILES
                   if not (snapshot / name).exists()]
        if not missing:
            return snapshot, []
        score = len(MODEL_FILES) - len(missing)
        if best is None or score > best[0]:
            best = (score, snapshot)

    if best is None:
        return None, list(MODEL_FILES)
    snapshot = best[1]
    return snapshot, [name for name in MODEL_FILES
                      if not (snapshot / name).exists()]


def check_tier3(load_model: bool = False) -> Check:
    """Tier 3: honest by default, authoritative on request.

    Constructing a `ModelDetector` is the only way to *know* whether tier 3
    works — it is the same call `dispatch.new_state()` makes, and its
    `available` flag is the real answer. It also loads ~2.8 GB and takes
    around seven seconds, which is not a reasonable default for a command
    whose job is to be run on a whim when something looks wrong.

    So the default is the cheap, clearly-labelled proxy: are the five files
    the pipeline actually loads present in the HuggingFace cache? That is a
    strong signal and it is not the same claim, so it is not reported as one
    — the summary says weights are on disk and the model was not loaded,
    rather than asserting tier 3 is available. Pretending to know is the one
    thing a diagnostic must not do (CLAUDE.md §5).

    `--check-model` swaps the proxy for the real thing. Both degrade to
    `WARN`: no weights means tiers 0-2 only, which is a working engine with
    a stated blind spot, not a broken one.
    """
    if load_model:
        try:
            from .detect.model import ModelDetector
        except Exception as exc:
            return Check(
                "Tier 3 model", WARN,
                f"could not import the detector ({type(exc).__name__})",
                details=[TIER3_CONSEQUENCE] + _pinned_interpreter_note(),
                fixes=["pip install -e \".[detectors]\""],
            )
        started = time.perf_counter()
        detector = ModelDetector()
        elapsed = time.perf_counter() - started
        if detector.available:
            return Check(
                "Tier 3 model", OK,
                f"loaded and available ({elapsed:.1f}s)",
                details=["openai/privacy-filter loaded from the local "
                         "HuggingFace cache; person, address, date and "
                         "account-number detection is live.",
                         "No network call was made: HF_HUB_OFFLINE=1 is set "
                         "before transformers is imported (I2)."],
            )
        snapshot, missing = _find_model_snapshot()
        details = [f"ModelDetector reports available = False after "
                   f"{elapsed:.1f}s.", TIER3_CONSEQUENCE]
        if snapshot is None:
            details.insert(1, "No openai/privacy-filter snapshot found in "
                              f"{_display_path(_hf_hub_cache())}.")
        elif missing:
            details.insert(1, "Snapshot found but incomplete; missing: "
                              + ", ".join(missing))
        else:
            details.insert(1, "The weights are on disk, so the failure is in "
                              "loading them — most often a torch / "
                              "torchvision / torchaudio version mismatch "
                              "(look for 'operator torchvision::nms does not "
                              "exist').")
        return Check("Tier 3 model", WARN, "not available",
                     details=details + _pinned_interpreter_note(),
                     fixes=_model_fixes())

    snapshot, missing = _find_model_snapshot()
    if snapshot is not None and not missing:
        return Check(
            "Tier 3 model", OK,
            "weights present on disk (not loaded)",
            details=[f"All {len(MODEL_FILES)} files the pipeline loads are "
                     f"in {_display_path(_hf_hub_cache())}.",
                     "This does not prove the model loads — re-run with "
                     "--check-model to construct the detector and read "
                     "ModelDetector.available (~2.8 GB, about 7s)."],
        )

    if snapshot is None:
        details = ["No openai/privacy-filter snapshot in "
                   f"{_display_path(_hf_hub_cache())}.", TIER3_CONSEQUENCE]
    else:
        details = ["Snapshot found but incomplete; missing: "
                   + ", ".join(missing), TIER3_CONSEQUENCE]
    return Check("Tier 3 model", WARN, "weights not found on disk",
                 details=details + _pinned_interpreter_note(),
                 fixes=_model_fixes())


def _model_fixes() -> list[str]:
    """README's exact download recipe, not a paraphrase of it.

    The `allow_patterns` list is the whole point: `snapshot_download`
    without it pulls ~17 GB, of which this project loads ~2.8 GB.
    """
    return [
        "Fetch only the files the pipeline loads (~2.8 GB, not the repo's "
        "~17 GB):",
        "  python3 -c \"from huggingface_hub import snapshot_download; "
        "snapshot_download('openai/privacy-filter', allow_patterns=["
        + ", ".join(f"'{name}'" for name in MODEL_FILES) + "])\"",
        "Everything runs offline afterwards; the plugin sets "
        "HF_HUB_OFFLINE=1 before importing transformers (I2).",
    ]


def _installed_plugin_dirs() -> list[tuple[str, str, Path]]:
    """Every cached copy of this plugin: `(marketplace, version, path)`.

    Codex's layout is `$CODEX_HOME/plugins/cache/<marketplace>/<plugin>/
    <version>/`, which is read directly rather than asked of `codex plugin
    list` — see the module docstring for why a diagnostic in *this* project
    does not shell out to an API client.
    """
    cache = _codex_home() / "plugins" / "cache"
    found: list[tuple[str, str, Path]] = []
    try:
        marketplaces = sorted(cache.iterdir())
    except OSError:
        return found
    for marketplace in marketplaces:
        plugin_dir = marketplace / PLUGIN_NAME
        try:
            versions = sorted(plugin_dir.iterdir())
        except OSError:
            continue
        for version in versions:
            if version.is_dir():
                found.append((marketplace.name, version.name, version))
    return found


def _plugin_enabled(marketplace: str) -> bool | None:
    """`plugins."<name>@<marketplace>".enabled` from Codex's config.toml.

    `None` means "could not tell" — no config file, unreadable, malformed, or
    no entry for this plugin — which is reported as such rather than assumed
    either way. An installed-but-disabled plugin fires no hooks at all, and
    that is otherwise indistinguishable from a forgotten daemon, so it is
    worth reading. Only the one boolean is read; nothing else in that file is
    inspected or printed (it holds unrelated user configuration).
    """
    config = _codex_home() / "config.toml"
    try:
        import tomllib
        with open(config, "rb") as handle:
            data = tomllib.load(handle)
    except Exception:
        return None
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return None
    entry = plugins.get(f"{PLUGIN_NAME}@{marketplace}")
    if not isinstance(entry, dict):
        return None
    value = entry.get("enabled")
    return bool(value) if isinstance(value, bool) else None


def _tracked_files(root: Path) -> list[str]:
    """Relative paths under `root` worth comparing between repo and cache.

    `PLUGIN_FILES` plus a recursive walk of `PLUGIN_TREES`, skipping
    `__pycache__` (a build artefact whose divergence is noise) and dotfiles
    (`.DS_Store` in particular, which macOS sprinkles into both trees at
    different times and which Codex never reads).
    """
    names = [name for name in PLUGIN_FILES if (root / name).is_file()]
    for tree in PLUGIN_TREES:
        base = root / tree
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            parts = path.relative_to(root).parts
            if any(p == "__pycache__" or p.startswith(".") for p in parts):
                continue
            names.append(str(path.relative_to(root)))
    return names


def check_plugin_install() -> Check:
    """Is a copy installed in Codex's cache, is it enabled, is it current?

    Three distinct failures wear the same "nothing happened" costume:

    * **Not installed.** `FAIL`. Codex never invokes a hook, so no amount of
      running daemon helps.
    * **Installed but disabled** in `config.toml`. `FAIL`, for the same
      reason and with a completely different fix.
    * **Installed but stale.** `WARN`. Codex installs a *copy*, so an edited
      `hooks/handler.py` in the checkout is not what runs until the plugin is
      re-added — the failure mode that has cost this project the most
      debugging time. It is a warning rather than a failure because the
      installed copy genuinely works; it just is not the code you are
      reading. The report names the diverging files so the difference between
      "my edit is not live" and "a README typo" is visible at a glance.

    Only the files Codex actually executes are compared (`PLUGIN_FILES` and
    `PLUGIN_TREES`). Comparing the whole tree would flag `.git`, byte-code
    caches and the test suite, none of which Codex reads, and a staleness
    signal that is always on is a staleness signal nobody looks at.

    No Codex home at all is `SKIP`, not `FAIL`: this command is genuinely
    useful in CI and in a bare checkout, and "Codex is not installed for this
    user" is a fact to state, not a fault to report.
    """
    codex_home = _codex_home()
    if not codex_home.is_dir():
        return Check(
            "Plugin install", SKIP,
            f"no Codex home at {_display_path(codex_home)}",
            details=["Codex is not installed for this user, so there is no "
                     "installed copy to compare. Every other check above "
                     "still applies."],
        )

    installed = _installed_plugin_dirs()
    if not installed:
        return Check(
            "Plugin install", FAIL,
            "not present in Codex's plugin cache",
            details=[f"Nothing under "
                     f"{_display_path(codex_home / 'plugins' / 'cache')}"
                     f"/*/{PLUGIN_NAME}/. Codex fires no hook for a plugin "
                     "it has not installed, so the ledger stays empty no "
                     "matter what else is running."],
            fixes=["codex plugin marketplace add inin-zou/codex-privacy-hud",
                   f"codex plugin add {PLUGIN_NAME}@{PLUGIN_NAME}",
                   "From a local checkout instead: codex plugin marketplace "
                   "add /path/to/codex-privacy-hud --json && codex plugin "
                   f"add {PLUGIN_NAME}@{PLUGIN_NAME} --json"],
        )

    repo = _repo_root()
    declared = None
    if repo is not None:
        try:
            declared = json.loads(
                (repo / ".claude-plugin" / "plugin.json").read_text()
            ).get("version")
        except Exception:
            declared = None

    # Compare against the copy matching this checkout's declared version when
    # Codex has one; otherwise the newest installed version, so the report is
    # about the code most likely to run.
    chosen = None
    if declared is not None:
        chosen = next((e for e in installed if e[1] == declared), None)
    if chosen is None:
        chosen = installed[-1]
    marketplace, version, path = chosen

    details = [f"{marketplace}/{PLUGIN_NAME} version " + ", ".join(
        sorted({v for _m, v, _p in installed}))
        + f" in {_display_path(codex_home / 'plugins' / 'cache')}"]

    enabled = _plugin_enabled(marketplace)
    if enabled is False:
        return Check(
            "Plugin install", FAIL,
            f"installed ({version}) but disabled in Codex config",
            details=details + [
                f'config.toml has plugins."{PLUGIN_NAME}@{marketplace}"'
                ".enabled = false, so no hook fires."],
            fixes=[f"codex plugin add {PLUGIN_NAME}@{marketplace}",
                   "or set enabled = true for that entry in "
                   f"{_display_path(codex_home / 'config.toml')}"],
        )
    if enabled is None:
        details.append("Could not read an enabled flag from "
                       f"{_display_path(codex_home / 'config.toml')}; "
                       "whether Codex has this plugin enabled is unverified.")

    if repo is None:
        return Check(
            "Plugin install", OK, f"installed, version {version}",
            details=details + [
                "Not running from a source checkout, so the installed copy "
                "cannot be compared against one. Staleness is unchecked."],
        )

    if declared is not None and declared != version and \
            not any(v == declared for _m, v, _p in installed):
        details.append(f"This checkout declares version {declared}; Codex has "
                       f"{version}. The installed copy predates your version "
                       "bump.")

    tracked = _tracked_files(repo)
    diverged = []
    for name in tracked:
        repo_hash = _sha256(repo / name)
        cached_hash = _sha256(path / name)
        if repo_hash is None or cached_hash is None or repo_hash != cached_hash:
            diverged.append(name)

    if not diverged:
        return Check(
            "Plugin install", OK,
            f"installed, version {version}, matches this checkout",
            details=details + [
                f"All {len(tracked)} executed files (hooks, manifest, skills) "
                "are byte-identical to the checkout."],
        )

    shown = ", ".join(diverged[:6])
    if len(diverged) > 6:
        shown += f", and {len(diverged) - 6} more"
    return Check(
        "Plugin install", WARN,
        f"installed copy is stale in {len(diverged)} file(s)",
        details=details + [
            f"Differs from this checkout: {shown}.",
            "Codex runs its own copy, so edits here are not live until you "
            "re-add the plugin. The installed copy still works — it is just "
            "not the code you are reading."],
        fixes=[f"codex plugin marketplace add {_shell_path(repo)} --json",
               f"codex plugin add {PLUGIN_NAME}@{marketplace} --json"],
    )


# --------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------- #

def run_checks(*, load_model: bool = False,
               timeout: float = DAEMON_TIMEOUT,
               probe_timeout: float = runtime.PROBE_TIMEOUT) -> list[Check]:
    """Run every check, in the order a failure cascades.

    Order matters for readability, not for control flow: nothing here
    short-circuits. A user with an unset `PLUGIN_DATA` also wants to know
    whether their model weights are in place, and stopping at the first
    failure would turn one command into four.

    A check that raises becomes a `FAIL` naming its exception class and
    nothing else. The message is withheld deliberately — see the module
    docstring on I1 — and the fix points at the real report, since a crash in
    the doctor is a bug in the doctor, not in the user's setup.
    """
    checks = [
        ("Python", check_python),
        ("PLUGIN_DATA", check_plugin_data),
        ("Ledger", check_ledger),
        ("Runtime pin", lambda: check_runtime_pin(probe_timeout)),
        ("Daemon", lambda: check_daemon(timeout)),
        ("Detector deps", check_detector_deps),
        ("Tier 3 model", lambda: check_tier3(load_model)),
        ("Plugin install", check_plugin_install),
    ]
    results = []
    for name, func in checks:
        try:
            results.append(func())
        except Exception as exc:  # a broken check must not hide the others
            results.append(Check(
                name, FAIL,
                f"the check itself failed ({type(exc).__name__})",
                details=["The exception message is withheld: a diagnostic in "
                         "a privacy tool must not print strings it did not "
                         "choose (I1)."],
                fixes=["This is a bug in privacy-hud's doctor, not "
                       "necessarily in your setup. Please report it with the "
                       "exception class above."],
            ))
    return results


def format_report(checks: list[Check]) -> str:
    """Plain text, fixed columns, no colour, no escape sequences at all.

    `ambient.py` writes exactly one control sequence (erase-to-end-of-line)
    because it redraws in place; this command prints once and exits, so it
    writes none. That makes the report identical on a terminal, through a
    pipe, and in a pasted bug report — and makes `NO_COLOR` respected by
    construction rather than by a branch that could be wrong.
    """
    lines = ["privacy-hud doctor", ""]
    for check in checks:
        marker = _MARKERS.get(check.status, "[????]")
        lines.append(f"  {marker} {check.name.ljust(_LABEL_WIDTH)} "
                     f"{check.summary}")
        for detail in check.details:
            lines.append(f"         {detail}")
        for fix in check.fixes:
            lines.append(f"      -> {fix}")
        lines.append("")

    counts = {status: 0 for status in (OK, WARN, FAIL, SKIP)}
    for check in checks:
        counts[check.status] = counts.get(check.status, 0) + 1

    tally = [f"{counts[OK]} ok", f"{counts[WARN]} warning(s)",
             f"{counts[FAIL]} failure(s)"]
    if counts[SKIP]:
        tally.append(f"{counts[SKIP]} skipped")
    lines.append("Summary: " + ", ".join(tally) + ".")

    if counts[FAIL]:
        lines.append("Setup is NOT usable — nothing will be recorded until "
                     "the [FAIL] items above are fixed.")
    elif counts[WARN]:
        lines.append("Setup is usable, with the limitations noted above.")
    else:
        lines.append("Setup is healthy.")

    lines.append("")
    lines.append("Reports infrastructure only: counts, versions, paths and "
                 "timestamps. No prompt, file content, detected value or "
                 "session content is ever printed.")
    return "\n".join(lines)


def exit_code(checks: list[Check]) -> int:
    """0 when the setup is usable, 1 when something is genuinely broken.

    Only `FAIL` is non-zero. `WARN` covers degraded-but-working — no model
    weights, an old `transformers`, a stale installed copy — and exiting
    non-zero for those would make the command useless in the setup script or
    CI job that is the obvious place to put it, and would misdescribe a
    plugin that is, in those states, still catching credentials and paths.
    """
    return 1 if any(c.status == FAIL for c in checks) else 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="privacy-hud-doctor",
        description="Health-check the Codex Privacy HUD setup: interpreter, "
                    "PLUGIN_DATA, ledger, the pinned runtime the hooks spawn "
                    "the daemon from, the daemon round trip, the detector "
                    "stack, and the copy of the plugin Codex actually runs.",
        epilog="Exit code 0 when the setup is usable (warnings included), "
               "1 when something is genuinely broken.",
    )
    parser.add_argument(
        "--check-model", action="store_true",
        help="construct the tier 3 ModelDetector to read its real "
             "availability instead of looking for the weights on disk "
             "(loads ~2.8 GB, takes about 7s)")
    parser.add_argument(
        "--timeout", type=float, default=DAEMON_TIMEOUT, metavar="SECONDS",
        help=f"daemon round-trip budget (default {DAEMON_TIMEOUT:g}, the same "
             "one hooks/handler.py uses)")
    return parser


def main(argv: list[str] | None = None, *, out=None) -> int:
    """Entry point for `python -m privacy_hud.doctor` and the
    `privacy-hud-doctor` console script. Returns a process exit code.

    `SystemExit` from argparse (`--help`, a usage error) is caught and turned
    back into an int for the same reason `ambient.main` does it: the
    console-script wrapper is handed this function's return value, and a
    function documented as returning an int should not raise through it.
    """
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = _build_parser().parse_args(argv)
    except SystemExit as exc:  # --help (0) or a usage error (2)
        return int(exc.code or 0)

    out = sys.stdout if out is None else out
    checks = run_checks(load_model=args.check_model, timeout=args.timeout)
    print(format_report(checks), file=out)
    return exit_code(checks)


if __name__ == "__main__":
    sys.exit(main())
