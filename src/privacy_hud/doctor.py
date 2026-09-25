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
would. `ambient.py` no longer opens a `Ledger` for its numbers either — it
reads `$PLUGIN_DATA/hud/<session_id>.json` (contract A) for those, and opens
a `Ledger` only to resolve *which* session to show, never for `percent` or
`blocked`. This module needs three scalars and nothing more, and a
diagnostic pointed at a user's real ledger should be *incapable* of writing
to it rather than merely careful not to.

The precise claim, since an approximate one would be the kind of overclaim
README's known-limits section forbids: no file this module names is ever
created or modified.
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
import math
import os
import socket
import sqlite3
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import (codex, offline, runtime, runtime_client,
               runtime_contract, runtime_messages, runtime_repair)
from .runtime import ledger_path as _ledger_path

# `runtime` is imported at module level, unlike `daemon` (see `_socket_path`
# for why that one is deferred), because it is stdlib-only and imports nothing
# else from this package except `codex`: there is no chain through it that a
# broken detector stack or a missing `transformers` could take down. It is
# also the module whose literals this file must agree with, and a deferred
# import would make that agreement conditional.
#
# `_ledger_path` used to come from `local_ui_server`, which imports `render`,
# `mcp_tools` and the matrix — the whole read stack — into a diagnostic that
# has to survive a broken install, and which closed a real import cycle
# (`doctor` -> `local_ui_server` -> `runtime` -> `doctor`). It resolves
# `$PLUGIN_DATA/ledger.db` and nothing else, so it lives in `runtime` (which
# already owns "which plugin-data directory") over `codex.LEDGER_NAME`, and
# `local_ui_server` re-exports it under its old name.

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

# --------------------------------------------------------------------- #
# Re-exports
#
# These names are defined elsewhere now — the Codex facts in `codex.py` (the
# single place this package knows anything about Codex the platform), the two
# path-printing helpers in `runtime.py` (which `main` below and
# `privacy-hud-setup` both need, and which a setup command must not have to
# import a 1700-line diagnostic to get). They are kept here under their old
# names rather than renamed at every call site because prose all over this
# file and several tests name them here: `tests/test_daemon.py` compares
# `doctor.SOCKET_NAME` against the hook client's literal,
# `tests/test_hud_contract.py` compares `doctor.PLUGIN_NAME` against the
# manifest, `tests/test_doctor.py` asserts `doctor.PROBE_EVENT` is harmless
# and exercises `doctor._shell_path` against a real shell. One definition,
# two spellings; see the defining module for the why of each value.
# --------------------------------------------------------------------- #

PLUGIN_NAME = codex.PLUGIN_NAME
SOCKET_NAME = codex.SOCKET_NAME
PROBE_EVENT = codex.PROBE_EVENT
_codex_home = codex.codex_home
_codex_data_candidates = codex.codex_data_candidates
_display_path = runtime.display_path
_shell_path = runtime.shell_path

#: Default daemon round-trip budget. Same 2.0 s `hooks/handler.py` uses, so
#: "the doctor says the daemon answers in time" means the same thing the hook
#: client means by it.
DAEMON_TIMEOUT = 2.0

#: Files Codex actually executes out of its cached copy. These are what
#: staleness is measured against — not the whole tree, which in a working
#: checkout also carries `.git`, `__pycache__`, and a test suite that Codex
#: never reads and whose divergence means nothing.
PLUGIN_FILES = (
    ".codex-plugin/plugin.json",
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
_LABEL_WIDTH = 24


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


def _repo_root() -> Path | None:
    """The source checkout this module was imported from, or `None`.

    Same `parents[2]` convention `local_ui_server._UI_DIR` uses. Returns
    `None` when the package was installed as a wheel into site-packages,
    where there is no `hooks/` tree to compare Codex's cached copy against —
    an honest "cannot check", never a manufactured verdict.
    """
    root = Path(__file__).resolve().parents[2]
    if (root / ".codex-plugin" / "plugin.json").is_file() and \
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
    helper when it is available, and otherwise derive it from `codex.py`,
    which is stdlib-only and imports nothing from this package — so the
    fallback cannot be taken down by the same broken chain. `daemon`'s helper
    now reads the name from there too; `hooks/handler.py` still hardcodes it
    (it is stdlib-only and never imports this package, so that literal is
    independently load-bearing regardless) and is compared against it.
    """
    try:
        from .daemon import _default_socket_path
        return Path(_default_socket_path(data_dir))
    except Exception:
        return codex.socket_path(data_dir)


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


def _plugin_data_export_fix(candidates: list[Path]) -> list[str]:
    """Shared "how to fix it" wording for a missing or unresolved
    `PLUGIN_DATA`. `check_plugin_data` and every check below that cannot
    proceed without a data directory (`check_ledger`, `check_runtime_pin`,
    `check_daemon`, via `_plugin_data_unset_check`) call this instead of
    each carrying its own copy of the same three cases, which is how a
    fix like "candidates found: ..." would otherwise drift out of sync
    between them."""
    if len(candidates) == 1:
        return [f"export PLUGIN_DATA={_shell_path(candidates[0])}"]
    if candidates:
        return ["Pick the directory Codex assigned to this plugin and "
                "export it, e.g. "
                f"export PLUGIN_DATA={_shell_path(candidates[0])}",
                "Candidates found: " + ", ".join(
                    _display_path(c) for c in candidates)]
    return [f"ls {_shell_path(codex.plugin_data_root())} "
            "and export the entry for this plugin as PLUGIN_DATA",
            "If that directory is empty, install the plugin first: "
            "codex plugin add codex-privacy-hud@codex-privacy-hud"]


def _plugin_data_unset_check(name: str) -> Check:
    """A `FAIL` `Check` named `name`, for the state `check_ledger`,
    `check_runtime_pin` and `check_daemon` all share with `check_plugin_data`
    itself: no resolvable `PLUGIN_DATA` at all (unset, and no Codex
    candidate either -- spec §6, there is no `/tmp` guess to fall back to).
    Without this guard each of those three called `_ledger_path()` and used
    the result unconditionally, so an unset `PLUGIN_DATA` crashed with
    `AttributeError` and `run_checks()` reported the opaque "the check
    itself failed" -- exactly the fresh-install state this whole file
    exists to diagnose clearly. One shared message also keeps the wording
    in sync with `check_plugin_data`'s own "not set" case instead of three
    near-duplicates drifting apart."""
    return Check(
        name, FAIL,
        "PLUGIN_DATA is not set — nothing is written until it is",
        details=["Codex assigns this value; the daemon and the hook "
                 "client must both use the same one or every hook "
                 "reports unavailable.",
                 "See the PLUGIN_DATA check above for how to set it."],
        fixes=_plugin_data_export_fix(_codex_data_candidates()),
    )


def check_plugin_data() -> Check:
    """`PLUGIN_DATA`: is it set, does it exist, is it the one Codex assigns?

    Unset is a `FAIL`, not a warning. There is no `/tmp` fallback any more
    (spec §6: `_ledger_path`, `daemon.main`, `hooks/handler.py` all refuse to
    guess) -- an unset `PLUGIN_DATA` now means every other component declines
    to write anything at all, which is exactly why the doctor cannot verify a
    setup whose location it does not know either.

    A value that exists but differs from Codex's assigned directory is a
    `WARN`, not a `FAIL`: running the daemon against a scratch directory is a
    legitimate thing to do deliberately (the tests do it), so the honest
    report is "this works, and it is not what Codex will use".
    """
    raw = os.environ.get("PLUGIN_DATA")
    candidates = _codex_data_candidates()

    # Empty and unset PLUGIN_DATA remain a FAIL even when the resolver
    # can discover a candidate. Guard None before accessing the path.
    # Resolve the installation root directly: a fenced ledger's parent
    # is the ledger subdirectory, not the plugin-data directory.
    data_dir = runtime.plugin_data_dir()
    if not raw or data_dir is None:
        return Check(
            "PLUGIN_DATA", FAIL,
            "not set — nothing is written until it is",
            details=["Codex assigns this value; the daemon and the hook "
                     "client must both use the same one or every hook "
                     "reports unavailable."],
            fixes=_plugin_data_export_fix(candidates),
        )

    if not data_dir.is_dir():
        return Check(
            "PLUGIN_DATA", FAIL,
            f"{_display_path(data_dir)} does not exist",
            details=["Set but pointing at nothing: the daemon would create "
                     "this directory, but Codex's hooks would still be "
                     "talking to the directory Codex itself assigned."],
            fixes=_plugin_data_export_fix(candidates),
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
        check.fixes = _plugin_data_export_fix(candidates)
    return check


def check_read_guard() -> Check:
    """The read guard toggle (`#36`): on or off, read from
    `$PLUGIN_DATA/settings.json` via `settings.Settings`.

    `OK` either way -- off is the default and a legitimate choice, not a
    fault, so this check exists only to make an otherwise invisible file
    answerable (see `settings.py`'s module docstring), the same reason
    `$privacy read status` exists. No `FAIL`/`WARN` branch here needs a
    fix: `Settings` already fails open (I6) on a missing, corrupt, or
    unreadable file, so there is nothing this check could catch that
    would call for one.
    """
    from .settings import Settings
    ledger = _ledger_path()
    if ledger is None:
        return _plugin_data_unset_check("Read guard")
    data_dir = ledger.parent
    if Settings(data_dir).deny_read:
        return Check("Read guard", OK, "on — sensitive-path reads denied")
    return Check("Read guard", OK, "off (default) — reads are not blocked")


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
    if path is None:
        return _plugin_data_unset_check("Ledger")
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
        # One read transaction, so the table list and the counts describe
        # the same snapshot. After #54's rebuild the legacy rows live in
        # `events_legacy_v1` and new rows in `events`; both are counted, or
        # the historical events would drop out of the total.
        conn.execute("BEGIN")
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        events = sum(
            conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("events", "events_legacy_v1") if table in tables)
        if "events" not in tables and "events_legacy_v1" not in tables:
            raise sqlite3.OperationalError("no events table")
        latest = conn.execute(
            "SELECT MAX(started_at) FROM sessions").fetchone()[0]
        conn.execute("COMMIT")
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


def _pin_receipt(data_dir) -> tuple[dict | None, str]:
    """The recorded selection, in the shape the pin check below reads.

    Receipt v2 records a *bundle* as well as an interpreter (#66), and the
    interpreter no longer supplies first-party code: the bundle does. So
    the `pythonpath` this hands the probe is the selected bundle's `src`,
    which is exactly what the bootstrap puts in front of `sys.path` before
    importing the package, and the probe's `privacy_hud` answer is
    therefore an answer about the code that would really run.

    Receipt v1 is passed through to `runtime.load_receipt` unchanged: a
    historical receipt is still readable, is still repair input, and still
    names an interpreter a hook would spawn. The three unusable states are
    named rather than collapsed into absence, because a receipt nobody can
    read must never read as "no receipt" (the #66 interim review).
    """
    root = Path(data_dir)
    state = runtime_contract.classify_receipt(root)
    if state == "absent":
        return None, "absent"
    if state in ("unreadable", "malformed"):
        return None, state
    if state == "v1":
        return runtime.load_receipt(root)
    try:
        receipt = runtime_contract.read_receipt(root)
    except runtime_contract.RuntimeRefusal:
        return None, "unreadable"
    probe = receipt.get("dependency_probe")
    return {
        "python": receipt["python"],
        "pythonpath": str(Path(str(receipt["selected_bundle_root"])) / "src"),
        "plugin_data": str(root),
        "recorded_at": receipt.get("recorded_at"),
        "recorded": dict(probe) if isinstance(probe, dict) else {},
        "env": receipt.get("env") or {},
    }, ""


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
    receipt, problem = _pin_receipt(data_dir)
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
    one by hand — and even then the daemon exits five minutes after the last
    session ends (and after four hours of total silence regardless) with
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
    ledger_path = _ledger_path()
    if ledger_path is None:
        return _plugin_data_unset_check("Runtime pin")
    # Not `ledger_path.parent`: after #66's storage transition the active
    # store is `$PLUGIN_DATA/ledger/active.db`, so that parent is the
    # `ledger/` directory and the receipt is not in it.
    data_dir = runtime.plugin_data_dir() or ledger_path.parent

    # Before the receipt is read, and not after: a receipt anyone can write
    # is a program anyone can choose for a hook to execute, so the client
    # declines to spawn from one -- and `runtime_contract.classify_receipt`
    # refuses to read it at all, which is the right refusal with the wrong
    # remedy attached. There is no `/tmp` fallback any more (spec §6) --
    # an unset `PLUGIN_DATA` already returned a FAIL above -- but a receipt
    # in a directory another local user can write to (a shared scratch
    # directory someone explicitly exported) is still possible, and silence
    # here would leave the user with a daemon that never starts and no line
    # saying why.
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
                     "A directory other local users can write to is what "
                     "produces this -- for example PLUGIN_DATA exported to "
                     "a shared scratch directory."],
            fixes=[f"chmod 600 {_shell_path(receipt_file)}"] + _setup_fixes(),
        )

    receipt, problem = _pin_receipt(data_dir)

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


def _probe_daemon(sock_path: Path, timeout: float,
                  activation=None) -> tuple[str, float, str, str]:
    """One protocol-2 hello over the socket `hooks/handler.py` owns.

    Returns `(outcome, elapsed_ms, extra, daemon_release)`. The outcomes
    are the ones that are actually distinguishable from a client, and each
    maps to a different remedy: `responsive` (a hello naming the selected
    build and activation epoch came back), `mismatch` (something answered
    in this protocol and it is not the selected runtime), `refused` (a
    stale socket file that outlived its process), `timeout` (accepted but
    wedged), `no_reply` (accepted, then closed without answering — what
    `daemon._Handler.handle()` does for a request it will not serve),
    `bad_reply` (something is listening and it is not speaking this
    protocol at all), and `error` for everything else, notably the
    `OSError` from an AF_UNIX path over the kernel's ~104-byte
    `sockaddr_un` limit.

    **No event is sent.** Protocol 1's probe carried a `PreCompact` event
    chosen because `dispatch()` returns an empty allow for it before
    touching the ledger; protocol 2 establishes liveness with the hello
    itself, so a diagnostic no longer sends anything to the thing it
    diagnoses at all. The daemon dispatches nothing on a connection whose
    hello did not match, so an unselected probe cannot record either.

    **Any JSON object used to count as healthy here.** It no longer does:
    a reply is `responsive` only when it is a structurally valid hello
    reply naming this build and this epoch, which is the same test
    `runtime_client` applies before it will send a hook payload. A release
    string is reported only out of such a reply — a release named by an
    unvalidated peer is a string that peer chose (I1).
    """
    unknown = runtime_messages.UNKNOWN_DAEMON_RELEASE
    if activation is None:
        # Nothing selected: the only hello that can be sent is one no
        # daemon will match, which still tells liveness from silence.
        probe_activation = _unselected_probe_activation()
    else:
        probe_activation = activation
    request = runtime_client.encode_frame(
        runtime_client.hello_request(probe_activation))
    started = time.perf_counter()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(sock_path))
        sock.sendall(request)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    except ConnectionRefusedError:
        return "refused", (time.perf_counter() - started) * 1000, "", unknown
    except socket.timeout:
        return "timeout", (time.perf_counter() - started) * 1000, "", unknown
    except OSError as exc:
        return ("error", (time.perf_counter() - started) * 1000,
                type(exc).__name__, unknown)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    elapsed = (time.perf_counter() - started) * 1000
    if not buf.strip():
        return "no_reply", elapsed, "", unknown
    try:
        reply = runtime_client.decode_frame(buf.rstrip(b"\n"))
    except runtime_client.FrameError:
        return "bad_reply", elapsed, "reply was not a JSON object", unknown
    if activation is not None and runtime_client.is_matching_hello_reply(
            reply, activation):
        return "responsive", elapsed, "", str(reply["release"])
    if _is_protocol_two_hello_response(reply):
        return "mismatch", elapsed, "", unknown
    return "bad_reply", elapsed, "not a protocol-2 hello", unknown


def _is_protocol_two_hello_response(reply) -> bool:
    """Did *this daemon's* protocol answer, even though it did not match?

    Deliberately structural and deliberately narrow: version 2, the hello
    op, and a boolean `ok`. It decides which remedy the user is given —
    "repair the runtime" rather than "something else owns this socket
    path" — and nothing else. No field of it is ever printed.
    """
    return (isinstance(reply, dict)
            and runtime_contract.is_int(reply.get("v"))
            and reply.get("v") == runtime_contract.PROTOCOL_VERSION
            and reply.get("op") == runtime_client.OP_HELLO
            and isinstance(reply.get("ok"), bool))


def _unselected_probe_activation():
    """A hello no daemon can match, for a data directory that selects
    nothing.

    Sending one is how "a daemon is listening" is told from "the socket
    file outlived its process" when there is no receipt to authenticate
    with. It cannot be mistaken for authorization: the daemon refuses it
    and dispatches nothing.
    """
    identity = runtime_contract.RuntimeIdentity(
        release=runtime_contract.RELEASE, build_id="0" * 64,
        protocol=runtime_contract.PROTOCOL_VERSION,
        storage_generation=runtime_contract.STORAGE_GENERATION,
        readable_schemas=runtime_contract.READABLE_SCHEMAS,
        writable_schemas=runtime_contract.WRITABLE_SCHEMAS,
        snapshot_versions=runtime_contract.SNAPSHOT_VERSIONS)
    return runtime_contract.Activation(
        identity=identity, epoch="0" * 32,
        bundle_root=_bundle_root(), python=Path(sys.executable))


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
    daemon exits five minutes after the last session ends — so "no socket"
    between sessions is
    the *correct* state of a healthy setup, not a fault, and reporting it as
    `FAIL` would train the user to ignore this line. What decides the verdict
    is therefore whether the auto-start is configured: with a usable runtime
    receipt, absence is a `WARN` that says the next hook will fix it; with no
    receipt, nothing will ever start a daemon and it stays a `FAIL`.

    `pinned` exists so a caller (a test, mostly) can state that directly
    instead of arranging a receipt on disk; left `None` it is read from the
    same `PLUGIN_DATA` everything else here uses.
    """
    ledger_path = _ledger_path()
    if ledger_path is None:
        return _plugin_data_unset_check("Daemon")
    # Not `ledger_path.parent`, for the same reason as above: the daemon
    # socket lives beside the receipt in `$PLUGIN_DATA`, not beside the
    # relocated active store.
    data_dir = runtime.plugin_data_dir() or ledger_path.parent
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

    outcome, elapsed, extra, _release = _probe_daemon(
        sock_path, timeout, _selected_activation(data_dir))
    took = f"{elapsed:.0f} ms"

    if outcome == "responsive":
        check = Check(
            "Daemon", OK, f"responsive ({took} round trip)",
            details=["Probed with a protocol-2 hello and nothing else: no "
                     "event is sent, so this cannot record anything or "
                     "touch the ledger."],
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

    if outcome == "mismatch":
        return Check(
            "Daemon", FAIL,
            f"answering ({took}), but not as the selected runtime",
            details=["A Privacy HUD daemon is listening and it is not the "
                     "build this plugin selected, so it will refuse every "
                     "hook payload this installation sends.",
                     "See the Runtime alignment check for the recovery "
                     "command."] + mismatch,
            fixes=["Run the command the Runtime alignment check prints, in "
                   "another terminal."],
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
        # The plugin-data directory, not the ledger's parent: after #66's
        # storage transition the active store lives one level down and the
        # receipt is not beside it.
        data_dir = runtime.plugin_data_dir()
        if data_dir is None:
            return []
        receipt, problem = _pin_receipt(data_dir)
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
                         "Model loading enforces offline mode and local-only "
                         "files regardless of inherited environment values."],
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
        f"  {offline.download_env_prefix()} python3 -c \"from huggingface_hub "
        "import snapshot_download; "
        "snapshot_download('openai/privacy-filter', allow_patterns=["
        + ", ".join(f"'{name}'" for name in MODEL_FILES) + "])\"",
        "Only the explicit download command accesses Hugging Face; runtime "
        "and diagnostic checks never fetch missing weights.",
    ]


def _installed_plugin_dirs() -> list[tuple[str, str, Path]]:
    """Every cached copy of this plugin: `(marketplace, version, path)`.

    Codex's layout is `$CODEX_HOME/plugins/cache/<marketplace>/<plugin>/
    <version>/`, which is read directly rather than asked of `codex plugin
    list` — see the module docstring for why a diagnostic in *this* project
    does not shell out to an API client.
    """
    cache = codex.plugin_cache_root()
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


def _declared_version(repo: Path | None) -> str | None:
    """The version this checkout's `.codex-plugin/plugin.json` declares.

    `None` when there is no checkout to read (`repo is None`) or the
    manifest is missing or malformed — the same "cannot tell, don't guess"
    posture as the rest of this module.
    """
    if repo is None:
        return None
    try:
        return json.loads(
            (repo / ".codex-plugin" / "plugin.json").read_text()
        ).get("version")
    except Exception:
        return None


def _installed_plugin_entry(installed: list[tuple[str, str, Path]] | None = None
                            ) -> tuple[str, str, Path] | None:
    """The cached copy this doctor reports on: `(marketplace, version, path)`.

    The one answer to "which copy of us did Codex install": the one matching
    this checkout's declared version when Codex has one, otherwise the newest.
    `check_plugin_install` and `check_mcp_server` both resolve the installed
    plugin through here rather than each re-deriving it.

    The whole entry, not just the path: `check_plugin_install` needs the
    marketplace and version that go with the copy it is reporting on, and
    used to recover them with `next(e for e in installed if e[2] == root)` —
    a generator expression with no default, over a *second* reading of the
    cache. A plugin removed between the two readings raised `StopIteration`
    out of a diagnostic whose whole job is to survive a broken install.
    Passing `installed` in keeps both facts from one reading.

    `None` covers every reason there is nothing to point at: no Codex home,
    or a Codex home with no cached copy of this plugin.
    """
    if not _codex_home().is_dir():
        return None
    if installed is None:
        installed = _installed_plugin_dirs()
    if not installed:
        return None
    declared = _declared_version(_repo_root())
    chosen = None
    if declared is not None:
        chosen = next((entry for entry in installed if entry[1] == declared),
                      None)
    return chosen if chosen is not None else installed[-1]


def _installed_plugin_root() -> Path | None:
    """Where Codex put this plugin, or `None` if it has not.
    `_installed_plugin_entry`'s path, for the callers that need only that."""
    entry = _installed_plugin_entry()
    return None if entry is None else entry[2]


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
      debugging time. It is a warning rather than a failure because file
      divergence alone does not establish a runtime failure. The installed
      copy differs from this checkout. The report names the diverging files
      so the difference between "my edit is not live" and "a README typo"
      is visible at a glance.

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
                     f"{_display_path(codex.plugin_cache_root())}"
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
    declared = _declared_version(repo)

    # Compare against the copy matching this checkout's declared version when
    # Codex has one; otherwise the newest installed version, so the report is
    # about the code most likely to run. `_installed_plugin_entry` makes that
    # choice, over the listing already read above — so the three facts come
    # from one reading of the cache and cannot disagree about which copy this
    # report is about. `installed` is non-empty and the Codex home is a
    # directory (both checked above), so the fallback is unreachable — it is
    # there because a diagnostic must not raise on a path it cannot reach.
    entry = _installed_plugin_entry(installed)
    marketplace, version, path = entry if entry is not None else installed[-1]

    details = [f"{marketplace}/{PLUGIN_NAME} version " + ", ".join(
        sorted({v for _m, v, _p in installed}))
        + f" in {_display_path(codex.plugin_cache_root())}"]

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
            "re-add the plugin. The installed copy differs from this "
            "checkout; this comparison does not establish whether it works."],
        fixes=[f"codex plugin marketplace add {_shell_path(repo)} --json",
               f"codex plugin add {PLUGIN_NAME}@{marketplace} --json"],
    )


#: How long the MCP probe waits for a server that has to start an interpreter
#: and open the ledger. Generous: a slow answer is a slow answer, and a
#: doctor that times out on a working server teaches users to ignore it.
MCP_TIMEOUT = 20.0

#: The tools the server is expected to expose, restated from
#: `mcp/server.py::EXPOSED_TOOLS`. Two copies because `mcp/` is not a package
#: and importing it here would drag in the optional SDK — the copies are
#: pinned together by
#: `tests/test_doctor.py::test_the_doctors_tool_list_matches_the_servers`.
MCP_TOOLS = (
    "privacy.get_exposure_detail",
    "privacy.get_session_summary",
    "privacy.list_exposures",
    "privacy.read_guard_status",
    "privacy.update_policy",
)

#: The name the manifest gives our server, from `.codex-plugin/plugin.json`'s
#: `mcpServers` object. Read by key rather than taking whatever the object's
#: first value happens to be: a manifest may legitimately grow a second
#: server, and probing an arbitrary one would report on something else
#: entirely — passing or failing for reasons that have nothing to do with
#: this plugin. `tests/test_codex_facts.py` pins the manifest's key set to
#: exactly this name, and `tests/test_doctor.py` pins this constant to it.
MCP_SERVER_NAME = "privacy-hud"

#: Presentation cap, applied only after a complete allowlist match.
#: Truncation is not a privacy filter.
_STDERR_QUOTE_CHARS = 200

_STDERR_WITHHELD = (
    "The server wrote to stderr; its contents are withheld. "
    "Check the runtime with privacy-hud-setup."
)

#: Copies of the launcher's fixed _fail messages, including its prefix.
#: test_doctor_stderr_allowlist_matches_all_launcher_fail_calls pins these
#: to every _fail call site in mcp/server.py.
_LAUNCHER_STDERR_LINES = frozenset({
    "privacy-hud mcp: PLUGIN_DATA is not set and no Codex plugin-data "
    "directory for this plugin could be resolved; the plugin is not "
    "installed, or several candidates matched — run privacy-hud-setup",
    "privacy-hud mcp: runtime.json is writable by others; refusing to "
    "execute the interpreter it names",
    "privacy-hud mcp: the recorded interpreter is not executable; "
    "run privacy-hud-setup",
})
_LAUNCHER_RECEIPT_ERROR = (
    r"privacy-hud mcp: no usable runtime\.json "
    r"\([A-Za-z_][A-Za-z0-9_]*\); run privacy-hud-setup"
)


def _stderr_tail(text: str, *, allow_launcher: bool = False) -> str:
    """Return an allowlisted startup diagnostic or fixed withholding text.

    Match the last nonblank LF-delimited line without stripping its content.
    Before any initialize response, permit only the launcher's fixed message
    shapes; the sole variable field is an ASCII exception-class identifier.
    A match constrains the text, not its provenance. After an initialize
    response, quote nothing. Apply the presentation cap only after matching.
    """
    import re

    lines = [line for line in (text or "").split("\n") if line.strip()]
    if not lines:
        return ""
    last = lines[-1]
    if not allow_launcher or not (
        last in _LAUNCHER_STDERR_LINES
        or re.fullmatch(_LAUNCHER_RECEIPT_ERROR, last) is not None
    ):
        return _STDERR_WITHHELD
    return last if len(last) <= _STDERR_QUOTE_CHARS else \
        last[:_STDERR_QUOTE_CHARS] + "…"


#: The session id the doctor's ledger-read probe asks about. Fixed and
#: synthetic: the probe reads, and must never name a real session.
MCP_PROBE_SESSION = "__privacy_hud_doctor_probe__"

#: A `privacy.get_session_summary` reply, per accounting variant: the
#: exact key set and the two copy constants it must carry. Kept as literals
#: rather than imported, like the rest of this module's expectations: the
#: doctor checks a server it may not share a package version with.
_LEGACY_SUMMARY_KEYS = frozenset({
    "accounting_version", "legacy_score", "legacy_cap", "legacy_percent",
    "legacy_permitted_crossing_rows", "legacy_boundary_kinds",
    "legacy_prevented_rows", "score_label", "accounting_note"})
_UNRECORDED_SUMMARY_KEYS = frozenset({
    "accounting_version", "percent", "score_label", "accounting_note"})
_LEGACY_SUMMARY_LABEL = "legacy permitted-crossing score"
_LEGACY_SUMMARY_NOTE = (
    "Historical accounting includes permitted crossings and may collapse "
    "different outcomes. It does not establish confirmed disclosure.")
_UNRECORDED_SUMMARY_LABEL = "No session on record"
_UNRECORDED_SUMMARY_NOTE = (
    "No session record is available in this ledger. The percentage and "
    "counts are unavailable.")
#: The version-2 summary (#54 Phase 3), in its emitted key order.
_V2_SUMMARY_FIELDS = (
    "accounting_version", "accounting_status", "profile_id",
    "confirmed_points", "budget_cap", "percent", "observations",
    "event_rows", "finding_occurrences", "distinct_subjects",
    "exposure_events", "intervention_events", "distinct_disclosures",
    "concrete_recipients", "permission_actions", "denials_issued",
    "denials_enforced", "reads_stopped", "rewrite_actions_issued",
    "rewrite_actions_enforced", "unresolved_actions",
    "unresolved_subject_events", "unresolved_recipient_events",
    "percentage_unavailable_reasons", "score_label", "accounting_note")
_V2_SUMMARY_COUNTS = _V2_SUMMARY_FIELDS[6:23]
_V2_SUMMARY_REASONS = (
    "accounting_unavailable", "unresolved_actions", "unresolved_subjects",
    "unresolved_recipients", "coverage_incomplete")
_V2_SUMMARY_LABEL = "confirmed disclosure points"
_V2_SUMMARY_NOTE = (
    "This score is a versioned policy index over evidenced disclosures, "
    "not a measurement of harm. Permission, a returned denial, a returned "
    "rewrite, and a successful tool result do not by themselves confirm "
    "disclosure or host enforcement.")


def _mcp_probe(command, cwd, env, timeout) -> tuple[list[str], bool]:
    """Speak enough MCP over stdio to list a server's tools and make one
    ledger-backed call. Returns `(tool names, whether the call succeeded)`.

    Listing alone is not enough: with MCP SDK 2.x every ledger-backed tool
    failed on a worker thread (0.7.4 and earlier) while `tools/list` and the
    settings-only tool kept answering, and this check passed. The call is
    `privacy.get_session_summary` on `MCP_PROBE_SESSION`, a read: it adds no
    session, policy, event or coverage row. A reply counts only if it is a
    summary; zero totals are not evidence of monitoring and are not read as
    any.

    Raw JSON-RPC rather than the `mcp` client SDK: one thing this check must
    be able to report is that the SDK is missing, which it cannot do if
    importing the SDK is how it runs. Requests are sent one at a time and
    each answer read before the next, so the server never sees end-of-input
    while a call is in flight.

    Before any initialize response, a failure may carry an allowlisted
    launcher diagnostic as an exception note. Other nonblank stderr produces
    fixed withholding text. Once initialize has answered, all stderr is
    withheld, including text matching a launcher message. A failed tool call
    quotes nothing: tool errors and tracebacks can contain sensitive text.
    """
    import queue
    import subprocess
    import threading

    proc = subprocess.Popen(
        command, cwd=str(cwd), env=env, text=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines: queue.Queue = queue.Queue()

    def pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    deadline = time.monotonic() + timeout

    def send(*messages) -> None:
        assert proc.stdin is not None
        proc.stdin.write("".join(json.dumps(m) + "\n" for m in messages))
        proc.stdin.flush()

    def answer(request_id: int) -> dict | None:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("the server did not answer in time")
            try:
                line = lines.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError("the server did not answer in time") from None
            if line is None:
                return None
            try:
                message = json.loads(line)
            except ValueError:
                continue  # a server that logs to stdout, which ours never does
            if isinstance(message, dict) and message.get("id") == request_id:
                return message

    def stderr_after_exit() -> str:
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        return proc.stderr.read() if proc.stderr is not None else ""

    listed = None
    initialize_answered = False
    try:
        try:
            send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2024-11-05",
                             "capabilities": {},
                             "clientInfo": {"name": "privacy-hud-doctor",
                                            "version": "1"}}})
            if answer(1) is not None:
                initialize_answered = True
                send({"jsonrpc": "2.0", "method": "notifications/initialized"},
                     {"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                      "params": {}})
                listed = answer(2)
        except BrokenPipeError:
            listed = None
        except TimeoutError as exc:
            proc.kill()
            _attach_stderr(
                exc, stderr_after_exit(),
                allow_launcher=not initialize_answered)
            raise
        if listed is None or "result" not in listed:
            failure = ValueError(
                "the server answered nothing this check could read")
            _attach_stderr(
                failure, stderr_after_exit(),
                allow_launcher=not initialize_answered)
            raise failure
        names = sorted(t["name"] for t in listed["result"].get("tools", []))
        try:
            send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "privacy.get_session_summary",
                             "arguments": {"session_id": MCP_PROBE_SESSION}}})
            called = answer(3)
        except (OSError, TimeoutError):
            called = None
        return names, _is_summary_reply(called)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def _is_summary_reply(message: dict | None) -> bool:
    """Whether a `tools/call` answer is a successful summary."""
    if not isinstance(message, dict) or "error" in message:
        return False
    result = message.get("result")
    if not isinstance(result, dict) or result.get("isError") is True:
        return False
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return False
    first = content[0]
    if not isinstance(first, dict) or not isinstance(first.get("text"), str):
        return False
    try:
        summary = json.loads(first["text"])
    except ValueError:
        return False
    return _is_summary(summary)


def _is_count(value) -> bool:
    return type(value) is int and value >= 0


def _is_finite(value) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _is_summary(summary) -> bool:
    """Exactly one of the three summary variants, with its label and note.

    `accounting_version` must be an actual integer, not a boolean. The old
    four-integer summary is rejected: it cannot say whether its numbers are
    legacy or whether the session was recorded at all.
    """
    if not isinstance(summary, dict):
        return False
    version = summary.get("accounting_version")
    if type(version) is not int:
        return False
    if version == 0:
        return (set(summary) == _UNRECORDED_SUMMARY_KEYS
                and summary["percent"] is None
                and summary["score_label"] == _UNRECORDED_SUMMARY_LABEL
                and summary["accounting_note"] == _UNRECORDED_SUMMARY_NOTE)
    if version == 1:
        return (set(summary) == _LEGACY_SUMMARY_KEYS
                and _is_finite(summary["legacy_score"])
                and summary["legacy_score"] >= 0
                and _is_finite(summary["legacy_cap"])
                and summary["legacy_cap"] > 0
                and _is_count(summary["legacy_percent"])
                and summary["legacy_percent"] <= 100
                and _is_count(summary["legacy_permitted_crossing_rows"])
                and _is_count(summary["legacy_boundary_kinds"])
                and _is_count(summary["legacy_prevented_rows"])
                and summary["score_label"] == _LEGACY_SUMMARY_LABEL
                and summary["accounting_note"] == _LEGACY_SUMMARY_NOTE)
    if version == 2:
        return _is_v2_summary(summary)
    return False


def _is_v2_summary(summary: dict) -> bool:
    """The exact version-2 summary: its keys, finite nonnegative numbers,
    actual integer counts, reasons in their fixed order without repeats,
    a null percentage exactly when a reason holds, and its label and
    note."""
    if set(summary) != set(_V2_SUMMARY_FIELDS):
        return False
    reasons = summary["percentage_unavailable_reasons"]
    if not isinstance(reasons, list) or not all(
            type(r) is str and r in _V2_SUMMARY_REASONS for r in reasons):
        return False
    order = [_V2_SUMMARY_REASONS.index(r) for r in reasons]
    if order != sorted(set(order)):
        return False
    status = summary["accounting_status"]
    profile_id = summary["profile_id"]
    pct = summary["percent"]
    return (status in ("available", "unavailable")
            and (status == "unavailable") == (
                "accounting_unavailable" in reasons)
            and type(profile_id) is str and len(profile_id) == 64
            and all(c in "0123456789abcdef" for c in profile_id)
            and _is_finite(summary["confirmed_points"])
            and summary["confirmed_points"] >= 0
            and _is_finite(summary["budget_cap"])
            and summary["budget_cap"] > 0
            and ((pct is None) if reasons
                 else (_is_count(pct) and pct <= 100))
            and all(_is_count(summary[k]) for k in _V2_SUMMARY_COUNTS)
            and summary["score_label"] == _V2_SUMMARY_LABEL
            and summary["accounting_note"] == _V2_SUMMARY_NOTE)


def _attach_stderr(
        exc: Exception, err: str | None, *,
        allow_launcher: bool = False) -> None:
    """Attach only an allowlisted startup diagnostic or fixed withholding
    text. Never attach an unfiltered stderr line."""
    said = _stderr_tail(err or "", allow_launcher=allow_launcher)
    if said:
        exc.add_note(said)


def check_mcp_server(timeout: float = MCP_TIMEOUT) -> Check:
    """Does Codex's copy of the plugin declare an MCP server, and does it run?

    This check exists because failure here is silent. Codex warns and ignores
    an `mcpServers` value it cannot parse, and a server that dies at launch
    leaves the plugin loaded with its hooks and skills intact — so from
    inside Codex, "wired" and "quietly not wired" look identical. The same
    shape as the hooks trust gate, and the reason `$privacy read status` and
    this check's neighbours exist.

    It launches the server the way Codex does — host `python3`, the installed
    plugin as `cwd`, `PLUGIN_ROOT` and `PLUGIN_DATA` in the environment — and
    compares the tools it lists against `MCP_TOOLS`. The comparison is
    `==`, not "contains": a tool that can loosen protection appearing here
    is exactly what this must catch.

    Setting `PLUGIN_DATA` here used to be load-bearing in a way it should not
    have been: whether Codex sets it for an MCP server is an assumption the
    design never sourced, and a probe that supplies the variable itself
    cannot tell the difference. The launcher now resolves the directory
    without it (`server._resolved_data_dir`), so this sets it for
    determinism — to name the same ledger this doctor reports on — rather
    than to keep the server alive.
    """
    root = _installed_plugin_root()
    if root is None:
        return Check("MCP server", WARN,
                     "Codex has no installed copy of this plugin to check",
                     fixes=["codex plugin marketplace add "
                            "inin-zou/codex-privacy-hud",
                            f"codex plugin add {PLUGIN_NAME}@{PLUGIN_NAME}"])
    manifest_path = root / ".codex-plugin" / "plugin.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return Check("MCP server", FAIL,
                     f"cannot read the installed manifest ({type(exc).__name__})",
                     fixes=["Reinstall: ./install.sh"])
    servers = manifest.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        return Check(
            "MCP server", FAIL,
            "the installed manifest declares no MCP server",
            details=[f"read from {manifest_path}",
                     "Codex caches a plugin by version, so a manifest change "
                     "does not reach an existing install until you reinstall."],
            fixes=["Reinstall: ./install.sh"])
    declared = servers.get(MCP_SERVER_NAME)
    if not isinstance(declared, dict):
        return Check(
            "MCP server", FAIL,
            f"the installed manifest declares no server named "
            f"{MCP_SERVER_NAME!r}",
            details=[f"read from {manifest_path}",
                     "it declares: " + ", ".join(sorted(servers)),
                     "Probing whichever server the manifest happens to list "
                     "first would report on something else entirely."],
            fixes=["Reinstall: ./install.sh"])
    command = [declared.get("command", "python3"), *declared.get("args", [])]
    # The plugin-data directory, not the ledger's parent: once the storage
    # transition has run, that parent is `$PLUGIN_DATA/ledger/` and holds
    # no receipt, socket or settings file at all, so a server launched
    # against it would report on a directory nothing writes to.
    data_dir = runtime.plugin_data_dir()
    env = dict(os.environ)
    env["PLUGIN_ROOT"] = str(root)
    if data_dir is not None:
        env["PLUGIN_DATA"] = str(data_dir)
    try:
        names, read_ok = _mcp_probe(command, root, env, timeout)
    except (OSError, ValueError, TimeoutError) as exc:
        # Put the probe diagnostic first: an allowlisted startup cause or
        # fixed withholding text. A match does not authenticate its source.
        details = ["Codex reports nothing when this happens: the plugin "
                   "loads, and the tools are simply absent."]
        said = list(getattr(exc, "__notes__", ()))
        if said:
            details.insert(0, f"probe diagnostic: {said[0]}")
        return Check("MCP server", FAIL,
                     f"the server did not start ({type(exc).__name__})",
                     details=details,
                     fixes=["Reinstall: ./install.sh",
                            "Then: privacy-hud-doctor"])
    if names != sorted(MCP_TOOLS):
        extra = sorted(set(names) - set(MCP_TOOLS))
        missing = sorted(set(MCP_TOOLS) - set(names))
        return Check(
            "MCP server", FAIL,
            "the server exposes a different set of tools than it should",
            details=([f"unexpected: {', '.join(extra)}"] if extra else [])
                    + ([f"missing: {', '.join(missing)}"] if missing else []),
            fixes=["A tool that can loosen protection must not be exposed — "
                   "see mcp/server.py::EXPOSED_TOOLS"])
    if not read_ok:
        return Check(
            "MCP server", FAIL,
            "server started, but the MCP ledger-read probe failed",
            details=["The tools are listed, but a ledger-backed call "
                     "(privacy.get_session_summary) did not return a "
                     "summary."],
            fixes=["Reinstall: ./install.sh",
                   "Then: privacy-hud-doctor"])
    return Check("MCP server", OK,
                 f"declared and answering — {len(names)} read/tighten-only "
                 "tools; ledger read succeeded")


# --------------------------------------------------------------------- #
# runtime source, alignment, and the native reader (#66 Pair 7)
# --------------------------------------------------------------------- #

def _first_party_origin() -> Path:
    """The directory the running `privacy_hud` package was imported from.

    A separate function so tests can substitute it, for the same reason
    `_module_version` is one: in-process the real answer is always this
    checkout, and a test asserting that would prove nothing about a
    machine with an installed bundle and an older distribution beside it.
    """
    import privacy_hud

    return Path(privacy_hud.__file__).resolve().parent


def _bundle_root() -> Path:
    """The bundle the running first-party code came out of: two
    directories above the package (`<bundle>/src/privacy_hud`)."""
    return _first_party_origin().parents[1]


def _installed_distribution() -> tuple[str, Path] | None:
    """An installed `privacy-hud` distribution in the dependency
    environment, as `(version, location)`, or `None`.

    This is the package #66 exists to stop being trusted: before the
    bundle was the source of first-party code, whichever distribution the
    daemon's interpreter found first is what ran. Reporting it is not the
    same as using it, and the sentence saying it is unused is printed only
    where one was actually found — asserting it blind would be a claim
    about a machine nobody looked at.
    """
    try:
        from importlib import metadata
    except ImportError:  # pragma: no cover - stdlib since 3.8
        return None
    try:
        distributions = list(metadata.distributions())
    except Exception:
        return None
    for dist in distributions:
        try:
            name = (dist.metadata["Name"] or "").replace("_", "-").lower()
        except Exception:
            continue
        if name != "privacy-hud":
            continue
        try:
            version = str(dist.version)
            location = Path(str(dist.locate_file("privacy_hud"))).resolve()
        except Exception:
            continue
        return version, location
    return None


def _selected_activation(data_dir: Path | None = None):
    """The selected runtime for `data_dir`, or `None`.

    `None` covers every reason there is no selection to report on: no
    resolvable plugin-data directory, no receipt, a receipt that is not a
    v2 receipt, or a bundle whose files no longer hash to the recorded
    build. Each of those is a different remedy in `check_runtime_source`;
    none of them is a runtime this doctor may describe as selected.
    """
    root = runtime.plugin_data_dir() if data_dir is None else Path(data_dir)
    if root is None:
        return None
    try:
        return runtime_contract.load_activation(root)
    except (runtime_contract.RuntimeRefusal, OSError, ValueError):
        return None


def _repair_command(data_dir: Path) -> str:
    """The recovery command, over the selected bundle when there is one
    and this bundle otherwise. Never a placeholder path (§D)."""
    activation = _selected_activation(data_dir)
    root = (Path(activation.bundle_root) if activation is not None
            else _bundle_root())
    return runtime_repair.format_repair_command(root, Path(data_dir))


def _runtime_setup_fail(name: str, data_dir: Path, details=()) -> Check:
    """§D's missing/unusable-setup block, as a check.

    Its last two lines are the remedy, which is where this file's report
    format already puts a sentence and the command that follows it.
    """
    body = runtime_messages.RUNTIME_SETUP_FAIL.format(
        repair_command=_repair_command(data_dir)).split("\n")
    return Check(name, FAIL, body[1], details=list(details),
                 fixes=[body[2], body[3], body[4]])


def check_runtime_source() -> Check:
    """Which tree is the running first-party code actually from?

    The question #66 exists to answer. Before it, an installed
    `privacy-hud` distribution in the daemon's interpreter decided what
    ran, so a plugin update could leave older code live with every other
    check reporting a healthy setup. Now the selected bundle supplies the
    code and the recorded environment supplies only dependencies, and this
    check states which bundle that is — provenance, not a version string
    read out of package metadata.

    An installed distribution is reported where one exists, with the
    sentence saying it is not used. Where none was found, nothing is said
    about one: §D appends that line "only when established".
    """
    data_dir = runtime.plugin_data_dir()
    if data_dir is None:
        return _plugin_data_unset_check("Runtime source")

    activation = _selected_activation(data_dir)
    if activation is None:
        state = runtime_contract.classify_receipt(Path(data_dir))
        return _runtime_setup_fail(
            "Runtime setup", data_dir,
            details=[f"The runtime receipt in {_display_path(data_dir)} is "
                     f"{state}.",
                     "Until a bundle is selected, nothing establishes which "
                     "copy of this plugin's code would run."])

    selected = Path(activation.bundle_root)
    running = _bundle_root()
    if os.path.realpath(running) != os.path.realpath(selected):
        return _runtime_setup_fail(
            "Runtime setup", data_dir,
            details=["This command is running code from "
                     f"{_display_path(running)}, and the selected bundle is "
                     f"{_display_path(selected)}.",
                     "Two trees, so what this report says about one of them "
                     "is not a statement about the other."])

    body = runtime_messages.DOCTOR_RUNTIME_SOURCE_OK.format(
        release=activation.identity.release).split("\n")
    details = [f"Bundle: {_display_path(selected)}",
               f"Build: {activation.identity.build_id[:16]}…, activation "
               f"epoch {activation.epoch[:8]}…"]
    installed = _installed_distribution()
    if installed is not None:
        version, location = installed
        details.append(runtime_messages.DOCTOR_OLD_DISTRIBUTION_UNUSED)
        details.append(f"That distribution is {version}, in "
                       f"{_display_path(location.parent)}.")
    return Check("Runtime source", OK, body[1], details=details)


def check_runtime_alignment(timeout: float = DAEMON_TIMEOUT) -> Check:
    """Is the daemon that is listening the build this plugin selected?

    Separate from the Daemon check on purpose, and separate from the
    detector and storage checks too: one of them passing has never
    established the others (§C). A daemon can answer promptly, hold a
    valid ledger, and still be an older build that will refuse every hook
    payload this installation sends.

    A release is printed only when it arrived inside a hello this client
    validated. Anything else is `unknown`: a version string from a peer
    that failed validation is a string that peer chose, and a diagnostic
    in a privacy tool does not print those (I1).
    """
    data_dir = runtime.plugin_data_dir()
    if data_dir is None:
        return _plugin_data_unset_check("Runtime alignment")
    activation = _selected_activation(data_dir)
    if activation is None:
        return Check(
            "Runtime alignment", SKIP,
            "no selected runtime to compare a daemon against",
            details=["See the Runtime source check: without a selection "
                     "there is nothing for a daemon to match."])

    sock_path = _socket_path(data_dir)
    if not sock_path.exists():
        return Check(
            "Runtime alignment", WARN, "no daemon is answering",
            details=["Alignment is unverified rather than wrong: nothing is "
                     "listening to compare against (see the Daemon check).",
                     "Monitoring is unverified while that is true."],
            fixes=["Nothing to fix if you are between sessions — the next "
                   "hook starts one, and it starts from the selected "
                   "bundle."],
        )

    outcome, _elapsed, _extra, release = _probe_daemon(sock_path, timeout,
                                                       activation)
    if outcome == "responsive":
        body = runtime_messages.DOCTOR_RUNTIME_ALIGNMENT_OK.split("\n")
        return Check("Runtime alignment", OK, body[1],
                     details=[f"Daemon release: {release}.",
                              "Alignment is one fact. Detector availability "
                              "and ledger validity are the checks above and "
                              "below; this sentence does not speak for "
                              "them."])
    if outcome in ("refused", "no_reply"):
        return Check(
            "Runtime alignment", WARN, "no daemon is answering",
            details=["Alignment is unverified rather than wrong: see the "
                     "Daemon check for what is on that socket path."],
            fixes=["Fix the Daemon check first; alignment cannot be "
                   "established until something answers."],
        )

    body = runtime_messages.DOCTOR_RUNTIME_MISMATCH.format(
        plugin_release=runtime_contract.RELEASE,
        daemon_release_or_unknown=(
            release if outcome == "responsive"
            else runtime_messages.UNKNOWN_DAEMON_RELEASE),
        repair_command=_repair_command(data_dir)).split("\n")
    return Check("Runtime alignment", FAIL, body[1], details=body[2:5],
                 fixes=body[5:])


def _native_item_configured() -> bool:
    """Is Codex configured to draw the plugin's native status item?

    Read from `[tui].status_line` in Codex's own config, the same place
    `install.sh` writes it. A machine whose HUD is the ambient pane has no
    stake in which reader the installed binary contains, and warning it
    about one would be a permanent warning about something that is not in
    use — which is how a report teaches its reader to skip a line.
    """
    config = _codex_home() / "config.toml"
    try:
        import tomllib

        data = tomllib.loads(config.read_text(encoding="utf-8"))
    except Exception:
        return False
    tui = data.get("tui")
    if not isinstance(tui, dict):
        return False
    items = tui.get("status_line")
    return isinstance(items, list) and "privacy" in items


def check_native_reader() -> Check:
    """The Codex binary's own Privacy item, which this plugin does not
    ship and does not replace.

    There is no check that can pass here, and that is the finding. A
    patched build's reader is compiled into the binary; installing or
    repairing the plugin never touches it, and a matching Codex version
    number is not evidence about which reader it contains (§A). So this
    reports the state as unverified and names the surface that does not
    depend on it.
    """
    if not _native_item_configured():
        return Check(
            "Native HUD compatibility", SKIP,
            "the native Privacy item is not configured",
            details=["Nothing here depends on the installed binary's "
                     "reader: `[tui].status_line` in Codex's config does "
                     "not list `privacy`."])
    data_dir = runtime.plugin_data_dir()
    if data_dir is None:
        return _plugin_data_unset_check("Native HUD compatibility")
    activation = _selected_activation(data_dir)
    root = (Path(activation.bundle_root) if activation is not None
            else _bundle_root())
    body = runtime_messages.DOCTOR_NATIVE_UNVERIFIED.format(
        ambient_command=runtime_repair.format_ambient_command(
            root, Path(data_dir))).split("\n")
    return Check("Native HUD compatibility", WARN, body[1],
                 details=body[2:3], fixes=body[3:])


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
        ("Runtime source", check_runtime_source),
        ("Read guard", check_read_guard),
        ("Ledger", check_ledger),
        ("Runtime pin", lambda: check_runtime_pin(probe_timeout)),
        ("Daemon", lambda: check_daemon(timeout)),
        ("Runtime alignment", lambda: check_runtime_alignment(timeout)),
        ("Detector deps", check_detector_deps),
        ("Tier 3 model", lambda: check_tier3(load_model)),
        ("Plugin install", check_plugin_install),
        ("MCP server", check_mcp_server),
        ("Native HUD compatibility", check_native_reader),
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
