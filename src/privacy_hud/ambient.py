# src/privacy_hud/ambient.py
"""The Level 1 ambient HUD: a standalone companion process that polls the
ledger and redraws `render.hud_line()` in place (design.md §4).

**Why this is a separate process and not a Codex status item.** Stock Codex's
`tui.status_line` accepts an ordered list of *built-in* status-item
identifiers only (PRD.md §9, architecture.md §9) — there is no plugin-owned
renderer, so nothing this package produces can appear under the Codex input
area without patching and recompiling Codex's own Rust source. Prior art
confirms the cost of that path: the forked-binary HUDs go stale on every
upstream Codex release, and `brandonwie/codex-hud`'s *default* mode avoids
patching entirely by doing exactly what this module does — a second terminal
pane, polling, one line redrawn in place. We deliberately do not patch the
Codex binary, and README's known-limits section must keep saying so
(CLAUDE.md §5: do not claim the plugin injects a native Codex footer).

**Why polling the DB rather than asking the daemon.** The daemon's unix
socket is the hook hot path, and that path already spends ~280 ms on real
tier-3 model inference per call. A HUD that redraws every two seconds has no
business adding load to it. The ledger runs in WAL mode (`PRAGMA
journal_mode=WAL`, `Ledger.__init__`), so a second connection reading while
the daemon writes is safe and blocks nobody. "Read-only" here means this
module never records, updates, or deletes an event: it opens a `Ledger` (whose
constructor runs `CREATE TABLE IF NOT EXISTS` DDL — a no-op against a ledger
the daemon already created) and calls `summary()`.

**Why the file-existence check before opening.** `sqlite3.connect()` CREATES
a database file that does not exist, so constructing a `Ledger` unconditionally
would leave an empty `ledger.db` behind wherever `PLUGIN_DATA` happens to point
— including `/tmp` in an unconfigured shell. A glance-only surface must not
create state. If the file is not there, there is nothing to show and we show
nothing.

**Session resolution is imported, never re-derived.** `_ledger_path()` and
`_latest_session_id()` come from `local_ui_server`. Duplicating the
"most-recently-started session" query has already caused one real production
bug in this project (stray test sessions shadowing the user's real session);
there is exactly one implementation of it and this module calls it.

**Failure is silence, never a traceback** (I6's spirit — never break the
surface the user is working in). No `PLUGIN_DATA`, no `ledger.db`, no sessions
yet, a corrupt row, a sqlite error: every one of them degrades to design.md
§4's "Disabled" state, which renders *nothing* — never a "privacy off" banner
that itself nags. Per `hud_line`'s own docstring, that state is not reachable
through its signature and "the caller must decide not to call `hud_line` at
all"; `_line_for()` returning `None` is that decision.

**No colour.** `hud_line` returns plain text, and design.md §3's band colours
are applied by a client that has the band — a channel this module's inputs do
not carry. Rather than invent a colour layer, we emit none, which makes
`NO_COLOR` respected by construction. The only escape sequence written
anywhere here is `\\x1b[K` (erase to end of line) in `--watch`, which is cursor
control, not colour, and is what makes the line redraw in place instead of
scrolling a useless log past the user.

I1: the line is a percentage, a bar, and a count of prevented events. No
session content, no data value, no path, no file name is ever printed.
I3: the percentage is `summary()["percent"]` verbatim — the disclosure number
the ledger already computed — never recomputed from raw event counts.
I5: nothing here implies disclosed data can be withdrawn.

Stdlib only.
"""
from __future__ import annotations

import argparse
import shutil
import sys
import time

from .ledger import Ledger
from .local_ui_server import _latest_session_id, _ledger_path
from .matrix.loader import Matrix, load_matrix
from .render import hud_line

#: Default redraw interval for `--watch`, in seconds.
DEFAULT_INTERVAL = 2.0

#: Floor for `--watch N`. A zero or negative interval would spin the loop as
#: fast as sqlite can answer, which is a busy-wait on the same disk the daemon
#: is writing to — a HUD that costs more than what it reports on.
MIN_INTERVAL = 0.1

#: Erase-to-end-of-line, so a shorter line never leaves the tail of a longer
#: previous one on screen. Paired with `\r` (carriage return, no line feed) it
#: is the whole of the redraw-in-place mechanism.
_CLEAR_LINE = "\r\x1b[K"

_MATRIX: Matrix | None = None


def _matrix() -> Matrix:
    """Load `tables.toml` once per process rather than once per redraw.

    A `--watch` loop calls this every interval for the life of the pane; the
    tables are a packaged, immutable-per-run data file, so re-reading and
    re-parsing them each tick would be pure waste. Loaded lazily instead of at
    import time so that importing this module (as `tests` and `--help` do)
    costs nothing.
    """
    global _MATRIX
    if _MATRIX is None:
        _MATRIX = load_matrix()
    return _MATRIX


def _session_exists(ledger: Ledger, session_id: str) -> bool:
    """Whether `session_id` is a session the ledger actually knows about.

    Only consulted for an explicit `--session-id`. `Ledger.summary()` answers
    for an unknown id with a well-formed zero — `percent: 0`, no exposures —
    and rendering that would put `Disclosure ░░░░░░░░░░ 0%` on screen for a
    session we have never heard of. A clean-looking number we cannot back is
    exactly the overclaim CLAUDE.md §5 forbids, so a typo'd or stale id
    degrades to the "Disabled" state (nothing rendered) instead.
    """
    row = ledger.conn.execute(
        "SELECT 1 FROM sessions WHERE session_id=? LIMIT 1", (session_id,)
    ).fetchone()
    return row is not None


def _line_for(session_id: str | None, width: int) -> str | None:
    """Build the HUD line, or return `None` when there is nothing to show.

    `None` is design.md §4's "Disabled" state and the reason this function
    exists: `hud_line` cannot express it (its docstring says so explicitly),
    and it must not be called at all in that case.

    Every failure mode collapses into `None`: no ledger file, no sessions
    recorded, an unknown explicit session id, a sqlite error, a corrupt row.
    Note in particular that an out-of-range percent is NOT clamped before
    reaching `hud_line` — `_check_band` failing loud on a percent outside
    [0, 100] is a deliberate upstream tripwire, and clamping here would hide a
    corrupt ledger behind a plausible-looking bar. The exception propagates to
    `safe_line()`, which turns it into silence rather than a wrong number.

    The connection is opened and closed per call rather than held across a
    `--watch` loop: opening sqlite is sub-millisecond, holding a reader open
    for hours against a file the daemon is actively writing buys nothing, and
    reopening means a ledger created (or replaced) after the HUD started is
    picked up on the next tick instead of requiring a restart.
    """
    path = _ledger_path()
    if not path.exists():
        # Do not let sqlite3.connect() create it — see the module docstring.
        return None

    ledger = Ledger(path, _matrix())
    try:
        if session_id:
            if not _session_exists(ledger, session_id):
                return None
            sid = session_id
        else:
            sid = _latest_session_id(ledger)
            if not sid:
                return None

        summary = ledger.summary(sid)
        # I3: `percent` is the ledger's disclosure number, used verbatim.
        return hud_line(int(summary.percent), width,
                        int(summary.prevented))
    finally:
        try:
            ledger.conn.close()
        except Exception:
            pass


def safe_line(session_id: str | None = None, width: int | None = None) -> str | None:
    """`_line_for()` with the failure guarantee attached.

    The broad `except Exception` is the point, not an oversight: this process
    renders into a pane the user is watching next to a live Codex session, and
    a traceback there is a worse outcome than a missing line for every possible
    cause. `KeyboardInterrupt` and `SystemExit` are BaseExceptions and so are
    deliberately not swallowed — Ctrl-C must still stop the loop.
    """
    if width is None:
        width = shutil.get_terminal_size().columns
    try:
        return _line_for(session_id, width)
    except Exception:
        return None


def run_once(session_id: str | None = None, *, out=None, err=None) -> int:
    """Print exactly one HUD line and return 0.

    Nothing is written to stdout in the "Disabled" state, so this composes
    byte-exactly into a shell prompt or another status bar: the caller either
    gets one line or gets nothing at all. The one-line explanation of *why*
    there is nothing goes to stderr, where a human running the command by hand
    sees it and a `$(...)` substitution does not. design.md §4's "never a
    'privacy off' banner that itself nags" is a rule about the ambient line
    itself; a person who just typed the command and got no output is owed an
    answer, and stderr is how it is given without polluting the surface.
    """
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    line = safe_line(session_id)
    if line is None:
        print("privacy-hud: no recorded session to report on yet.", file=err)
        return 0
    print(line, file=out)
    return 0


def run_watch(session_id: str | None = None,
              interval: float = DEFAULT_INTERVAL, *, out=None) -> int:
    """Redraw the HUD line in place every `interval` seconds until Ctrl-C.

    In place, not appended: `\\r` returns to column 0 and `\\x1b[K` erases what
    was there, so the pane holds exactly one line for the life of the session.
    A scrolling log of near-identical lines would be unreadable and would fight
    the Codex session in the neighbouring pane for the user's attention, which
    is precisely what design.md §4's "ambient" means it must not do.

    In the "Disabled" state the line is cleared and nothing is drawn — so a HUD
    that was showing a percentage for a session that has since gone away blanks
    out rather than freezing on a stale number.

    Ctrl-C is a normal exit, not a failure: emit the newline the redraw loop
    has been withholding (every frame ends mid-line, by design) so the shell
    prompt lands on a clean row, and return 0.
    """
    out = sys.stdout if out is None else out
    interval = max(float(interval), MIN_INTERVAL)
    try:
        while True:
            line = safe_line(session_id)
            out.write(_CLEAR_LINE + (line or ""))
            out.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        out.write("\n")
        out.flush()
        return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="privacy-hud-ambient",
        description="Ambient Level 1 privacy HUD: one line, polled from the "
                    "local disclosure ledger. Run it in a terminal pane beside "
                    "your Codex session.",
    )
    # Mutually exclusive so that `--once --watch` is a usage error the user
    # sees immediately, rather than one of the two silently winning.
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--once", action="store_true",
        help="print one line and exit (the default with no flags)")
    mode.add_argument(
        "--watch", nargs="?", type=float, const=DEFAULT_INTERVAL, default=None,
        metavar="SECONDS",
        help=f"redraw in place every SECONDS (default {DEFAULT_INTERVAL:g})")
    parser.add_argument(
        "--session-id", default=None, metavar="ID",
        help="report on this session instead of the most recently started one")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for `python -m privacy_hud.ambient` and the
    `privacy-hud-ambient` console script. Returns a process exit code.

    `--help` and a usage error are the only non-zero paths, and they come from
    argparse's own `SystemExit`, which is caught here so that this function
    keeps its "returns an int" contract for the console-script wrapper rather
    than raising through it. Every *runtime* failure — the ones the user cannot
    do anything about mid-session — exits 0 with no output.
    """
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = _build_parser().parse_args(argv)
    except SystemExit as exc:  # --help (0) or a usage error (2)
        return int(exc.code or 0)

    if args.watch is not None:
        return run_watch(args.session_id, args.watch)
    return run_once(args.session_id)


if __name__ == "__main__":
    sys.exit(main())
