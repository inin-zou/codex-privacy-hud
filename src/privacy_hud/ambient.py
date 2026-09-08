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

That argument bounds the *frequency* of daemon contact, not its existence, and
there is exactly one question here the ledger cannot answer: **which session**
these numbers are about. See `_SessionPin` — the reading is polled every two
seconds, the identity is resolved about once every thirty.

**Why the file-existence check before opening.** `sqlite3.connect()` CREATES
a database file that does not exist, so constructing a `Ledger` unconditionally
would leave an empty `ledger.db` behind wherever `PLUGIN_DATA` happens to point
— including `/tmp` in an unconfigured shell. A glance-only surface must not
create state. If the file is not there, there is nothing to show and we show
nothing.

**Session resolution is imported, never re-derived.** `_ledger_path()` comes
from `local_ui_server`; *which session to show* comes from
`mcp_tools.resolve_audit_session`, the same function `$privacy` and the local
UI use. This module used to call `local_ui_server._latest_session_id` — the
most recently *started* session — which was left in place when `$privacy`
moved off it, and that left one machine with two surfaces that could name two
different sessions: the pane beside the window and the audit typed into it,
disagreeing about whose numbers were on screen. Two surfaces guessing the same
wrong answer is a bug; two surfaces giving different answers is a worse one,
because it makes the user distrust the surface that is right. Duplicating this
query has already caused one real production bug here (stray test sessions
shadowing the user's real session); there is one implementation of the whole
resolution now, and this module calls it.

**What this module does NOT say about session ambiguity.** `resolve_audit_
session` can come back uncertain — two Codex windows active in the same
moment, or no daemon to ask. `$privacy` prints `ResolvedSession.note`, a
two-sentence caveat, above a full-width table. The ambient line has no such
room: at 52 columns it is already `PRIVACY  Disclosure ███░░░░░░░ 28%  ›`, and
below 28 columns it is `⬤ 28%`. There is no honest way to fit a second,
differently-scoped warning into that, and the obvious shortcut — reusing
`⚠unverified` — is forbidden: that marker means *coverage*, "this session's
record has a known hole", and a glyph that also meant "I am not sure which
session this is" would be a glyph that means nothing (see "Three states, not
two" below, which is the work that would undo). So this surface says nothing
about ambiguity at all, and `--session-id` is the answer for anyone who needs
certainty in the pane. A HUD is a glance surface; the place to ask a question
it cannot answer in 52 columns is `$privacy`.

**Failure is silence, never a traceback** (I6's spirit — never break the
surface the user is working in). No `PLUGIN_DATA`, no `ledger.db`, no sessions
yet, a corrupt row, a sqlite error: every one of them degrades to design.md
§4's "Disabled" state, which renders *nothing* — never a "privacy off" banner
that itself nags. Per `hud_line`'s own docstring, that state is not reachable
through its signature and "the caller must decide not to call `hud_line` at
all"; `_line_for()` returning `None` is that decision.

**Three states, not two.** "Disabled" (render nothing) and a real reading are
not the whole space, and treating them as if they were is what let an I7
self-audit read as a clean pass against a session the daemon had never seen —
see `ledger.py`'s docstring for the incident. The third state is design.md §4's
"Engine degraded": a line IS drawn, carrying whatever the ledger actually
holds, with `⚠unverified` saying that what it holds is not a complete account.
It replaces neither of the others. "Disabled" still means there is nothing to
report on; unverified means there is something to report on and part of it was
never recorded. The distinction the user needs is between `0%` meaning "nothing
sensitive was disclosed" and `0%` meaning "I have no idea what was disclosed",
and for a privacy tool a single glyph is the cheapest honest way to draw it.
`Ledger.coverage()` decides which one this is; this module never infers it.

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

from . import mcp_tools
from .ledger import Ledger
from .local_ui_server import _ledger_path
from .matrix.loader import Matrix, load_matrix
from .render import hud_line

#: Default redraw interval for `--watch`, in seconds.
DEFAULT_INTERVAL = 2.0

#: How long a resolved session id is held before `--watch` asks again, in
#: seconds. Argued in full in `_SessionPin`; the short version is that it is
#: two orders of magnitude longer than the redraw interval on purpose.
RESOLVE_INTERVAL = 30.0

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


def _resolve_session_id() -> str | None:
    """Which session this pane is about, per `mcp_tools.resolve_audit_session`.

    Opens and closes its own `Ledger`, rather than reusing `_line_for`'s: the
    two run on different schedules now (identity ~30 s, reading ~2 s), and
    threading one connection between them would couple them back together for
    the sake of a sub-millisecond `sqlite3.connect`. The file-existence check
    is the same one `_line_for` makes and for the same reason — `connect()`
    creates the file, and a glance-only surface must not create state.

    Returns only an id. `ResolvedSession.basis`/`.note` are deliberately
    dropped here: this surface has nowhere honest to put them (see the module
    docstring), and pretending otherwise is what the `⚠unverified` glyph must
    not be conscripted into.

    Never raises — a corrupt ledger, an unreadable data dir, a wedged daemon:
    all of them are "no id", the same answer as a fresh install, and
    `_line_for` renders that as silence.
    """
    path = _ledger_path()
    if not path.exists():
        return None
    ledger = None
    try:
        ledger = Ledger(path, _matrix())
        return mcp_tools.resolve_audit_session(ledger, path.parent).session_id
    except Exception:
        return None
    finally:
        if ledger is not None:
            try:
                ledger.conn.close()
            except Exception:
                pass


class _SessionPin:
    """The session a HUD pane is showing, resolved rarely and held in between.

    **Why not once per redraw.** Two independent reasons, and either alone
    would be enough.

    The first is load. Resolution asks the daemon over its unix socket, and
    that socket is the hook hot path — the thing this module's opening
    paragraphs go out of their way not to touch. Asking every two seconds for
    the life of a pane would put the HUD back on the path it deliberately
    polls the database to stay off of, and the daemon answers serially, so a
    query arriving mid-scan waits (`daemon.QUERY_TIMEOUT`, 5 s) — a redraw loop
    is the wrong place to inherit that.

    The second is the surface itself. A HUD pane sits beside one Codex window
    and the user reads it out of the corner of their eye. "Most recently
    active session" is a signal that legitimately changes every few seconds
    when two windows are busy; a line resolved per redraw would hop between
    sessions mid-glance, so the number would be correct and the pane would
    still be lying about whose it is. Holding the id for a stretch makes the
    pane mean one thing at a time.

    **Why re-resolve at all, then.** A pane outlives sessions: the window it
    sits next to gets closed and reopened, Codex restarts, `start_clean_
    session` mints a new id. Pinning forever would freeze the HUD on a session
    that ended hours ago, which is the stale-number failure `run_watch` blanks
    the line to avoid. Thirty seconds is long enough that no redraw is ever
    waiting on the daemon and short enough that a new session shows up before
    the user wonders why it has not.

    **No id is not cached.** When resolution comes back empty — a ledger with
    no sessions at all — the deadline is not armed, so the next redraw asks
    again. Otherwise starting the pane before Codex would leave it blank for
    up to `interval` seconds after the session actually began, and "nothing
    yet" is exactly the state a user is most likely to be staring at while
    waiting for the first line to appear.

    **`--session-id` short-circuits the whole thing.** An explicitly pinned
    session is an answer, not a question: no daemon is asked, ever, and the id
    is returned unchanged whether or not anything is listening.
    """

    def __init__(self, explicit: str | None = None, *,
                 interval: float | None = None) -> None:
        # `RESOLVE_INTERVAL` is read here rather than used as a default
        # argument, which would bind it once at class-definition time and make
        # the module constant unpatchable — the shape of "configurable" that
        # only looks configurable.
        self.explicit = explicit
        self._interval = max(
            float(RESOLVE_INTERVAL if interval is None else interval), 0.0)
        self._session_id: str | None = None
        self._resolved_at: float | None = None

    def current(self) -> str | None:
        """The id to render this frame. Cheap on all but ~1 call in 15."""
        if self.explicit:
            return self.explicit
        # `monotonic`, not `time()`: a wall clock stepped by NTP would either
        # pin the id for hours or re-ask on every frame, and neither failure
        # would be visible in the pane.
        now = time.monotonic()
        if (self._session_id is not None and self._resolved_at is not None
                and now - self._resolved_at < self._interval):
            return self._session_id
        self._session_id = _resolve_session_id()
        self._resolved_at = now
        return self._session_id


def _line_for(session_id: str | None, width: int, *,
              explicit: bool = False) -> str | None:
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

    `session_id` arrives already resolved — `_SessionPin` owns that, on its own
    much slower schedule — so this function no longer chooses a session, it
    only reads one. `explicit` says the id came from `--session-id` rather than
    from resolution, which is the only case that gets the `_session_exists`
    gate: a typo must degrade to silence, while a live session the daemon named
    but the ledger has no row for is the genuinely unrecorded case and belongs
    on screen under `⚠unverified`, which is what `Ledger.coverage` returns for
    it below.
    """
    path = _ledger_path()
    if not path.exists():
        # Do not let sqlite3.connect() create it — see the module docstring.
        return None

    ledger = Ledger(path, _matrix())
    try:
        if not session_id:
            # No session resolved. Two very different situations share that
            # shape, and only one of them is "Disabled": a ledger nothing has
            # ever used, and a ledger that watched hook events go by unobserved
            # and recorded not one of them (`Ledger.unattributed_gaps`).
            # Rendering nothing for the second is how the incident in
            # `ledger.py`'s docstring stayed invisible for a whole audit.
            # There is no session to take a percentage from, so the line
            # carries the ledger's own figure — zero, because that is
            # genuinely all it holds — under the `⚠unverified` marker that
            # says the figure is not a reading of anything.
            if ledger.unattributed_gaps():
                return hud_line(0, width, 0, unverified=True)
            return None
        if explicit and not _session_exists(ledger, session_id):
            return None
        sid = session_id

        summary = ledger.summary(sid)
        coverage = ledger.coverage(sid)
        # I3: `percent` is the ledger's disclosure number, used verbatim.
        return hud_line(int(summary.percent), width,
                        int(summary.prevented),
                        unverified=not coverage.verified)
    finally:
        try:
            ledger.conn.close()
        except Exception:
            pass


def safe_line(pin: _SessionPin | None = None,
              width: int | None = None) -> str | None:
    """`_line_for()` with the failure guarantee attached.

    The broad `except Exception` is the point, not an oversight: this process
    renders into a pane the user is watching next to a live Codex session, and
    a traceback there is a worse outcome than a missing line for every possible
    cause. `KeyboardInterrupt` and `SystemExit` are BaseExceptions and so are
    deliberately not swallowed — Ctrl-C must still stop the loop.

    Takes a `_SessionPin` rather than a bare id because *which* session to draw
    is now a resolved answer with a cadence of its own, and the pin is what
    holds that answer between frames. A fresh, unpinned `_SessionPin()` is the
    default, so `safe_line()` still means "resolve and draw one line"; a caller
    in a loop passes the same pin every frame, which is what keeps the pane
    from hopping between sessions.
    """
    if pin is None:
        pin = _SessionPin()
    if width is None:
        width = shutil.get_terminal_size().columns
    try:
        return _line_for(pin.current(), width, explicit=bool(pin.explicit))
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
    line = safe_line(_SessionPin(session_id))
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

    One `_SessionPin` for the life of the loop, not one per frame: the reading
    is polled every `interval` seconds, the *identity* behind it is resolved
    about once every `RESOLVE_INTERVAL`. See `_SessionPin` for why those two
    cadences are deliberately two orders of magnitude apart.

    Ctrl-C is a normal exit, not a failure: emit the newline the redraw loop
    has been withholding (every frame ends mid-line, by design) so the shell
    prompt lands on a clean row, and return 0.
    """
    out = sys.stdout if out is None else out
    interval = max(float(interval), MIN_INTERVAL)
    pin = _SessionPin(session_id)
    try:
        while True:
            line = safe_line(pin)
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
        help="pin the HUD to this session instead of resolving the live one "
             "(the same resolution $privacy uses)")
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
