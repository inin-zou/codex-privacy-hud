# src/privacy_hud/hud_snapshot.py
"""Contract A (spec §4.1): the HUD snapshot file, its one writer and its
Python reader.

`$PLUGIN_DATA/hud/<session_id>.json` carries ten fields and no strings:

    {"v": 2, "accounting_version": 1, "percent": 28,
     "confirmed_points": null, "denials_issued": null,
     "legacy_prevented_rows": 2, "unresolved_actions": null,
     "unverified": false, "hidden": false, "updated_at": 1757900000.0}

**Version 2 (#54 phase 1).** `accounting_version` says which accounting the
numbers are, and every quantity is nullable, so no reading is invented:

- 0, unrecorded: every quantity null, `unverified` true.
- 1, legacy: `percent` and `legacy_prevented_rows` are numbers; the other
  three are null. A legacy percentage is the legacy permitted-crossing
  score, and `legacy_prevented_rows` counts rows, not denied calls.
- 2, reserved for new accounting: finite nonnegative `confirmed_points`,
  integer `denials_issued` and `unresolved_actions`, null legacy count. A
  numeric percentage requires `unresolved_actions == 0` and `unverified`
  false. No phase 1 writer publishes it.

A version 1 file (`percent`, `blocked`, ...) is still read, as explicitly
legacy: `blocked` becomes `legacy_prevented_rows`, never a denial count.
Counts above `MAX_COUNT` (2^53 - 1, the largest integer both JSON readers
represent exactly) are malformed.

Two readers exist: `ambient.py` (this package) and the Codex status-line patch
(`privacy_status.rs`). Both apply the same rules, which live here as
constants so the Rust port can cite one source: a file older than
`STALE_AFTER` seconds is treated as absent, any schema version other than
`SNAPSHOT_VERSION` or the legacy version 1 is treated as absent, and every
malformed byte is treated as absent. "Absent" renders nothing. A frozen daemon must never leave a
frozen number on screen, and a number that cannot be vouched for is never
drawn.

**Why a file, not the socket.** The Codex TUI repaints its status line often.
Asking the daemon over its unix socket on each repaint would put the HUD back
on the hook hot path that `ambient.py` deliberately stays off. A sub-kilobyte
file read is microseconds and needs no daemon to be answering.

**Why atomic.** The writer writes `<sid>.json.tmp` and `os.replace`s it. A
reader therefore sees either the old snapshot or the new one, never a
truncated one — `test_publish_is_atomic_under_a_concurrent_reader` hammers
this.

**I1.** There is nowhere to put content: the schema in
`tests/matrix/hud_snapshot.schema.json` has no string-typed field and
`additionalProperties: false`. `session_id` is the file *name*, which the
ledger already uses as a row key; it is a UUID, not content.

`_daemon.json` is a second, tiny file in the same directory with one bit the
per-session files cannot carry: whether the ledger holds hook events it
watched go by without recording (`Ledger.unattributed_gaps()`). `ambient.py`
used to open sqlite for that one question; now the daemon answers it here at
startup and readers stay sqlite-free.

**Why there is a heartbeat** (`heartbeat()`, spec §4.1). Snapshots are
written on hook events, and both readers treat a file older than
`STALE_AFTER` as absent. Those two facts together used to mean that a
session which merely went quiet — the user reading, thinking, or away from
the keyboard for 31 seconds — lost its status item, and that `_daemon.json`
(written once, at daemon start) went stale half a minute in, so
`ambient.py` stopped rendering the unattributed-gaps line for the entire
remaining life of the daemon. Staleness is supposed to mean "the daemon
that writes this is gone", and without a heartbeat it meant "nothing has
happened lately", which is the opposite of the claim the rule exists to
make. So the daemon re-stamps `updated_at` on the snapshots of the sessions
it believes are live every `HEARTBEAT_INTERVAL` seconds, changing no other
field. The numbers still only ever change on a hook event; the heartbeat is
the daemon saying "still here", which is exactly what a reader checking
`updated_at` is asking.

Stdlib only.
"""
from __future__ import annotations

import json
import math
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypeGuard

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .ledger import SessionSummary

SNAPSHOT_VERSION = 2
#: The legacy snapshot version, still read and normalized to accounting 1.
LEGACY_SNAPSHOT_VERSION = 1
#: `_daemon.json`'s own version. Separate from `SNAPSHOT_VERSION`: the
#: marker's contract did not change when the snapshot's did.
DAEMON_MARKER_VERSION = 1
#: The largest count either reader accepts: 2^53 - 1, which JSON readers in
#: both languages represent exactly.
MAX_COUNT = 2**53 - 1
#: A snapshot older than this many seconds is treated as absent.
STALE_AFTER = 30.0
#: How often the daemon re-stamps a live session's snapshot (`heartbeat`).
#: Comfortably under `STALE_AFTER` so a single missed beat — a daemon busy
#: with a tier-3 scan when the interval elapsed — cannot make a live
#: session's item blink out. Two beats can be missed before a reader gives
#: up, which is the margin this number buys.
HEARTBEAT_INTERVAL = 10.0
#: `sweep()` removes snapshots older than this; matches the daemon's own
#: four-hour bound on a leaked session reference (daemon.py, "Lifetime policy").
SWEEP_AFTER = 4 * 3600.0
_DAEMON_MARKER = "_daemon.json"


def hud_dir(data_dir) -> Path:
    return Path(data_dir) / "hud"


def snapshot_path(data_dir, session_id: str) -> Path:
    """Where `session_id`'s snapshot lives. Refuses anything that could name
    a file outside `hud/`: the id is used as a file name, and a hook payload
    is untrusted input."""
    if not session_id or "/" in session_id or session_id.startswith(".") \
            or os.sep in session_id:
        raise ValueError("session_id is not a safe file name")
    return hud_dir(data_dir) / f"{session_id}.json"


@dataclass(frozen=True, kw_only=True)
class Snapshot:
    """One validated snapshot, normalized to version 2's fields."""

    accounting_version: Literal[0, 1, 2]
    percent: int | None
    confirmed_points: float | None
    denials_issued: int | None
    legacy_prevented_rows: int | None
    unresolved_actions: int | None
    unverified: bool
    hidden: bool
    updated_at: float

    def doc(self, *, hidden: bool, updated_at: float) -> dict:
        """This reading as a version 2 document, with `hidden` and
        `updated_at` replaced and every reading field kept."""
        return {"v": SNAPSHOT_VERSION,
                "accounting_version": self.accounting_version,
                "percent": self.percent,
                "confirmed_points": self.confirmed_points,
                "denials_issued": self.denials_issued,
                "legacy_prevented_rows": self.legacy_prevented_rows,
                "unresolved_actions": self.unresolved_actions,
                "unverified": self.unverified,
                "hidden": hidden, "updated_at": updated_at}


class HudPublisher:
    """The only writer of contract A. One instance per daemon."""

    def __init__(self, data_dir) -> None:
        self.data_dir = Path(data_dir)
        # The `unattributed_gaps` bit this publisher last wrote, so
        # `heartbeat()` can re-stamp `_daemon.json` without re-opening the
        # ledger to ask a question whose answer it already published. `None`
        # until `mark_daemon` has run; the heartbeat then falls back to
        # reading the file it wrote, and re-stamps nothing if there is no
        # file either. It never guesses a value — a wrong bit here would put
        # a "record incomplete" banner on a complete session, or take one
        # off an incomplete one.
        self._unattributed_gaps: bool | None = None
        # The sessions *this* publisher has written a reading for. A
        # snapshot carries no producer identity (#66 §A), so this is the
        # only thing that can tell a reading this process derived from one
        # a previous daemon left behind, and `heartbeat` re-stamps nothing
        # that is not in here. Deliberately per-instance and never
        # persisted: a file that said who wrote it would be a file anyone
        # could write that claim into.
        self._published: set[str] = set()

    # -- writing -----------------------------------------------------------

    def _write(self, path: Path, doc: dict) -> None:
        d = hud_dir(self.data_dir)
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(doc, fh, separators=(",", ":"))
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, path)

    def _current_hidden(self, session_id: str) -> bool:
        snap = read_snapshot(self.data_dir, session_id, ignore_staleness=True)
        return bool(snap.hidden) if snap else False

    def publish(self, session_id: str, *, summary: SessionSummary,
                unverified: bool) -> None:
        """Write `summary` as a version 2 snapshot.

        A legacy summary publishes accounting 1 with its percentage and
        prevented-row count; an unrecorded summary publishes accounting 0
        with every quantity null and `unverified` true. No quantity is
        converted or defaulted: the document is validated before it is
        written, and an invalid one raises rather than reaching a reader.

        A version-2 summary (#54 Phase 4) publishes accounting 2 with its
        nullable percentage, confirmed points, denials issued and unresolved
        actions, exactly as the summary holds them. Key loss changes the
        percentage, never `unverified`, which stays the coverage flag.
        """
        fields: dict[str, int | float | bool | None]
        if summary.accounting_version == 2:
            from .accounting import AccountingSummary
            if not isinstance(summary, AccountingSummary):
                raise ValueError("snapshot does not satisfy contract A")
            doc = {"v": SNAPSHOT_VERSION, "accounting_version": 2,
                   "percent": summary.percent,
                   "confirmed_points": summary.confirmed_points,
                   "denials_issued": summary.denials_issued,
                   "legacy_prevented_rows": None,
                   "unresolved_actions": summary.unresolved_actions,
                   "unverified": bool(unverified),
                   "hidden": self._current_hidden(session_id),
                   "updated_at": time.time()}
            if _parse(doc) is None:
                raise ValueError("snapshot does not satisfy contract A")
            self._write(snapshot_path(self.data_dir, session_id), doc)
            self._published.add(session_id)
            return
        if summary.accounting_version == 1:
            fields = {"accounting_version": 1,
                      "percent": summary.legacy_percent,
                      "legacy_prevented_rows": summary.legacy_prevented_rows,
                      "unverified": bool(unverified)}
        elif summary.accounting_version == 0:
            fields = {"accounting_version": 0, "percent": None,
                      "legacy_prevented_rows": None, "unverified": True}
        else:
            raise ValueError("snapshot does not satisfy contract A")
        doc = {"v": SNAPSHOT_VERSION,
               "accounting_version": fields["accounting_version"],
               "percent": fields["percent"],
               "confirmed_points": None, "denials_issued": None,
               "legacy_prevented_rows": fields["legacy_prevented_rows"],
               "unresolved_actions": None,
               "unverified": fields["unverified"],
               "hidden": self._current_hidden(session_id),
               "updated_at": time.time()}
        if _parse(doc) is None:
            raise ValueError("snapshot does not satisfy contract A")
        self._write(snapshot_path(self.data_dir, session_id), doc)
        # Only after the write succeeded, for the same reason
        # `mark_daemon` records its bit last: claiming a reading we failed
        # to publish would let a later heartbeat keep an older daemon's
        # file alive under this publisher's name.
        self._published.add(session_id)

    def set_hidden(self, session_id: str, hidden: bool) -> None:
        """Contract B. Flips `hidden`, refreshes `updated_at`, keeps every
        reading field. A missing or malformed snapshot is left alone: a
        reading cannot be built from its absence, and the status call then
        reports `absent`."""
        snap = read_snapshot(self.data_dir, session_id, ignore_staleness=True)
        if snap is None:
            return
        self._write(snapshot_path(self.data_dir, session_id),
                    snap.doc(hidden=bool(hidden), updated_at=time.time()))

    def retire(self, session_id: str) -> None:
        self._published.discard(session_id)
        try:
            snapshot_path(self.data_dir, session_id).unlink()
        except (FileNotFoundError, ValueError):
            pass

    def sweep(self, max_age_s: float = SWEEP_AFTER, *,
              now: float | None = None) -> int:
        """Delete snapshots (and stray `.tmp` files) older than `max_age_s`.
        Returns how many were removed. Never raises."""
        now = time.time() if now is None else now
        removed = 0
        d = hud_dir(self.data_dir)
        if not d.is_dir():
            return 0
        for p in d.iterdir():
            if p.name == _DAEMON_MARKER:
                continue
            try:
                if p.name.endswith(".tmp") or now - p.stat().st_mtime > max_age_s:
                    p.unlink()
                    removed += 1
            except OSError:
                continue
        return removed

    def heartbeat(self, session_ids: Iterable[str]) -> None:
        """Re-stamp `updated_at` on each listed session's snapshot and on
        `_daemon.json`, changing nothing else. The daemon calls this every
        `HEARTBEAT_INTERVAL` seconds for the sessions it believes are live;
        see the module docstring for why staleness would otherwise mean the
        wrong thing.

        Writes nothing for a session with no snapshot file (retired, or
        never started) and nothing for one whose file no longer parses —
        refreshing a file we cannot read would be vouching for bytes we did
        not understand. Individual write failures are skipped rather than
        raised: a heartbeat is housekeeping for a display surface (I6), and
        one unwritable snapshot must not cost the others theirs.

        **And nothing for a reading this publisher did not write** (#66).
        A daemon restarted in a data directory that still holds an older
        daemon's snapshots would otherwise keep those readings alive
        forever: `updated_at` is what both readers use to decide a reading
        is still current, so re-stamping an inherited file is a claim that
        numbers this process never derived describe the runtime running
        now. Explicit repair retires the old publisher's files before the
        replacement starts; this is what holds when a daemon comes up
        without one.
        """
        for session_id in session_ids:
            if session_id not in self._published:
                continue
            try:
                path = snapshot_path(self.data_dir, session_id)
            except ValueError:
                continue
            snap = read_snapshot(self.data_dir, session_id,
                                 ignore_staleness=True)
            if snap is None:
                continue
            try:
                self._write(path, snap.doc(hidden=snap.hidden,
                                           updated_at=time.time()))
            except OSError:
                continue
        gaps = self._unattributed_gaps
        if gaps is None:
            gaps = read_daemon_marker(self.data_dir, ignore_staleness=True)
        if gaps is not None:
            try:
                self.mark_daemon(unattributed_gaps=gaps)
            except OSError:
                pass

    def mark_daemon(self, *, unattributed_gaps: bool) -> None:
        gaps = bool(unattributed_gaps)
        self._write(hud_dir(self.data_dir) / _DAEMON_MARKER,
                    {"v": DAEMON_MARKER_VERSION,
                     "unattributed_gaps": gaps,
                     "updated_at": time.time()})
        # Only after the write succeeded: remembering a bit we failed to
        # publish would let a later heartbeat "preserve" a value no reader
        # ever saw.
        self._unattributed_gaps = gaps


# -- reading -----------------------------------------------------------------

def _load(path: Path) -> dict | None:
    """The file's JSON object, or `None`. Version checks belong to the
    specific reader: the snapshot and the marker have different ones.
    Non-finite numbers (`NaN`, `Infinity`) are refused at parse time."""
    try:
        with open(path, "rb") as fh:
            doc = json.load(fh, parse_constant=_refuse_constant)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _refuse_constant(name: str):
    raise ValueError(f"non-finite number {name}")


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v) -> TypeGuard[int | float]:
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return False
    try:
        return math.isfinite(v)
    except OverflowError:
        return False


def _is_count(v) -> bool:
    return _is_int(v) and 0 <= v <= MAX_COUNT


def _is_percent(v) -> bool:
    return _is_int(v) and 0 <= v <= 100


_V2_KEYS = frozenset({
    "v", "accounting_version", "percent", "confirmed_points",
    "denials_issued", "legacy_prevented_rows", "unresolved_actions",
    "unverified", "hidden", "updated_at"})
_V1_KEYS = frozenset({"v", "percent", "blocked", "unverified", "hidden",
                      "updated_at"})


def _parse(doc) -> Snapshot | None:
    """Validate one snapshot document, version 2 or legacy version 1, and
    normalize it. `None` for any violation: extra or missing fields, a
    boolean used as a number, a non-finite or out-of-range number, or a
    cross-field combination the accounting variant does not allow."""
    if not isinstance(doc, dict):
        return None
    v = doc.get("v")
    if not _is_int(v):
        return None
    if v == LEGACY_SNAPSHOT_VERSION:
        if set(doc) != _V1_KEYS:
            return None
        percent, blocked = doc["percent"], doc["blocked"]
        unverified, hidden = doc["unverified"], doc["hidden"]
        updated_at = doc["updated_at"]
        if not (_is_percent(percent) and _is_count(blocked)
                and isinstance(unverified, bool)
                and isinstance(hidden, bool) and _is_num(updated_at)
                and updated_at >= 0):
            return None
        return Snapshot(accounting_version=1, percent=percent,
                        confirmed_points=None, denials_issued=None,
                        legacy_prevented_rows=blocked,
                        unresolved_actions=None, unverified=unverified,
                        hidden=hidden, updated_at=float(updated_at))
    if v != SNAPSHOT_VERSION or set(doc) != _V2_KEYS:
        return None
    version = doc["accounting_version"]
    percent = doc["percent"]
    points = doc["confirmed_points"]
    denials = doc["denials_issued"]
    rows = doc["legacy_prevented_rows"]
    unresolved = doc["unresolved_actions"]
    unverified, hidden = doc["unverified"], doc["hidden"]
    updated_at = doc["updated_at"]
    if not (isinstance(unverified, bool) and isinstance(hidden, bool)
            and _is_num(updated_at) and updated_at >= 0):
        return None
    if not _is_int(version):
        return None
    if version == 0:
        ok = (percent is None and points is None and denials is None
              and rows is None and unresolved is None and unverified)
    elif version == 1:
        ok = (_is_percent(percent) and _is_count(rows) and points is None
              and denials is None and unresolved is None)
    elif version == 2:
        ok = (rows is None and _is_num(points) and points >= 0
              and _is_count(denials) and _is_count(unresolved)
              and (percent is None
                   or (_is_percent(percent) and unresolved == 0
                       and not unverified)))
    else:
        ok = False
    if not ok:
        return None
    return Snapshot(accounting_version=version, percent=percent,
                    confirmed_points=(None if points is None
                                      else float(points)),
                    denials_issued=denials, legacy_prevented_rows=rows,
                    unresolved_actions=unresolved, unverified=unverified,
                    hidden=hidden, updated_at=float(updated_at))


def read_snapshot(data_dir, session_id: str, *, now: float | None = None,
                  ignore_staleness: bool = False) -> Snapshot | None:
    """Contract A's reader. `None` for every failure: missing, unreadable,
    malformed, wrong version, out-of-range, or stale (unless
    `ignore_staleness`, which only the writer uses to carry `hidden` across
    a restart). `hidden` is returned, not folded into `None`, so a caller
    can distinguish "nothing to show" from "asked not to show"."""
    try:
        path = snapshot_path(data_dir, session_id)
    except ValueError:
        return None
    snap = _parse(_load(path))
    if snap is None:
        return None
    now = time.time() if now is None else now
    if not ignore_staleness and now - snap.updated_at > STALE_AFTER:
        return None
    return snap


def read_daemon_marker(data_dir, *, now: float | None = None,
                       ignore_staleness: bool = False) -> bool | None:
    """The daemon's `unattributed_gaps` bit, or `None` if there is no fresh
    answer. `ignore_staleness` is for the writer only — `heartbeat()` uses it
    to carry the bit forward across a publisher that did not write it — and
    never for a reader, for whom a stale marker means a dead daemon."""
    doc = _load(hud_dir(data_dir) / _DAEMON_MARKER)
    if doc is None or doc.get("v") != DAEMON_MARKER_VERSION:
        return None
    gaps, updated_at = doc.get("unattributed_gaps"), doc.get("updated_at")
    if not (isinstance(gaps, bool) and _is_num(updated_at)):
        return None
    now = time.time() if now is None else now
    if not ignore_staleness and now - float(updated_at) > STALE_AFTER:
        return None
    return gaps


def daemon_marker_age(data_dir, *, now: float | None = None) -> float | None:
    """Seconds since `_daemon.json`'s `updated_at`, when
    `read_daemon_marker` would call the marker fresh, else `None`.

    For repair's quiescence gate and its diagnostics (#71): the age is the
    one fact about the file they report, and the gate waits on it. The same
    validity and freshness rules as `read_daemon_marker`, so the two never
    disagree about whether a marker counts.
    """
    doc = _load(hud_dir(data_dir) / _DAEMON_MARKER)
    if doc is None or doc.get("v") != DAEMON_MARKER_VERSION:
        return None
    gaps, updated_at = doc.get("unattributed_gaps"), doc.get("updated_at")
    if not (isinstance(gaps, bool) and _is_num(updated_at)):
        return None
    now = time.time() if now is None else now
    age = now - float(updated_at)
    if age > STALE_AFTER:
        return None
    return age
