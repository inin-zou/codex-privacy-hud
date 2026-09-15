# src/privacy_hud/hud_snapshot.py
"""Contract A (spec §4.1): the HUD snapshot file, its one writer and its
Python reader.

`$PLUGIN_DATA/hud/<session_id>.json` carries six fields and no strings:

    {"v": 1, "percent": 28, "blocked": 2, "unverified": false,
     "hidden": false, "updated_at": 1757900000.0}

Two readers exist: `ambient.py` (this package) and the Codex status-line patch
(`privacy_status.rs`). Both apply the same rules, which live here as
constants so the Rust port can cite one source: a file older than
`STALE_AFTER` seconds is treated as absent, any schema version other than
`SNAPSHOT_VERSION` is treated as absent, and every malformed byte is treated
as absent. "Absent" renders nothing. A frozen daemon must never leave a
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

Stdlib only.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

SNAPSHOT_VERSION = 1
#: A snapshot older than this many seconds is treated as absent.
STALE_AFTER = 30.0
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


@dataclass(frozen=True)
class Snapshot:
    percent: int
    blocked: int
    unverified: bool
    hidden: bool
    updated_at: float


class HudPublisher:
    """The only writer of contract A. One instance per daemon."""

    def __init__(self, data_dir) -> None:
        self.data_dir = Path(data_dir)

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

    def publish(self, session_id: str, *, percent: int, blocked: int,
                unverified: bool) -> None:
        percent = int(percent)
        if not 0 <= percent <= 100:
            raise ValueError("percent outside 0..100")
        doc = {"v": SNAPSHOT_VERSION, "percent": percent,
               "blocked": max(0, int(blocked)), "unverified": bool(unverified),
               "hidden": self._current_hidden(session_id),
               "updated_at": time.time()}
        self._write(snapshot_path(self.data_dir, session_id), doc)

    def set_hidden(self, session_id: str, hidden: bool) -> None:
        """Contract B. Flips `hidden`, refreshes `updated_at`, changes nothing
        else. On a session with no snapshot yet, writes a zero one so the
        preference is not lost."""
        snap = read_snapshot(self.data_dir, session_id, ignore_staleness=True)
        doc = {"v": SNAPSHOT_VERSION,
               "percent": snap.percent if snap else 0,
               "blocked": snap.blocked if snap else 0,
               "unverified": snap.unverified if snap else False,
               "hidden": bool(hidden), "updated_at": time.time()}
        self._write(snapshot_path(self.data_dir, session_id), doc)

    def retire(self, session_id: str) -> None:
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

    def mark_daemon(self, *, unattributed_gaps: bool) -> None:
        self._write(hud_dir(self.data_dir) / _DAEMON_MARKER,
                    {"v": SNAPSHOT_VERSION,
                     "unattributed_gaps": bool(unattributed_gaps),
                     "updated_at": time.time()})


# -- reading -----------------------------------------------------------------

def _load(path: Path) -> dict | None:
    try:
        with open(path, "rb") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("v") != SNAPSHOT_VERSION:
        return None
    return doc


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


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
    doc = _load(path)
    if doc is None:
        return None
    try:
        percent, blocked = doc["percent"], doc["blocked"]
        unverified, hidden, updated_at = doc["unverified"], doc["hidden"], doc["updated_at"]
    except KeyError:
        return None
    if not (_is_int(percent) and 0 <= percent <= 100 and _is_int(blocked)
            and blocked >= 0 and isinstance(unverified, bool)
            and isinstance(hidden, bool) and _is_num(updated_at)):
        return None
    now = time.time() if now is None else now
    if not ignore_staleness and now - float(updated_at) > STALE_AFTER:
        return None
    return Snapshot(percent=percent, blocked=blocked, unverified=unverified,
                    hidden=hidden, updated_at=float(updated_at))


def read_daemon_marker(data_dir, *, now: float | None = None) -> bool | None:
    doc = _load(hud_dir(data_dir) / _DAEMON_MARKER)
    if doc is None:
        return None
    gaps, updated_at = doc.get("unattributed_gaps"), doc.get("updated_at")
    if not (isinstance(gaps, bool) and _is_num(updated_at)):
        return None
    now = time.time() if now is None else now
    if now - float(updated_at) > STALE_AFTER:
        return None
    return gaps
