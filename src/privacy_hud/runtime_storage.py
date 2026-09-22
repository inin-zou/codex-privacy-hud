# src/privacy_hud/runtime_storage.py
"""The fenced active ledger store, and the crash-recoverable transition to
it (#66, Pair 4).

Storage layout generation 1:

```text
$PLUGIN_DATA/ledger/active.db          the ledger every 0.8.0 process opens
$PLUGIN_DATA/ledger.db/                a DIRECTORY; never a file, never a link
$PLUGIN_DATA/legacy-retired/<id>/      the original database and its sidecars
$PLUGIN_DATA/runtime-transition.json   the journal
$PLUGIN_DATA/runtime-transition.lock   transition exclusion
```

**Why a directory where the database used to be.** A handshake constrains
code that performs one. It cannot constrain a 0.7.1 `Ledger.__init__` that
opens `$PLUGIN_DATA/ledger.db` and runs `executescript(SCHEMA)`,
`PRAGMA journal_mode=WAL` and an `ALTER TABLE` before any hook protocol
exists. What does constrain it is the operating system: `sqlite3.connect`
on a directory fails, and a directory cannot be opened as a database by
any version of anything. The fence is therefore a permanent occupant of
the old pathname rather than a check.

It is protection against *supported legacy entry points* opening the
historical pathname. It is not a security boundary: same-user code that
deliberately opens `ledger/active.db` is not prevented by any of this.

**What the transition does and does not do.** It preserves. A
generation-0 database stays generation 0; a prepared 5401 one keeps every
object and every cell. Nothing here migrates accounting — that stays with
the daemon, at a genuine new-session boundary (#54 phase 2). An
unsupported or altered schema is preserved and refused, never repaired.

**Crash recovery reads the filesystem, not just the journal.** A crash can
land between a rename and the journal write that records it, so every step
is idempotent and every re-entry re-derives where it is from what is
actually on disk. The journal says what was intended; the filesystem says
what happened, and where they disagree the filesystem wins. Nothing
unexpected is ever overwritten: a file that reappears at the fenced path,
or an active store that already exists, stops the transition and leaves
both candidates in place.

I1: the journal holds a stage name, an opaque transition id and a
timestamp. No ledger values, no schema dumps, no paths derived from
content.
"""
from __future__ import annotations

import errno
import fcntl
import json
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from . import codex, ledger_schema
from .runtime_contract import (
    Activation,
    JSONObject,
    RuntimeRefusal,
)

#: `$PLUGIN_DATA/ledger/` — the directory that holds the active store.
ACTIVE_DIR_NAME = "ledger"
#: `$PLUGIN_DATA/ledger/active.db`.
ACTIVE_DB_NAME = "active.db"
#: `$PLUGIN_DATA/ledger.db` — a directory after the transition.
LEGACY_NAME = codex.LEDGER_NAME
#: `$PLUGIN_DATA/legacy-retired/<transition-id>/`.
RETIRED_DIR_NAME = "legacy-retired"
#: The verified copy, staged inside the transition directory until it is
#: published. Named, not derived: a fixed basename cannot encode anything.
STAGED_DB_NAME = "staged.db"
JOURNAL_NAME = "runtime-transition.json"
TRANSITION_LOCK_NAME = "runtime-transition.lock"
JOURNAL_VERSION = 1

#: SQLite's sidecars, in the order they are retired. The database first:
#: a crash after it moves leaves the old path free and the sidecars
#: behind, which the next attempt finishes. The reverse order would strip
#: a live database of its write-ahead log.
_SIDECARS = ("", "-wal", "-shm")

#: The fixed stages. A journal never holds anything else, and the order
#: here is the order they are reached.
STAGES: tuple[str, ...] = (
    "validated", "quiesced", "backup_verified", "retirement_started",
    "legacy_retired", "legacy_fenced", "active_published",
    "snapshots_retired", "receipt_published", "ready",
)

#: The last stage this module reaches. `snapshots_retired`,
#: `receipt_published` and `ready` belong to the repair operation: they are
#: about publishers and processes, not storage, and only repair can know
#: that the selected daemon answered.
FINAL_STORAGE_STAGE = "active_published"

#: Test-only. Called with each stage name immediately after that stage is
#: durably journalled, so a test can terminate a real process between two
#: durable steps. Not settable from any configuration, environment
#: variable or tool input.
_stage_failpoint = None


@dataclass(frozen=True)
class CutoverResult:
    schema_version: Literal[0, 5401]
    preserved_existing: bool
    transition_id: str


# --------------------------------------------------------------------- #
# paths
# --------------------------------------------------------------------- #

def active_path(data_dir) -> Path:
    """`$PLUGIN_DATA/ledger/active.db`."""
    return Path(data_dir) / ACTIVE_DIR_NAME / ACTIVE_DB_NAME


def legacy_path(data_dir) -> Path:
    """`$PLUGIN_DATA/ledger.db`: a database before the transition, a
    directory after it."""
    return Path(data_dir) / LEGACY_NAME


def retired_dir(data_dir, transition_id: str) -> Path:
    return Path(data_dir) / RETIRED_DIR_NAME / transition_id


def journal_path(data_dir) -> Path:
    return Path(data_dir) / JOURNAL_NAME


def is_fenced(data_dir) -> bool:
    """True when the historical pathname is the directory fence."""
    path = legacy_path(data_dir)
    return path.is_dir() and not path.is_symlink()


# --------------------------------------------------------------------- #
# the journal
# --------------------------------------------------------------------- #

class TransitionLock:
    """Exclusion over the whole storage transition for one data directory.

    Separate from the writer lease on purpose. Repair holds *this* across
    publication and daemon startup while it deliberately gives the writer
    lease back, so the daemon it just selected can take the lease it needs.
    One lock for "a transition is in progress", another for "someone is
    writing the ledger".
    """

    def __init__(self, *, data_dir: Path, path: Path, fd: int) -> None:
        self.data_dir = Path(data_dir)
        self.path = Path(path)
        self._fd: int | None = fd

    @property
    def held(self) -> bool:
        return self._fd is not None

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        with _TRANSITIONS_LOCK:
            _TRANSITIONS.pop(str(self.data_dir), None)
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            os.close(fd)

    def __enter__(self) -> "TransitionLock":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


_TRANSITIONS: dict[str, TransitionLock] = {}
_TRANSITIONS_LOCK = threading.Lock()


def acquire_transition(data_dir) -> TransitionLock:
    """Take the transition lock, or raise `RuntimeRefusal("holder_unknown")`
    when another process holds it."""
    root = Path(data_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    path = root / TRANSITION_LOCK_NAME
    key = str(root)
    with _TRANSITIONS_LOCK:
        held = _TRANSITIONS.get(key)
        if held is not None and held.held:
            raise RuntimeRefusal("transition_incomplete")
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EACCES):
                raise RuntimeRefusal("holder_unknown") from exc
            raise
        lock = TransitionLock(data_dir=root, path=path, fd=fd)
        _TRANSITIONS[key] = lock
        return lock


def owns_transition(data_dir) -> bool:
    """Whether *this process* holds the transition lock for `data_dir`."""
    with _TRANSITIONS_LOCK:
        held = _TRANSITIONS.get(str(Path(data_dir).resolve()))
        return held is not None and held.held


def read_journal(data_dir) -> JSONObject | None:
    """The transition journal, or `None` when there is none or it cannot be
    read as one. A malformed journal is not repaired here; the filesystem
    is re-read either way."""
    try:
        raw = journal_path(data_dir).read_bytes()
    except OSError:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("v") != JOURNAL_VERSION:
        return None
    if doc.get("stage") not in STAGES:
        return None
    return doc


def prepare_storage(data_dir, *, activation: Activation) -> CutoverResult:
    """Move this installation to the fenced active store, preserving
    everything, and return what was found.

    Pair 4 scaffolding: reports the layout without changing it.
    """
    root = Path(data_dir).resolve()
    source = legacy_path(root)
    version: Literal[0, 5401] = 0
    preserved = source.is_file()
    if preserved:
        version = _validated_version(source)
    return CutoverResult(schema_version=version, preserved_existing=preserved,
                         transition_id=secrets.token_hex(16))


def _validated_version(path: Path) -> Literal[0, 5401]:
    """The schema generation of an existing database, read-only, refusing
    anything this build cannot write."""
    conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro",
                           uri=True, isolation_level=None)
    try:
        version = ledger_schema.validate_schema(conn)
    except ledger_schema.UnsupportedAccounting:
        raise RuntimeRefusal("ledger_unsupported") from None
    finally:
        conn.close()
    if version not in activation_readable():
        raise RuntimeRefusal("ledger_unsupported")
    return version  # type: ignore[return-value]


def activation_readable() -> tuple[int, ...]:
    from .runtime_contract import WRITABLE_SCHEMAS

    return WRITABLE_SCHEMAS
