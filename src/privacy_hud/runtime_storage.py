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
opens `$PLUGIN_DATA/ledger.db` without the current handshake or writer
lease. Its initializer leaves a valid prepared 5401 schema unchanged;
it adds `source_kind` only when that column is absent. Historical session
and coverage methods can still mutate a prepared ledger. What does constrain it is the operating system: `sqlite3.connect`
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
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from . import codex, hud_snapshot, ledger_schema
from .runtime_contract import (
    STORAGE_GENERATION,
    WRITABLE_SCHEMAS,
    Activation,
    JSONObject,
    RuntimeRefusal,
)
from .runtime_owner import owns_writer

#: `$PLUGIN_DATA/ledger/` — the directory that holds the active store.
ACTIVE_DIR_NAME = codex.ACTIVE_DIR_NAME
#: `$PLUGIN_DATA/ledger/active.db`.
ACTIVE_DB_NAME = codex.ACTIVE_DB_NAME
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

#: An opaque transition id: 32 lowercase hex characters, like an
#: activation epoch. Nothing about a ledger can be encoded in it.
_TRANSITION_ID = re.compile(r"[0-9a-f]{32}")

#: How long a probe waits for `connect()` on the daemon socket. A live
#: listener answers from the kernel's backlog instantly; a dead one's
#: leftover socket file refuses instantly.
_PROBE_TIMEOUT = 0.25

#: Ceiling on one open-file inspection. `lsof` over a handful of explicit
#: pathnames answers in well under a second; the ceiling is for a wedged
#: filesystem, and expiring it is a refusal rather than an empty answer.
_INSPECT_TIMEOUT = 30.0

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


def resolved_ledger_path(data_dir) -> Path:
    """The database this generation opens. `codex.ledger_path` is the
    definition; this name exists for callers already holding this
    module."""
    return codex.ledger_path(data_dir)


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

    The caller must already hold both the transition lock and the writer
    lease for `data_dir`; this checks that itself rather than trusting the
    convention, because it is about to retire a database. Refuses with
    `transition_incomplete` when it does not.

    Idempotent and resumable. Every step below is derived from what is on
    disk, so calling this again after a crash finishes the transition,
    returns an already-finished one unchanged, or refuses and leaves every
    candidate file in place. It never overwrites a file it did not put
    there, and it never restores a database to the fenced pathname.

    Raises `RuntimeRefusal`:

    * `ledger_unsupported` — the existing schema is not one this build
      writes, or does not match its recorded version. Preserved, refused,
      never repaired.
    * `holder_unknown` — something may still be holding the old ledger.
    * `transition_incomplete` — ownership is missing, a database has
      reappeared at the fenced path, or two candidate active stores exist.
    """
    root = Path(data_dir).resolve()
    _require_ownership(root)
    _validate(root, activation)

    journal = read_journal(root)
    transition_id = _transition_id(journal)
    legacy = legacy_path(root)
    active = active_path(root)
    retired = retired_dir(root, transition_id)
    staged = retired / STAGED_DB_NAME
    retained = retired / LEGACY_NAME

    source = _source(legacy)
    if source is not None and retained.exists():
        # The original was retained and something is at the historical path
        # again. Two candidates, no way to tell which the user means, and
        # overwriting either would destroy records. Both stay.
        raise RuntimeRefusal("transition_incomplete")
    if legacy.exists() and source is None and not is_fenced(root):
        # Neither a database nor the fence: a symlink, a socket, something
        # else entirely. Not ours to replace.
        raise RuntimeRefusal("transition_incomplete")

    preserved = (source is not None or retained.exists()
                 or bool(journal and journal.get("preserved_existing")))
    probe = source or (active if active.is_file()
                       else (staged if staged.is_file() else None))
    version: Literal[0, 5401] = 0 if probe is None else _validated_version(probe)
    _record(root, transition_id, "validated", preserved)

    if not _quiescent(root):
        raise RuntimeRefusal("holder_unknown")
    _record(root, transition_id, "quiesced", preserved)

    if source is not None:
        retired.mkdir(parents=True, exist_ok=True)
        _chmod_private(retired)
        _fsync_dir(retired.parent)
        if staged.exists() or staged.is_symlink():
            if staged.is_symlink() or not staged.is_file():
                raise RuntimeRefusal("transition_incomplete")
            try:
                matches = _fingerprint(source) == _fingerprint(staged)
            except (sqlite3.Error, OSError):
                raise RuntimeRefusal("transition_incomplete") from None
            if not matches:
                raise RuntimeRefusal("transition_incomplete")
        else:
            _stage_backup(source, staged)
        _record(root, transition_id, "backup_verified", preserved)

        _record(root, transition_id, "retirement_started", preserved)
        _retire(source, retained)
        _record(root, transition_id, "legacy_retired", preserved)

    if source is None and retained.is_file() and not is_fenced(root):
        # The inter-rename window only: the database was moved and a
        # sidecar was not, so the retained original is still separated
        # from its write-ahead log. Once the fence is in place there is
        # nothing left at the historical pathname to retire -- and calling
        # `_retire` anyway would hand it the fence directory as a source
        # and a destination that already exists, which is the ambiguity
        # that function correctly refuses. A crash between the fence and
        # publication was therefore unrecoverable: every retry refused,
        # forever, on a transition that had already preserved everything.
        _retire(legacy, retained)
        _record(root, transition_id, "legacy_retired", preserved)

    _fence(root)
    _record(root, transition_id, "legacy_fenced", preserved)

    if preserved:
        _publish_active(staged, active)
    else:
        # A fresh installation gets the fence and a directory for the
        # active store, and nothing else. The daemon initializes the
        # database on the first genuine SessionStart; inventing one here
        # would invent a ledger nobody wrote.
        active.parent.mkdir(parents=True, exist_ok=True)
        _chmod_private(active.parent)
    _record(root, transition_id, "active_published", preserved)

    return CutoverResult(schema_version=version, preserved_existing=preserved,
                         transition_id=transition_id)


# --------------------------------------------------------------------- #
# the steps
# --------------------------------------------------------------------- #

def _require_ownership(root: Path) -> None:
    """Both exclusions, held by this process, verified here rather than
    promised by the caller."""
    if not owns_transition(root) or not owns_writer(root):
        raise RuntimeRefusal("transition_incomplete")


def _validate(root: Path, activation: Activation) -> None:
    """The bundle's storage generation, and a data directory this user owns
    and nobody else can write."""
    if activation.identity.storage_generation != STORAGE_GENERATION:
        raise RuntimeRefusal("runtime_mismatch")
    try:
        info = os.lstat(root)
    except OSError:
        raise RuntimeRefusal("transition_incomplete") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022):
        raise RuntimeRefusal("transition_incomplete")


def _source(legacy: Path) -> Path | None:
    """The database at the historical path, or `None`. A symlink is never
    a source: it names bytes somewhere this transition did not look."""
    if legacy.is_symlink() or not legacy.is_file():
        return None
    return legacy


def _transition_id(journal: JSONObject | None) -> str:
    """Resume the journalled transition, or start one. Opaque and random:
    it names an attempt, and nothing about a ledger."""
    if journal is not None:
        recorded = journal.get("transition_id")
        if isinstance(recorded, str) and _TRANSITION_ID.fullmatch(recorded):
            return recorded
    return secrets.token_hex(16)


def _quiescent(root: Path) -> bool:
    """Whether anything is visibly still able to hold the old ledger.

    Three signals. The first is the one that matters, and it is about
    files rather than about processes: `open_holders` asks the operating
    system who has the database or a sidecar open, unknown processes
    included, and refuses outright when it cannot ask. The other two are
    about a *Privacy HUD* process specifically — something answering on
    the daemon socket, and a daemon marker young enough to mean a live
    publisher — and they catch a daemon that is starting but has not
    opened the ledger yet. Anything at the socket path that is not a
    socket, or that cannot be classified, counts as a holder: "I could not
    tell" is not "nobody".

    This is called before the backup, before retirement and before the
    fence, so it is also the recheck that stands between a holder
    appearing and a file moving underneath it.
    """
    holders = {pid for pid in open_holders(root) if pid != os.getpid()}
    if holders:
        return False
    sock = codex.socket_path(root)
    try:
        info = os.stat(sock)
    except FileNotFoundError:
        info = None
    except OSError:
        return False
    if info is not None:
        if not stat.S_ISSOCK(info.st_mode):
            return False
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(_PROBE_TIMEOUT)
            probe.connect(str(sock))
            return False
        except (ConnectionRefusedError, FileNotFoundError):
            pass
        except OSError:
            return False
        finally:
            probe.close()
    return hud_snapshot.read_daemon_marker(root) is None


#: Where `lsof` is on the systems this runs on, for the case where it is
#: not on the inherited `PATH`. Repair is launched from an installer, a
#: managed wrapper and a hook, none of which has the user's shell `PATH`
#: -- and on macOS `lsof` lives in `/usr/sbin`, which a minimal `PATH`
#: does not include. Without this, holder inspection failed closed on
#: exactly those invocations, so repair refused every time and could
#: never complete. Absolute, ordinary system locations only; the `PATH`
#: lookup still comes first.
_LSOF_LOCATIONS = ("/usr/sbin/lsof", "/usr/bin/lsof", "/bin/lsof",
                   "/usr/local/bin/lsof", "/opt/homebrew/bin/lsof")


def _inspector():
    """The way this host can be asked who has a file open, or `None`.

    `None` is not "nobody": it is "this host cannot answer", which
    `open_holders` turns into a refusal (#66 Pair 5). Two answers exist:
    `/proc` on Linux, which needs no subprocess, and `lsof` everywhere
    else. Neither is guessed at — each is checked for before it is used.
    """
    if sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir():
        return _proc_holders
    lsof = shutil.which("lsof")
    if not lsof:
        for candidate in _LSOF_LOCATIONS:
            if os.access(candidate, os.X_OK) and Path(candidate).is_file():
                lsof = candidate
                break
    if lsof:
        return lambda paths: _lsof_holders(lsof, paths)
    return None


def holder_paths(data_dir) -> list[Path]:
    """Every file a ledger user could be holding, in every place this
    layout puts one.

    The retired copies are included on purpose: a transition that was
    interrupted after a rename left its files under `legacy-retired/`, and
    a process that had the database open before the rename is holding
    *that* file now. File identity has to be followed across retirement or
    the recheck before publication asks about the wrong inode.
    """
    root = Path(data_dir)
    bases = [legacy_path(root), active_path(root)]
    retired_root = root / RETIRED_DIR_NAME
    try:
        entries = sorted(retired_root.iterdir())
    except FileNotFoundError:
        entries = []
    except OSError:
        raise RuntimeRefusal("holder_unknown") from None
    for entry in entries:
        if entry.is_dir() and not entry.is_symlink():
            bases.append(entry / LEGACY_NAME)
            bases.append(entry / STAGED_DB_NAME)
    found = []
    for base in bases:
        for suffix in _SIDECARS:
            path = Path(str(base) + suffix)
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                raise RuntimeRefusal("holder_unknown") from None
            if stat.S_ISLNK(info.st_mode):
                raise RuntimeRefusal("holder_unknown")
            if stat.S_ISREG(info.st_mode):
                found.append(path)
    return found


def open_holders(data_dir) -> frozenset[int]:
    """Every process with the ledger database or one of its sidecars open.

    Unknown processes included: what matters is the descriptor, not
    whether the holder is recognizable as a Privacy HUD process. An idle
    reader in a process with no socket, no marker and no name this release
    knows still holds the file, and a transition performed underneath it
    would be a transition performed on a database somebody is using.

    Raises `RuntimeRefusal("holder_unknown")` when the question cannot be
    answered at all: a host with no way to inspect open files fails
    closed, because "I could not ask" is not "nobody".
    """
    paths = holder_paths(data_dir)
    if not paths:
        return frozenset()
    inspect = _inspector()
    if inspect is None:
        raise RuntimeRefusal("holder_unknown")
    return inspect(paths)


def _lsof_holders(lsof: str, paths: list[Path]) -> frozenset[int]:
    """`lsof` over exactly these pathnames. It matches by device and inode
    rather than by name, which is what makes it an answer about files and
    not about strings."""
    try:
        completed = subprocess.run(
            [lsof, "-n", "-P", "-F", "pn", "--", *[str(p) for p in paths]],
            capture_output=True, text=True, timeout=_INSPECT_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeRefusal("holder_unknown") from None
    # 0: holders found. 1: none found, which lsof also reports for a path
    # it could not examine -- so an error line is a refusal, not an empty
    # answer.
    if completed.returncode not in (0, 1):
        raise RuntimeRefusal("holder_unknown")
    if completed.stderr.strip():
        raise RuntimeRefusal("holder_unknown")
    holders = set()
    for line in completed.stdout.splitlines():
        if line.startswith("p"):
            try:
                holders.add(int(line[1:]))
            except ValueError:
                raise RuntimeRefusal("holder_unknown") from None
    return frozenset(holders)


def _proc_holders(paths: list[Path]) -> frozenset[int]:
    """`/proc/<pid>/fd` for every process this user owns, matched on
    `(st_dev, st_ino)`.

    Another user's processes are skipped rather than refused: this is a
    single-user layout, the files are 0600, and refusing because `root`
    has processes would refuse on every machine. A process of *this*
    user whose descriptors cannot be listed is a refusal — that is the
    incomplete visibility the question is about.
    """
    targets = set()
    for path in paths:
        try:
            info = path.stat()
        except OSError:
            raise RuntimeRefusal("holder_unknown") from None
        targets.add((info.st_dev, info.st_ino))
    if not targets:
        return frozenset()
    uid = os.getuid()
    holders = set()
    try:
        entries = os.listdir("/proc")
    except OSError:
        raise RuntimeRefusal("holder_unknown") from None
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            if os.stat(f"/proc/{pid}").st_uid != uid:
                continue
            descriptors = os.listdir(f"/proc/{pid}/fd")
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            raise RuntimeRefusal("holder_unknown") from None
        for fd in descriptors:
            try:
                info = os.stat(f"/proc/{pid}/fd/{fd}")
            except (FileNotFoundError, ProcessLookupError):
                continue
            except OSError:
                raise RuntimeRefusal("holder_unknown") from None
            if (info.st_dev, info.st_ino) in targets:
                holders.add(pid)
                break
    return frozenset(holders)


def _stage_backup(source: Path, staged: Path) -> None:
    """Copy `source` to `staged` with SQLite's own backup API, then compare
    the two.

    The backup API, not a file copy: it reads through the write-ahead log,
    so a row committed and never checkpointed arrives. `mode=ro` on the
    source, so the copy cannot be the thing that changes it.
    """
    for suffix in _SIDECARS:
        _remove(Path(str(staged) + suffix))
    src = sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True,
                          isolation_level=None)
    try:
        dst = sqlite3.connect(staged, isolation_level=None)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    os.chmod(staged, 0o600)
    if _fingerprint(source) != _fingerprint(staged):
        _remove(staged)
        raise RuntimeRefusal("transition_incomplete")
    _fsync_file(staged)
    _fsync_dir(staged.parent)


def _fingerprint(path: Path) -> tuple:
    """Everything the comparison is allowed to notice, read in memory and
    never written anywhere: the schema version, every object's definition,
    every row with each cell's storage class, the sequence state, and the
    existing foreign-key violations.

    Existing violations are part of the fingerprint rather than an error:
    a ledger that already has them keeps them, and what must not happen is
    a *new* one appearing in the copy.
    """
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True,
                           isolation_level=None)
    try:
        objects = sorted(conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master"))
        tables = [row[1] for row in objects if row[0] == "table"]
        cells = []
        for name in sorted(tables):
            rows = sorted(
                (tuple((type(v).__name__, v) for v in row)
                 for row in conn.execute(f'SELECT * FROM "{_quote(name)}"')),
                key=repr)
            cells.append((name, rows))
        violations = sorted(map(repr, conn.execute("PRAGMA foreign_key_check")))
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        return (version, objects, cells, violations)
    finally:
        conn.close()


def _quote(identifier: str) -> str:
    return identifier.replace('"', '""')


def _retire(source: Path, retained: Path) -> None:
    """Move the database and its sidecars under the transition directory,
    the database first. Never overwrites: a destination that already holds
    a file while the source still has one is an ambiguity, not a retry."""
    for suffix in _SIDECARS:
        src = Path(str(source) + suffix)
        dst = Path(str(retained) + suffix)
        if not src.exists():
            continue
        if dst.exists():
            raise RuntimeRefusal("transition_incomplete")
        os.replace(src, dst)
    _fsync_dir(retained.parent)
    _fsync_dir(source.parent)


def _fence(root: Path) -> None:
    """Make the historical pathname a directory, or confirm it already is
    one. A file there is never replaced."""
    legacy = legacy_path(root)
    if is_fenced(root):
        return
    if legacy.exists() or legacy.is_symlink():
        raise RuntimeRefusal("transition_incomplete")
    legacy.mkdir(mode=0o700)
    _fsync_dir(root)


def _publish_active(staged: Path, active: Path) -> None:
    """Put the verified copy at the active path, atomically, once."""
    active.parent.mkdir(parents=True, exist_ok=True)
    _chmod_private(active.parent)
    if active.is_file():
        if staged.is_file():
            # A staged copy and a published one, both claiming to be the
            # active store. Neither is discarded.
            raise RuntimeRefusal("transition_incomplete")
        return
    if not staged.is_file():
        raise RuntimeRefusal("transition_incomplete")
    os.replace(staged, active)
    _fsync_dir(active.parent)
    _fsync_dir(staged.parent)


# --------------------------------------------------------------------- #
# durability
# --------------------------------------------------------------------- #

def record_stage(data_dir, transition_id: str, stage: str,
                 preserved: bool) -> None:
    """Publish one of the stages beyond `FINAL_STORAGE_STAGE`.

    `snapshots_retired`, `receipt_published` and `ready` are reached by
    `runtime_repair`, which owns publishers, receipts and the daemon that
    answered. The journal is still this module's, so the writing of it
    stays here and the vocabulary cannot drift.
    """
    if stage not in STAGES:
        raise RuntimeRefusal("transition_incomplete")
    _record(Path(data_dir).resolve(), transition_id, stage, preserved)


def _record(root: Path, transition_id: str, stage: str,
            preserved: bool) -> None:
    """Publish one stage durably, then give a test the chance to kill this
    process between two durable steps."""
    _write_json(journal_path(root), {
        "v": JOURNAL_VERSION,
        "transition_id": transition_id,
        "stage": stage,
        "preserved_existing": bool(preserved),
        "updated_at": time.time(),
    })
    if _stage_failpoint is not None:
        _stage_failpoint(stage)


def _write_json(path: Path, doc: JSONObject) -> None:
    """Atomic replacement, with the file and its directory both durable
    before the call returns."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", closefd=False) as handle:
            json.dump(doc, handle, sort_keys=True)
            handle.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def _fsync_file(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        pass


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _validated_version(path: Path) -> Literal[0, 5401]:
    """The schema generation of an existing database, read on its own
    read-only connection, refusing anything this build cannot write.

    Read-only and before anything else touches the file: refusing a ledger
    *after* opening it read-write, or after a journal-mode change, would
    already have written to a database we have just decided we do not
    understand.
    """
    try:
        conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro",
                               uri=True, isolation_level=None)
    except sqlite3.Error:
        raise RuntimeRefusal("ledger_unsupported") from None
    try:
        version = ledger_schema.validate_schema(conn)
    except (ledger_schema.UnsupportedAccounting, sqlite3.Error):
        raise RuntimeRefusal("ledger_unsupported") from None
    finally:
        conn.close()
    if version not in WRITABLE_SCHEMAS:
        raise RuntimeRefusal("ledger_unsupported")
    return version  # type: ignore[return-value]
