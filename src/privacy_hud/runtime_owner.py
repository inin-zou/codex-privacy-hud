# src/privacy_hud/runtime_owner.py
"""Exclusive writer ownership of the ledger (#66, Pair 3).

One process writes the ledger: the daemon that matches the selected
runtime. Everything else — MCP, the local browser, ambient, the skill —
opens a real read-only connection and cannot change a byte, whatever SQL
it runs.

The lease is an `flock` on `$PLUGIN_DATA/runtime-writer.lock`, taken before
any writable connection exists and held for as long as that connection
does. Two facts make it a *lease* rather than a mutex:

* **Exclusion.** `flock(LOCK_EX | LOCK_NB)` on a file nobody unlinks.
  Another process is refused immediately, never queued: "another process
  owns the ledger" is already the answer its caller needs, and a blocking
  wait would put an unbounded stall inside a hook's two-second budget.
  Within one process ownership is shared and reference counted — a process
  that owns the ledger owns it once, and `flock` conflicting between two
  descriptors of the same process is an artefact of the lock, not a fact
  about who may write.
* **Currency.** A lease is valid only while the selection that granted it
  is still the selection on disk. `assert_current()` re-reads the receipt
  and refuses when the recorded build or activation epoch has moved —
  which is exactly what an explicit repair does while activating a
  replacement runtime. The ledger calls it before `BEGIN IMMEDIATE`, again
  once the transaction is held, and once more before the outer `COMMIT`,
  so a repair that lands mid-write causes a rollback rather than a write
  by a runtime that is no longer selected.

Absence of a receipt is a state, not an error: a fresh installation and
every temporary test root have none. What `assert_current` compares is the
*recorded selection at acquisition* against the recorded selection now, so
"there was no receipt and there still is none" is current, and "there was
none and now there is one" is not. No environment variable, argument or
configuration disables any of this.

I1: nothing here reads the ledger or hook content. The lock file is opened
`O_CREAT` and never written to, so it holds no bytes at all.
"""
from __future__ import annotations

import errno
import fcntl
import os
import sys
import threading
from pathlib import Path

from . import runtime_contract
from .runtime_contract import (
    Activation,
    RuntimeIdentity,
    RuntimeRefusal,
    is_build_id,
    is_epoch,
    load_activation,
    read_receipt,
)

#: `$PLUGIN_DATA/runtime-writer.lock`. Created on demand, never unlinked:
#: deleting it would let the next starter take a lock on a fresh inode
#: while the incumbent still holds the old one, and both would then
#: believe they own the ledger (the same argument as `daemon`'s startup
#: lock, which this file deliberately mirrors).
WRITER_LOCK_NAME = "runtime-writer.lock"

#: What `_recorded_selection` returns for a data directory with no usable
#: receipt. A distinct object rather than `None` so "unreadable" and
#: "absent" are the same *comparable* value and neither is confused with a
#: real selection.
_NO_SELECTION = ("", "")


def _recorded_selection(data_dir: Path) -> tuple[str, str]:
    """`(build_id, epoch)` from the receipt in `data_dir`, or `_NO_SELECTION`.

    Deliberately cheap: it reads the receipt's two identity fields and does
    not recompute the bundle digest. `load_activation` is the call that
    verifies a bundle actually *is* the build it claims; this one only has
    to notice that the selection changed, and it runs on every write
    transaction.

    Anything it cannot read as a v2 selection — no receipt, a receipt this
    user no longer owns or others can write, malformed JSON, receipt v1 —
    is `_NO_SELECTION`. That is conservative in the direction that matters:
    a lease acquired against a real selection stops being current the
    moment that selection becomes unreadable.
    """
    try:
        receipt = read_receipt(data_dir)
    except RuntimeRefusal:
        return _NO_SELECTION
    build = receipt.get("selected_build_id")
    epoch = receipt.get("activation_epoch")
    if not is_build_id(build) or not is_epoch(epoch):
        return _NO_SELECTION
    return (str(build), str(epoch))


class _Ownership:
    """The `flock` itself: one per data directory *per process*.

    `flock` conflicts between two descriptors even inside one process, so
    without this a process that legitimately writes the ledger from two
    places would lock itself out. Ownership is a property of the process,
    not of the call site, so the descriptor is shared and reference
    counted; the last handle to close gives it back.
    """

    def __init__(self, fd: int, selection: tuple[str, str]) -> None:
        self.fd: int | None = fd
        self.selection = selection
        self.refs = 0

    def release(self) -> None:
        fd, self.fd = self.fd, None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            os.close(fd)


#: Live `_Ownership` objects by resolved data directory. Guarded by
#: `_OWNERS_LOCK`, because a daemon acquires from its main thread while its
#: worker threads are already running.
_OWNERS: dict[str, _Ownership] = {}
_OWNERS_LOCK = threading.Lock()


class WriterLease:
    """Proof that this process may write the ledger under `data_dir`.

    Construct one with `acquire_writer`. Close it with `close()` or by
    leaving its `with` block; closing makes every later `assert_current()`
    on *this* handle refuse, so a lease cannot outlive the connection it
    authorized, and releases the underlying lock once no handle is left.
    """

    def __init__(self, *, activation: Activation, data_dir: Path, path: Path,
                 owner: _Ownership) -> None:
        self.activation = activation
        self.data_dir = Path(data_dir)
        self.path = Path(path)
        self._owner: _Ownership | None = owner
        self._selection = owner.selection

    @property
    def held(self) -> bool:
        return self._owner is not None and self._owner.fd is not None

    def assert_current(self) -> None:
        """Raise `RuntimeRefusal("runtime_mismatch")` unless this lease is
        still held and the runtime it was granted for is still the selected
        one."""
        if not self.held:
            raise RuntimeRefusal("runtime_mismatch")
        if _recorded_selection(self.data_dir) != self._selection:
            raise RuntimeRefusal("runtime_mismatch")

    def close(self) -> None:
        """Release this handle. Idempotent. The lock file stays on disk."""
        owner, self._owner = self._owner, None
        if owner is None:
            return
        with _OWNERS_LOCK:
            owner.refs -= 1
            if owner.refs <= 0:
                _OWNERS.pop(str(self.data_dir), None)
                owner.release()

    def __enter__(self) -> "WriterLease":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def acquire_writer(data_dir: Path, *, activation: Activation) -> WriterLease:
    """Take exclusive ledger ownership under `data_dir` for `activation`.

    Raises `RuntimeRefusal("holder_unknown")` when another process holds it
    — the caller cannot tell who, and must not guess — and
    `RuntimeRefusal("runtime_mismatch")` when the receipt on disk selects a
    different build or epoch than the activation being offered. A real
    `OSError` (a read-only filesystem, a missing parent that cannot be
    created) propagates: it is a failure to ask the question, not an answer
    to it.
    """
    root = Path(data_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    path = root / WRITER_LOCK_NAME
    key = str(root)
    with _OWNERS_LOCK:
        owner = _OWNERS.get(key)
        if owner is not None and owner.fd is not None:
            _check_selection(owner.selection, activation)
            owner.refs += 1
            return WriterLease(activation=activation, data_dir=root,
                               path=path, owner=owner)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EACCES):
                raise RuntimeRefusal("holder_unknown") from exc
            raise
        owner = _Ownership(fd, _recorded_selection(root))
        try:
            _check_selection(owner.selection, activation)
        except RuntimeRefusal:
            owner.release()
            raise
        owner.refs = 1
        _OWNERS[key] = owner
        return WriterLease(activation=activation, data_dir=root, path=path,
                           owner=owner)


def _check_selection(selection: tuple[str, str],
                     activation: Activation) -> None:
    """Refuse an activation the recorded selection contradicts. A data
    directory with no selection at all contradicts nothing."""
    if selection == _NO_SELECTION:
        return
    if selection != (activation.identity.build_id, activation.epoch):
        raise RuntimeRefusal("runtime_mismatch")


def owns_writer(data_dir) -> bool:
    """Whether *this process* currently holds the writer lease for
    `data_dir`.

    For the one caller that must verify its own caller's ownership rather
    than take it: `runtime_storage.prepare_storage` retires and republishes
    a database, and "the repair operation promised it holds the lease" is
    not evidence.
    """
    with _OWNERS_LOCK:
        owner = _OWNERS.get(str(Path(data_dir).resolve()))
        return owner is not None and owner.fd is not None


def unselected_activation() -> Activation:
    """The identity of the code running right now, with no selection behind
    it.

    A `build_id` and an `activation_epoch` are empty strings, which no
    receipt can ever contain (both are fixed-length hex), so this can never
    be mistaken for a selected runtime and can never match one. Its
    capability fields are this source tree's own, because they describe
    what this code can read and write regardless of whether anybody chose
    it.

    It exists for the one honest case: a data directory with no receipt at
    all — a fresh installation, or a temporary root in a test. There is no
    selection to match, so ownership there is decided by exclusion alone,
    and `acquire_writer` says so by recording that there was no selection.
    """
    identity = RuntimeIdentity(
        release=runtime_contract.RELEASE, build_id="",
        protocol=runtime_contract.PROTOCOL_VERSION,
        storage_generation=runtime_contract.STORAGE_GENERATION,
        readable_schemas=runtime_contract.READABLE_SCHEMAS,
        writable_schemas=runtime_contract.WRITABLE_SCHEMAS,
        snapshot_versions=runtime_contract.SNAPSHOT_VERSIONS)
    return Activation(identity=identity, epoch="",
                      bundle_root=Path(__file__).resolve().parents[2],
                      python=Path(sys.executable))


def running_activation(data_dir: Path) -> Activation:
    """The selected runtime for `data_dir`, or `unselected_activation()`
    when nothing is selected.

    Note what this does *not* do: it never substitutes an unselected
    activation for a selection it merely failed to verify. If a receipt
    exists, `acquire_writer` compares against it, so a bundle whose digest
    no longer matches its receipt yields `runtime_mismatch` rather than a
    lease. The fallback applies only where `_recorded_selection` also finds
    nothing.
    """
    try:
        return load_activation(data_dir)
    except RuntimeRefusal:
        return unselected_activation()
