# src/privacy_hud/runtime_owner.py
"""Exclusive writer ownership of the ledger (#66, Pair 3).

One process writes the ledger: the daemon that matches the selected
runtime. Everything else — MCP, the local browser, ambient, the skill —
opens a real read-only connection and cannot change a byte, whatever SQL
it runs.

The lease is an `flock` on `$PLUGIN_DATA/runtime-writer.lock`, taken before
any writable connection exists and held for as long as that connection
does. Two facts make it a *lease* rather than a mutex:

* **Exclusion.** `flock(LOCK_EX | LOCK_NB)` on a file nobody unlinks. A
  second writer in this process or any other is refused immediately, never
  queued: "another process owns the ledger" is already the answer its
  caller needs, and a blocking wait would put an unbounded stall inside a
  hook's two-second budget.
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
from pathlib import Path

from .runtime_contract import (
    Activation,
    RuntimeRefusal,
    is_build_id,
    is_epoch,
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


class WriterLease:
    """Proof that this process may write the ledger under `data_dir`.

    Construct one with `acquire_writer`. Close it with `close()` or by
    leaving its `with` block; closing releases the `flock` and makes every
    later `assert_current()` refuse, so a lease cannot outlive the
    connection it authorized.
    """

    def __init__(self, *, activation: Activation, data_dir: Path, path: Path,
                 fd: int, selection: tuple[str, str]) -> None:
        self.activation = activation
        self.data_dir = Path(data_dir)
        self.path = Path(path)
        self._fd: int | None = fd
        self._selection = selection

    @property
    def held(self) -> bool:
        return self._fd is not None

    def assert_current(self) -> None:
        """Raise `RuntimeRefusal("runtime_mismatch")` unless this lease is
        still held and the runtime it was granted for is still the selected
        one."""
        if self._fd is None:
            raise RuntimeRefusal("runtime_mismatch")
        if _recorded_selection(self.data_dir) != self._selection:
            raise RuntimeRefusal("runtime_mismatch")

    def close(self) -> None:
        """Release the lease. Idempotent. The lock file stays on disk."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            os.close(fd)

    def __enter__(self) -> "WriterLease":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def acquire_writer(data_dir: Path, *, activation: Activation) -> WriterLease:
    """Take exclusive ledger ownership under `data_dir` for `activation`.

    Raises `RuntimeRefusal("holder_unknown")` when another process (or
    another lease in this one) already holds it — the caller cannot tell
    who, and must not guess — and `RuntimeRefusal("runtime_mismatch")` when
    the receipt on disk selects a different build or epoch than the
    activation being offered. A real `OSError` (a read-only filesystem, a
    missing parent that cannot be created) propagates: it is a failure to
    ask the question, not an answer to it.
    """
    root = Path(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    path = root / WRITER_LOCK_NAME
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EACCES):
            raise RuntimeRefusal("holder_unknown") from exc
        raise
    selection = _recorded_selection(root)
    if selection != _NO_SELECTION and selection != (
            activation.identity.build_id, activation.epoch):
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        raise RuntimeRefusal("runtime_mismatch")
    return WriterLease(activation=activation, data_dir=root, path=path,
                       fd=fd, selection=selection)
