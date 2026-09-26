# tests/runtime_helpers.py
"""Fixtures for #66's runtime contract: temporary bundles, receipts v2 and
activations. Everything is built under a test's own temporary directory;
nothing here reads or writes a real plugin installation.

A test bundle is a copy of this checkout's covered files with a freshly
generated `runtime-build.json`, so a test never depends on whether the
checkout's own manifest has been regenerated since the last edit.
"""
from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from privacy_hud import runtime_contract as contract

REPO = Path(__file__).resolve().parent.parent
TEST_EPOCH = "0123456789abcdef0123456789abcdef"


def make_bundle(dest: Path) -> Path:
    """Copy the covered files of this checkout into `dest` and write its
    manifest. Returns `dest`."""
    dest.mkdir(parents=True, exist_ok=True)
    for rel in contract.covered_files(REPO):
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, target)
    write_manifest(dest)
    return dest


def write_manifest(bundle: Path) -> dict:
    manifest = contract.build_manifest(bundle)
    (bundle / contract.MANIFEST_NAME).write_text(
        contract.render_manifest(manifest), encoding="utf-8")
    return manifest


def bundle_build_id(bundle: Path) -> str:
    return json.loads((bundle / contract.MANIFEST_NAME).read_text(
        encoding="utf-8"))["build_id"]


def write_receipt_v2(data_dir: Path, *, bundle: Path, python,
                     build_id: str | None = None, epoch: str = TEST_EPOCH,
                     env: dict | None = None, mode: int = 0o600,
                     **overrides) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    receipt = {
        "v": 2,
        "python": str(python),
        "env": dict(env or {}),
        "dependency_probe": {},
        "selected_bundle_root": str(bundle),
        "selected_build_id": build_id or bundle_build_id(bundle),
        "activation_epoch": epoch,
        "storage_generation": 1,
        "recorded_at": time.time(),
    }
    receipt.update(overrides)
    path = data_dir / contract.RECEIPT_NAME
    path.write_text(json.dumps(receipt), encoding="utf-8")
    path.chmod(mode)
    return path


def write_receipt_v1(data_dir: Path, *, python, pythonpath: str = "",
                     mode: int = 0o600) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / contract.RECEIPT_NAME
    path.write_text(json.dumps({
        "v": 1, "python": str(python), "pythonpath": pythonpath,
        "plugin_data": str(data_dir), "recorded_at": time.time(),
        "recorded": {}, "env": {}}), encoding="utf-8")
    path.chmod(mode)
    return path


def activation(*, build_id: str = "a" * 64, epoch: str = TEST_EPOCH,
               bundle_root: Path = REPO,
               python: Path | None = None) -> contract.Activation:
    """An in-memory activation for an in-process `Daemon`. No files."""
    identity = contract.RuntimeIdentity(
        release=contract.RELEASE, build_id=build_id,
        protocol=contract.PROTOCOL_VERSION,
        storage_generation=contract.STORAGE_GENERATION,
        readable_schemas=contract.READABLE_SCHEMAS,
        writable_schemas=contract.WRITABLE_SCHEMAS,
        snapshot_versions=contract.SNAPSHOT_VERSIONS)
    return contract.Activation(identity=identity, epoch=epoch,
                               bundle_root=bundle_root,
                               python=python or Path(sys.executable))


def make_venv(dest: Path) -> Path:
    """A bare virtual environment (no pip, no system site-packages).
    Returns its interpreter."""
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(dest)],
                   check=True, capture_output=True, timeout=120)
    return dest / "bin" / "python"


def site_packages(venv_python: Path) -> Path:
    out = subprocess.run(
        [str(venv_python), "-I", "-c",
         "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        check=True, capture_output=True, text=True, timeout=60)
    return Path(out.stdout.strip())


def plant_old_distribution(directory: Path, sentinel: Path) -> None:
    """An old `privacy_hud` package (with dist-info) whose import writes
    `sentinel` and then stops the process. Stands in for 0.7.1 installed in
    the dependency environment."""
    package = directory / "privacy_hud"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text(
        f"open({str(sentinel)!r}, 'a').write('old privacy_hud imported\\n')\n"
        "raise SystemExit(97)\n", encoding="utf-8")
    info = directory / "privacy_hud-0.7.1.dist-info"
    info.mkdir(exist_ok=True)
    (info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: privacy-hud\nVersion: 0.7.1\n",
        encoding="utf-8")


# --------------------------------------------------------------------- #
# writer leases (#66 Pair 3)
# --------------------------------------------------------------------- #

#: Every lease handed out below, so `conftest`'s autouse fixture can give
#: the descriptors back even when a test abandons its ledger. Two handles
#: on one directory are fine — `acquire_writer` reference counts ownership
#: within a process — and cross-process exclusion is unaffected, which is
#: what `test_runtime_ownership` proves with a real second process.
_OPEN_LEASES: list = []


def writer_lease(data_dir, *, selected=None, keep: bool = False):
    """A real `WriterLease` on a temporary data root.

    Real, not a stand-in: it takes the same `flock` on the same
    `runtime-writer.lock` that the daemon takes, under the test's own
    directory. No argument and no environment variable turns the ledger's
    ownership checks off, so this is how a test becomes a writer.

    `keep=True` withholds the lease from the per-test cleanup, for a
    fixture that outlives one test (a module-scoped `State`, say). Its
    descriptor then lives for the run, which is why it is opt-in.
    """
    from privacy_hud.runtime_owner import acquire_writer, running_activation

    # Whatever `data_dir` selects, or an unselected activation when it
    # selects nothing. Not the synthetic `activation()` above: a root that
    # already holds a receipt selects a real build, and a lease offered
    # another one is correctly refused.
    lease = acquire_writer(
        Path(data_dir),
        activation=selected or running_activation(Path(data_dir)))
    if not keep:
        _OPEN_LEASES.append(lease)
    return lease


def writer_ledger(path, matrix, *, data_dir=None, selected=None,
                  keep: bool = False, **kwargs):
    """An initializing `Ledger` at `path`, holding a real lease.

    The lease is taken in `data_dir`, defaulting to the database's own
    directory — which is what `$PLUGIN_DATA` is for a real installation
    before #66's relocation, and what a test's `tmp_path` is here.
    """
    from privacy_hud.ledger import Ledger

    kwargs.setdefault(
        "writer_lease",
        writer_lease(data_dir if data_dir is not None else Path(path).parent,
                     selected=selected, keep=keep))
    return Ledger(path, matrix, **kwargs)


def close_writer(ledger) -> None:
    """Close a `writer_ledger` and give its lease back straight away.

    Plain `ledger.conn.close()` leaves the lease held until the test ends,
    which is fine until the test then starts a *second process* that needs
    it — an MCP server over stdio, a daemon, a repair. Ownership is real
    and cross-process, so a test that seeds a ledger and then hands the
    data root to another process has to stop owning it first.
    """
    try:
        ledger.conn.close()
    finally:
        lease = getattr(ledger, "_lease", None)
        if lease is not None:
            lease.close()
            if lease in _OPEN_LEASES:
                _OPEN_LEASES.remove(lease)


def release_leases() -> None:
    """Close every lease `writer_lease` handed out. Idempotent."""
    while _OPEN_LEASES:
        _OPEN_LEASES.pop().close()


def writer_state(data_dir, *, selected=None, keep: bool = False):
    """`dispatch.new_state` under a real lease, the way the daemon builds
    it.

    `new_state` has no lease default (#66): whoever opens the daemon's
    writable ledger has to have taken ownership first. This is that step,
    spelled once instead of in every test that needs a daemon's state.
    """
    from privacy_hud.dispatch import new_state

    return new_state(
        data_dir,
        writer_lease=writer_lease(data_dir, selected=selected, keep=keep))


def writer_state_with_detectors(
        data_dir, *, detectors: list, selected=None, keep: bool = False):
    """Build a real leased state with an explicitly supplied test stack.

    Use for contracts whose assertions do not require production model
    initialization or inference. The temporary model placeholder never
    reaches an engine. Ordinary writer_state retains the production stack.

    The construction patch is process-global while active: call this during
    setup, before starting a daemon thread.
    """
    from unittest.mock import patch

    from privacy_hud import dispatch as dispatch_mod
    from privacy_hud.detect.model import StubModelDetector

    with patch.object(
            dispatch_mod, "ModelDetector",
            return_value=StubModelDetector([])):
        state = writer_state(data_dir, selected=selected, keep=keep)
        state.detectors = detectors
    return state


# --------------------------------------------------------------------- #
# a daemon to write policy to (#66 Pair 6)
# --------------------------------------------------------------------- #

#: One bundle copy for the whole run. `make_bundle` copies a few hundred
#: files and recomputes a digest; every daemon a test starts wants the
#: same bundle, and copying it per test is the difference between a
#: second and a minute.
_SHARED_BUNDLE: list[Path] = []


def shared_bundle() -> Path:
    if not _SHARED_BUNDLE:
        _SHARED_BUNDLE.append(
            make_bundle(Path(tempfile.mkdtemp(prefix="phB")) / "bundle"))
    return _SHARED_BUNDLE[0]


def short_data_dir(prefix: str = "phd") -> Path:
    """A `$PLUGIN_DATA` short enough to hold a unix socket.

    `AF_UNIX` paths are capped at about 104 bytes and a pytest temporary
    directory already spends most of that on the test's own name, so any
    test that starts a daemon takes one of these instead — the same
    `tempfile.mkdtemp` every socket test in this suite already uses.
    """
    return Path(tempfile.mkdtemp(prefix=prefix)).resolve()


def select_runtime(data_dir) -> None:
    """Give `data_dir` a receipt v2 over the shared bundle, if it has none.

    Written *before* a test takes its writer lease: a lease records the
    selection it was granted under, and a receipt appearing afterwards is
    correctly a mismatch.
    """
    from privacy_hud import runtime_contract

    if (Path(data_dir) / runtime_contract.RECEIPT_NAME).exists():
        return
    write_receipt_v2(Path(data_dir), bundle=shared_bundle(),
                     python=sys.executable)


@contextlib.contextmanager
def policy_daemon(data_dir):
    """A real daemon serving `data_dir`, stopped on the way out.

    Policy mutations travel to the daemon that owns the ledger (#66 Pair
    6), so a surface test that saves a rule needs one. Real, not a
    stand-in: the point of the RPC is that the rule is applied under the
    daemon's own serialized ledger access, and a stand-in would be a
    second copy of exactly the code under test.
    """
    from privacy_hud import codex
    from privacy_hud.daemon import Daemon
    from privacy_hud.runtime_contract import load_activation

    root = Path(data_dir)
    select_runtime(root)
    socket_path = codex.socket_path(root)
    daemon = Daemon(socket_path, root, idle_timeout=3600, poll_interval=0.05,
                    activation=load_activation(root))
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20.0
    while not socket_path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    try:
        yield daemon
    finally:
        daemon.stop()
        thread.join(timeout=20.0)
