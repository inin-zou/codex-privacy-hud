# tests/runtime_helpers.py
"""Fixtures for #66's runtime contract: temporary bundles, receipts v2 and
activations. Everything is built under a test's own temporary directory;
nothing here reads or writes a real plugin installation.

A test bundle is a copy of this checkout's covered files with a freshly
generated `runtime-build.json`, so a test never depends on whether the
checkout's own manifest has been regenerated since the last edit.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
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
#: the file descriptors back even when a test abandons its ledger. A test
#: root is private to one test, so nothing here contends; the list exists
#: to bound descriptors across a whole suite run, not to serialize.
_OPEN_LEASES: list = []


def writer_lease(data_dir, *, selected=None):
    """A real `WriterLease` on a temporary data root.

    Real, not a stand-in: it takes the same `flock` on the same
    `runtime-writer.lock` that the daemon takes, under the test's own
    directory. No argument and no environment variable turns the ledger's
    ownership checks off, so this is how a test becomes a writer.
    """
    from privacy_hud.runtime_owner import acquire_writer

    lease = acquire_writer(Path(data_dir), activation=selected or activation())
    _OPEN_LEASES.append(lease)
    return lease


def writer_ledger(path, matrix, *, data_dir=None, selected=None, **kwargs):
    """An initializing `Ledger` at `path`, holding a real lease.

    The lease is taken in `data_dir`, defaulting to the database's own
    directory — which is what `$PLUGIN_DATA` is for a real installation
    before #66's relocation, and what a test's `tmp_path` is here.
    """
    from privacy_hud.ledger import Ledger

    lease = writer_lease(data_dir if data_dir is not None else Path(path).parent,
                         selected=selected)
    return Ledger(path, matrix, writer_lease=lease, **kwargs)


def release_leases() -> None:
    """Close every lease `writer_lease` handed out. Idempotent."""
    while _OPEN_LEASES:
        _OPEN_LEASES.pop().close()
