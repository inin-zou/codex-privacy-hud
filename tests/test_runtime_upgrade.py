# tests/test_runtime_upgrade.py
"""#66 Pair 8: the upgrade this release exists for, run end to end.

Every other test in this suite establishes one property of 0.8.0 against
a setup built for that property. This file starts from the state a real
user is actually in — an 0.7.1-era environment, an 0.7.1 process holding
the ledger open with committed rows still in its write-ahead log, and an
updated bundle that appeared beside it — and runs the whole sequence: the
new hook before repair, the refusal while a holder is still up, explicit
repair after it stops, the genuine Phase 2 boundary afterwards, and the
historical code trying to come back.

**What "the old daemon" is here.** The vendored 0.7.1 fixture is the
ledger half of that release, so the old daemon is reproduced as the two
things it is to this release: a live process holding the historical
ledger open in WAL mode, and a listener on the historical socket path
speaking protocol 1. Both are real; neither is a stand-in for the other.

Everything happens in a temporary directory this test made. No
installation, data directory or process outside it is read, written or
signalled.
"""
from __future__ import annotations

import json
import os
import shutil
import socketserver
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from privacy_hud import (
    codex,
    ledger_schema,
    mcp_tools,
    runtime_client,
    runtime_commands,
    runtime_contract as contract,
    runtime_repair as repair,
    runtime_storage as storage,
)
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.runtime_contract import RuntimeRefusal
from privacy_hud.runtime_owner import acquire_writer, unselected_activation
from runtime_helpers import (
    REPO,
    make_bundle,
    make_venv,
    plant_old_distribution,
    site_packages,
    write_receipt_v1,
)
from test_runtime_repair import _no_installer_on_path, stop_runtime

M = load_matrix()
HISTORICAL = REPO / "tests" / "fixtures" / "runtime_071"
HANDLER = REPO / "hooks" / "handler.py"
CANARY = "CANARY-upgrade-4b1c7e-PAYLOAD"
OLD_SESSION = "0199e2e0-b10c-4000-8000-0000000007a1"
NEW_SESSION = "0199e2e0-b10c-4000-8000-0000000008b2"

#: The 0.7.1 ledger, in a live process that keeps its connection open.
#: It commits and never checkpoints, so the rows stay in the WAL -- which
#: is the state the relocation has to carry across, and the one a file
#: copy would silently lose.
_OLD_DAEMON = """
import sys, time
sys.path.insert(0, sys.argv[1])
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix

led = Ledger(sys.argv[2], load_matrix())
led.start_session(sys.argv[3], cwd="/work", model="gpt-5")
led.record(sys.argv[3], turn_id="t1", kind="exposed", data_type="email",
           source="support.log", destination="model_context",
           value_hash=b"\\x01" * 16, masked_example="jo***@acme.com",
           tool_name="Read", protection=None)
sys.stdout.write("ready\\n")
sys.stdout.flush()
time.sleep(900)
"""

_HISTORICAL_OPEN = """
import sys
sys.path.insert(0, sys.argv[1])
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
Ledger(sys.argv[2], load_matrix()).conn.close()
"""


# --------------------------------------------------------------------- #
# an old installation, and the bundle that arrived beside it
# --------------------------------------------------------------------- #

class Upgrade:
    """One throwaway machine: an old data directory, an old interpreter
    with an old distribution installed in it, and an updated bundle."""

    def __init__(self) -> None:
        import tempfile

        self.root = Path(tempfile.mkdtemp(prefix="phu")).resolve()
        self.bundle = make_bundle(self.root / "b")
        self.data = self.root / "d"
        self.data.mkdir(parents=True)
        self.python = make_venv(self.root / "v")
        self.sentinel = self.root / "old-import.txt"
        plant_old_distribution(site_packages(self.python), self.sentinel)
        self.old_daemon: subprocess.Popen | None = None
        self.listener = None
        self.listener_thread = None

    # -- the old daemon ------------------------------------------------ #

    def start_old_daemon(self, session_id: str = OLD_SESSION) -> None:
        self.old_daemon = subprocess.Popen(
            [sys.executable, "-I", "-c", _OLD_DAEMON, str(HISTORICAL),
             str(storage.legacy_path(self.data)), session_id],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.old_daemon.stdout.readline()
        assert line.strip() == "ready", (line, self.old_daemon.stderr.read())

    def start_old_socket(self) -> list:
        """A protocol-1 listener on the historical socket path, recording
        every frame that reaches it."""
        seen: list = []

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                line = self.rfile.readline()
                if not line:
                    return
                seen.append(line.decode("utf-8", "replace"))
                self.wfile.write(b"{}\n")

        path = codex.socket_path(self.data)
        self.listener = socketserver.ThreadingUnixStreamServer(str(path),
                                                               Handler)
        os.chmod(path, 0o600)
        self.listener_thread = threading.Thread(
            target=self.listener.serve_forever, daemon=True)
        self.listener_thread.start()
        return seen

    def stop_old_socket(self) -> None:
        if self.listener is not None:
            self.listener.shutdown()
            self.listener.server_close()
            self.listener_thread.join(timeout=10)
            self.listener = None

    def stop_old_daemon(self) -> None:
        if self.old_daemon is not None:
            self.old_daemon.terminate()
            try:
                self.old_daemon.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.old_daemon.kill()
                self.old_daemon.wait(timeout=30)
            self.old_daemon = None

    # -- running things ------------------------------------------------ #

    def hook(self, payload: dict) -> tuple[int, str]:
        proc = subprocess.run(
            [sys.executable, str(HANDLER)], input=json.dumps(payload),
            capture_output=True, text=True, timeout=120,
            env={"PATH": "/usr/bin:/bin", "PLUGIN_DATA": str(self.data)})
        return proc.returncode, proc.stdout

    def bootstrap(self, *args, bundle: Path | None = None,
                  timeout: float = 180.0):
        root = self.bundle if bundle is None else bundle
        env = {k: v for k, v in os.environ.items()
               if k not in ("PYTHONPATH", "PLUGIN_DATA")}
        return subprocess.run(
            [sys.executable, "-I", str(root / "scripts" / "runtime.py"),
             "--plugin-data", str(self.data), *args],
            capture_output=True, text=True, timeout=timeout, env=env)

    def historical_open(self, path: Path):
        return subprocess.run(
            [sys.executable, "-I", "-c", _HISTORICAL_OPEN, str(HISTORICAL),
             str(path)], capture_output=True, text=True, timeout=180)

    def close(self) -> None:
        self.stop_old_socket()
        self.stop_old_daemon()
        stop_runtime(self.data)
        shutil.rmtree(self.root, ignore_errors=True)


@pytest.fixture
def upgrade():
    machine = Upgrade()
    try:
        yield machine
    finally:
        machine.close()


# --------------------------------------------------------------------- #
# reading a database without trusting its write-ahead log
# --------------------------------------------------------------------- #

def _raw(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro",
                           uri=True, isolation_level=None)


def _cells(path: Path) -> dict:
    """Every row of every table with each cell's storage class, so a value
    silently retyped on the way across is a difference, not a match."""
    conn = _raw(path)
    try:
        out = {}
        for name in [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
                " AND name NOT LIKE 'sqlite_%' ORDER BY name")]:
            rows = [tuple((type(v).__name__, v) for v in row)
                    for row in conn.execute(f'SELECT * FROM "{name}"')]
            out[name] = sorted(rows, key=repr)
        return out
    finally:
        conn.close()


def _preserved(before: dict, after: dict) -> bool:
    """Is every table that existed before still there, byte-for-byte?

    A table the current writer's startup adds because the older release
    never had it (`scan_gaps`, say) is allowed, and must be empty: the
    transition preserves what was recorded and creates nothing that
    claims to have been. Nothing that was there may change.
    """
    kept = {name: rows for name, rows in after.items() if name in before}
    added = {name: rows for name, rows in after.items() if name not in before}
    return kept == before and all(not rows for rows in added.values())


def _generation(path: Path) -> int:
    conn = _raw(path)
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def _wal_resident(path: Path, table: str) -> bool:
    """Is there committed data that only the write-ahead log holds?

    Read the main database file alone, with `immutable=1`, which is
    exactly the shortcut the storage transition must never take: it
    ignores the log. A row the live connection sees and this read does not
    is a row that exists only in the WAL.
    """
    wal = Path(str(path) + "-wal")
    if not wal.is_file() or wal.stat().st_size == 0:
        return False
    live = _raw(path)
    try:
        live_count = live.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
    finally:
        live.close()
    frozen = sqlite3.connect(
        f"{path.resolve().as_uri()}?immutable=1", uri=True)
    try:
        frozen_count = frozen.execute(
            f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
    except sqlite3.DatabaseError:
        return True
    finally:
        frozen.close()
    return live_count > frozen_count


# --------------------------------------------------------------------- #
# the decisive sequence
# --------------------------------------------------------------------- #

def test_upgrade_071_running_daemon_wal_then_old_restart(upgrade):
    """Old environment, old running daemon, updated bundle, WAL-bearing
    ledger, fenced activation, a genuine Phase 2 boundary, and an old
    daemon that cannot come back.

    This is the release's evidence. Each numbered block below is one step
    of the contract's required sequence; a failure in any of them is a
    failure of the upgrade, not of a component.
    """
    data, bundle = upgrade.data, upgrade.bundle

    # 1. an isolated old environment, including a v1 receipt
    write_receipt_v1(data, python=upgrade.python)
    assert contract.classify_receipt(data) == "v1"

    # 2. the actual old ledger code, in a live process, holding it open
    upgrade.start_old_daemon()
    legacy = storage.legacy_path(data)
    assert legacy.is_file()

    # 3. committed data that only the write-ahead log holds
    assert _wal_resident(legacy, "events"), (
        "the setup does not actually contain WAL-resident committed data")
    before_cells = _cells(legacy)
    assert _generation(legacy) == 0

    # 4. the updated bundle is here, and the old environment is untouched
    assert (bundle / "scripts" / "runtime.py").is_file()
    assert contract.load_identity(bundle).release == contract.RELEASE
    assert contract.classify_receipt(data) == "v1"

    # 5. the new hook, before repair: it refuses, and nothing it was given
    #    reaches the old daemon
    seen = upgrade.start_old_socket()
    code, out = upgrade.hook({
        "hook_event_name": "PreToolUse", "session_id": OLD_SESSION,
        "tool_name": "Bash", "tool_input": {"command": f"echo {CANARY}"}})
    assert code == 0
    assert CANARY not in "".join(seen), (
        "a payload reached a daemon that never established its identity")
    assert all('"op": "hello"' in frame or '"op":"hello"' in frame
               for frame in seen), seen
    if out.strip():
        decision = json.loads(out)
        assert CANARY not in json.dumps(decision)
    upgrade.stop_old_socket()

    # 6a. explicit repair, while the old daemon is still up: refused,
    #     because a holder it cannot identify is not a holder it may stop
    with pytest.raises(RuntimeRefusal) as refusal:
        repair.repair_runtime(bundle, data, allow_degraded=True)
    assert refusal.value.code == "holder_unknown"
    assert not storage.is_fenced(data)
    assert legacy.is_file()
    assert _cells(legacy) == before_cells

    # 6b. the user closes it, as the refusal told them to, and repairs
    upgrade.stop_old_daemon()
    with _no_installer_on_path(upgrade.root / "offline-bin") as stubs:
        result = repair.repair_runtime(bundle, data, allow_degraded=True)
    assert stubs.calls() == []
    assert result.preserved_existing is True

    # 7. first-party code is 0.8.0's, and the old distribution is still
    #    installed in the interpreter that supplies dependencies
    probe = upgrade.bootstrap("probe")
    assert probe.returncode == 0, probe.stderr
    reported = json.loads(probe.stdout)
    assert reported["release"] == contract.RELEASE
    assert Path(reported["first_party_origin"]) == (bundle / "src"
                                                    / "privacy_hud")
    assert not upgrade.sentinel.exists(), (
        "the old installed distribution was imported")
    assert (site_packages(upgrade.python) / "privacy_hud").is_dir()

    # 8. every typed cell survived the relocation
    active = storage.active_path(data)
    assert active.is_file()
    assert _preserved(before_cells, _cells(active))

    # 9. repair itself retained generation 0
    assert _generation(active) == 0

    # 10. a genuine new-session boundary prepares 5401, and production
    #     accounting stays legacy
    activation = contract.load_activation(data)
    with runtime_client.connect_runtime(data, activation=activation,
                                        timeout=30.0) as connection:
        connection.request(runtime_client.OP_EVENT, {"payload": {
            "hook_event_name": "SessionStart", "session_id": NEW_SESSION,
            "cwd": "/work", "model": "gpt-5"}})
    assert _generation(active) == ledger_schema.PREPARED_VERSION
    after = _cells(active)
    assert after["events_legacy_v1"] == before_cells["events"]
    assert not after["events"], (
        "the rebuilt events table starts empty; legacy rows are not "
        "copied into it")
    ledger = runtime_commands.open_reader(data)
    try:
        summary = mcp_tools.get_session_summary(ledger, OLD_SESSION)
        assert summary.accounting_version == 1
    finally:
        ledger.conn.close()

    # 11-12. the historical code, restarted against the historical root,
    #        cannot open the fence and cannot touch the active store
    assert storage.is_fenced(data)
    frozen = _cells(active)
    historical = upgrade.historical_open(storage.legacy_path(data))
    assert historical.returncode != 0
    assert storage.legacy_path(data).is_dir()
    assert _cells(active) == frozen
    assert _generation(active) == ledger_schema.PREPARED_VERSION

    # 13. the surfaces a user reaches, on the repaired installation
    audit = runtime_commands.audit(data, activation=activation,
                                   session_id=OLD_SESSION)
    assert audit.runtime_mismatch is False
    assert audit.banner == ""
    assert audit.text
    ambient = upgrade.bootstrap("ambient", "--once")
    assert ambient.returncode == 0, ambient.stderr
    saved = runtime_commands.update_policy(
        data, activation=activation, session_id=OLD_SESSION,
        rule_type="block_path", selector="/etc/hosts")
    assert saved.get("saved") is True

    # 14. a client from another cached bundle cannot replace the selection
    other = make_bundle(upgrade.root / "other")
    receipt_before = (data / contract.RECEIPT_NAME).read_bytes()
    stale = upgrade.bootstrap("probe", bundle=other)
    assert stale.returncode != 0
    assert (data / contract.RECEIPT_NAME).read_bytes() == receipt_before
    assert contract.load_activation(data).epoch == activation.epoch


def test_cutover_refuses_while_an_unknown_legacy_connection_is_open(
        upgrade):
    """Item 15, on its own: an already-open connection from a process this
    release cannot identify blocks the transition until it is gone.

    Not a daemon, not a socket, not a marker -- just a descriptor. The
    cutover asks the operating system who has the file open, and "I could
    not tell" is not "nobody".
    """
    data = upgrade.data
    write_receipt_v1(data, python=upgrade.python)
    upgrade.start_old_daemon()
    legacy = storage.legacy_path(data)
    before = _cells(legacy)

    with pytest.raises(RuntimeRefusal) as refusal:
        with storage.acquire_transition(data):
            with acquire_writer(
                    data, activation=unselected_activation()) as lease:
                storage.prepare_storage(data, activation=lease.activation)
    assert refusal.value.code == "holder_unknown"
    assert legacy.is_file() and not storage.is_fenced(data)
    assert _cells(legacy) == before

    upgrade.stop_old_daemon()
    with storage.acquire_transition(data):
        with acquire_writer(data,
                            activation=unselected_activation()) as lease:
            result = storage.prepare_storage(data,
                                             activation=lease.activation)
    assert result.preserved_existing is True
    assert _cells(storage.active_path(data)) == before


@pytest.mark.parametrize("stage", storage.STAGES[
    :storage.STAGES.index(storage.FINAL_STORAGE_STAGE) + 1])
def test_cutover_resumes_after_a_crash_at_every_durable_stage(upgrade, stage):
    """A machine that loses power mid-transition can still be repaired.

    Every stage, not a sample: the journal exists so a retry can tell
    which of them was reached, and a stage whose retry refuses is a
    machine whose ledger is fenced and whose repair can never complete.
    """
    data = upgrade.data
    write_receipt_v1(data, python=upgrade.python)
    upgrade.start_old_daemon()
    legacy = storage.legacy_path(data)
    before = _cells(legacy)
    upgrade.stop_old_daemon()

    child = f"""
import os, sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from privacy_hud import runtime_storage as storage
from privacy_hud.runtime_owner import acquire_writer, unselected_activation

def failpoint(stage):
    if stage == {stage!r}:
        os._exit(3)

storage._stage_failpoint = failpoint
root = Path(sys.argv[2])
with storage.acquire_transition(root):
    with acquire_writer(root, activation=unselected_activation()) as lease:
        storage.prepare_storage(root, activation=lease.activation)
os._exit(0)
"""
    crashed = subprocess.run(
        [sys.executable, "-I", "-c", child, str(REPO / "src"), str(data)],
        capture_output=True, text=True, timeout=300)
    assert crashed.returncode == 3, crashed.stderr

    with storage.acquire_transition(data):
        with acquire_writer(data,
                            activation=unselected_activation()) as lease:
            result = storage.prepare_storage(data,
                                             activation=lease.activation)

    active = storage.active_path(data)
    assert active.is_file()
    assert _cells(active) == before
    assert _generation(active) == 0
    assert storage.is_fenced(data)
    assert result.preserved_existing is True
    retained = (storage.retired_dir(data, result.transition_id)
                / storage.LEGACY_NAME)
    assert retained.is_file()
    assert _cells(retained) == before


# --------------------------------------------------------------------- #
# the other prepared-ledger states
# --------------------------------------------------------------------- #

def test_upgrade_from_valid_prepared_ledger(upgrade):
    """A ledger #54 already prepared upgrades without being migrated
    again: 5401 in, 5401 out, every value where it was."""
    data, bundle = upgrade.data, upgrade.bundle
    write_receipt_v1(data, python=upgrade.python)
    upgrade.start_old_daemon()
    upgrade.stop_old_daemon()

    legacy = storage.legacy_path(data)
    lease = acquire_writer(data / "seed", activation=unselected_activation())
    from privacy_hud.ledger import Ledger

    led = Ledger(legacy, M, writer_lease=lease)
    try:
        with led._write_transaction():
            led.prepare_session_boundary("prepared")
            led.start_session("prepared", cwd="/w", model="m")
    finally:
        led.conn.close()
        lease.close()
    assert _generation(legacy) == ledger_schema.PREPARED_VERSION
    before = _cells(legacy)

    with _no_installer_on_path(upgrade.root / "offline-bin"):
        result = repair.repair_runtime(bundle, data, allow_degraded=True)

    active = storage.active_path(data)
    assert result.preserved_existing is True
    assert _generation(active) == ledger_schema.PREPARED_VERSION
    assert _preserved(before, _cells(active))
    assert storage.is_fenced(data)


def test_upgrade_refuses_altered_prepared_ledger(upgrade):
    """A prepared ledger carrying a column no schema of ours declares is
    preserved and refused.

    The alteration is not attributed to any release: nothing establishes
    that 0.7.1 produces this state, and a test that said so would be
    asserting a reproducer nobody has. What is under test is the refusal.
    """
    data, bundle = upgrade.data, upgrade.bundle
    write_receipt_v1(data, python=upgrade.python)
    upgrade.start_old_daemon()
    upgrade.stop_old_daemon()

    legacy = storage.legacy_path(data)
    lease = acquire_writer(data / "seed", activation=unselected_activation())
    from privacy_hud.ledger import Ledger

    led = Ledger(legacy, M, writer_lease=lease)
    try:
        with led._write_transaction():
            led.prepare_session_boundary("prepared")
            led.start_session("prepared", cwd="/w", model="m")
    finally:
        led.conn.close()
        lease.close()
    raw = sqlite3.connect(legacy)
    raw.execute("ALTER TABLE events ADD COLUMN unexpected_column TEXT")
    raw.commit()
    raw.close()
    before = _cells(legacy)
    receipt_before = (data / contract.RECEIPT_NAME).read_bytes()

    with _no_installer_on_path(upgrade.root / "offline-bin"):
        with pytest.raises(RuntimeRefusal) as refusal:
            repair.repair_runtime(bundle, data, allow_degraded=True)

    assert refusal.value.code == "ledger_unsupported"
    assert legacy.is_file() and not storage.is_fenced(data)
    assert _cells(legacy) == before
    assert (data / contract.RECEIPT_NAME).read_bytes() == receipt_before
    assert not storage.active_path(data).exists()


def test_upgrade_without_receipt_uses_explicit_install(upgrade):
    """With no receipt at all there is no interpreter to inherit, and
    nothing is guessed: repair refuses until the installer names one.

    That is what `install.sh --repair-runtime` supplies, and it is the
    difference between an installation that chose its interpreter and one
    that found something on a PATH.
    """
    data, bundle = upgrade.data, upgrade.bundle
    upgrade.start_old_daemon()
    upgrade.stop_old_daemon()
    assert contract.classify_receipt(data) == "absent"

    with _no_installer_on_path(upgrade.root / "offline-bin") as stubs:
        with pytest.raises(RuntimeRefusal) as refusal:
            repair.repair_runtime(bundle, data, allow_degraded=True)
        assert refusal.value.code in ("setup_missing", "dependencies_unusable")
        assert not storage.is_fenced(data)
        assert not (data / contract.RECEIPT_NAME).exists()

        result = repair.repair_runtime(bundle, data,
                                       python=upgrade.python,
                                       allow_degraded=True)
    assert stubs.calls() == []
    assert result.preserved_existing is True
    receipt = json.loads((data / contract.RECEIPT_NAME).read_text())
    assert Path(receipt["python"]) == upgrade.python
    assert Path(receipt["selected_bundle_root"]) == bundle


# --------------------------------------------------------------------- #
# install.sh, run for real
# --------------------------------------------------------------------- #

def _offline_pip_env(home: Path) -> dict:
    """An environment where pip cannot reach an index.

    The managed-environment branch is a real `venv` plus a real `pip`, and
    CI has run neither: `PRIVACY_HUD_FAKE=1` builds the environment
    `--without-pip` and skips the dependency install entirely. Running it
    for real without pinning pip offline would download torch on any
    developer machine with a network, so the index is turned off and the
    branch takes its own documented degraded path.
    """
    env = {k: v for k, v in os.environ.items()
           if k not in ("PYTHONPATH", "PLUGIN_DATA", "PRIVACY_HUD_FAKE",
                        "VIRTUAL_ENV")}
    env.update({
        "HOME": str(home),
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        "PIP_NO_INDEX": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_RETRIES": "0",
        "PIP_TIMEOUT": "1",
    })
    return env


@pytest.mark.skipif(sys.platform != "darwin",
                    reason="install.sh targets macOS")
def test_repair_builds_a_managed_environment_for_real(upgrade, tmp_path):
    """`install.sh --repair-runtime`'s managed branch, with no fake mode.

    A real venv is created with a real pip, the wrappers are written, the
    bootstrap's `setup` runs through it, and a daemon answers for the
    selected build.

    **What this does not establish.** The index is turned off, so the
    dependencies were not installed and the environment is the degraded
    one. "A managed replacement is built and can run the bundled code" is
    proved here; "a managed replacement has transformers and torch in it"
    is not, and cannot be without a download.
    """
    home = tmp_path / "home"
    home.mkdir()
    data = upgrade.data
    # A recorded interpreter that cannot run the bundled code at all, so
    # the branch under test is the one that builds a replacement rather
    # than reusing what is there.
    broken = upgrade.root / "broken-python"
    broken.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
    broken.chmod(0o755)
    write_receipt_v1(data, python=broken)
    upgrade.start_old_daemon()
    legacy = storage.legacy_path(data)
    before = _cells(legacy)
    upgrade.stop_old_daemon()

    proc = subprocess.run(
        ["sh", str(upgrade.bundle / "install.sh"), "--repair-runtime",
         "--plugin-data", str(data), "--yes", "--no-model"],
        capture_output=True, text=True, timeout=900,
        env=_offline_pip_env(home))

    share = home / ".local" / "share" / "codex-privacy-hud"
    assert proc.returncode == 0, proc.stdout + proc.stderr
    managed = share / "runtime" / "bin" / "python"
    assert managed.is_file() and os.access(managed, os.X_OK)
    assert (share / "runtime" / "pyvenv.cfg").is_file()
    for name in ("doctor", "ambient", "ui", "mcp", "daemon"):
        wrapper = share / "bin" / f"privacy-hud-{name}"
        assert wrapper.is_file()
        text = wrapper.read_text(encoding="utf-8")
        assert str(upgrade.bundle / "scripts" / "runtime.py") in text
        assert str(data) in text

    # The recorded environment was not written into, and no Codex
    # installation was touched.
    assert broken.read_text(encoding="utf-8") == "#!/bin/sh\nexit 9\n"
    assert not (home / ".codex").exists()

    receipt = json.loads((data / contract.RECEIPT_NAME).read_text())
    assert receipt["v"] == contract.RECEIPT_VERSION
    assert Path(receipt["python"]) == managed.resolve() or \
        Path(receipt["python"]) == managed
    assert Path(receipt["selected_bundle_root"]) == upgrade.bundle
    assert storage.is_fenced(data)
    assert _preserved(before, _cells(storage.active_path(data)))

    activation = contract.load_activation(data)
    with runtime_client.connect_runtime(data, activation=activation,
                                        timeout=30.0) as connection:
        assert connection.hello["release"] == contract.RELEASE


@pytest.mark.skipif(sys.platform != "darwin",
                    reason="install.sh targets macOS")
def test_fresh_install_asks_pip_for_the_bundles_own_extras(upgrade, tmp_path):
    """The fresh-install path, for real, as far as its first network step.

    CI has never run this: `PRIVACY_HUD_FAKE=1` skips the venv, the
    dependency install, the plugin registration and the patched-binary
    fetch together, so the one thing #66 changed here -- installing the
    bundle's declared extras instead of `privacy-hud @ git+https://...`
    -- was unexercised. With no index available the step fails, which is
    correct (a fresh install without dependencies is a broken install);
    what is asserted is the request pip was actually given, out of pip's
    own log, and that the failure left no Codex installation behind.
    """
    home = tmp_path / "home"
    home.mkdir()
    log = tmp_path / "pip.log"
    # A `codex` that answers `--version` and nothing else: the installer
    # refuses to run without one, and nothing in this test reaches a step
    # that would invoke it for real.
    stub_bin = tmp_path / "stub-bin"
    stub_bin.mkdir()
    stub = stub_bin / "codex"
    stub.write_text('#!/bin/sh\n[ "$1" = --version ] && echo "codex-cli '
                    '0.155.1" && exit 0\nexit 0\n', encoding="utf-8")
    stub.chmod(0o755)
    env = _offline_pip_env(home)
    env["PATH"] = f"{stub_bin}:{env['PATH']}"
    env["PIP_LOG"] = str(log)

    proc = subprocess.run(
        ["sh", str(upgrade.bundle / "install.sh"), "--yes", "--no-model"],
        capture_output=True, text=True, timeout=900, env=env)

    assert proc.returncode != 0
    assert log.is_file(), proc.stdout + proc.stderr
    requested = log.read_text(encoding="utf-8", errors="replace")
    assert "git+https" not in requested, (
        "#66 removed the application install; only dependencies are asked "
        "for")
    assert "transformers" in requested
    assert not (home / ".codex").exists()
    assert not (home / ".local" / "bin" / "codex").exists()
