# tests/test_runtime_repair.py
"""#66 Pair 5: explicit repair, the installer's repair mode, and process
lifecycle.

Nothing here is simulated away. Repair runs the real state machine against
a real bundle copy, a real virtual environment and a real ledger under the
test's own temporary directory; the holders it has to notice are real
processes holding real descriptors; the daemon it starts is the real
daemon, and every test that starts one stops it again.

Nothing here reads or writes the owner's installation: every path is under
`tmp_path`, and the only processes signalled are ones the test started.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

import pytest

from privacy_hud import runtime_contract as contract
from privacy_hud import runtime_repair as repair
from privacy_hud import runtime_storage as storage
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.runtime_contract import RuntimeRefusal
from privacy_hud.runtime_owner import acquire_writer, unselected_activation
from runtime_helpers import (
    REPO,
    make_bundle,
    make_venv,
    write_receipt_v1,
    write_receipt_v2,
)

M = load_matrix()

#: Repair starts a real daemon and waits for its hello. A bare virtual
#: environment has no model to load, so this is generous rather than tight.
STARTUP = 90.0


# --------------------------------------------------------------------- #
# a private installation
# --------------------------------------------------------------------- #

class Install:
    """One throwaway installation: a bundle, an interpreter and a data
    directory, with everything the test needs to reach them.

    Its own short root under `$TMPDIR`, not `tmp_path`: repair starts a
    real daemon, and a unix socket path is capped at about 104 bytes. A
    pytest temporary directory already spends most of that on the test's
    own name, which is the same reason every other socket test in this
    suite takes a `tempfile.mkdtemp(prefix="ph...")`.
    """

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="phr")).resolve()
        self.bundle = make_bundle(self.root / "b")
        self.data = self.root / "d"
        self.data.mkdir(parents=True, exist_ok=True)
        self.python = make_venv(self.root / "v")

    def bootstrap(self, *args, timeout: float = 120.0):
        return subprocess.run(
            [sys.executable, "-I", str(self.bundle / "scripts" / "runtime.py"),
             "--plugin-data", str(self.data), *args],
            capture_output=True, text=True, timeout=timeout, env=_clean_env())

    def receipt_bytes(self) -> bytes:
        return (self.data / contract.RECEIPT_NAME).read_bytes()


def _clean_env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if k not in ("PYTHONPATH", "PLUGIN_DATA")}
    return env


@pytest.fixture
def install():
    inst = Install()
    try:
        yield inst
    finally:
        stop_runtime(inst.data)
        shutil.rmtree(inst.root, ignore_errors=True)


def seed_ledger(data_dir: Path) -> Path:
    """A private ledger at the historical pathname, with one session and
    one recorded row."""
    data_dir.mkdir(parents=True, exist_ok=True)
    path = storage.legacy_path(data_dir)
    lease = acquire_writer(data_dir / "seed-owner",
                           activation=unselected_activation())
    led = Ledger(path, M, writer_lease=lease)
    led.start_session("s1", cwd="/w", model="m")
    led.record("s1", turn_id="t1", kind="exposed", data_type="email",
               source="support.log", destination="model_context",
               value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
               tool_name="Read", protection=None)
    led.conn.close()
    lease.close()
    return path


def stop_runtime(data_dir: Path) -> None:
    """Terminate anything this test left holding the test's own ledger.

    Only pids discovered as holders of files under `data_dir`, which is a
    temporary directory this test created; no name matching, and nothing
    outside the test tree can be reached this way.
    """
    for _ in range(80):
        try:
            holders = storage.open_holders(data_dir)
        except RuntimeRefusal:
            return
        live = [pid for pid in holders if pid != os.getpid()]
        if not live:
            return
        for pid in live:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        time.sleep(0.25)


def _hello(data_dir: Path) -> dict:
    """Connect to the daemon the way a client does and return its hello."""
    from privacy_hud.runtime_client import connect_runtime

    activation = contract.load_activation(data_dir)
    with connect_runtime(data_dir, activation=activation, timeout=10.0) as c:
        return dict(c.hello)


def _await_daemon(data_dir: Path, deadline: float = STARTUP) -> dict:
    state = contract.classify_receipt(data_dir)
    assert state == "v2", f"no activation to wait for: the receipt is {state}"
    end = time.monotonic() + deadline
    last: Exception | None = None
    while time.monotonic() < end:
        try:
            return _hello(data_dir)
        except Exception as exc:  # noqa: BLE001 - retried until the deadline
            last = exc
            time.sleep(0.25)
    raise AssertionError(f"no daemon answered within {deadline:g}s: {last!r}")


# --------------------------------------------------------------------- #
# offline repair from a historical receipt
# --------------------------------------------------------------------- #

def test_v1_receipt_repairs_offline_with_usable_dependencies(install):
    """A 0.7.1-era receipt is repair input, and repair needs no network.

    The environment it names can already run the bundled code, so nothing
    is installed: no pip, no download, no `git+https`. What comes out is a
    receipt v2 selecting this bundle and a daemon that completes the
    handshake for it.
    """
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)

    with _no_installer_on_path(install.root / "offline-bin") as stubs:
        result = repair.repair_runtime(install.bundle, install.data,
                                       allow_degraded=True)

    assert stubs.calls() == []
    assert result.preserved_existing is True
    receipt = json.loads(install.receipt_bytes().decode("utf-8"))
    assert receipt["v"] == contract.RECEIPT_VERSION
    assert receipt["storage_generation"] == contract.STORAGE_GENERATION
    assert Path(receipt["python"]) == install.python
    assert Path(receipt["selected_bundle_root"]) == install.bundle

    activation = contract.load_activation(install.data)
    assert activation.epoch == result.activation.epoch
    assert storage.is_fenced(install.data)
    assert storage.active_path(install.data).is_file()

    hello = _await_daemon(install.data)
    assert hello["build_id"] == activation.identity.build_id
    assert hello["activation_epoch"] == activation.epoch


def test_failed_probe_preserves_receipt_bytes(install):
    """A probe that fails leaves the working receipt exactly as it was.

    Overwriting it would turn one broken interpreter into a broken
    installation: the receipt that still names a usable one is the thing
    that has to survive a failed repair.
    """
    seed_ledger(install.data)
    write_receipt_v2(install.data, bundle=install.bundle,
                     python=install.python)
    before = install.receipt_bytes()
    broken = install.root / "broken-python"
    broken.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
    broken.chmod(0o755)

    with pytest.raises(RuntimeRefusal) as refusal:
        repair.repair_runtime(install.bundle, install.data, python=broken,
                              allow_degraded=True)

    assert refusal.value.code == "dependencies_unusable"
    assert install.receipt_bytes() == before
    assert not storage.is_fenced(install.data)
    assert storage.legacy_path(install.data).is_file()


def test_receipt_states_are_validated_before_activation(install):
    """Unreadable, malformed and v1 receipts are three states, not absence.

    Collapsing them into "no receipt" is what would let a receipt nobody
    can read become permission to take ownership and activate. Each state
    is named, and the two that cannot be understood refuse rather than
    activating on their own.
    """
    path = install.data / contract.RECEIPT_NAME
    assert contract.classify_receipt(install.data) == "absent"

    write_receipt_v1(install.data, python=install.python)
    assert contract.classify_receipt(install.data) == "v1"

    write_receipt_v2(install.data, bundle=install.bundle,
                     python=install.python)
    assert contract.classify_receipt(install.data) == "v2"

    path.write_text("{not json", encoding="utf-8")
    path.chmod(0o600)
    assert contract.classify_receipt(install.data) == "malformed"

    path.chmod(0o666)
    assert contract.classify_receipt(install.data) == "unreadable"

    before = install.receipt_bytes()
    with pytest.raises(RuntimeRefusal) as refusal:
        repair.repair_runtime(install.bundle, install.data,
                              allow_degraded=True)
    assert refusal.value.code == "setup_missing"
    assert install.receipt_bytes() == before
    assert not storage.is_fenced(install.data)


# --------------------------------------------------------------------- #
# holders
# --------------------------------------------------------------------- #

_IDLE_READER = textwrap.dedent("""
    import sqlite3, sys, time
    conn = sqlite3.connect(sys.argv[1])
    conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
    sys.stdout.write("ready\\n")
    sys.stdout.flush()
    time.sleep(600)
""")


def test_unknown_open_file_holder_refuses_cutover(install):
    """An idle reader in an unrecognized process blocks the transition.

    It has no daemon socket, no marker and no name this release knows. It
    does have the database open, which is the only fact that matters: a
    transition that retired the file underneath it would be a transition
    performed on a database somebody else is still using.
    """
    path = seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    reader = subprocess.Popen(
        [sys.executable, "-I", "-c", _IDLE_READER, str(path)],
        stdout=subprocess.PIPE, text=True)
    try:
        assert reader.stdout is not None
        assert reader.stdout.readline().strip() == "ready"
        assert reader.pid in storage.open_holders(install.data)

        with pytest.raises(RuntimeRefusal) as refusal:
            repair.repair_runtime(install.bundle, install.data,
                                  allow_degraded=True)
        assert refusal.value.code == "holder_unknown"
        assert reader.poll() is None, "an unknown holder was signalled"
    finally:
        reader.terminate()
        reader.wait(timeout=30)

    assert not storage.is_fenced(install.data)
    assert storage.legacy_path(install.data).is_file()
    assert contract.classify_receipt(install.data) == "v1"


def test_missing_inspection_capability_refuses_cutover(install, monkeypatch):
    """No way to ask who holds the ledger is not an answer of "nobody"."""
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    monkeypatch.setattr(storage, "_inspector", lambda: None)

    with pytest.raises(RuntimeRefusal) as refusal:
        storage.open_holders(install.data)
    assert refusal.value.code == "holder_unknown"

    with pytest.raises(RuntimeRefusal) as second:
        repair.repair_runtime(install.bundle, install.data,
                              allow_degraded=True)
    assert second.value.code == "holder_unknown"
    assert not storage.is_fenced(install.data)


def test_repair_refuses_changed_process_identity(install, monkeypatch):
    """A holder whose identity moved between discovery and signalling is
    never signalled.

    The pid is not the process: between the moment a holder is recognized
    and the moment a signal would be sent, that pid can belong to something
    else entirely. Revalidation is the check, and a changed identity is a
    refusal rather than a signal sent anyway.
    """
    path = seed_ledger(install.data)
    holder = subprocess.Popen(
        [sys.executable, "-I", "-c", _IDLE_READER, str(path)],
        stdout=subprocess.PIPE, text=True)
    signalled: list[int] = []
    monkeypatch.setattr(repair, "_signal",
                        lambda pid, sig: signalled.append(pid))
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "ready"
        identity = repair.process_identity(holder.pid)
        assert identity is not None

        moved = dict(identity)
        moved["started"] = str(identity["started"]) + "x"
        with pytest.raises(RuntimeRefusal) as refusal:
            repair.stop_holders(install.data, {holder.pid: moved},
                                deadline=time.monotonic() + 5.0)
        assert refusal.value.code == "holder_unknown"
        assert signalled == []
        assert holder.poll() is None
    finally:
        holder.terminate()
        holder.wait(timeout=30)


# --------------------------------------------------------------------- #
# one activation
# --------------------------------------------------------------------- #

_PARALLEL_REPAIR = textwrap.dedent("""
    import sys, time
    from pathlib import Path
    sys.path.insert(0, sys.argv[1])
    from privacy_hud import runtime_repair
    from privacy_hud.runtime_contract import RuntimeRefusal

    gate = Path(sys.argv[4])
    while not gate.exists():
        time.sleep(0.01)
    try:
        result = runtime_repair.repair_runtime(
            Path(sys.argv[2]), Path(sys.argv[3]), allow_degraded=True)
    except RuntimeRefusal as refusal:
        sys.stdout.write("refused:" + refusal.code + "\\n")
        raise SystemExit(1)
    sys.stdout.write("activated:" + result.activation.epoch + "\\n")
""")


def test_parallel_repairs_select_one_epoch(install):
    """Two repairs at once leave one activation and one daemon.

    The transition lock is what decides, and it decides once: whoever loses
    refuses instead of publishing a second epoch or starting a second
    writer.
    """
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    gate = install.root / "go"
    children = [
        subprocess.Popen(
            [sys.executable, "-I", "-c", _PARALLEL_REPAIR,
             str(install.bundle / "src"), str(install.bundle),
             str(install.data), str(gate)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=_clean_env())
        for _ in range(2)
    ]
    gate.write_text("go", encoding="utf-8")
    outputs = [child.communicate(timeout=STARTUP * 2) for child in children]

    activated = [out.strip().split(":", 1)[1] for out, _ in outputs
                 if out.startswith("activated:")]
    assert activated, f"neither repair succeeded: {outputs}"
    epoch = contract.load_activation(install.data).epoch
    assert set(activated) <= {epoch}

    hello = _await_daemon(install.data)
    assert hello["activation_epoch"] == epoch
    holders = [pid for pid in storage.open_holders(install.data)
               if pid != os.getpid()]
    assert len(holders) == 1, f"more than one runtime is holding it: {holders}"


# --------------------------------------------------------------------- #
# failures the user is shown
# --------------------------------------------------------------------- #

def test_storage_failure_is_reported_without_exception_text(install,
                                                            monkeypatch):
    """A durability failure is rendered as fixed copy and no success.

    `OSError` carries a path and an operating-system message this plugin
    did not write. It never reaches the user, and a repair that failed
    never prints the sentence that says a runtime is running.
    """
    import errno

    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)

    def explode(path):
        raise OSError(errno.EIO, "injected durability failure",
                      "/secret/path")

    monkeypatch.setattr(storage, "_fsync_dir", explode)
    out = io.StringIO()
    code = repair.main(["--bundle-root", str(install.bundle),
                        "--plugin-data", str(install.data),
                        "--allow-degraded"], out=out)
    captured = out.getvalue()
    assert code != 0
    assert "injected durability failure" not in captured
    assert "/secret/path" not in captured
    assert "Errno" not in captured
    assert "is running from the selected plugin bundle" not in captured
    assert contract.classify_receipt(install.data) == "v1"


def test_repair_command_shell_quotes_metacharacters(tmp_path):
    """The printed command survives being pasted into a shell.

    A bundle path containing `$(...)` is a path, not a command to run. The
    quoting is `shlex.join`'s, and this runs the result to prove it: the
    argv the fake installer sees is the intended one, and the substitution
    never executes.
    """
    bundle = tmp_path / "plug in $(touch pwned)"
    bundle.mkdir()
    data = tmp_path / "data dir; touch also-pwned"
    data.mkdir()
    (bundle / "install.sh").write_text(
        '#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done\n',
        encoding="utf-8")

    command = repair.format_repair_command(bundle, data)
    proc = subprocess.run(["sh", "-c", command], capture_output=True,
                          text=True, cwd=tmp_path, timeout=60)

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [
        "--repair-runtime", "--plugin-data", str(data), "--yes"]
    assert not (tmp_path / "pwned").exists()
    assert not (tmp_path / "also-pwned").exists()
    assert not (bundle / "pwned").exists()


# --------------------------------------------------------------------- #
# runtime paths never install anything
# --------------------------------------------------------------------- #

_INSTALLER_NAMES = ("pip", "pip3", "curl", "wget", "git", "uv", "uvx",
                    "easy_install")


class _PathStubs:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.log = directory / "calls.log"

    def calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return [line for line in self.log.read_text().splitlines() if line]


def _stub_installers(directory: Path) -> _PathStubs:
    directory.mkdir(parents=True, exist_ok=True)
    stubs = _PathStubs(directory)
    for name in _INSTALLER_NAMES:
        script = directory / name
        script.write_text(
            f'#!/bin/sh\nprintf "%s %s\\n" {name} "$*" >> "{stubs.log}"\n'
            "exit 1\n", encoding="utf-8")
        script.chmod(0o755)
    return stubs


@contextlib.contextmanager
def _no_installer_on_path(directory: Path):
    """Put a recording, always-failing stub for every installer this
    project could reach for at the front of `PATH`."""
    stubs = _stub_installers(directory)
    saved = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{directory}:{saved}"
    try:
        yield stubs
    finally:
        os.environ["PATH"] = saved


def test_runtime_paths_never_install_dependencies(install):
    """Probe, doctor and ambient run their live guards and install nothing.

    Every installer this project could plausibly reach for is on `PATH` as
    a recorder that fails if it is called. The runtime commands run to
    completion, and the log stays empty (I2: only explicit installation
    downloads).
    """
    seed_ledger(install.data)
    write_receipt_v2(install.data, bundle=install.bundle,
                     python=install.python)
    stubs = _stub_installers(install.root / "stub-bin")
    env = _clean_env()
    env["PATH"] = f"{stubs.directory}:{env.get('PATH', '')}"

    for args in (["probe"], ["doctor"], ["ambient", "--once"]):
        proc = subprocess.run(
            [sys.executable, "-I",
             str(install.bundle / "scripts" / "runtime.py"),
             "--plugin-data", str(install.data), *args],
            capture_output=True, text=True, timeout=180, env=env)
        assert "Traceback" not in proc.stderr, proc.stderr

    assert stubs.calls() == []


# --------------------------------------------------------------------- #
# the installer's repair mode
# --------------------------------------------------------------------- #

pytestmark_darwin = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="install.sh is macOS-only (BSD sed, xattr)")

INSTALL_SH = REPO / "install.sh"


def _fake_home(tmp_path: Path) -> tuple[Path, dict, Path]:
    home = tmp_path / "home"
    home.mkdir()
    officialbin = tmp_path / "officialbin"
    officialbin.mkdir()
    fake = officialbin / "codex"
    fake.write_text('#!/bin/sh\n[ "$1" = --version ] && echo "codex-cli '
                    '0.154.0" && exit 0\necho official "$@"\n',
                    encoding="utf-8")
    fake.chmod(0o755)
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text('model = "gpt-5.4"\n',
                                                 encoding="utf-8")
    (home / ".zshrc").write_text("# user rc\n", encoding="utf-8")
    # The interpreter running the suite is on PATH because `install.sh`
    # builds an installer-owned environment with the newest suitable
    # `python3` it can find, and the platform `/usr/bin/python3` is 3.9 on
    # macOS. A host with no python >= 3.11 cannot be repaired at all, which
    # the installer says rather than works around.
    env = {"HOME": str(home),
           "PATH": f"{officialbin}:{Path(sys.executable).parent}"
                   ":/usr/bin:/bin:/usr/sbin",
           "SHELL": "/bin/zsh", "PRIVACY_HUD_FAKE": "1",
           "PRIVACY_HUD_TARGET": "aarch64-apple-darwin"}
    return home, env, officialbin


@pytestmark_darwin
def test_repair_mode_does_not_replace_codex_binary(tmp_path, install):
    """`--repair-runtime` repairs the runtime and nothing else.

    No forwarder, no patched binary, no `config.toml` edit, no PATH line.
    A user running it to recover monitoring is not consenting to have their
    Codex installation changed.
    """
    home, env, _ = _fake_home(tmp_path)
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    before_cfg = (home / ".codex" / "config.toml").read_bytes()
    before_rc = (home / ".zshrc").read_bytes()

    proc = subprocess.run(
        ["sh", str(install.bundle / "install.sh"), "--repair-runtime",
         "--plugin-data", str(install.data), "--yes", "--no-model"],
        capture_output=True, text=True, timeout=600, env=env)

    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert not (home / ".local" / "bin" / "codex").exists()
    assert not list((home / ".local" / "share").glob(
        "codex-privacy-hud/0.154.0/*"))
    assert (home / ".codex" / "config.toml").read_bytes() == before_cfg
    assert (home / ".zshrc").read_bytes() == before_rc
    assert contract.classify_receipt(install.data) == "v2"


@pytestmark_darwin
def test_unusable_manual_environment_is_not_modified(tmp_path, install):
    """An interpreter the user manages is never written to.

    When the recorded environment cannot run the bundled code, repair
    builds its own beside the installation and records that one. The
    original keeps every byte it had.
    """
    home, env, _ = _fake_home(tmp_path)
    seed_ledger(install.data)
    manual = tmp_path / "manual-venv"
    manual.mkdir()
    (manual / "bin").mkdir()
    fake_python = manual / "bin" / "python3"
    fake_python.write_text("#!/bin/sh\nexit 11\n", encoding="utf-8")
    fake_python.chmod(0o755)
    write_receipt_v1(install.data, python=fake_python)
    before = {p: p.read_bytes() for p in manual.rglob("*") if p.is_file()}

    proc = subprocess.run(
        ["sh", str(install.bundle / "install.sh"), "--repair-runtime",
         "--plugin-data", str(install.data), "--yes", "--no-model"],
        capture_output=True, text=True, timeout=600, env=env)

    assert proc.returncode == 0, proc.stderr + proc.stdout
    after = {p: p.read_bytes() for p in manual.rglob("*") if p.is_file()}
    assert after == before

    managed = home / ".local" / "share" / "codex-privacy-hud" / "runtime"
    assert managed.is_dir(), "no installer-owned environment was created"
    receipt = json.loads(install.receipt_bytes().decode("utf-8"))
    assert Path(receipt["python"]) != fake_python
    assert str(managed) in receipt["python"]


@pytestmark_darwin
def test_uninstall_preserves_fence_and_history(tmp_path, install):
    """A default uninstall leaves the ledger and its fence alone."""
    home, env, _ = _fake_home(tmp_path)
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    repair.repair_runtime(install.bundle, install.data, allow_degraded=True)
    _await_daemon(install.data)
    active_before = storage.active_path(install.data).read_bytes()
    retired = sorted((install.data / storage.RETIRED_DIR_NAME).iterdir())

    share = home / ".local" / "share" / "codex-privacy-hud"
    share.mkdir(parents=True, exist_ok=True)
    (share / "manifest.json").write_text(json.dumps({
        "v": 1, "created": [], "edited": {},
        "plugin_data": str(install.data), "model_snapshot": ""}),
        encoding="utf-8")

    proc = subprocess.run(
        ["sh", str(install.bundle / "install.sh"), "--uninstall"],
        capture_output=True, text=True, timeout=600, env=env)

    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert storage.is_fenced(install.data)
    assert storage.active_path(install.data).read_bytes() == active_before
    assert sorted((install.data / storage.RETIRED_DIR_NAME).iterdir()) == retired


@pytestmark_darwin
def test_uninstall_stops_owned_runtime_before_environment_removal(tmp_path,
                                                                  install):
    """Uninstall stops the runtime it owns before removing what runs it.

    Otherwise the venv disappears underneath a live daemon, which then
    keeps the ledger open with an interpreter whose files are gone.
    """
    home, env, _ = _fake_home(tmp_path)
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    repair.repair_runtime(install.bundle, install.data, allow_degraded=True)
    _await_daemon(install.data)
    running = [pid for pid in storage.open_holders(install.data)
               if pid != os.getpid()]
    assert len(running) == 1

    share = home / ".local" / "share" / "codex-privacy-hud"
    share.mkdir(parents=True, exist_ok=True)
    venv_copy = share / "venv"
    shutil.copytree(install.python.parent.parent, venv_copy,
                    symlinks=True, dirs_exist_ok=True)
    (share / "manifest.json").write_text(json.dumps({
        "v": 1, "created": [str(venv_copy) + "/"], "edited": {},
        "plugin_data": str(install.data), "model_snapshot": ""}),
        encoding="utf-8")

    proc = subprocess.run(
        ["sh", str(install.bundle / "install.sh"), "--uninstall"],
        capture_output=True, text=True, timeout=600, env=env)

    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert not share.exists()
    for _ in range(80):
        if not _alive(running[0]):
            break
        time.sleep(0.25)
    assert not _alive(running[0]), (
        "the owned runtime survived removal of the environment it runs in")


def _alive(pid: int) -> bool:
    """Is `pid` a running process?

    `os.kill(pid, 0)` is not the question: repair spawns the daemon from
    this process, so once it exits it is a zombie until something reaps
    it, and signalling a zombie succeeds. The process state is the fact
    that matters, and `Z` is not alive.
    """
    completed = subprocess.run(["ps", "-o", "state=", "-p", str(pid)],
                               capture_output=True, text=True, timeout=30)
    state = completed.stdout.strip()
    return bool(state) and not state.startswith("Z")


# --------------------------------------------------------------------- #
# the bundle a fresh installation runs
# --------------------------------------------------------------------- #

def test_installed_bundle_is_resolved_not_guessed(tmp_path, monkeypatch):
    """Two cached copies are an error, never a newest-directory choice."""
    from privacy_hud import codex

    cache = tmp_path / "codex" / "plugins" / "cache"
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    one = (cache / codex.MARKETPLACE_NAME / codex.PLUGIN_NAME
           / contract.RELEASE)
    make_bundle(one)
    assert repair.resolve_installed_bundle(contract.RELEASE) == one

    two = (cache / "another-marketplace" / codex.PLUGIN_NAME
           / contract.RELEASE)
    make_bundle(two)
    with pytest.raises(RuntimeRefusal) as refusal:
        repair.resolve_installed_bundle(contract.RELEASE)
    assert refusal.value.code == "bundle_invalid"


def test_repair_reports_preservation_and_degradation_separately(install):
    """Model degradation is its own sentence, and is never implied by a
    successful handshake."""
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    out = io.StringIO()
    code = repair.main(["--bundle-root", str(install.bundle),
                        "--plugin-data", str(install.data),
                        "--allow-degraded"], out=out)
    output = out.getvalue()
    assert code == 0, output
    assert "Privacy HUD 0.8.2 is running from the selected plugin bundle." \
        in output
    assert "Existing ledger records were preserved." in output
    assert "Deep-scan detection is unavailable." in output
    assert "Runtime alignment does not establish detector availability." \
        in output


def test_sqlite_is_not_left_holding_the_retired_database(install):
    """Belt and braces: repair closes every connection it opened."""
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    repair.repair_runtime(install.bundle, install.data, allow_degraded=True)
    _await_daemon(install.data)
    transition = json.loads(
        storage.journal_path(install.data).read_text())["transition_id"]
    retained = storage.retired_dir(install.data, transition) / storage.LEGACY_NAME
    assert retained.is_file()
    conn = sqlite3.connect(retained)
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    finally:
        conn.close()


@pytest.mark.parametrize("old_bundle_missing", [False, True])
def test_repair_accepts_existing_v2_selection(install, old_bundle_missing):
    seed_ledger(install.data)
    before = storage._fingerprint(storage.legacy_path(install.data))
    overrides = {}
    if old_bundle_missing:
        overrides["selected_bundle_root"] = str(install.root / "removed-bundle")
    write_receipt_v2(
        install.data,
        bundle=install.bundle,
        python=install.python,
        build_id="f" * 64 if old_bundle_missing else None,
        **overrides,
    )
    old_epoch = json.loads(install.receipt_bytes())["activation_epoch"]

    with _no_installer_on_path(install.root / "offline-bin") as stubs:
        result = repair.repair_runtime(
            install.bundle, install.data, allow_degraded=True
        )

    assert stubs.calls() == []
    assert result.activation.epoch != old_epoch
    assert storage.is_fenced(install.data)
    assert storage._fingerprint(storage.active_path(install.data)) == before
    assert _await_daemon(install.data)["activation_epoch"] == result.activation.epoch


def test_repair_resumes_after_receipt_publication_and_start_failure(
    install, monkeypatch
):
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    before = storage._fingerprint(storage.legacy_path(install.data))

    def fail_start(*args, **kwargs):
        raise RuntimeRefusal("runtime_starting")

    with monkeypatch.context() as patch:
        patch.setattr(repair, "_start_daemon", fail_start)
        with pytest.raises(RuntimeRefusal) as failure:
            repair.repair_runtime(
                install.bundle, install.data, allow_degraded=True
            )

    assert failure.value.code == "runtime_starting"
    assert contract.classify_receipt(install.data) == "v2"
    assert storage.read_journal(install.data)["stage"] == "receipt_published"
    previous_epoch = json.loads(install.receipt_bytes())["activation_epoch"]

    result = repair.repair_runtime(
        install.bundle, install.data, allow_degraded=True
    )

    assert result.activation.epoch != previous_epoch
    assert storage._fingerprint(storage.active_path(install.data)) == before
    assert storage.read_journal(install.data)["stage"] == "ready"
    assert _await_daemon(install.data)["activation_epoch"] == result.activation.epoch


def test_offline_repair_cli_runs_without_installers(install):
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)

    with _no_installer_on_path(install.root / "offline-bin") as stubs:
        completed = install.bootstrap(
            "repair", "--offline", "--allow-degraded", timeout=240
        )

    assert completed.returncode == 0, completed.stderr
    assert "Privacy HUD 0.8.2 is running" in completed.stdout
    assert "Traceback" not in completed.stderr
    assert stubs.calls() == []
    assert contract.classify_receipt(install.data) == "v2"
    assert storage.is_fenced(install.data)
    assert _await_daemon(install.data)["ready"] is True


@pytest.mark.parametrize(
    "code", ["runtime_mismatch", "transition_incomplete", "runtime_starting"]
)
def test_incomplete_repair_copy_does_not_invent_a_holder(code):
    bundle = Path("/review bundle")
    data = Path("/review data")
    out = io.StringIO()

    repair._report_failure(code, bundle, data, out)

    command = repair.format_repair_command(bundle, data)
    assert out.getvalue() == (
        "Privacy HUD runtime repair did not complete.\n"
        "Existing ledger files were preserved. Activation may be incomplete.\n"
        "Run this command in another terminal:\n"
        f"  {command}\n"
    )
