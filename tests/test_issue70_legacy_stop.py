# tests/test_issue70_legacy_stop.py
"""#70: explicit repair recognizes, stops and replaces a verified legacy
daemon in one invocation, and refuses everything it cannot verify.

The legacy daemon here is launched the way 0.7.x hooks launched one --
the recorded interpreter running `-m privacy_hud.daemon`, with the data
directory in `PLUGIN_DATA` -- from a stand-in package on `PYTHONPATH`. It
holds the ledger and its sidecars, binds the daemon socket, and publishes
a heartbeat. Nothing here terminates it before repair runs: that is the
defect, and a test that did would not cover it (#70).

astra's ownership rules (#66 follow-up §C), each exercised: same user;
stable identity (pid, start time, executable, exact argv); a supported
launch form; a validated relationship to this installation's recorded
interpreter; the process holding this data directory's ledger by device
and inode; revalidation before any signal; refusal when a process cannot
be inspected. SIGTERM once, never SIGKILL.

Everything is under temporary directories. The only processes signalled
are the test's own children.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from privacy_hud import runtime_contract as contract
from privacy_hud import runtime_messages
from privacy_hud import runtime_repair as repair
from privacy_hud import runtime_storage as storage
from runtime_helpers import write_receipt_v1
from test_runtime_repair import (
    _IDLE_READER,
    Install,
    _clean_env,
    _fake_home,
    pytestmark_darwin,
    seed_ledger,
    stop_runtime,
)


@pytest.fixture
def install():
    """`test_runtime_repair`'s private installation, torn down the same
    way: anything left holding its ledger is stopped, then it is removed."""
    import shutil

    inst = Install()
    try:
        yield inst
    finally:
        stop_runtime(inst.data)
        shutil.rmtree(inst.root, ignore_errors=True)

#: A 0.7.x-shaped daemon: `privacy_hud.daemon` run as a module. Stdlib
#: only. It opens `$PLUGIN_DATA/ledger.db` and keeps it open, binds
#: `$PLUGIN_DATA/daemon.sock`, and re-stamps `hud/_daemon.json` until it
#: is terminated -- which, like a real one, leaves the socket file and the
#: marker behind. `FAKE_BACKDATE` shortens how long that marker stays
#: fresh so the test does not spend thirty seconds waiting for it.
_LEGACY_DAEMON = textwrap.dedent("""
    import json, os, signal, socket, sqlite3, sys, time
    root = os.environ["PLUGIN_DATA"]
    if os.environ.get("FAKE_IGNORE_TERM") == "1":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    conn = sqlite3.connect(os.path.join(root, "ledger.db"))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(os.path.join(root, "daemon.sock"))
    server.listen(4)
    hud = os.path.join(root, "hud")
    os.makedirs(hud, exist_ok=True)
    backdate = float(os.environ.get("FAKE_BACKDATE", "0"))
    first = True
    while True:
        tmp = os.path.join(hud, "_daemon.json.tmp")
        with open(tmp, "w") as fh:
            json.dump({"v": 1, "unattributed_gaps": False,
                       "updated_at": time.time() - backdate}, fh)
        os.replace(tmp, os.path.join(hud, "_daemon.json"))
        if first:
            sys.stdout.write("ready\\n")
            sys.stdout.flush()
            first = False
        time.sleep(0.2)
""")


def plant_legacy_package(directory: Path) -> Path:
    package = directory / "privacy_hud"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "daemon.py").write_text(_LEGACY_DAEMON, encoding="utf-8")
    return directory


@contextlib.contextmanager
def legacy_daemon(install, *, python=None, data=None,
                  tail=repair.LEGACY_DAEMON_ARGS, backdate: float = 28.0,
                  ignore_term: bool = False):
    """A running legacy daemon, reaped (and, if a test left it alive,
    killed -- it is this test's own child) on the way out."""
    legacy = plant_legacy_package(install.root / "legacy")
    env = _clean_env()
    env.update(PYTHONPATH=str(legacy),
               PLUGIN_DATA=str(data or install.data),
               FAKE_BACKDATE=str(backdate),
               FAKE_IGNORE_TERM="1" if ignore_term else "0")
    argv = [str(python or install.python), *tail]
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, text=True, env=env,
                            cwd="/", start_new_session=True)
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "ready"
        holders = storage.open_holders(data or install.data)
        assert proc.pid in holders
        yield proc
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=30)


def _alive(proc: subprocess.Popen) -> bool:
    return proc.poll() is None


def _terminated_by_sigterm(proc: subprocess.Popen) -> bool:
    try:
        return proc.wait(timeout=30) == -signal.SIGTERM
    except subprocess.TimeoutExpired:
        return False


def _run_main(install, *extra, python=None):
    out, err = io.StringIO(), io.StringIO()
    argv = ["--bundle-root", str(install.bundle),
            "--plugin-data", str(install.data), "--allow-degraded"]
    if python is not None:
        argv += ["--python", str(python)]
    code = repair.main(argv + list(extra), out=out, err=err)
    diagnostics = [json.loads(line) for line in err.getvalue().splitlines()
                   if line.strip()]
    return code, out.getvalue(), diagnostics


def _assert_untouched(install) -> None:
    assert not storage.is_fenced(install.data)
    assert storage.legacy_path(install.data).is_file()
    assert contract.classify_receipt(install.data) == "v1"


# --------------------------------------------------------------------- #
# the surfaces that stop it
# --------------------------------------------------------------------- #

@pytestmark_darwin
def test_repair_command_stops_verified_legacy_daemon(tmp_path, install):
    """The public repair command, with the legacy daemon still running:
    it is identified, asked once to exit, and the transition completes in
    the same invocation. No pid, no `kill`, no retry."""
    _home, env, _ = _fake_home(tmp_path)
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    with legacy_daemon(install) as daemon:
        proc = subprocess.run(
            ["sh", str(install.bundle / "install.sh"), "--repair-runtime",
             "--plugin-data", str(install.data), "--yes", "--no-model"],
            capture_output=True, text=True, timeout=600, env=env)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert _terminated_by_sigterm(daemon)

    out = proc.stdout
    stopping = out.index(runtime_messages.LEGACY_DAEMON_STOPPING)
    stopped = out.index(runtime_messages.LEGACY_DAEMON_STOPPED)
    running = out.index(runtime_messages.REPAIR_SUCCESS.split("\n")[1])
    assert stopping < stopped < running
    assert "Close other Privacy HUD processes" not in out
    assert storage.is_fenced(install.data)
    assert contract.classify_receipt(install.data) == "v2"


def test_stop_runtime_stops_verified_legacy_daemon(install):
    """`repair --stop-runtime` shares the classifier: the same verified
    legacy daemon is stopped, and storage is left exactly where it was."""
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    with legacy_daemon(install) as daemon:
        completed = install.bootstrap("repair", "--stop-runtime")
        assert completed.returncode == 0, completed.stderr
        assert _terminated_by_sigterm(daemon)
    _assert_untouched(install)


@pytestmark_darwin
def test_uninstall_stops_verified_legacy_daemon(tmp_path, install):
    """Uninstall reaches the same stop through `repair --stop-runtime`."""
    home, env, _ = _fake_home(tmp_path)
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    share = home / ".local" / "share" / "codex-privacy-hud"
    share.mkdir(parents=True, exist_ok=True)
    (share / "manifest.json").write_text(json.dumps({
        "v": 1, "created": [], "edited": {},
        "plugin_data": str(install.data), "model_snapshot": ""}),
        encoding="utf-8")
    with legacy_daemon(install) as daemon:
        proc = subprocess.run(
            ["sh", str(install.bundle / "install.sh"), "--uninstall"],
            capture_output=True, text=True, timeout=600, env=env)
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert _terminated_by_sigterm(daemon)
    assert "stopped the Privacy HUD runtime for" in proc.stdout + proc.stderr
    assert storage.legacy_path(install.data).is_file()


def test_daemon_of_another_data_directory_is_untouched(install):
    """A legacy daemon from the same interpreter serving a different data
    directory holds none of this ledger's files, and is not this repair's
    business."""
    other = install.root / "other"
    seed_ledger(other)
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    with legacy_daemon(install, data=other) as daemon:
        try:
            repair.repair_runtime(install.bundle, install.data,
                                  allow_degraded=True)
            assert _alive(daemon)
        finally:
            stop_runtime(install.data)
    assert storage.is_fenced(install.data)
    assert storage.legacy_path(other).is_file()


# --------------------------------------------------------------------- #
# what is never signalled
# --------------------------------------------------------------------- #

@pytest.mark.parametrize("tail", [
    ("-m", "privacy_hud.daemon", "--verbose"),
    ("-c", "import runpy; runpy.run_module('privacy_hud.daemon', "
           "run_name='__main__')"),
])
def test_unsupported_launch_form_is_never_signalled(install, tail):
    """"privacy_hud" somewhere in a command line is not a launch form."""
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    with legacy_daemon(install, tail=tail) as daemon:
        code, out, diagnostics = _run_main(install)
        assert _alive(daemon), "an unverified holder was signalled"
    assert code == 1
    assert runtime_messages.HOLDER_UNVERIFIED in out
    assert [d["check"] for d in diagnostics] == ["unverified"]
    assert diagnostics[0]["reason"] == "launch_form"
    assert diagnostics[0]["pids"] == [daemon.pid]
    assert diagnostics[0]["signalled"] is False
    _assert_untouched(install)


def test_other_interpreter_is_never_signalled(install):
    """The right launch form from an interpreter this installation did not
    record is somebody else's daemon."""
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    with legacy_daemon(install, python=sys.executable) as daemon:
        code, out, diagnostics = _run_main(install)
        assert _alive(daemon)
    assert code == 1
    assert runtime_messages.HOLDER_UNVERIFIED in out
    assert diagnostics[0]["reason"] == "interpreter"
    _assert_untouched(install)


def test_no_recorded_interpreter_is_never_signalled(install):
    """With no receipt there is no installation interpreter to relate a
    legacy process to, so none is verified."""
    seed_ledger(install.data)
    with legacy_daemon(install) as daemon:
        code, out, diagnostics = _run_main(install, python=install.python)
        assert _alive(daemon)
    assert code == 1
    assert runtime_messages.HOLDER_UNVERIFIED in out
    assert diagnostics[0]["reason"] == "installation"
    assert not storage.is_fenced(install.data)


def test_unknown_holder_blocks_every_signal(install):
    """Every holder is classified before any is signalled: one unknown
    reader means the verified daemon is not stopped either."""
    path = seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    signals: list[tuple[int, int]] = []
    reader = subprocess.Popen(
        [sys.executable, "-I", "-c", _IDLE_READER, str(path)],
        stdout=subprocess.PIPE, text=True)
    try:
        assert reader.stdout is not None
        assert reader.stdout.readline().strip() == "ready"
        with legacy_daemon(install) as daemon, pytest.MonkeyPatch.context() \
                as patch:
            patch.setattr(repair, "_signal",
                          lambda pid, sig: signals.append((pid, sig)))
            code, out, diagnostics = _run_main(install)
            assert _alive(daemon) and reader.poll() is None
    finally:
        reader.terminate()
        reader.wait(timeout=30)
    assert code == 1 and signals == []
    assert runtime_messages.HOLDER_UNVERIFIED in out
    assert diagnostics[0]["pids"] == [reader.pid]
    _assert_untouched(install)


def test_identity_change_before_signalling_sends_nothing(install,
                                                         monkeypatch):
    """Revalidation happens immediately before the signal. An identity
    that moved after classification is refused, and nothing is sent."""
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    seen: set[int] = set()
    real = repair.process_identity

    def moving(pid: int):
        identity = real(pid)
        if identity is not None and pid in seen:
            identity = dict(identity, started="moved")
        seen.add(pid)
        return identity

    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(repair, "process_identity", moving)
    monkeypatch.setattr(repair, "_signal",
                        lambda pid, sig: signals.append((pid, sig)))
    with legacy_daemon(install) as daemon:
        code, out, diagnostics = _run_main(install)
        assert _alive(daemon)
    assert code == 1 and signals == []
    assert runtime_messages.HOLDER_UNVERIFIED in out
    assert diagnostics[0]["check"] == "unverified"
    assert diagnostics[0]["reason"] == "changed"
    _assert_untouched(install)


def test_uninspectable_process_is_refused(install, monkeypatch):
    """A platform that cannot say exactly what a process is running gets
    a refusal, not a best guess from `ps` text."""
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    monkeypatch.setattr(repair, "_process_image", lambda pid: None)
    with legacy_daemon(install) as daemon:
        code, out, diagnostics = _run_main(install)
        assert _alive(daemon)
    assert code == 1
    assert runtime_messages.HOLDER_INSPECTION_FAILED in out
    assert diagnostics[0]["check"] == "identity"
    assert diagnostics[0]["reason"] == "uninspectable"
    _assert_untouched(install)


def test_stop_timeout_is_reported_without_escalation(install, monkeypatch):
    """A verified daemon that ignores SIGTERM gets one SIGTERM, then a
    refusal. It is never killed."""
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    monkeypatch.setattr(repair, "QUIESCE_TIMEOUT", 2.0)
    signals: list[tuple[int, int]] = []

    def record(pid: int, sig: int) -> None:
        signals.append((pid, sig))
        os.kill(pid, sig)

    monkeypatch.setattr(repair, "_signal", record)
    with legacy_daemon(install, ignore_term=True) as daemon:
        code, out, diagnostics = _run_main(install)
        time.sleep(0.5)
        assert _alive(daemon), "the daemon was killed"
    assert code == 1
    assert signals == [(daemon.pid, signal.SIGTERM)]
    assert runtime_messages.HOLDER_STOP_TIMEOUT in out
    assert runtime_messages.HOLDER_UNVERIFIED not in out
    assert diagnostics[0]["check"] == "stop_timeout"
    assert diagnostics[0]["signalled"] is True
    _assert_untouched(install)


def test_stop_runtime_leaves_unverified_holder_running(install):
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    with legacy_daemon(install, tail=("-m", "privacy_hud.daemon", "-x")) \
            as daemon:
        completed = install.bootstrap("repair", "--stop-runtime")
        assert completed.returncode == 1
        assert _alive(daemon)
    _assert_untouched(install)


# --------------------------------------------------------------------- #
# the classifier, rule by rule
# --------------------------------------------------------------------- #

def _framework(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A framework layout: `F/bin/python3.12`, its app launcher, and a
    virtual environment whose `bin/python` links to the former."""
    framework = tmp_path / "Python.framework" / "Versions" / "3.12"
    (framework / "bin").mkdir(parents=True)
    base = framework / "bin" / "python3.12"
    base.write_text("", encoding="utf-8")
    app = (framework / "Resources" / "Python.app" / "Contents" / "MacOS"
           / "Python")
    app.parent.mkdir(parents=True)
    app.write_text("", encoding="utf-8")
    venv = tmp_path / "venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").symlink_to(base)
    return base, app, venv / "python"


def _identity(argv, *, executable, launcher=None, uid=None) -> dict:
    return {"pid": 4242, "uid": str(os.getuid() if uid is None else uid),
            "started": "Thu Sep 24 00:00:00 2026", "args": " ".join(argv),
            "executable": executable, "argv": list(argv),
            "launcher": launcher}


def test_classifier_accepts_the_direct_legacy_form(tmp_path):
    base, _app, venv = _framework(tmp_path)
    identity = _identity([str(venv), *repair.LEGACY_DAEMON_ARGS],
                         executable=str(base))
    assert repair.classify_holder(identity, tmp_path, tmp_path,
                                  interpreter=venv) == "legacy"


def test_classifier_accepts_the_framework_relaunch(tmp_path):
    """macOS framework Python re-executes its app launcher: argv[0] is
    the launcher, and the interpreter the process was started as is only
    in `__PYVENV_LAUNCHER__`."""
    _base, app, venv = _framework(tmp_path)
    identity = _identity([str(app), *repair.LEGACY_DAEMON_ARGS],
                         executable=str(app), launcher=str(venv))
    assert repair.classify_holder(identity, tmp_path, tmp_path,
                                  interpreter=venv) == "legacy"


def test_classifier_accepts_the_current_bootstrap(tmp_path):
    base, _app, venv = _framework(tmp_path)
    bundle = tmp_path / "bundle"
    bootstrap = bundle / "scripts" / "runtime.py"
    bootstrap.parent.mkdir(parents=True)
    bootstrap.write_text("", encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    identity = _identity([str(venv), "-I", str(bootstrap), "--plugin-data",
                          str(data), "daemon"], executable=str(base))
    assert repair.classify_holder(identity, data, bundle,
                                  interpreter=None) == "current"
    other = tmp_path / "elsewhere"
    other.mkdir()
    with pytest.raises(storage.QuiescenceRefusal) as refusal:
        repair.classify_holder(identity, other, bundle, interpreter=None)
    assert refusal.value.reason == "data_dir"


@pytest.mark.parametrize("case, reason", [
    ("other_user", "user"),
    ("extra_argument", "launch_form"),
    ("other_module", "launch_form"),
    ("substring_only", "launch_form"),
    ("other_interpreter", "interpreter"),
    ("framework_without_launcher", "interpreter"),
    ("framework_other_launcher", "interpreter"),
    ("basename_only", "interpreter"),
    ("no_interpreter", "installation"),
])
def test_classifier_refuses(tmp_path, case, reason):
    base, app, venv = _framework(tmp_path)
    interpreter: Path | None = venv
    legacy = list(repair.LEGACY_DAEMON_ARGS)
    argv = [str(venv), *legacy]
    kwargs: dict = {"executable": str(base)}
    if case == "other_user":
        kwargs["uid"] = os.getuid() + 1
    elif case == "extra_argument":
        argv.append("--verbose")
    elif case == "other_module":
        argv = [str(venv), "-m", "privacy_hud.daemonx"]
    elif case == "substring_only":
        argv = [str(venv), "-c", "import privacy_hud.daemon"]
    elif case == "other_interpreter":
        kwargs["executable"] = sys.executable
        argv = [sys.executable, *legacy]
    elif case == "framework_without_launcher":
        argv = [str(app), *legacy]
        kwargs = {"executable": str(app)}
    elif case == "framework_other_launcher":
        argv = [str(app), *legacy]
        kwargs = {"executable": str(app), "launcher": str(base)}
    elif case == "basename_only":
        argv = ["python", *legacy]
    elif case == "no_interpreter":
        interpreter = None
    identity = _identity(argv, **kwargs)
    with pytest.raises(storage.QuiescenceRefusal) as refusal:
        repair.classify_holder(identity, tmp_path, tmp_path,
                               interpreter=interpreter)
    assert refusal.value.check == "unverified"
    assert refusal.value.reason == reason
    assert refusal.value.pids == (4242,)


@pytest.mark.parametrize("missing", ["executable", "argv"])
def test_classifier_refuses_what_it_cannot_inspect(tmp_path, missing):
    _base, _app, venv = _framework(tmp_path)
    identity = _identity([str(venv), *repair.LEGACY_DAEMON_ARGS],
                         executable=str(venv))
    identity[missing] = None
    with pytest.raises(storage.QuiescenceRefusal) as refusal:
        repair.classify_holder(identity, tmp_path, tmp_path,
                               interpreter=venv)
    assert refusal.value.check == "identity"
    assert refusal.value.reason == "uninspectable"


def test_process_image_reads_this_process_exactly():
    """The exact argv and executable of a real process, on this platform,
    or `None` where it cannot be read unambiguously."""
    image = repair._process_image(os.getpid())
    if image is None:
        pytest.skip("this platform cannot inspect argv unambiguously")
    executable, argv, _launcher = image
    assert Path(executable).is_absolute()
    assert argv[1:] == sys.orig_argv[1:]


# --------------------------------------------------------------------- #
# the copy
# --------------------------------------------------------------------- #

def test_legacy_stop_copy_is_astras():
    assert runtime_messages.LEGACY_DAEMON_STOPPING == (
        "Stopping the verified legacy Privacy HUD daemon for this data "
        "directory.")
    assert runtime_messages.LEGACY_DAEMON_STOPPED == (
        "The legacy Privacy HUD daemon stopped. Checking that storage can "
        "be moved safely.")
    assert runtime_messages.HOLDER_UNVERIFIED == (
        "Privacy HUD could not verify the identity of a process using this "
        "ledger.\n"
        "No stop signal was sent. The storage transition did not start.\n"
        "Existing ledger files were preserved.")
    assert runtime_messages.HOLDER_INSPECTION_FAILED == (
        "Privacy HUD could not inspect processes using this ledger.\n"
        "The storage transition did not start. Existing ledger files were "
        "preserved.")
    assert runtime_messages.HOLDER_STOP_TIMEOUT == (
        "The verified Privacy HUD process did not stop within 20 seconds.\n"
        "The storage transition did not start. Existing ledger files were "
        "preserved.")


def test_stop_deadline_is_the_one_the_copy_names():
    assert repair.QUIESCE_TIMEOUT == 20.0
    assert "within 20 seconds" in runtime_messages.HOLDER_STOP_TIMEOUT


def test_no_signal_copy_is_not_used_after_a_signal():
    """"No stop signal was sent" is only true before signalling."""
    refusal = storage.QuiescenceRefusal("holders", pids=(1,))
    assert repair.refusal_message(refusal) == \
        runtime_messages.HOLDER_UNVERIFIED
    refusal.signalled = True
    assert "No stop signal was sent" not in repair.refusal_message(refusal)
