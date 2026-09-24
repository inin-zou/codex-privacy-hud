# src/privacy_hud/runtime_repair.py
"""Explicit runtime repair (#66, Pair 5).

Repair is the one operation that changes which runtime is selected. A hook
may start an already-selected, compatible runtime; only this may quiesce
the old one, relocate the ledger behind the fence and publish a new
activation. That separation is deliberate: it keeps process termination
and a database relocation out of the two-second budget of a tool call.

The state machine, in order, and every step refuses rather than guessing:

1. **The bundle.** `load_identity` over the bundle the installer itself
   lives in. Its files must hash to the build it claims.
2. **The receipt, classified.** `absent`, `v1`, `v2`, `malformed` and
   `unreadable` are five different facts. Only the first three supply an
   interpreter; an unreadable receipt is not evidence of anything, least
   of all permission to take ownership, so repair over one requires an
   explicitly named interpreter.
3. **The probe.** The candidate interpreter is asked, in its own process,
   to import *this bundle's* first-party code and the dependencies. No
   `pip`, no network, no download: installation is the installer's, and
   it is explicit (I2).
4. **Quiescence.** `runtime_storage.open_holders` asks the operating
   system who has the ledger open — unknown processes included — and a
   host that cannot answer refuses. Recognized Privacy HUD processes for
   *this* data directory are revalidated, asked once to exit, and waited
   for; anything else is a refusal. No `pkill`, no name matching, no
   escalation to `SIGKILL`, and no claim of immunity against a hostile
   same-user race.
5. **The transition.** `prepare_storage`, under both exclusions, which
   rechecks holders itself before it moves a file.
6. **The old publisher's snapshots**, retired before the replacement
   publishes anything, so no inherited reading can survive the cutover.
7. **The receipt**, published atomically with a fresh activation epoch.
8. **The daemon**, started through the bundled bootstrap and required to
   complete a handshake. Success is printed after that and not before.

I1: nothing here reads hook content or ledger values. Refusals carry a
fixed `FailureCode`, and what reaches the user is fixed copy from
`runtime_messages` — never an exception message, an errno, or a path an
operating system chose.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path

from . import codex, hud_snapshot, offline, runtime_messages, runtime_storage
from .runtime_client import connect_runtime
from .runtime_contract import (
    PINNED_ENV_NAMES,
    RECEIPT_NAME,
    RECEIPT_VERSION,
    RELEASE,
    STORAGE_GENERATION,
    Activation,
    JSONObject,
    RuntimeRefusal,
    classify_receipt,
    load_identity,
    read_receipt,
)
from .runtime_owner import acquire_writer, unselected_activation

__all__ = [
    "LEGACY_DAEMON_ARGS", "RepairResult", "classify_holder",
    "format_repair_command", "main", "process_identity",
    "quiescence_diagnostic", "refusal_message", "repair_runtime",
    "resolve_installed_bundle", "stop_holders", "stop_selected_runtime",
]

#: How long the whole quiescence step may take: revalidate, ask to exit,
#: wait. Bounded and graceful. A process that has not exited by then is a
#: refusal, not a `SIGKILL` target — repair does not get to decide that a
#: process holding a database must die.
QUIESCE_TIMEOUT = 20.0

#: How long the replacement daemon has to bind and answer a handshake. A
#: cold start loads the deep-scan model before it binds.
STARTUP_TIMEOUT = 180.0

#: Per-attempt connect budget while waiting for that handshake.
HELLO_TIMEOUT = 2.0

#: Ceiling on the interpreter probe. The same reasoning as
#: `runtime.PROBE_TIMEOUT`: an interpreter that cannot import its stack
#: inside a minute cannot serve a hook either.
PROBE_TIMEOUT = 120.0

#: Environment names removed from everything this module starts. No
#: inherited path may supply first-party code (#66 Pair 1).
STRIPPED_ENV = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                "PYTHONUSERBASE", "PYTHONEXECUTABLE", "PYTHONINSPECT",
                "PRIVACY_HUD_MCP_REEXEC", "PRIVACY_HUD_BOOTSTRAP_REEXEC")

#: Dependencies the probe reports. Their absence is degradation, not
#: failure; failing to import the bundle's own code is failure.
PROBED_DEPENDENCIES = ("transformers", "torch", "mcp")

#: The probe child. One flat string: the interpreter under test may have
#: no `privacy_hud` on its path at all, which is part of what is measured.
_PROBE_SOURCE = """
import importlib, json, sys
sys.path.insert(0, sys.argv[1])
out = {}
try:
    import privacy_hud
    from privacy_hud import runtime_contract
except BaseException:
    raise SystemExit(2)
out["first_party"] = str(privacy_hud.__file__)
out["release"] = runtime_contract.RELEASE
out["version"] = ".".join(str(p) for p in sys.version_info[:3])
for name in %(modules)r:
    try:
        module = importlib.import_module(name)
    except BaseException:
        out[name] = None
        continue
    out[name] = str(getattr(module, "__version__", "") or "present")
sys.stdout.write(json.dumps(out))
""" % {"modules": list(PROBED_DEPENDENCIES)}


@dataclass(frozen=True)
class RepairResult:
    activation: Activation
    preserved_existing: bool
    degraded: bool


# --------------------------------------------------------------------- #
# the command a user is told to run
# --------------------------------------------------------------------- #

def format_repair_command(bundle_root: Path, data_dir: Path) -> str:
    """The exact command a user is told to run, shell-quoted.

    `shlex.join` over a fixed argv, so a path containing spaces or shell
    metacharacters is one argument and never a command substitution.
    """
    return shlex.join([
        "sh", str(Path(bundle_root) / "install.sh"),
        "--repair-runtime", "--plugin-data", str(data_dir), "--yes",
    ])


def format_ambient_command(bundle_root: Path, data_dir: Path) -> str:
    """The bundled ambient launcher, shell-quoted, for another terminal.

    The bootstrap rather than a console script: it re-execs into the
    selected interpreter itself, so `python3` here is only the thing that
    reads the bootstrap, and the pane ends up running the same bundle
    everything else does. Same quoting rule as the repair command — a
    real installed path with a space in it is one argument.
    """
    return shlex.join([
        "python3", str(Path(bundle_root) / "scripts" / "runtime.py"),
        "--plugin-data", str(data_dir), "ambient", "--watch",
    ])


def resolve_installed_bundle(release: str) -> Path:
    """The single installed plugin bundle for `release`, from Codex's own
    plugin cache.

    Codex runs a *copy* of the plugin out of
    `$CODEX_HOME/plugins/cache/<marketplace>/<plugin>/<version>/`, and
    that copy is what a fresh installation must invoke. More than one
    match is an error: "the newest directory" is a guess, and the whole
    point of #66 is that nothing guesses which code runs.
    """
    root = codex.plugin_cache_root()
    try:
        marketplaces = sorted(p for p in root.iterdir()
                              if p.is_dir() and not p.is_symlink())
    except OSError:
        raise RuntimeRefusal("bundle_invalid") from None
    found = [market / codex.PLUGIN_NAME / release for market in marketplaces]
    found = [path for path in found
             if (path / "scripts" / "runtime.py").is_file()]
    if len(found) != 1:
        raise RuntimeRefusal("bundle_invalid")
    return found[0]


# --------------------------------------------------------------------- #
# processes
# --------------------------------------------------------------------- #

def _signal(pid: int, sig: int) -> None:
    """The one place a signal is sent. Named so a test can watch it, and
    so nothing else in this module reaches `os.kill` directly."""
    os.kill(pid, sig)


def _ps_identity(pid: int) -> tuple[str, str, str] | None:
    """`(uid, start time, args)` from `ps`, or `None`."""
    try:
        completed = subprocess.run(
            ["ps", "-ww", "-o", "uid=,lstart=,args=", "-p", str(int(pid))],
            capture_output=True, text=True, timeout=30.0)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    line = completed.stdout.strip()
    if not line:
        return None
    parts = line.split(None, 6)
    if len(parts) < 7:
        return None
    return parts[0], " ".join(parts[1:6]), parts[6]


def process_identity(pid: int) -> dict | None:
    """The facts that make a pid the same process later, or `None`.

    A pid is not a process: between the moment a holder is recognized and
    the moment a signal would be sent, that number can belong to
    something else entirely. `lstart` is the discriminator — a start time
    plus a pid is an identity a reused number cannot forge — and the
    user, the executable and the exact argument vector come with it,
    because "same pid, same start time, different program" is the case
    that matters after an `exec`.

    `executable`, `argv` and `launcher` come from `_process_image` and are
    `None` where this platform cannot read them exactly; a holder with
    `None` there is refused, never guessed at from `ps` text (#70). The
    start time is read on both sides of the image, so an image read from
    a process that replaced this one under the same pid is not recorded
    as this one's.

    I1: facts about *this user's own* processes, held in memory for the
    length of one repair and never written anywhere.
    """
    before = _ps_identity(pid)
    if before is None:
        return None
    image = (_process_image(int(pid))
             if before[0] == str(os.getuid()) else None)
    after = _ps_identity(pid)
    if after is None:
        return None
    if after != before:
        image = None
    executable, argv, launcher = (image if image is not None
                                  else (None, None, None))
    return {"pid": int(pid), "uid": before[0], "started": before[1],
            "args": before[2], "executable": executable,
            "argv": argv, "launcher": launcher}


#: The legacy daemon launch form this release can stop (#70): what 0.7.x
#: hooks ran, `[recorded_python, "-m", "privacy_hud.daemon"]`, with the
#: data directory in `PLUGIN_DATA`. Exactly this argument vector after the
#: interpreter, and nothing else: another module, an extra argument, or
#: "privacy_hud" inside a `-c` string is a different program.
LEGACY_DAEMON_ARGS = ("-m", "privacy_hud.daemon")

#: `__PYVENV_LAUNCHER__`: what a macOS framework Python's stub sets to the
#: interpreter path it was started as, before re-executing the framework's
#: app launcher. It is the only place that path survives the re-exec.
_LAUNCHER_ENV = b"__PYVENV_LAUNCHER__="

#: `sysctl` names for a process's exact argument vector on macOS.
_CTL_KERN = 1
_KERN_PROCARGS2 = 49


def _process_image(pid: int) -> tuple[str, list[str], str | None] | None:
    """`(executable, argv, launcher)` for `pid`, read exactly, or `None`.

    Exactly means from the kernel's own record, never by splitting `ps`
    text: an argument containing a space and two arguments are the same
    string to `ps`, and astra's rule is to refuse where the platform
    cannot tell them apart (#70). Linux: `/proc/<pid>/exe` and the
    NUL-separated `/proc/<pid>/cmdline`. macOS: `proc_pidpath` and
    `KERN_PROCARGS2`. Anything else: `None`.

    `launcher` is only ever read on macOS. `KERN_PROCARGS2` returns a
    buffer that also contains the process environment; only the
    `__PYVENV_LAUNCHER__` value is retained in the returned image, and
    none of it is logged or persisted. `process_identity` calls this only
    for a process of this user. Nothing of the old package is executed to
    learn any of this.
    """
    if sys.platform.startswith("linux"):
        try:
            executable = os.readlink(f"/proc/{int(pid)}/exe")
            raw = Path(f"/proc/{int(pid)}/cmdline").read_bytes()
        except (OSError, ValueError):
            return None
        if not raw:
            return None
        argv = [os.fsdecode(part) for part in raw.split(b"\0")]
        if argv and argv[-1] == "":
            argv.pop()
        return (executable, argv, None) if argv else None
    if sys.platform == "darwin":
        return _darwin_image(int(pid))
    return None


def _darwin_image(pid: int) -> tuple[str, list[str], str | None] | None:
    import ctypes
    import ctypes.util
    import struct

    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        path = ctypes.create_string_buffer(4096)
        if libc.proc_pidpath(pid, path, ctypes.sizeof(path)) <= 0:
            return None
        executable = os.fsdecode(path.value)
        mib = (ctypes.c_int * 3)(_CTL_KERN, _KERN_PROCARGS2, pid)
        size = ctypes.c_size_t(0)
        if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
            return None
    except (OSError, AttributeError, ValueError):
        return None
    raw = buffer.raw[:size.value]
    if len(raw) < 4:
        return None
    argc = struct.unpack_from("i", raw)[0]
    _exec_path, _, rest = raw[4:].partition(b"\0")
    parts = rest.lstrip(b"\0").split(b"\0")
    if argc <= 0 or len(parts) < argc:
        return None
    argv = [os.fsdecode(part) for part in parts[:argc]]
    launcher = None
    for entry in parts[argc:]:
        if not entry:
            break
        if entry.startswith(_LAUNCHER_ENV):
            launcher = os.fsdecode(entry[len(_LAUNCHER_ENV):])
            break
    return executable, argv, launcher


def _launched_as(identity: dict, interpreter: Path) -> bool:
    """Was this process started as `interpreter`, this installation's
    recorded one?

    Two shapes, each a relation between exact facts rather than a name:

    * **Direct.** `argv[0]` is the recorded path, as the legacy hook
      passed it, and the executable is that path's real file.
    * **macOS framework relaunch.** The framework's stub re-executes its
      app launcher, so `argv[0]` and the executable are both
      `<framework>/Resources/Python.app/Contents/MacOS/Python` for the
      framework the recorded interpreter resolves into, and the path it
      was started as survives only in `__PYVENV_LAUNCHER__`, which must be
      the recorded path exactly.

    A basename, a different interpreter of the same version, or a
    framework launcher with no or another launcher path is none of these.
    """
    recorded = str(interpreter)
    if not os.path.isabs(recorded):
        return False
    executable = identity.get("executable")
    argv = identity.get("argv") or []
    try:
        real = Path(os.path.realpath(recorded))
    except (OSError, ValueError):
        return False
    if argv[0] == recorded and executable == str(real):
        return True
    if real.parent.name != "bin":
        return False
    app = (real.parent.parent / "Resources" / "Python.app" / "Contents"
           / "MacOS" / "Python")
    return (executable == str(app) and argv[0] == executable
            and identity.get("launcher") == recorded)


def classify_holder(identity: dict, data_dir: Path, bundle: Path, *,
                    interpreter: Path | None) -> str:
    """What a process holding this data directory's ledger is, or a
    refusal saying why it cannot be stopped (#70).

    Returns `"current"` for this installation's bundled bootstrap serving
    this data directory, and `"legacy"` for a supported legacy daemon of
    this installation. Every one of astra's rules applies, and none of
    them is a substring:

    * the same user;
    * an identity read exactly -- executable and argument vector -- or a
      refusal (`identity`/`uninspectable`);
    * a supported launch form: the bundled bootstrap, or exactly
      `LEGACY_DAEMON_ARGS` after the interpreter;
    * for a legacy daemon, a relationship to this installation's recorded
      `interpreter` (`_launched_as`); with none recorded, nothing is;
    * a relationship to this data directory: the bootstrap names it, and
      a legacy daemon -- which took it from its environment -- was found
      holding this directory's ledger by device and inode, which is how
      the caller found it at all.

    A receipt, a marker pid, an executable basename or a protocol reply
    is not among the evidence. Nothing here signals anything.
    """
    pid = int(identity.get("pid") or 0)

    def refuse(reason: str) -> runtime_storage.QuiescenceRefusal:
        return runtime_storage.QuiescenceRefusal("unverified", pids=(pid,),
                                                 reason=reason)

    if identity.get("uid") != str(os.getuid()):
        raise refuse("user")
    executable = identity.get("executable")
    argv = identity.get("argv")
    if (not isinstance(executable, str) or not isinstance(argv, list)
            or not argv or not all(isinstance(a, str) for a in argv)):
        raise runtime_storage.QuiescenceRefusal(
            "identity", pids=(pid,), reason="uninspectable")
    try:
        bootstrap = str((Path(bundle) / "scripts" / "runtime.py").resolve())
        named = Path(data_dir).resolve()
    except OSError:
        raise refuse("installation") from None
    if bootstrap in argv:
        if (len(argv) != 6 or argv[1:4] !=
                ["-I", bootstrap, "--plugin-data"] or argv[5] != "daemon"):
            raise refuse("launch_form")
        if interpreter is None:
            raise refuse("installation")
        if not _launched_as(identity, Path(interpreter)):
            raise refuse("interpreter")
        try:
            if Path(argv[4]).resolve() == named:
                return "current"
        except OSError:
            pass
        raise refuse("data_dir")
    if tuple(argv[1:]) != LEGACY_DAEMON_ARGS:
        raise refuse("launch_form")
    if interpreter is None:
        raise refuse("installation")
    if not _launched_as(identity, Path(interpreter)):
        raise refuse("interpreter")
    return "legacy"


def _recorded_interpreter(data_dir: Path) -> Path | None:
    """The interpreter this installation recorded, from a receipt this
    code can read as one, or `None`. Legacy daemons were started as it."""
    if classify_receipt(data_dir) not in ("v1", "v2"):
        return None
    try:
        recorded = read_receipt(data_dir).get("python")
    except RuntimeRefusal:
        return None
    if not isinstance(recorded, str) or not os.path.isabs(recorded):
        return None
    return Path(recorded)


def stop_holders(data_dir, holders: dict, *, deadline: float,
                 on_signal=None) -> bool:
    """Ask each classified holder to exit, and wait for it. Returns whether
    any signal was sent.

    Revalidation comes immediately before signalling, and covers every
    holder before any is signalled: each must still hold this data
    directory's ledger by device and inode, and still have exactly the
    identity it was classified with. One identity that moved means this
    repair no longer knows what it is looking at, and it refuses with
    nothing sent. A holder that has exited, or has closed the ledger, is
    not signalled.

    `SIGTERM` once, then waiting until `deadline`. There is no
    escalation: a process that ignores it is reported, never killed.
    `on_signal` is called once, just before the first signal.
    """
    current_holders = set(runtime_storage.open_holders(data_dir))
    current_holders.discard(os.getpid())
    unexpected = current_holders.difference(holders)
    if unexpected:
        raise runtime_storage.QuiescenceRefusal(
            "holders", pids=unexpected, reason="new_holder")
    recheck = {}
    for pid, recorded in holders.items():
        current = process_identity(pid)
        if current is None:
            if pid in current_holders:
                raise runtime_storage.QuiescenceRefusal(
                    "identity", pids=(pid,), reason="uninspectable")
            continue
        if current != recorded:
            raise runtime_storage.QuiescenceRefusal(
                "unverified", pids=(pid,), reason="changed")
        if pid in current_holders:
            recheck[pid] = current
    if not recheck:
        return False

    if on_signal is not None:
        on_signal()
    for pid in recheck:
        try:
            _signal(pid, signal.SIGTERM)
        except OSError:
            continue

    while True:
        remaining = [pid for pid, recorded in recheck.items()
                     if process_identity(pid) == recorded]
        if not remaining:
            return True
        if time.monotonic() >= deadline:
            refusal = runtime_storage.QuiescenceRefusal(
                "stop_timeout", pids=remaining)
            refusal.signalled = True
            raise refusal
        time.sleep(0.1)


def _quiesce(data_dir: Path, bundle: Path, *, progress=None,
             settle: bool = True) -> bool:
    """Leave nothing holding the ledger, or refuse. Returns whether a stop
    signal was sent.

    Discovery is about files, not about names: `open_holders` answers who
    has the database or a sidecar open. Every holder is then classified
    (`classify_holder`) before any is signalled; one that is not this
    installation's, for this data directory, refuses the whole step with
    nothing sent. The verified ones are revalidated and asked once to
    exit (`stop_holders`).

    Afterwards the holders and the socket are checked again. `settle` is
    repair's: it also waits out a heartbeat the stopped daemon left behind
    (#71), rechecking holders and the socket on every pass. The stop-only
    operation does not wait on a heartbeat -- it answers whether processes
    are gone, not whether storage may move.
    """
    deadline = time.monotonic() + QUIESCE_TIMEOUT
    holders = {pid for pid in runtime_storage.open_holders(data_dir)
               if pid != os.getpid()}
    signalled = False
    if holders:
        interpreter = _recorded_interpreter(data_dir)
        owned: dict[int, dict] = {}
        legacy = False
        for pid in sorted(holders):
            identity = process_identity(pid)
            if identity is None:
                if pid in runtime_storage.open_holders(data_dir):
                    raise runtime_storage.QuiescenceRefusal(
                        "identity", pids=(pid,), reason="uninspectable")
                continue
            kind = classify_holder(identity, data_dir, bundle,
                                   interpreter=interpreter)
            legacy = legacy or kind == "legacy"
            owned[pid] = identity

        def stopping() -> None:
            if legacy and progress is not None:
                progress(runtime_messages.LEGACY_DAEMON_STOPPING)

        signalled = stop_holders(data_dir, owned, deadline=deadline,
                                 on_signal=stopping)
        if signalled and legacy and progress is not None:
            progress(runtime_messages.LEGACY_DAEMON_STOPPED)

    def waiting() -> None:
        if progress is not None:
            progress(runtime_messages.HEARTBEAT_WAITING)

    try:
        if settle:
            runtime_storage.await_quiescence(data_dir, on_wait=waiting)
        else:
            runtime_storage.check_quiescence(data_dir, heartbeat=False)
    except runtime_storage.QuiescenceRefusal as refusal:
        refusal.signalled = refusal.signalled or signalled
        raise
    return signalled


def stop_selected_runtime(data_dir) -> bool:
    """Stop the runtime this installation owns, for uninstallation.

    `repair --stop-runtime`. The same classifier as repair, so the same
    verified legacy daemon is stopped here, and nothing repair would
    refuse to signal is signalled (#70). Under the transition lock, so it
    never races a repair. Storage is not touched.

    Returns whether the data directory is now free of holders and of a
    live listener. It never raises: uninstall has to proceed either way,
    and what it needs to know is whether it is about to delete the
    interpreter of a live process.
    """
    root = Path(data_dir)
    if not root.is_dir():
        return True
    try:
        bundle = _selected_bundle(root)
    except RuntimeRefusal:
        # No readable v2 selection: there is no bundle whose bootstrap
        # could identify a current runtime. A legacy daemon is still
        # identified against the recorded interpreter.
        bundle = root
    try:
        with runtime_storage.acquire_transition(root):
            _quiesce(root, bundle, settle=False)
    except (RuntimeRefusal, OSError):
        return False
    return True


def _selected_bundle(data_dir: Path) -> Path:
    receipt = read_receipt(data_dir)
    root = receipt.get("selected_bundle_root")
    if not isinstance(root, str):
        raise RuntimeRefusal("setup_missing")
    return Path(root)


# --------------------------------------------------------------------- #
# the interpreter
# --------------------------------------------------------------------- #

def _candidate_python(data_dir: Path, state: str,
                      explicit: Path | None) -> Path:
    """Which interpreter this repair will record.

    An explicitly named one wins: that is the installer having probed the
    host and decided. Otherwise the receipt supplies it, and only a
    receipt this code can actually read as one — `unreadable` and
    `malformed` supply nothing, which is what stops a receipt nobody can
    read from becoming permission to activate.
    """
    if explicit is not None:
        python = Path(explicit)
        if not python.is_absolute() or not os.access(python, os.X_OK):
            raise RuntimeRefusal("setup_missing")
        return python
    if state not in ("v1", "v2"):
        raise RuntimeRefusal("setup_missing")
    receipt = read_receipt(data_dir)
    recorded = receipt.get("python")
    if not isinstance(recorded, str) or not os.path.isabs(recorded):
        raise RuntimeRefusal("setup_missing")
    return Path(recorded)


def _child_env(data_dir: Path, base: dict | None = None) -> dict:
    env = dict(os.environ if base is None else base)
    for name in STRIPPED_ENV:
        env.pop(name, None)
    env["PYTHONNOUSERSITE"] = "1"
    env["PLUGIN_DATA"] = str(data_dir)
    offline.force_offline(env)
    return env


def _probe(bundle: Path, python: Path, data_dir: Path) -> JSONObject:
    """Ask the candidate interpreter, in its own process, whether it can
    run *this bundle's* code.

    A real import, not a `find_spec`: an installed dependency that fails
    on import is the documented trap on this project, and the answer that
    matters is whether the daemon will come up, not whether a file
    exists. The child is isolated (`-I`) and offline (I2), and it is
    handed the bundle's `src` and nothing else, so a stale distribution
    in the same environment cannot answer for it.
    """
    try:
        completed = subprocess.run(
            [str(python), "-I", "-B", "-c", _PROBE_SOURCE, str(bundle / "src")],
            capture_output=True, text=True, timeout=PROBE_TIMEOUT,
            env=_child_env(data_dir))
    except (OSError, subprocess.SubprocessError):
        raise RuntimeRefusal("dependencies_unusable") from None
    if completed.returncode != 0:
        raise RuntimeRefusal("dependencies_unusable")
    try:
        result = json.loads(completed.stdout)
    except ValueError:
        raise RuntimeRefusal("dependencies_unusable") from None
    if not isinstance(result, dict):
        raise RuntimeRefusal("dependencies_unusable")
    if result.get("release") != RELEASE:
        raise RuntimeRefusal("dependencies_unusable")
    origin = result.get("first_party")
    package = (bundle / "src" / "privacy_hud").resolve()
    if not isinstance(origin, str):
        raise RuntimeRefusal("dependencies_unusable")
    try:
        inside = Path(origin).resolve().is_relative_to(package)
    except OSError:
        raise RuntimeRefusal("dependencies_unusable") from None
    if not inside:
        raise RuntimeRefusal("dependencies_unusable")
    return result


def _dependency_probe(result: JSONObject) -> JSONObject:
    """The sanitized slice of the probe the receipt records: versions and
    capabilities, nothing about this host."""
    return {name: result.get(name) for name in PROBED_DEPENDENCIES
            if isinstance(result.get(name), str) or result.get(name) is None}


# --------------------------------------------------------------------- #
# publication
# --------------------------------------------------------------------- #

def _pinned_env(data_dir: Path, state: str) -> dict:
    """The allowlisted cache settings to carry forward: the ones already
    recorded, else the ones this process was started with."""
    recorded: dict = {}
    if state in ("v1", "v2"):
        try:
            existing = read_receipt(data_dir).get("env")
        except RuntimeRefusal:
            existing = None
        if isinstance(existing, dict):
            recorded = {name: value for name, value in existing.items()
                        if name in PINNED_ENV_NAMES and isinstance(value, str)}
    if recorded:
        return recorded
    return {name: os.environ[name] for name in PINNED_ENV_NAMES
            if os.environ.get(name)}


def _write_receipt(data_dir: Path, receipt: JSONObject) -> None:
    """Atomically, 0600. A hook may read this file at any moment, and it
    names a program that hook will execute."""
    final = Path(data_dir) / RECEIPT_NAME
    temp = final.with_name(final.name + ".tmp")
    payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, final)
    os.chmod(final, 0o600)


def _retire_snapshots(data_dir: Path, transition_id: str) -> None:
    """Move the old publisher's readings out of the way before the
    replacement publishes anything.

    Snapshot v2 does not authenticate its producer, so a reading left
    behind by a daemon that has just been stopped would keep rendering as
    though it described the running runtime. Retired, not deleted: it is
    the same preservation rule the ledger gets.
    """
    source = hud_snapshot.hud_dir(data_dir)
    if not source.is_dir() or source.is_symlink():
        return
    dest = runtime_storage.retired_dir(data_dir, transition_id) / "hud"
    try:
        entries = sorted(source.iterdir())
    except OSError:
        raise RuntimeRefusal("transition_incomplete") from None
    if not entries:
        return
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(dest, 0o700)
    for entry in entries:
        if entry.is_file() and not entry.is_symlink():
            os.replace(entry, dest / entry.name)


def _start_daemon(data_dir: Path, activation: Activation) -> None:
    """Start the selected runtime through the bundled bootstrap.

    The selected interpreter, isolated, with the bootstrap's own path —
    never `-m privacy_hud.daemon`, which would import whichever
    `privacy_hud` that interpreter finds first.
    """
    bootstrap = Path(activation.bundle_root) / "scripts" / "runtime.py"
    try:
        subprocess.Popen(
            [str(activation.python), "-I", str(bootstrap),
             "--plugin-data", str(data_dir), "daemon"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
            env=_child_env(data_dir), cwd=str(Path(activation.bundle_root)))
    except (OSError, ValueError):
        raise RuntimeRefusal("runtime_starting") from None


def _await_handshake(data_dir: Path, activation: Activation) -> None:
    """Wait for the replacement daemon to answer as the selected build.

    Success is printed after this and not before: a repair that published
    a receipt and started nothing has not repaired anything.
    """
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        try:
            connect_runtime(data_dir, activation=activation,
                            timeout=HELLO_TIMEOUT).close()
            return
        except RuntimeRefusal:
            time.sleep(0.2)
    raise RuntimeRefusal("runtime_starting")


# --------------------------------------------------------------------- #
# the state machine
# --------------------------------------------------------------------- #

def repair_runtime(bundle_root: Path, data_dir: Path, *,
                   python: Path | None = None,
                   allow_degraded: bool = False,
                   progress=None) -> RepairResult:
    """Select `bundle_root`, move the ledger behind the fence, and start a
    matching daemon. See the module docstring for the ordered steps.

    `progress`, when given, is called with fixed progress copy from
    `runtime_messages` as steps that can take a while begin.

    A failed preflight preserves the existing receipt and ledger location.
    A later failure may leave a fenced store or a published selection.
    Retry resumes from the recorded selection and filesystem state.
    No failing path reports repair success.
    """
    bundle = Path(bundle_root).resolve()
    root = Path(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()

    identity = load_identity(bundle)
    if identity.storage_generation != STORAGE_GENERATION:
        raise RuntimeRefusal("runtime_mismatch")

    state = classify_receipt(root)
    candidate = _candidate_python(root, state, python)
    probe = _probe(bundle, candidate, root)
    degraded = any(probe.get(name) is None for name in ("transformers",
                                                        "torch"))
    if degraded and not allow_degraded:
        raise RuntimeRefusal("dependencies_unusable")

    with runtime_storage.acquire_transition(root):
        runtime_storage.validate_existing_ledger(root)
        signalled = _quiesce(root, bundle, progress=progress)
        lease_activation = unselected_activation()
        if classify_receipt(root) == "v2":
            receipt = read_receipt(root)
            lease_activation = Activation(
                identity=replace(
                    identity,
                    build_id=str(receipt["selected_build_id"]),
                ),
                epoch=str(receipt["activation_epoch"]),
                bundle_root=bundle,
                python=candidate,
            )
        with acquire_writer(root, activation=lease_activation) as lease:
            try:
                cutover = runtime_storage.prepare_storage(
                    root, activation=lease.activation)
            except runtime_storage.QuiescenceRefusal as refusal:
                refusal.signalled = refusal.signalled or signalled
                raise
            _retire_snapshots(root, cutover.transition_id)
            runtime_storage.record_stage(root, cutover.transition_id,
                                         "snapshots_retired",
                                         cutover.preserved_existing)
            epoch = secrets.token_hex(16)
            activation = Activation(identity=identity, epoch=epoch,
                                    bundle_root=bundle, python=candidate)
            _write_receipt(root, {
                "v": RECEIPT_VERSION,
                "python": str(candidate),
                "env": _pinned_env(root, state),
                "dependency_probe": _dependency_probe(probe),
                "selected_bundle_root": str(bundle),
                "selected_build_id": identity.build_id,
                "activation_epoch": epoch,
                "storage_generation": STORAGE_GENERATION,
                "recorded_at": time.time(),
            })
            runtime_storage.record_stage(root, cutover.transition_id,
                                         "receipt_published",
                                         cutover.preserved_existing)
        # The lease is given back here, deliberately and while the
        # transition lock is still held: the daemon about to start needs
        # the lease, and nothing else may begin a transition meanwhile.
        _start_daemon(root, activation)
        _await_handshake(root, activation)
        runtime_storage.record_stage(root, cutover.transition_id, "ready",
                                     cutover.preserved_existing)

    return RepairResult(activation=activation,
                        preserved_existing=cutover.preserved_existing,
                        degraded=degraded)


# --------------------------------------------------------------------- #
# the command line
# --------------------------------------------------------------------- #

#: Which fixed message each refusal code is shown as. Every code has one:
#: an unmapped code would print nothing, and a repair that failed
#: silently is worse than one that failed loudly.
_REFUSAL_COPY = {
    "ledger_unsupported": runtime_messages.LEDGER_UNSUPPORTED,
    "holder_unknown": runtime_messages.UNKNOWN_HOLDER,
    "runtime_mismatch": runtime_messages.REPAIR_FAILED,
    "transition_incomplete": runtime_messages.REPAIR_FAILED,
    "runtime_starting": runtime_messages.REPAIR_FAILED,
}


#: `"diagnostic"` in the one line a quiescence refusal prints to stderr.
QUIESCENCE_DIAGNOSTIC = "quiescence_refusal"


def quiescence_diagnostic(refusal: runtime_storage.QuiescenceRefusal) -> dict:
    """The allowlisted facts about a quiescence refusal (#71).

    Captured inside the failing invocation, because a probe run afterwards
    can miss a race. Fixed identifiers, holder pids, an errno, a heartbeat
    age, a timestamp and the release: nothing here is a path, a ledger
    value, an id, a hash or exception text (I1), and nothing is written
    to disk.
    """
    return {
        "diagnostic": QUIESCENCE_DIAGNOSTIC,
        "release": RELEASE,
        "time": round(time.time(), 3),
        "check": refusal.check,
        "reason": refusal.reason,
        "pids": list(refusal.pids),
        "errno": refusal.errno,
        "heartbeat_age": refusal.heartbeat_age,
        "signalled": bool(refusal.signalled),
    }


#: A socket check that could not be asked, as opposed to one answered.
_SOCKET_INSPECTION = ("stat_error", "connect_error")


def refusal_message(refusal: RuntimeRefusal) -> str:
    """The fixed copy for a refusal, still holding its `{repair_command}`.

    A quiescence refusal is shown as the branch it came from (#70):
    uninspectable processes or files, a verified process that did not stop,
    or a holder that could not be verified. The last says no stop signal
    was sent, which is only true before one was -- after a signal, what
    is left is a repair that did not complete, and that is what it says.
    """
    if isinstance(refusal, runtime_storage.QuiescenceRefusal):
        if refusal.check == "transition_lock":
            return runtime_messages.TRANSITION_BUSY
        if refusal.check == "stop_timeout":
            return runtime_messages.HOLDER_STOP_TIMEOUT
        if refusal.signalled:
            return runtime_messages.QUIESCENCE_AFTER_STOP
        if (refusal.check in ("inspection", "identity")
                or (refusal.check == "socket"
                    and refusal.reason in _SOCKET_INSPECTION)):
            return runtime_messages.HOLDER_INSPECTION_FAILED
        return runtime_messages.HOLDER_UNVERIFIED
    message = _REFUSAL_COPY.get(refusal.code)
    if message is None:
        return runtime_messages.RUNTIME_SETUP_FAIL
    return message


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="privacy-hud-repair")
    parser.add_argument("--bundle-root", required=True, metavar="DIR")
    parser.add_argument("--plugin-data", required=True, metavar="DIR")
    parser.add_argument("--python", default=None, metavar="ABSOLUTE_PYTHON")
    parser.add_argument("--allow-degraded", action="store_true")
    return parser


def _report_failure(code: str, bundle: Path, data_dir: Path, out) -> None:
    message = _REFUSAL_COPY.get(code)
    if message is None:
        message = runtime_messages.RUNTIME_SETUP_FAIL.format(
            repair_command=format_repair_command(bundle, data_dir))
    print(message.format(
        repair_command=format_repair_command(bundle, data_dir)
    ), file=out)


def main(argv: list[str] | None = None, *, out=None, err=None) -> int:
    """`runtime.py --plugin-data DIR setup` and `install.sh
    --repair-runtime` both land here.

    Every failure is rendered from fixed copy. An `OSError` from a
    durability step carries a path and an operating-system message this
    plugin did not write, and neither reaches the user: what they see is
    that the transition did not complete and their files were preserved.
    """
    stream = sys.stdout if out is None else out
    errors = sys.stderr if err is None else err
    try:
        args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    bundle = Path(args.bundle_root)
    data_dir = Path(args.plugin_data)
    try:
        result = repair_runtime(
            bundle, data_dir,
            python=Path(args.python) if args.python else None,
            allow_degraded=args.allow_degraded,
            progress=lambda message: print(message, file=stream, flush=True))
    except RuntimeRefusal as refusal:
        print(refusal_message(refusal).format(
            repair_command=format_repair_command(bundle, data_dir)),
            file=stream)
        if isinstance(refusal, runtime_storage.QuiescenceRefusal):
            print(json.dumps(quiescence_diagnostic(refusal),
                             sort_keys=True), file=errors)
        return 1
    except OSError:
        # Deliberately not the exception: an errno and a pathname are a
        # string this plugin did not choose (I1), and the user's next
        # action is the same either way.
        _report_failure("transition_incomplete", bundle, data_dir, stream)
        return 1
    template = (runtime_messages.REPAIR_SUCCESS if result.preserved_existing
                else runtime_messages.REPAIR_SUCCESS_FRESH)
    print(template.format(release=result.activation.identity.release),
          file=stream)
    if result.degraded:
        print(runtime_messages.MODEL_DEGRADED, file=stream)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    sys.exit(main())
