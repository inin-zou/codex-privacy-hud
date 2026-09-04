#!/usr/bin/env python3
# hooks/handler.py
"""Thin hook client. Stdlib only (Global Constraint) — every import here is
paid on every tool call and is a new way to break a user's session.

Forwards the hook payload to the daemon over a unix socket and relays the
reply. All policy lives in the daemon.

It also starts the daemon when nothing is listening. That belongs here, and
only here, for a reason that is easy to miss: **hooks are Codex's child
processes, so `PLUGIN_DATA` and `PLUGIN_ROOT` are already in this process's
environment.** A daemon spawned from here inherits the exactly-correct
`PLUGIN_DATA`, which turns this project's most expensive bug — a hand-started
daemon listening on a socket no hook will ever connect to — from a thing the
doctor detects into a thing that cannot happen. What it must NOT do is guess
the interpreter: this file is executed through its `#!/usr/bin/env python3`
shebang against Codex's minimal `PATH`, which on a typical machine resolves to
a system Python with no `transformers` at all, and a daemon started there
comes up with tier 3 silently dead while reporting itself healthy. So the
interpreter is read from the receipt `privacy-hud-setup` wrote (see
`privacy_hud/runtime.py`), and if there is no usable receipt no daemon is
started — the honest missing-daemon path is kept instead.

The hot path is unchanged: when a daemon is listening this file does one
`connect()`, one write, one read, and imports nothing beyond the four modules
below. Everything the spawn needs is imported lazily inside `_spawn_daemon`,
which only runs when `connect()` fails.
"""
import json
import os
import socket
import sys

TIMEOUT = 2.0  # seconds
# Was 0.12s under the assumption that tier 3 (the model detector) rarely
# ran. Engine._scan() now runs tier 3 unconditionally on every qualifying
# observation (see engine.py's fix commit) -- measured real round trip for
# a short PostToolUse payload is ~280ms, not the sub-millisecond regex-only
# cost 120ms was calibrated against. 2s leaves headroom under the tightest
# observed Codex-side hook timeout (SessionEnd is clamped to 3s on newer
# Codex builds -- see architecture.md's platform-drift note) while comfortably
# covering slower/larger payloads up to MAX_TIER3_CHARS.
EGRESS_EVENTS = {"PreToolUse"}

# --- lazy daemon start ------------------------------------------------------
# These five literals are the contract with `privacy_hud/runtime.py`, restated
# here because this file is stdlib-only and never imports the package (that
# constraint is what keeps a broken install from breaking Codex, and it is
# asserted by tests/test_handler.py). tests/test_runtime.py parses this file
# and asserts every one of them matches `runtime.py`, so the duplication is
# checked rather than trusted -- the same treatment `daemon.sock` already gets.
RECEIPT_NAME = "runtime.json"
RECEIPT_VERSION = 1
LATCH_NAME = "daemon.spawn-attempt"
SPAWN_COOLDOWN = 30.0
DAEMON_MODULE = "privacy_hud.daemon"
NO_SPAWN_ENV = "PRIVACY_HUD_NO_SPAWN"
PINNED_ENV_NAMES = ("HF_HOME", "HF_HUB_CACHE", "TRANSFORMERS_CACHE")
# `daemon.main`'s "nothing is wrong -- the daemon you wanted already exists"
# exit code, deliberately outside the 0/1 usable/broken convention. Not a
# failure, so a child that exits with it does not latch as one.
EXIT_ALREADY_RUNNING = 3

# Holds the `Popen` handle for the lifetime of this process. Two reasons, both
# learned the hard way elsewhere: a dropped handle makes a child that exited
# instantly indistinguishable from one still booting (so `poll()` below has
# something to ask), and `Popen.__del__` running while a child is still alive
# emits a ResourceWarning that would land on the hook's stderr, which Codex
# reads. Never joined: waiting is the one thing this must not do.
_spawned = []


def _deny(reason):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _looks_like_egress(payload):
    if payload.get("hook_event_name") not in EGRESS_EVENTS:
        return False
    ti = payload.get("tool_input") or {}
    blob = json.dumps(ti) if isinstance(ti, dict) else str(ti)
    return "://" in blob or payload.get("tool_name", "").startswith("mcp")


def _unverified(payload, starting):
    """I6: fail open on ingress, fail closed on egress.

    `starting` only changes the wording. It is worth changing: "unavailable"
    and "still starting" call for different actions from the user (fix the
    setup vs. try again in a moment), and this is the only place that knows
    which one it is. Neither message claims the call was checked.
    """
    if _looks_like_egress(payload):
        if starting:
            return _deny("Privacy HUD is still starting and could not verify "
                         "this call. Retry in a few seconds, or allow once.")
        return _deny("Privacy HUD could not verify this call. "
                     "Run $privacy to review, or allow once.")
    if starting:
        return {"systemMessage": "Privacy HUD is starting — this call is "
                                 "unverified."}
    return {"systemMessage": "Privacy HUD unavailable — disclosure unverified."}


def _spawn_daemon(data_dir):
    """Start the daemon detached. Returns True when one is expected to be
    coming up — either this call launched it, or a recent call did.

    Returns without doing anything at all if auto-spawn is disabled, if
    another hook attempted a spawn within `SPAWN_COOLDOWN` seconds, or if the
    receipt is missing, unreadable, of an unknown version, or names an
    interpreter that is not an executable file. Every one of those degrades to
    exactly the behaviour this file had before auto-spawn existed (I6): the
    caller still gets its fail-open/fail-closed answer, and Codex is never
    blocked by a daemon that could not be started.

    It never waits for the daemon to be usable. `Daemon.__init__` loads ~2.8
    GB before it binds, roughly seven seconds, and this process is inside a
    5 s Codex hook timeout on the hot path of a tool call. So the spawn is
    fire-and-forget and this hook -- and the next few -- are answered as
    unverified. That window is real and is documented in the README rather
    than papered over.

    The cooldown latch is what keeps the cold-start window from forking one
    interpreter per hook: during those seven seconds there is no socket file,
    so every hook lands here. Correctness does not depend on it -- `daemon.py`
    holds an exclusive `flock` across startup, so a racing second daemon exits
    3 (`EXIT_ALREADY_RUNNING`) without touching the winner's socket -- but a
    storm of doomed 2.8 GB-capable interpreters is worth not starting.
    """
    # Deferred on purpose: the common case is a daemon that answers, and it
    # must not pay an import it will never use. `os` and `json` are already
    # loaded for the hot path.
    import subprocess
    import time

    if (os.environ.get(NO_SPAWN_ENV) or "").strip() not in ("", "0"):
        return False

    latch = os.path.join(data_dir, LATCH_NAME)
    try:
        if time.time() - os.stat(latch).st_mtime < SPAWN_COOLDOWN:
            # A spawn happened seconds ago. Whether a daemon is on its way
            # decides the wording of the reply, and the latch already knows:
            # an attempt that launched a process records a pid, one that could
            # not records an error. Saying "unavailable" while a daemon is
            # mid-load, or "starting" when nothing ever started, are both
            # wrong in a way the user would act on.
            try:
                with open(latch) as handle:
                    record = json.load(handle)
                return bool(record.get("pid")) and not record.get("error") \
                    and record.get("exit") in (None, 0, EXIT_ALREADY_RUNNING)
            except (OSError, ValueError, AttributeError):
                return False
    except OSError:
        pass  # no latch, or an unreadable one: proceed

    def _latch(**fields):
        # Infrastructure only (I1): a timestamp, a pid, an exit status, an
        # exception class name. Never a payload, never an exception message.
        try:
            with open(latch, "w") as handle:
                json.dump({"at": time.time(), **fields}, handle)
        except OSError:
            pass

    try:
        with open(os.path.join(data_dir, RECEIPT_NAME)) as handle:
            # This file names a program this process is about to execute, so
            # who can write it matters. `PLUGIN_DATA` defaults to /tmp
            # everywhere in this plugin when Codex does not set it, and a
            # world-writable /tmp/runtime.json planted by another local user
            # would otherwise be an arbitrary-exec hole. `fstat` on the open
            # handle rather than `stat` on the path: the check has to describe
            # the bytes actually read, not a file that may have been swapped
            # since. `write_receipt` creates it 0600, so this never fires on a
            # real setup.
            info = os.fstat(handle.fileno())
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                _latch(error="receipt is writable by others")
                return False
            receipt = json.load(handle)
        if not isinstance(receipt, dict) or receipt.get("v") != RECEIPT_VERSION:
            raise ValueError("unusable receipt")
        python = receipt["python"]
        if not isinstance(python, str) or not python:
            raise ValueError("unusable receipt")
    except (OSError, ValueError, KeyError) as exc:
        # No receipt means setup was never run. Deliberately silent here and
        # loud in `privacy-hud-doctor`: a hook is not a place to lecture, and
        # the reply already says the call was not verified.
        _latch(error=type(exc).__name__)
        return False

    if not os.access(python, os.X_OK) or os.path.isdir(python):
        _latch(error="pinned interpreter is not executable")
        return False

    env = dict(os.environ)
    # PLUGIN_DATA is NOT taken from the receipt. It is already correct in this
    # process because Codex put it there, and that is the whole reason this
    # spawn belongs in the hook client.
    env["PLUGIN_DATA"] = data_dir
    pythonpath = receipt.get("pythonpath")
    if isinstance(pythonpath, str) and pythonpath:
        parts = [pythonpath] + [p for p in env.get("PYTHONPATH", "").split(
            os.pathsep) if p]
        seen, ordered = set(), []
        for part in parts:
            if part not in seen:
                seen.add(part)
                ordered.append(part)
        env["PYTHONPATH"] = os.pathsep.join(ordered)
    recorded_env = receipt.get("env")
    if isinstance(recorded_env, dict):
        # Where the pinned interpreter should look for model weights. Only
        # filled in where this environment says nothing: the live value is
        # newer and Codex's is authoritative.
        for name in PINNED_ENV_NAMES:
            value = recorded_env.get(name)
            if isinstance(value, str) and value and not env.get(name):
                env[name] = value

    try:
        proc = subprocess.Popen(
            [python, "-m", DAEMON_MODULE],
            # A hook's stdout IS its reply to Codex and its stderr is read by
            # Codex; a detached daemon must inherit neither. DEVNULL rather
            # than a log file is also an I1 decision: an exception message or
            # traceback written to a file in PLUGIN_DATA is a string this
            # plugin did not choose, and could carry payload text. What the
            # daemon's failures cost in diagnosability is bought back by the
            # exit status recorded in the latch and by privacy-hud-doctor.
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            # Detach: the daemon must outlive this hook process, and must not
            # die with the process group when Codex's hook times out or the
            # terminal running Codex goes away.
            start_new_session=True,
            close_fds=True,
            env=env,
            # Never hold the session's cwd: a daemon that outlives it would
            # pin an unmountable volume or a deleted directory.
            cwd="/",
        )
    except (OSError, ValueError) as exc:
        # Popen raises here when the recorded interpreter has been deleted or
        # is not executable -- the stale-pin case, caught synchronously.
        _latch(error=type(exc).__name__)
        return False

    _spawned.append(proc)
    # Non-blocking. Exit 3 is EXIT_ALREADY_RUNNING and means a daemon is
    # already there -- not a failure, so it is recorded as an outcome and not
    # as an error. In practice a child cannot have exec'd yet, so this is
    # almost always None; it costs nothing and it is the only way an
    # instantly-dead child is distinguishable from one still booting.
    _latch(pid=proc.pid, exit=proc.poll())
    return True


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return {}
    data_dir = os.environ.get("PLUGIN_DATA", "/tmp")
    sock_path = os.path.join(data_dir, "daemon.sock")
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect(sock_path)
    except Exception:
        # Only a failed *connect* means nothing is listening. This is
        # deliberately not the same `except` as the exchange below: the cold
        # model load is ~7s against a 2s client timeout, the daemon answers
        # requests serially, and so a timeout mid-conversation is what a BUSY
        # daemon looks like. Treating that as death would spawn a rival and
        # leave two ~2.8 GB processes fighting over one socket.
        starting = False
        try:
            starting = _spawn_daemon(data_dir)
        except Exception:
            pass  # I6: a failed spawn must never break Codex
        return _unverified(payload, starting)

    try:
        s.sendall((json.dumps({"v": 1, "op": "event",
                               "payload": payload}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode())
    except Exception:
        # Something answered and then the exchange failed: a wedged, busy or
        # mid-restart daemon. No spawn -- see above.
        return _unverified(payload, False)


if __name__ == "__main__":
    try:
        out = main()
    except Exception:
        out = {}
    sys.stdout.write(json.dumps(out) if out else "")
    sys.exit(0)
