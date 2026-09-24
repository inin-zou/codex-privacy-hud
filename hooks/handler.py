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
import time

TIMEOUT = 2.0  # seconds -- ONE budget: connect, hello, event and reply
# Was 0.12s under the assumption that tier 3 (the model detector) rarely
# ran. Engine._scan() now runs tier 3 unconditionally on every qualifying
# observation (see engine.py's fix commit) -- measured real round trip for
# a short PostToolUse payload is ~280ms, not the sub-millisecond regex-only
# cost 120ms was calibrated against. 2s leaves headroom under the tightest
# observed Codex-side hook timeout (SessionEnd is clamped to 3s on newer
# Codex builds -- see architecture.md's platform-drift note) while comfortably
# covering slower/larger payloads up to MAX_TIER3_CHARS.

# The client half of I6: the events a failure must fail *closed* on. The
# daemon's half is `privacy_hud/codex.py`'s `EGRESS_EVENTS`, which is where
# everything this project knows about Codex the platform lives; this file is
# stdlib-only and never imports the package, so it restates the set and
# `tests/test_runtime.py` compares the two -- checked rather than trusted,
# the same treatment `daemon.sock` and the receipt literals below get.
EGRESS_EVENTS = {"PreToolUse"}

# --- lazy daemon start ------------------------------------------------------
# These literals are the contract with `privacy_hud/runtime.py` and
# `privacy_hud/runtime_contract.py`, restated here because this file is
# stdlib-only and never imports the package (that constraint is what keeps a
# broken install from breaking Codex, and it is asserted by
# tests/test_handler.py). tests/test_runtime.py parses this file and asserts
# every one of them matches, so the duplication is checked rather than
# trusted -- the same treatment `daemon.sock` already gets.
RECEIPT_NAME = "runtime.json"
RECEIPT_VERSION = 2
MANIFEST_NAME = "runtime-build.json"
LATCH_NAME = "daemon.spawn-attempt"
SPAWN_COOLDOWN = 30.0
NO_SPAWN_ENV = "PRIVACY_HUD_NO_SPAWN"
PINNED_ENV_NAMES = ("HF_HOME", "HF_HUB_CACHE", "TRANSFORMERS_CACHE")
#: #66: the daemon is started through this bundle's bootstrap, in the
#: receipt's interpreter, in isolated mode. Never `-m privacy_hud.daemon`:
#: that would import whichever `privacy_hud` the interpreter finds first.
BOOTSTRAP = ("scripts", "runtime.py")
#: Removed from the spawned daemon's environment (see `scripts/runtime.py`).
STRIPPED_ENV = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                "PYTHONUSERBASE", "PYTHONEXECUTABLE", "PYTHONINSPECT",
                "PRIVACY_HUD_MCP_REEXEC")
#: I2: assigned into the child's environment last, after every merge, so an
#: inherited value cannot turn the network back on in the process that loads
#: the model. A copy of `privacy_hud.offline.FORCED_ENV`, which this file
#: cannot import; `tests/test_offline.py` pins the two together.
OFFLINE_ENV = {
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "HF_DATASETS_OFFLINE": "1",
    "HF_HUB_DISABLE_TELEMETRY": "1",
    "DO_NOT_TRACK": "1",
    "HF_HUB_DISABLE_UPDATE_CHECK": "1",
    "DISABLE_SAFETENSORS_CONVERSION": "1",
}
# `daemon.main`'s "another daemon already owns the socket" exit code. #66:
# that says something holds the socket, not that it is a compatible daemon,
# so a latch recording it no longer reads as "starting"; only a matching
# hello proves a compatible daemon is serving.
EXIT_ALREADY_RUNNING = 3

# --- socket protocol 2 (#66) ---------------------------------------------
# Restated from `privacy_hud/runtime_client.py` and `runtime_contract.py`;
# tests/test_runtime_protocol.py pins every one of them.
PROTOCOL_VERSION = 2
STORAGE_GENERATION = 1
READABLE_SCHEMAS = (0, 5401)
HELLO_FRAME_LIMIT = 16384  # 16 KiB
EVENT_FRAME_LIMIT = 8388608  # 8 MiB
HELLO_REPLY_FIELDS = ("v", "op", "ok", "release", "build_id",
                      "activation_epoch", "storage_generation",
                      "schema_version", "ready")

# --- fixed copy (#66), restated from `privacy_hud/runtime_messages.py` ----
INGRESS_REFUSAL = (
    "Privacy HUD runtime mismatch — this event was not checked by a "
    "compatible daemon.\n"
    "Run $privacy repair to get the recovery command.")
EGRESS_REFUSAL = (
    "Privacy HUD issued a denial because no compatible daemon could verify "
    "this outbound call.\n"
    "Run $privacy repair to get the recovery command.")
STARTING_INGRESS = "Privacy HUD is starting — this event is unverified."
STARTING_EGRESS = (
    "Privacy HUD issued a denial because the daemon is still starting.\n"
    "Retry after startup completes.")



def _setup_hint():
    """The reply to `SessionStart` (Codex fires it with the first turn, so
    once per session) when the plugin is installed but `privacy-hud-setup`
    has never recorded an interpreter -- the state `codex plugin add` alone
    leaves you in. Every later hook in that session keeps the plain
    "unavailable" answer: a hook is not a place to lecture, but the first
    turn is where one line saves a trip to the README.

    The command names the copy of `install.sh` Codex placed beside this file
    when it installed the plugin, so the hint carries no URL (I2: this file
    contains no endpoint, not even one meant for a human to paste) and the
    user runs the same script the README's one-liner downloads. `--yes`
    because the installer, run from inside a Codex session, has no terminal
    to ask about the model download and would otherwise skip it.
    """
    script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "install.sh")
    if os.path.isfile(script):
        command = "  sh %s --yes" % script
    else:
        command = "  install.sh --yes  (from the codex-privacy-hud repository)"
    return {"systemMessage": (
        "Privacy HUD is installed but not set up, so nothing is being "
        "recorded. Run `$privacy setup` here, or in another terminal:\n"
        + command + "\nthen restart Codex.")}

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
    # `.startswith("mcp")`, not `"mcp__"`: Codex's own spelling. The daemon
    # applies the same predicate as `codex.is_mcp_tool`, so the two ends
    # cannot disagree about which call this is.
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
            return _deny(STARTING_EGRESS)
        return _deny("Privacy HUD could not verify this call. "
                     "Run $privacy to review.")
    if starting:
        return {"systemMessage": STARTING_INGRESS}
    return {"systemMessage": "Privacy HUD unavailable — disclosure unverified."}


def _runtime_refusal(payload):
    """#66: something answered, but not a daemon of the selected build and
    epoch -- or this hook's own bundle is not the selected one. The payload
    was not sent. I6 still decides the shape: a warning on ingress, a
    denial on egress. Neither claims the host enforced anything."""
    if _looks_like_egress(payload):
        return _deny(EGRESS_REFUSAL)
    return {"systemMessage": INGRESS_REFUSAL}


def _bundle_root():
    """This hook's own plugin bundle: two directories above this file."""
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def _own_build_id(bundle_root):
    """The `build_id` this bundle's manifest declares, or None. Read, not
    recomputed: the daemon verifies the digest of the bundle it runs from,
    and a hook that hashed the whole bundle on every tool call would pay
    for a check the daemon already makes."""
    try:
        with open(os.path.join(bundle_root, MANIFEST_NAME)) as handle:
            manifest = json.load(handle)
    except (OSError, ValueError):
        return None
    build_id = manifest.get("build_id") if isinstance(manifest, dict) else None
    return build_id if isinstance(build_id, str) and build_id else None


def _read_selection(data_dir):
    """Receipt v2's selection, or raise.

    Returns `(receipt, python)`. Raises `ValueError` for a receipt that is
    unsafe (writable by others: it names a program this process executes),
    of another version -- receipt v1 is repair input only, and its
    `pythonpath` must never select application code -- or does not select
    this bundle's build, and `OSError` when there is none.
    """
    with open(os.path.join(data_dir, RECEIPT_NAME)) as handle:
        # `fstat` on the open handle rather than `stat` on the path: the
        # check has to describe the bytes actually read. There is no `/tmp`
        # default (spec §6), and this stays as defence in depth against a
        # receipt another local user could have written.
        info = os.fstat(handle.fileno())
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("receipt is writable by others")
        receipt = json.load(handle)
    if not isinstance(receipt, dict):
        raise ValueError("unusable receipt")
    version = receipt.get("v")
    if isinstance(version, bool) or version != RECEIPT_VERSION:
        raise ValueError("unusable receipt")
    python = receipt.get("python")
    if not isinstance(python, str) or not os.path.isabs(python):
        raise ValueError("unusable receipt")
    root = receipt.get("selected_bundle_root")
    bundle_root = _bundle_root()
    if not isinstance(root, str) or os.path.realpath(root) != bundle_root:
        raise ValueError("runtime mismatch")
    build_id = _own_build_id(bundle_root)
    if build_id is None or receipt.get("selected_build_id") != build_id:
        raise ValueError("runtime mismatch")
    return receipt, python


def _spawn_daemon(data_dir):
    """Start the daemon detached. Returns True when one is expected to be
    coming up — either this call launched it, or a recent call did.

    Returns without doing anything at all if auto-spawn is disabled, if
    another hook attempted a spawn within `SPAWN_COOLDOWN` seconds, or if the
    receipt is missing, unreadable, not receipt v2 (v1 is repair input
    only), does not select this bundle's build, or names an interpreter
    that is not an executable file. Every one of those degrades to
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
                    and record.get("exit") in (None, 0)
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
        receipt, python = _read_selection(data_dir)
    except ValueError as exc:
        # Fixed strings from `_read_selection`, never file content (I1).
        _latch(error=str(exc) if str(exc) in (
            "receipt is writable by others", "runtime mismatch")
            else "ValueError")
        return False
    except OSError as exc:
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
    # #66: no inherited path may supply first-party code. The bootstrap runs
    # the interpreter with `-I` as well; removing these keeps them from
    # reaching anything the daemon starts.
    for name in STRIPPED_ENV:
        env.pop(name, None)
    env["PYTHONNOUSERSITE"] = "1"
    recorded_env = receipt.get("env")
    if isinstance(recorded_env, dict):
        # Where the pinned interpreter should look for model weights. Only
        # filled in where this environment says nothing: the live value is
        # newer and Codex's is authoritative.
        for name in PINNED_ENV_NAMES:
            value = recorded_env.get(name)
            if isinstance(value, str) and value and not env.get(name):
                env[name] = value
    env.update(OFFLINE_ENV)

    try:
        proc = subprocess.Popen(
            [python, "-I", os.path.join(_bundle_root(), *BOOTSTRAP),
             "--plugin-data", data_dir, "daemon"],
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


class _Frame(Exception):
    """A frame that was oversized, truncated, or not a JSON object."""


def _read_frame(s, limit, deadline):
    """One newline-terminated JSON object of at most `limit` bytes, before
    `deadline`. Raises `socket.timeout` when the budget runs out, `_Frame`
    for anything malformed."""
    buf = b""
    while b"\n" not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout()
        s.settimeout(remaining)
        chunk = s.recv(min(65536, limit + 2 - len(buf)))
        if not chunk:
            raise _Frame()
        buf += chunk
        if len(buf) > limit + 1 and b"\n" not in buf:
            raise _Frame()
    line, rest = buf.split(b"\n", 1)
    if len(line) > limit or rest:
        raise _Frame()
    try:
        value = json.loads(line.decode("utf-8"))
    except ValueError:
        raise _Frame() from None
    if not isinstance(value, dict):
        raise _Frame()
    return value


def _send(s, message, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout()
    s.settimeout(remaining)
    s.sendall((json.dumps(message, separators=(",", ":")) + "\n").encode())


def _is_int(value, expected):
    return (isinstance(value, int) and not isinstance(value, bool)
            and value == expected)


def _matching_hello(reply, build_id, epoch):
    return (sorted(reply) == sorted(HELLO_REPLY_FIELDS)
            and _is_int(reply["v"], PROTOCOL_VERSION)
            and reply["op"] == "hello" and reply["ok"] is True
            and isinstance(reply["release"], str)
            and reply["build_id"] == build_id
            and reply["activation_epoch"] == epoch
            and _is_int(reply["storage_generation"], STORAGE_GENERATION)
            and isinstance(reply["schema_version"], int)
            and not isinstance(reply["schema_version"], bool)
            and reply["schema_version"] in READABLE_SCHEMAS
            and reply["ready"] is True)


def _selection(data_dir):
    """`("ok", (build_id, epoch))`, `("setup_missing", None)` or
    `("runtime_mismatch", None)`, from receipt v2 and this bundle's
    manifest. Never raises."""
    try:
        receipt, _python = _read_selection(data_dir)
    except ValueError as exc:
        if str(exc) == "runtime mismatch":
            return "runtime_mismatch", None
        return "setup_missing", None
    except Exception:
        return "setup_missing", None
    epoch = receipt.get("activation_epoch")
    if (not isinstance(epoch, str) or len(epoch) != 32
            or epoch.strip("0123456789abcdef")):
        return "setup_missing", None
    return "ok", (receipt["selected_build_id"], epoch)


def _exchange(s, payload, build_id, epoch, deadline, *, delivery_key):
    """Hello, then -- only after a matching hello on this connection -- the
    event. Every step shares `deadline`. Nothing the daemon sends is
    relayed unless it is a valid event reply; a protocol error object never
    becomes hook output.

    `delivery_key` (#54 Phase 4) identifies this one delivery to the
    daemon's accounting. It travels in the event frame only, so it never
    crosses a handshake that failed."""
    try:
        _send(s, {"v": PROTOCOL_VERSION, "op": "hello",
                  "build_id": build_id, "activation_epoch": epoch,
                  "storage_generation": STORAGE_GENERATION}, deadline)
        reply = _read_frame(s, HELLO_FRAME_LIMIT, deadline)
    except socket.timeout:
        # Accepted and then silent past the budget: what a busy daemon looks
        # like (see the connect branch in `main`).
        return _unverified(payload, False)
    except (_Frame, OSError):
        # Something answered, and it was not a daemon speaking protocol 2:
        # an older daemon closes on a hello it does not know.
        return _runtime_refusal(payload)
    if not _matching_hello(reply, build_id, epoch):
        return _runtime_refusal(payload)

    try:
        data = (json.dumps({"v": PROTOCOL_VERSION, "op": "event",
                            "build_id": build_id, "activation_epoch": epoch,
                            "delivery_key": delivery_key,
                            "payload": payload}, separators=(",", ":"))
                + "\n").encode()
    except (TypeError, ValueError):
        return _unverified(payload, False)
    if len(data) > EVENT_FRAME_LIMIT + 1:
        return _unverified(payload, False)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _unverified(payload, False)
        s.settimeout(remaining)
        s.sendall(data)
        # Sent. From here a failure is an unknown outcome, reported as
        # unverified and never replayed.
        reply = _read_frame(s, EVENT_FRAME_LIMIT, deadline)
    except (socket.timeout, _Frame, OSError):
        return _unverified(payload, False)
    output = reply.get("output")
    if (not _is_int(reply.get("v"), PROTOCOL_VERSION)
            or reply.get("op") != "event" or reply.get("ok") is not True
            or not isinstance(output, dict)):
        return _unverified(payload, False)
    return output


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    data_dir = os.environ.get("PLUGIN_DATA")
    if not data_dir:
        # Codex always sets this for a real hook. By hand, with nothing set,
        # do nothing rather than write a ledger into whatever directory the
        # caller happened to be sitting in (spec §6; the old `/tmp` default
        # is what put a stray ledger.db beside this repo on 2026-09-03).
        return {}
    # One budget for the whole exchange (#66), taken before anything else.
    deadline = time.monotonic() + TIMEOUT

    status, selected = _selection(data_dir)
    if status == "runtime_mismatch":
        # This hook's bundle is not the selected one: nothing is sent to
        # whatever daemon may be listening, and none is started.
        return _runtime_refusal(payload)
    if status != "ok":
        # No usable receipt v2 (none, v1, damaged): no daemon can be
        # verified and none is started.
        if (payload.get("hook_event_name") == "SessionStart"
                and not os.path.exists(os.path.join(data_dir, RECEIPT_NAME))):
            return _setup_hint()
        return _unverified(payload, False)
    build_id, epoch = selected
    # One delivery key per invocation, before the transport attempt (#54
    # Phase 4). Nothing retries with it: a failed exchange is reported as
    # unverified, never replayed.
    delivery_key = os.urandom(16).hex()

    sock_path = os.path.join(data_dir, "daemon.sock")
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(max(deadline - time.monotonic(), 0.001))
        s.connect(sock_path)
    except Exception:
        # Only a failed *connect* means nothing is listening. This is
        # deliberately not the same `except` as the exchange below: the cold
        # model load is ~7s against a 2s client budget, the daemon answers
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
        return _exchange(s, payload, build_id, epoch, deadline,
                         delivery_key=delivery_key)
    finally:
        try:
            s.close()
        except OSError:
            pass


if __name__ == "__main__":
    try:
        out = main()
    except Exception:
        out = {}
    sys.stdout.write(json.dumps(out) if out else "")
    sys.exit(0)
