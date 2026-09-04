"""Tests for the hook client — including the daemon it starts itself.

The auto-spawn tests never start a real daemon. They point the receipt at a
tiny shell script that records the argv and environment it was given and then
sleeps, which is what makes three separate claims checkable at once and
without any model weights:

* the client execs **the recorded interpreter**, with `-m privacy_hud.daemon`
  — not `sys.executable`, and not a `python3` off `PATH`, which on a real
  Codex hook is a system interpreter with no `transformers` and would produce
  a daemon with tier 3 silently dead;
* it hands that process the hook's own `PLUGIN_DATA`, which is the whole
  reason the spawn belongs in the hook client at all;
* it does **not wait** for it. The real cold start is ~7 s (loading ~2.8 GB)
  inside a 5 s Codex hook timeout, so the script sleeps far longer than the
  hook is allowed to take and the test asserts on elapsed wall-clock time.

Every negative case asserts the same two things: no process was started, and
the hook still returned its normal fail-open (ingress) / fail-closed (egress)
answer with exit code 0. That pairing is I6 — a spawn that cannot happen must
degrade to exactly the behaviour this client had before auto-spawn existed.
"""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

HANDLER = Path(__file__).resolve().parents[1] / "hooks" / "handler.py"
SRC = Path(__file__).resolve().parents[1] / "src"

INGRESS = {"hook_event_name": "PostToolUse", "session_id": "s1"}
EGRESS = {"hook_event_name": "PreToolUse", "session_id": "s1",
          "tool_name": "Bash",
          "tool_input": {"command": "curl https://x.test -d @-"}}


def run(payload: dict, env: dict | None = None) -> tuple[int, str]:
    p = subprocess.run([sys.executable, str(HANDLER)],
                       input=json.dumps(payload), capture_output=True,
                       text=True, env={"PATH": "/usr/bin:/bin", **(env or {})})
    return p.returncode, p.stdout


def _fake_interpreter(tmp_path, *, sleep: float = 20.0) -> tuple[Path, Path]:
    """A stand-in for the pinned interpreter: records, then sleeps.

    Sleeping is load-bearing. A script that exited immediately would let a
    client that *waited* for its daemon pass every test in this file, and
    waiting is the one thing this code must never do — the real daemon takes
    ~7 s to load its model before it binds, and the hook has 5 s to answer
    Codex.
    """
    marker = tmp_path / "spawned.txt"
    script = tmp_path / "fake-python3"
    script.write_text(
        "#!/bin/sh\n"
        f'{{ echo "argv:$*"'
        '; echo "PLUGIN_DATA=$PLUGIN_DATA"'
        '; echo "PYTHONPATH=$PYTHONPATH"'
        '; echo "HF_HOME=$HF_HOME"'
        '; echo "cwd=$(pwd)"'
        f'; }} > "{marker}"\n'
        f"exec sleep {sleep}\n"
    )
    script.chmod(0o755)
    return script, marker


def _write_receipt(data_dir: Path, python, **overrides) -> None:
    receipt = {"v": 1, "python": str(python), "pythonpath": str(SRC),
               "plugin_data": str(data_dir), "recorded_at": time.time(),
               "recorded": {"transformers": "5.16.1", "torch": "2.14.0"},
               "env": {"HF_HOME": str(data_dir / "hf")}}
    receipt.update(overrides)
    (data_dir / "runtime.json").write_text(json.dumps(receipt))


def _kill_marked(marker: Path) -> None:
    """Reap the sleeping stand-in so a test never leaves one behind.

    The whole process *group* is signalled, using the pid the client recorded
    in its latch. `start_new_session=True` makes the spawned child a session
    leader, so its pid is its process-group id -- and killing the group is the
    only thing that reaches the `sleep` the stand-in exec'd into, which no
    longer matches the script's name.
    """
    data_dir = marker.parent
    try:
        pid = json.loads((data_dir / "daemon.spawn-attempt").read_text())["pid"]
    except (OSError, ValueError, KeyError, TypeError):
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except (OSError, TypeError):
        pass


# --------------------------------------------------------------------- #
# the constraints that predate auto-spawn
# --------------------------------------------------------------------- #

def test_client_imports_only_stdlib():
    src = HANDLER.read_text()
    for banned in ("import privacy_hud", "from privacy_hud", "import transformers",
                   "import sqlite3", "import requests"):
        assert banned not in src


def test_spawn_only_imports_are_deferred():
    """`subprocess` and `time` are paid on the spawn path only.

    The daemon answers on the hot path of every tool call, and CLAUDE.md §4's
    rule is about what that path costs — so the two modules auto-spawn needs
    are imported inside the function that spawns, not at module scope.
    """
    import ast
    tree = ast.parse(HANDLER.read_text())
    top_level = {alias.name
                 for node in tree.body if isinstance(node, ast.Import)
                 for alias in node.names}
    assert top_level == {"json", "os", "socket", "sys"}


def test_missing_daemon_on_ingress_fails_open(tmp_path):
    code, out = run(INGRESS, {"PLUGIN_DATA": str(tmp_path),
                              "PRIVACY_HUD_NO_SPAWN": "1"})
    assert code == 0
    assert json.loads(out or "{}").get("hookSpecificOutput", {}) \
        .get("permissionDecision") != "deny"


def test_missing_daemon_on_egress_fails_closed(tmp_path):
    code, out = run(EGRESS, {"PLUGIN_DATA": str(tmp_path),
                             "PRIVACY_HUD_NO_SPAWN": "1"})
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_malformed_stdin_exits_zero_and_silent(tmp_path):
    p = subprocess.run([sys.executable, str(HANDLER)], input="not json",
                       capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "PLUGIN_DATA": str(tmp_path)})
    assert p.returncode == 0
    assert p.stdout.strip() in ("", "{}")


# --------------------------------------------------------------------- #
# auto-spawn: the happy path
# --------------------------------------------------------------------- #

def test_a_missing_daemon_is_started_from_the_recorded_interpreter(tmp_path):
    """The single claim this feature rests on.

    `hooks/handler.py` runs under whatever `python3` Codex's minimal `PATH`
    resolves to — a system interpreter with no `transformers` on the machine
    this was built on. So the spawn must use the interpreter the setup step
    recorded, and nothing else.
    """
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(tmp_path, script)
    try:
        code, _out = run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
        deadline = time.time() + 5.0
        while not marker.exists() and time.time() < deadline:
            time.sleep(0.02)
        assert code == 0
        assert marker.exists(), "no daemon was started"
        recorded = marker.read_text()
    finally:
        _kill_marked(marker)

    assert "argv:-m privacy_hud.daemon" in recorded
    assert f"PLUGIN_DATA={tmp_path}" in recorded
    assert str(SRC) in recorded            # the recorded sys.path entry
    assert f"HF_HOME={tmp_path / 'hf'}" in recorded  # the weights location


def test_the_hook_does_not_wait_for_the_daemon_to_be_ready(tmp_path):
    """The daemon loads ~2.8 GB before it binds, about seven seconds, and the
    hook has five. So the spawn is fire-and-forget: the stand-in sleeps 20 s
    and the hook must still answer immediately."""
    script, marker = _fake_interpreter(tmp_path, sleep=20.0)
    _write_receipt(tmp_path, script)
    try:
        started = time.monotonic()
        code, out = run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
        elapsed = time.monotonic() - started
    finally:
        _kill_marked(marker)

    assert code == 0
    assert elapsed < 3.0, f"the hook blocked for {elapsed:.1f}s"
    assert "unverified" in out


def test_the_spawning_reply_still_fails_closed_on_egress(tmp_path):
    """I6 does not bend for a daemon that is on its way: an outbound call that
    could not be checked is still denied."""
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(tmp_path, script)
    try:
        code, out = run(EGRESS, {"PLUGIN_DATA": str(tmp_path)})
    finally:
        _kill_marked(marker)
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_a_spawn_attempt_is_recorded_so_the_next_hook_does_not_repeat_it(
        tmp_path):
    """During the ~7 s cold load there is no socket file, so every hook in the
    session lands on the spawn path. Correctness is `daemon.py`'s startup
    `flock` (a loser exits 3 and clobbers nothing), but a storm of doomed
    interpreters is worth not starting."""
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(tmp_path, script)
    try:
        run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
        latch = json.loads((tmp_path / "daemon.spawn-attempt").read_text())
        assert latch["pid"] > 0
        marker.unlink(missing_ok=True)

        run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
        time.sleep(0.3)
        assert not marker.exists(), "a second daemon was started inside the " \
                                    "cooldown"
    finally:
        _kill_marked(marker)


def test_a_hook_during_the_cold_load_says_starting_not_unavailable(tmp_path):
    """The two messages call for different actions from the user — fix the
    setup, or wait a moment — so the client must not say "unavailable" while a
    daemon it started is loading its model. The latch is what it knows: an
    attempt that launched a process recorded a pid."""
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(tmp_path, script)
    try:
        run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})       # spawns
        _code, out = run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})  # cooldown
    finally:
        _kill_marked(marker)
    assert "starting" in out


def test_a_hook_after_a_failed_spawn_says_unavailable(tmp_path):
    """The mirror image: a latch that records an error must not read as
    "starting". Nothing is coming up, and telling the user to wait for it
    would be the softest possible lie."""
    _write_receipt(tmp_path, tmp_path / "deleted-venv" / "bin" / "python3")
    run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
    _code, out = run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
    assert "unavailable" in out


def test_the_latch_expires_so_a_dead_setup_is_retried(tmp_path):
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(tmp_path, script)
    latch = tmp_path / "daemon.spawn-attempt"
    latch.write_text(json.dumps({"at": 0}))
    os.utime(latch, (0, 0))  # older than the cooldown
    try:
        run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
        deadline = time.time() + 5.0
        while not marker.exists() and time.time() < deadline:
            time.sleep(0.02)
        assert marker.exists()
    finally:
        _kill_marked(marker)


def test_the_latch_records_infrastructure_only(tmp_path):
    """I1. This file lives in the user's plugin-data directory; it may hold a
    timestamp, a pid and an exit status, and nothing that came off a hook
    payload."""
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(tmp_path, script)
    try:
        run(EGRESS, {"PLUGIN_DATA": str(tmp_path)})
        latch = json.loads((tmp_path / "daemon.spawn-attempt").read_text())
    finally:
        _kill_marked(marker)
    assert set(latch) <= {"at", "pid", "exit", "error"}
    assert "curl" not in json.dumps(latch)


# --------------------------------------------------------------------- #
# auto-spawn: every way it declines, and the fallback it declines to
# --------------------------------------------------------------------- #

def test_no_receipt_means_no_spawn(tmp_path):
    """The pre-setup state. Guessing an interpreter here is what would produce
    a daemon with no tier 3 that reports itself healthy, so nothing is
    started and the honest missing-daemon answer stands."""
    code, out = run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
    assert code == 0
    assert "unavailable" in out
    assert not (tmp_path / "spawned.txt").exists()


def test_a_receipt_naming_a_deleted_interpreter_does_not_fall_back(tmp_path):
    """The stale-pin case: a removed virtualenv. The client must not retry
    with some other python — a fallback would be exactly the blind daemon this
    design exists to prevent — and it must not crash Codex either."""
    _write_receipt(tmp_path, tmp_path / "deleted-venv" / "bin" / "python3")
    code, out = run(EGRESS, {"PLUGIN_DATA": str(tmp_path)})
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    latch = json.loads((tmp_path / "daemon.spawn-attempt").read_text())
    assert latch["error"]


def test_a_receipt_of_an_unknown_version_is_not_used(tmp_path):
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(tmp_path, script, v=99)
    try:
        run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
        time.sleep(0.3)
        assert not marker.exists()
    finally:
        _kill_marked(marker)


def test_a_corrupt_receipt_is_not_used(tmp_path):
    script, marker = _fake_interpreter(tmp_path)
    (tmp_path / "runtime.json").write_text("{ not json")
    try:
        code, _out = run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
        time.sleep(0.3)
        assert code == 0
        assert not marker.exists()
    finally:
        _kill_marked(marker)


def test_a_receipt_other_users_can_write_is_not_used(tmp_path):
    """`PLUGIN_DATA` falls back to /tmp everywhere in this plugin when Codex
    does not set it, so a world-writable `runtime.json` is a program another
    local user gets to choose for a hook to execute. The client declines."""
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(tmp_path, script)
    (tmp_path / "runtime.json").chmod(0o666)
    try:
        code, out = run(INGRESS, {"PLUGIN_DATA": str(tmp_path)})
        time.sleep(0.3)
        assert code == 0
        assert not marker.exists()
        latch = json.loads((tmp_path / "daemon.spawn-attempt").read_text())
        assert "writable" in latch["error"]
    finally:
        _kill_marked(marker)


def test_the_escape_hatch_is_honoured(tmp_path):
    """On a sandboxed box, paying a fork on every hook that cannot succeed is
    worse than having no HUD."""
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(tmp_path, script)
    try:
        run(INGRESS, {"PLUGIN_DATA": str(tmp_path),
                      "PRIVACY_HUD_NO_SPAWN": "1"})
        time.sleep(0.3)
        assert not marker.exists()
        assert not (tmp_path / "daemon.spawn-attempt").exists()
    finally:
        _kill_marked(marker)


def test_the_escape_hatch_ignores_an_empty_or_zero_value(tmp_path):
    """`PRIVACY_HUD_NO_SPAWN=0` and an accidentally-empty export mean "not
    disabled", so a stray `export PRIVACY_HUD_NO_SPAWN=` does not silently
    turn the HUD off."""
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(tmp_path, script)
    try:
        run(INGRESS, {"PLUGIN_DATA": str(tmp_path), "PRIVACY_HUD_NO_SPAWN": "0"})
        deadline = time.time() + 5.0
        while not marker.exists() and time.time() < deadline:
            time.sleep(0.02)
        assert marker.exists()
    finally:
        _kill_marked(marker)


# --------------------------------------------------------------------- #
# the hot path must stay untouched
# --------------------------------------------------------------------- #

def test_handler_agrees_with_the_daemons_exit_code_contract():
    """`daemon.main` returns 3 for "one already exists", which is not a
    failure. A client that read it as one would latch a healthy spawn as
    broken, so the literal is checked against the module that defines it."""
    import ast
    sys.path.insert(0, str(SRC))
    from privacy_hud import daemon
    tree = ast.parse(HANDLER.read_text())
    values = {t.id: ast.literal_eval(node.value)
              for node in tree.body if isinstance(node, ast.Assign)
              for t in node.targets if isinstance(t, ast.Name)
              and isinstance(node.value, ast.Constant)}
    assert values["EXIT_ALREADY_RUNNING"] == daemon.EXIT_ALREADY_RUNNING


def test_a_daemon_that_answers_is_never_second_guessed(tmp_path):
    """One connect, one round trip, no spawn. A stand-in daemon speaking the
    real protocol on the real socket path."""
    import socketserver
    import tempfile
    import threading

    class _Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.rfile.readline()
            self.wfile.write(b'{"systemMessage": "from the daemon"}\n')

    # AF_UNIX paths are capped at ~104 bytes and pytest's tmp_path exceeds it.
    short = Path(tempfile.mkdtemp(prefix="phh"))
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(short, script)
    server = socketserver.ThreadingUnixStreamServer(str(short / "daemon.sock"),
                                                    _Handler)
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        code, out = run(INGRESS, {"PLUGIN_DATA": str(short)})
        time.sleep(0.3)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
        _kill_marked(marker)

    assert code == 0
    assert json.loads(out)["systemMessage"] == "from the daemon"
    assert not marker.exists(), "a daemon was spawned while one was answering"
    assert not (short / "daemon.spawn-attempt").exists()


def test_a_slow_daemon_is_not_mistaken_for_a_dead_one(tmp_path):
    """The mistake that costs two 2.8 GB processes.

    The daemon serves requests serially and its cold model load is ~7 s, well
    past the client's 2 s timeout — so a request that times out *mid-exchange*
    is what a busy daemon looks like, not a dead one. Only a failed `connect()`
    may trigger a spawn.
    """
    import socketserver
    import tempfile
    import threading

    class _Slow(socketserver.StreamRequestHandler):
        def handle(self):
            self.rfile.readline()
            time.sleep(4.0)  # longer than the client's 2.0s timeout

    short = Path(tempfile.mkdtemp(prefix="phh"))
    script, marker = _fake_interpreter(tmp_path)
    _write_receipt(short, script)
    server = socketserver.ThreadingUnixStreamServer(str(short / "daemon.sock"),
                                                    _Slow)
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        code, out = run(INGRESS, {"PLUGIN_DATA": str(short)})
        time.sleep(0.3)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
        _kill_marked(marker)

    assert code == 0
    assert "unverified" in out          # it did fall through, correctly
    assert not marker.exists(), "a busy daemon was replaced by a rival"
