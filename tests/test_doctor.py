"""Tests for `privacy-hud-doctor`.

Four things are being defended.

**The verdicts.** A doctor's whole value is that its `OK`/`WARN`/`FAIL` means
something, so each check is driven through its real failure modes with real
artefacts on disk — a missing socket, a *stale* socket that outlived its
process, a socket someone else is listening on, an absent ledger, a corrupt
one, weights that are present-but-incomplete. Nothing here asserts on prose;
the assertions are on status, on exit code, and on the presence of a remedy.

**The exit-code policy.** Degraded-but-working must stay exit 0. Missing model
weights, an old `transformers`, a stale installed plugin copy — the engine
still runs tiers 0-2 in all of them, and a command that exits non-zero there
is unusable in the setup script or CI job that is the obvious place to put it.
`FAIL` is reserved for "nothing this plugin promises can happen".

**The read-only guarantee.** `sqlite3.connect()` creates missing database
files and `Ledger.__init__` runs DDL — the trap `ambient.py` documents at
length. A doctor pointed at a user's real `PLUGIN_DATA` that leaves a stray
`ledger.db` behind, or that touches the one already there, is worse than no
doctor. Two tests snapshot the directory and the ledger's mtime/contents
across a full `main()` run.

**Every failing check carries a fix.** Enforced as a property over all
statuses rather than case by case, so a new check cannot be added without one.

These run without model weights, without a daemon, and without Codex: every
environment-dependent input (`PLUGIN_DATA`, `CODEX_HOME`, `HF_HOME`, the
`transformers`/`torch` versions, the interpreter version) is injected, which
is also the only way the assertions mean anything — a test that asserted on
"whatever happens to be installed on this machine" would pass everywhere and
prove nothing.

`AF_UNIX` note: the kernel caps socket paths at ~104 bytes (macOS) / 108
(Linux) and pytest's `tmp_path` routinely exceeds that, so every test that
binds or connects to a socket puts it under a short `tempfile.mkdtemp()`
directory, exactly as `tests/test_daemon.py` does.
"""
from __future__ import annotations

import json
import os
import socketserver
import sqlite3
import subprocess
import tempfile
import threading
import tomllib
from pathlib import Path

import pytest

from privacy_hud import doctor
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix

M = load_matrix()

#: I5 (never imply recall) and CLAUDE.md §5 (no overclaiming) apply to this
#: command's output too.
BANNED = ("undo", "revoke", "remove from context", "your data is protected",
          "100% secure")


# --------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------- #

@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    """Point every environment-sourced path at a temp directory.

    Without this, the checks read the developer's real `~/.codex` and real HF
    cache, and the suite's verdicts would depend on whose laptop it ran on.
    `HF_HOME` is aimed at an empty tree so the tier 3 check reports "no
    weights" by default — the same state CI runs in.
    """
    data = tmp_path / "plugin-data"
    data.mkdir()
    codex = tmp_path / "codex-home"
    monkeypatch.setenv("PLUGIN_DATA", str(data))
    monkeypatch.setenv("CODEX_HOME", str(codex))
    monkeypatch.setenv("HF_HOME", str(tmp_path / "hf"))
    monkeypatch.delenv("HF_HUB_CACHE", raising=False)
    return data


@pytest.fixture
def short_sockdir():
    """A short-named directory for AF_UNIX paths. See the module docstring."""
    path = Path(tempfile.mkdtemp(prefix="phd"))
    yield path


class _EchoHandler(socketserver.StreamRequestHandler):
    """Answers one newline-delimited request the way the real daemon does.

    Speaks `hooks/handler.py`'s protocol rather than a simplified stand-in,
    so this exercises the same read-until-newline / parse-a-JSON-object path
    the probe uses against a live daemon. `self.server.reply` decides what
    comes back, which is how the "something else is listening" cases are set
    up.
    """

    def handle(self):
        line = self.rfile.readline()
        if not line:
            return
        self.server.seen.append(json.loads(line.decode()))
        reply = self.server.reply
        if reply is None:  # accept, then close with no answer
            return
        self.wfile.write(reply)


def _serve(sock_path: Path, reply: bytes | None):
    server = socketserver.ThreadingUnixStreamServer(str(sock_path),
                                                    _EchoHandler)
    # The real daemon chmods its socket 0600 in `Daemon.__init__` rather than
    # relying on the process umask; the stand-in must do the same or every
    # "responsive" test would trip the permissions warning instead.
    os.chmod(sock_path, 0o600)
    server.reply = reply
    server.seen = []
    thread = threading.Thread(target=server.serve_forever, kwargs={
        "poll_interval": 0.02}, daemon=True)
    thread.start()
    return server, thread


def _stop(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


def _by_name(checks, name):
    return next(c for c in checks if c.name == name)


# --------------------------------------------------------------------- #
# the pinned floor must not drift from pyproject
# --------------------------------------------------------------------- #

def test_min_python_matches_pyproject_requires_python():
    """`MIN_PYTHON` is hardcoded; this is what keeps it honest.

    Parsing a PEP 440 specifier properly needs `packaging`, so the module
    pins the floor as a tuple instead. A diagnostic that reports the wrong
    floor is worse than one with a hardcoded right one — so the duplication
    is checked here rather than trusted.
    """
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    requires = data["project"]["requires-python"]
    assert requires.startswith(">=")
    declared = doctor._version_tuple(requires[2:].strip())
    assert declared[:2] == doctor.MIN_PYTHON


def test_console_script_is_registered():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    assert data["project"]["scripts"]["privacy-hud-doctor"] == \
        "privacy_hud.doctor:main"


# --------------------------------------------------------------------- #
# Python check
# --------------------------------------------------------------------- #

def test_python_at_floor_is_ok():
    check = doctor.check_python((3, 11, 0))
    assert check.status == doctor.OK


def test_python_below_floor_fails_with_a_fix():
    check = doctor.check_python((3, 10, 14))
    assert check.status == doctor.FAIL
    assert check.fixes


@pytest.mark.parametrize("relative", [
    "/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud",
    "/Desktop/OpenAI privacy hackathon/codex-privacy-hud",
    "/weird/it's here/x",
    '/weird/say "hi"/x',
    "/weird/$HOME literal/x",
])
def test_shell_path_of_a_home_relative_path_survives_a_real_shell(relative):
    """The remedy lines are commands the user pastes, so the quoting has to be
    right in a shell rather than merely look right.

    This exists because the obvious approach is wrong: `~'/Desktop/a b'` does
    not expand — POSIX tilde expansion applies only when no character of the
    tilde-prefix is quoted, and with no unquoted slash the whole word is the
    tilde-prefix. Asserting against a real `sh` is the only way to keep that
    from regressing, and this project's own checkout path (spaces included) is
    one of the cases.
    """
    bash = "/bin/sh"
    if not Path(bash).exists():
        pytest.skip("no POSIX shell available")
    absolute = str(Path.home()) + relative

    quoted = doctor._shell_path(absolute)

    result = subprocess.run(
        [bash, "-c", f"printf %s {quoted}"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == absolute


def test_shell_path_leaves_an_ordinary_home_path_readable():
    """Quoting only when it is needed: the overwhelmingly common remedy is
    `export PLUGIN_DATA=~/.codex/plugins/data/...`, and wrapping that in
    machinery would make the most-copied line in the report the ugliest."""
    plain = str(Path.home()) + "/.codex/plugins/data/codex-privacy-hud"
    assert doctor._shell_path(plain) == \
        "~/.codex/plugins/data/codex-privacy-hud"


def test_shell_path_of_a_path_outside_home_with_spaces_is_quoted():
    quoted = doctor._shell_path("/tmp/two words/x")
    result = subprocess.run(["/bin/sh", "-c", f"printf %s {quoted}"],
                            capture_output=True, text=True)
    assert result.stdout == "/tmp/two words/x"


def test_display_path_keeps_the_account_name_out_of_the_report():
    """A small thing, but this is a privacy tool: the report is exactly the
    kind of output a user pastes into an issue tracker."""
    shown = doctor._display_path(str(Path.home()) + "/.codex/x")
    assert shown == "~/.codex/x"
    assert Path.home().name not in shown


def test_version_tuple_tolerates_real_wheel_versions():
    # Every one of these ships in this stack: a torch local version, a
    # transformers dev build, a release candidate.
    assert doctor._version_tuple("2.14.0+cpu") == (2, 14, 0)
    assert doctor._version_tuple("5.16.0.dev0") == (5, 16, 0)
    assert doctor._version_tuple("2.5.0a1") == (2, 5, 0)
    assert doctor._version_tuple("") == ()


# --------------------------------------------------------------------- #
# PLUGIN_DATA
# --------------------------------------------------------------------- #

def test_unset_plugin_data_fails_because_everything_defaults_to_tmp(
        monkeypatch, tmp_path):
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    check = doctor.check_plugin_data()
    assert check.status == doctor.FAIL
    assert check.fixes


def test_plugin_data_pointing_at_nothing_fails(monkeypatch, tmp_path):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path / "does-not-exist"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    check = doctor.check_plugin_data()
    assert check.status == doctor.FAIL
    assert check.fixes


def test_existing_plugin_data_with_no_codex_install_is_ok(isolated_env):
    assert doctor.check_plugin_data().status == doctor.OK


def test_plugin_data_matching_codex_assignment_is_ok(isolated_env, monkeypatch,
                                                     tmp_path):
    assigned = tmp_path / "codex-home" / "plugins" / "data" / \
        "codex-privacy-hud-codex-privacy-hud"
    assigned.mkdir(parents=True)
    monkeypatch.setenv("PLUGIN_DATA", str(assigned))
    assert doctor.check_plugin_data().status == doctor.OK


def test_plugin_data_disagreeing_with_codex_warns_and_names_the_real_one(
        isolated_env, tmp_path):
    """The single most expensive misconfiguration this project has hit.

    A warning rather than a failure: pointing the daemon at a scratch
    directory is a legitimate deliberate act (this suite does it). What the
    report owes the user is the directory Codex actually assigns, spelled out
    rather than described.
    """
    assigned = tmp_path / "codex-home" / "plugins" / "data" / \
        "codex-privacy-hud-codex-privacy-hud"
    assigned.mkdir(parents=True)

    check = doctor.check_plugin_data()

    assert check.status == doctor.WARN
    assert any(str(assigned) in fix or "codex-privacy-hud-codex-privacy-hud"
               in fix for fix in check.fixes)


# --------------------------------------------------------------------- #
# Ledger — read-only, and it must stay that way
# --------------------------------------------------------------------- #

def test_missing_ledger_warns_rather_than_fails(isolated_env):
    check = doctor.check_ledger()
    assert check.status == doctor.WARN
    assert check.fixes


def test_missing_ledger_check_does_not_create_one(isolated_env):
    """`sqlite3.connect()` creates missing files; `mode=ro` must not.

    This is the guarantee that makes the command safe to run against a real
    `PLUGIN_DATA` — see `ambient.py`'s module docstring for the same trap.
    """
    doctor.check_ledger()
    assert list(isolated_env.iterdir()) == []


def test_populated_ledger_reports_counts(isolated_env):
    led = Ledger(isolated_env / "ledger.db", M)
    led.start_session("s1", cwd="/repo", model="gpt-5")
    led.record("s1", turn_id="t1", kind="exposed", data_type="email",
               source="support.log", destination="model_context",
               value_hash=b"\x01" * 16, masked_example="jo***@acme.com",
               tool_name="Read", protection=None)
    led.conn.close()

    check = doctor.check_ledger()

    assert check.status == doctor.OK
    assert "1 session" in check.summary
    assert "1 events" in check.summary


def test_ledger_with_no_sessions_warns(isolated_env):
    Ledger(isolated_env / "ledger.db", M).conn.close()
    check = doctor.check_ledger()
    assert check.status == doctor.WARN
    assert check.fixes


def test_corrupt_ledger_fails_with_an_actionable_fix(isolated_env):
    (isolated_env / "ledger.db").write_bytes(b"this is not a sqlite database")
    check = doctor.check_ledger()
    assert check.status == doctor.FAIL
    assert check.fixes


def test_ledger_check_never_prints_session_content(isolated_env):
    """I1: counts and ages only.

    The seeded row carries a `cwd`, a `model`, a `source` filename, a
    `data_type` and a masked exemplar. None of them may appear in the report
    — a doctor that dumps the ledger is a privacy incident, and a masked
    exemplar is still a value.
    """
    led = Ledger(isolated_env / "ledger.db", M)
    led.start_session("session-abc123", cwd="/private/repo", model="gpt-5")
    led.record("session-abc123", turn_id="t1", kind="exposed",
               data_type="email", source="support.log",
               destination="model_context", value_hash=b"\x02" * 16,
               masked_example="jo***@acme.com", tool_name="Read",
               protection=None)
    led.conn.close()

    check = doctor.check_ledger()
    text = " ".join([check.summary, *check.details, *check.fixes])

    for secret in ("session-abc123", "/private/repo", "support.log",
                   "jo***@acme.com", "gpt-5"):
        assert secret not in text


# --------------------------------------------------------------------- #
# Daemon — the round trip, not the socket file
# --------------------------------------------------------------------- #

def test_no_socket_fails_and_says_how_to_start_the_daemon(isolated_env):
    check = doctor.check_daemon(timeout=0.5)
    assert check.status == doctor.FAIL
    assert any("privacy_hud.daemon" in fix for fix in check.fixes)


def test_responsive_daemon_is_ok(isolated_env, monkeypatch, short_sockdir):
    sock_path = short_sockdir / "d.sock"
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)
    server, thread = _serve(sock_path, b"{}\n")
    try:
        check = doctor.check_daemon(timeout=2.0)
    finally:
        _stop(server, thread)

    assert check.status == doctor.OK


def test_probe_sends_the_documented_protocol_and_a_harmless_event(
        isolated_env, monkeypatch, short_sockdir):
    """The probe must be the wire format `hooks/handler.py` owns, and must
    carry an event that cannot record anything.

    `PreCompact` is named in `dispatch.py`'s own mapping table as an event
    with no `Observation` defined, so `dispatch()` returns an empty allow
    *before* it touches the ledger, starts a session, builds an `Engine` or
    runs a detector. No `session_id` is sent either, so there is nothing for
    a future mapping to attribute the probe to. If someone ever swaps this
    for a real event, a diagnostic starts writing to the thing it diagnoses —
    hence the assertion.
    """
    sock_path = short_sockdir / "d.sock"
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)
    server, thread = _serve(sock_path, b"{}\n")
    try:
        doctor.check_daemon(timeout=2.0)
    finally:
        _stop(server, thread)

    assert server.seen == [{"v": 1, "op": "event",
                            "payload": {"hook_event_name": "PreCompact"}}]
    assert doctor.PROBE_EVENT not in {"SessionStart", "SessionEnd",
                                      "UserPromptSubmit", "PostToolUse",
                                      "PreToolUse", "SubagentStart"}


def test_stale_socket_that_outlived_its_process_fails(isolated_env, monkeypatch,
                                                      short_sockdir):
    """The failure this check exists for.

    A unix socket file survives a `kill -9`, so `Path.exists()` stays `True`
    while every hook silently falls through to I6's fail-open. Bind, then
    close without unlinking, and the file is left exactly as a crashed daemon
    leaves it.
    """
    sock_path = short_sockdir / "d.sock"
    server, thread = _serve(sock_path, b"{}\n")
    _stop(server, thread)
    assert sock_path.exists()  # the file outlived the listener
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)

    check = doctor.check_daemon(timeout=0.5)

    assert check.status == doctor.FAIL
    assert any("rm " in fix for fix in check.fixes)


def test_socket_path_that_is_a_regular_file_fails(isolated_env, monkeypatch,
                                                  short_sockdir):
    sock_path = short_sockdir / "d.sock"
    sock_path.write_text("not a socket")
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)

    check = doctor.check_daemon(timeout=0.5)

    assert check.status == doctor.FAIL
    assert check.fixes


def test_listener_that_never_answers_fails(isolated_env, monkeypatch,
                                           short_sockdir):
    sock_path = short_sockdir / "d.sock"
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)
    server, thread = _serve(sock_path, None)  # accept, then close
    try:
        check = doctor.check_daemon(timeout=1.0)
    finally:
        _stop(server, thread)

    assert check.status == doctor.FAIL
    assert check.fixes


def test_listener_speaking_something_else_fails(isolated_env, monkeypatch,
                                                short_sockdir):
    """A well-formed reply that is not a JSON object means the socket path is
    being served by something that is not this daemon — a different failure
    from "nothing is listening", with a different fix."""
    sock_path = short_sockdir / "d.sock"
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)
    server, thread = _serve(sock_path, b"HTTP/1.1 404 Not Found\n")
    try:
        check = doctor.check_daemon(timeout=1.0)
    finally:
        _stop(server, thread)

    assert check.status == doctor.FAIL
    assert check.fixes


def test_world_readable_socket_warns_without_failing(isolated_env, monkeypatch,
                                                     short_sockdir):
    """The daemon chmods its socket 0600 for a reason: at wider permissions
    any local user can inject hook events into the disclosure ledger. It is a
    warning, not a failure — the daemon works, and the exit code is reserved
    for setups that cannot work at all."""
    sock_path = short_sockdir / "d.sock"
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)
    server, thread = _serve(sock_path, b"{}\n")
    os.chmod(sock_path, 0o666)
    try:
        check = doctor.check_daemon(timeout=2.0)
    finally:
        _stop(server, thread)

    assert check.status == doctor.WARN
    assert check.fixes


# --------------------------------------------------------------------- #
# Detector stack
# --------------------------------------------------------------------- #

def _pin_versions(monkeypatch, *, transformers, torch):
    versions = {"transformers": transformers, "torch": torch}
    monkeypatch.setattr(doctor, "_module_version", versions.get)


def test_detector_deps_at_the_floors_are_ok(monkeypatch):
    _pin_versions(monkeypatch, transformers="5.16.0", torch="2.5.0")
    assert doctor.check_detector_deps().status == doctor.OK


def test_transformers_below_floor_warns_with_the_consequence(monkeypatch):
    """`transformers < 5.16` does not recognize the `openai_privacy_filter`
    architecture at all, so tier 3 is dead — but tiers 0-2 still run, which
    is why this is a warning. The warning has to state the consequence in the
    user's terms, not ours."""
    _pin_versions(monkeypatch, transformers="4.44.2", torch="2.5.0")
    check = doctor.check_detector_deps()
    assert check.status == doctor.WARN
    assert any("names and addresses will not be detected" in d.lower()
               for d in check.details)
    assert check.fixes


def test_transformers_without_torch_warns(monkeypatch):
    """README's specific trap: torch is one of *transformers'* extras, so
    `pip install transformers` leaves an importable transformers and a
    silently dead tier 3. A check that only looked at transformers would call
    this healthy."""
    _pin_versions(monkeypatch, transformers="5.16.1", torch=None)
    check = doctor.check_detector_deps()
    assert check.status == doctor.WARN
    assert any("names and addresses will not be detected" in d.lower()
               for d in check.details)


def test_neither_package_installed_warns_but_does_not_fail(monkeypatch):
    _pin_versions(monkeypatch, transformers=None, torch=None)
    assert doctor.check_detector_deps().status == doctor.WARN


def test_old_torch_warns(monkeypatch):
    _pin_versions(monkeypatch, transformers="5.16.1", torch="2.1.0")
    assert doctor.check_detector_deps().status == doctor.WARN


def _seed_weights(tmp_path, names):
    snapshot = (tmp_path / "hf" / "hub" / doctor.MODEL_CACHE_DIRNAME /
                "snapshots" / "abc123")
    snapshot.mkdir(parents=True)
    for name in names:
        (snapshot / name).write_bytes(b"x")
    return snapshot


def test_tier3_without_weights_warns_and_gives_the_download_recipe(
        isolated_env, tmp_path):
    check = doctor.check_tier3(load_model=False)
    assert check.status == doctor.WARN
    assert any("snapshot_download" in fix for fix in check.fixes)
    assert any("names and addresses will not be detected" in d.lower()
               for d in check.details)


def test_tier3_with_all_weights_is_ok_but_does_not_claim_availability(
        isolated_env, tmp_path):
    """The cheap check is a proxy, and must be labelled as one.

    Constructing a `ModelDetector` is the only thing that *knows*; files on
    disk are strong evidence and a different claim. Overclaiming here would
    be exactly the failure CLAUDE.md §5 is about, so the summary says the
    weights are present and the model was not loaded — it never says tier 3
    is available.
    """
    _seed_weights(tmp_path, doctor.MODEL_FILES)
    check = doctor.check_tier3(load_model=False)
    assert check.status == doctor.OK
    assert "not loaded" in check.summary
    assert "available" not in check.summary
    assert any("--check-model" in d for d in check.details)


def test_tier3_with_partial_weights_warns_and_names_what_is_missing(
        isolated_env, tmp_path):
    _seed_weights(tmp_path, ["config.json", "tokenizer.json"])
    check = doctor.check_tier3(load_model=False)
    assert check.status == doctor.WARN
    assert any("model.safetensors" in d for d in check.details)


def test_tier3_ignores_the_onnx_and_original_variants(isolated_env, tmp_path):
    """The full HF repo is ~17 GB because it ships ONNX exports and a
    duplicate `original/` checkpoint this project never loads. Only README's
    five verified-sufficient files decide the verdict; anything else on disk
    must not change it, in either direction."""
    snapshot = _seed_weights(tmp_path, doctor.MODEL_FILES)
    (snapshot / "onnx").mkdir()
    (snapshot / "original").mkdir()
    assert doctor.check_tier3(load_model=False).status == doctor.OK


def test_tier3_treats_a_dangling_snapshot_symlink_as_missing(isolated_env,
                                                             tmp_path):
    """The hub stores snapshot entries as symlinks into `blobs/`. A blob
    garbage-collected out from under the snapshot leaves a link that
    `is_file()`-style checks can get wrong; the pipeline cannot load it, so
    the doctor must not say it can."""
    snapshot = _seed_weights(tmp_path, doctor.MODEL_FILES)
    (snapshot / "model.safetensors").unlink()
    (snapshot / "model.safetensors").symlink_to(snapshot / "gone.bin")
    assert doctor.check_tier3(load_model=False).status == doctor.WARN


def test_check_model_flag_reports_a_detector_that_says_unavailable(
        isolated_env, monkeypatch):
    """`--check-model` reads the real `ModelDetector.available`, which is
    what `dispatch.new_state()` builds. An unavailable one is still only a
    warning: the engine runs tiers 0-2 around it."""
    import privacy_hud.detect.model as model_module

    class _Unavailable:
        def __init__(self, *_a, **_k):
            self.available = False

    monkeypatch.setattr(model_module, "ModelDetector", _Unavailable)
    check = doctor.check_tier3(load_model=True)
    assert check.status == doctor.WARN
    assert check.fixes


def test_check_model_flag_reports_a_detector_that_says_available(
        isolated_env, monkeypatch):
    import privacy_hud.detect.model as model_module

    class _Available:
        def __init__(self, *_a, **_k):
            self.available = True

    monkeypatch.setattr(model_module, "ModelDetector", _Available)
    assert doctor.check_tier3(load_model=True).status == doctor.OK


def test_default_run_does_not_load_the_model(isolated_env, monkeypatch):
    """~2.8 GB and about seven seconds is not a reasonable default for a
    command run on a whim. The cheap path must not construct the detector."""
    import privacy_hud.detect.model as model_module

    def _boom(*_a, **_k):
        raise AssertionError("ModelDetector must not be constructed without "
                             "--check-model")

    monkeypatch.setattr(model_module, "ModelDetector", _boom)
    doctor.run_checks(load_model=False, timeout=0.2)


# --------------------------------------------------------------------- #
# Plugin install — installed, enabled, and current
# --------------------------------------------------------------------- #

def _fake_repo(tmp_path, *, version="0.1.0", handler="print('hi')\n") -> Path:
    repo = tmp_path / "repo"
    (repo / ".claude-plugin").mkdir(parents=True)
    (repo / "hooks").mkdir(parents=True)
    (repo / "skills" / "privacy").mkdir(parents=True)
    (repo / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "codex-privacy-hud", "version": version}))
    (repo / "hooks" / "hooks.json").write_text('{"hooks": {}}')
    (repo / "hooks" / "handler.py").write_text(handler)
    (repo / "skills" / "privacy" / "SKILL.md").write_text("# privacy\n")
    return repo


def _install(tmp_path, repo, *, marketplace="codex-privacy-hud",
             version="0.1.0", handler=None, enabled=True):
    dest = (tmp_path / "codex-home" / "plugins" / "cache" / marketplace /
            "codex-privacy-hud" / version)
    dest.mkdir(parents=True)
    for name in doctor._tracked_files(repo):
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((repo / name).read_bytes())
    if handler is not None:
        (dest / "hooks" / "handler.py").write_text(handler)
    if enabled is not None:
        config = tmp_path / "codex-home" / "config.toml"
        config.write_text(
            f'[plugins."codex-privacy-hud@{marketplace}"]\n'
            f"enabled = {'true' if enabled else 'false'}\n")
    return dest


def test_no_codex_home_is_skipped_not_failed(isolated_env):
    """This command is genuinely useful in CI and in a bare checkout. "Codex
    is not installed for this user" is a fact to state, not a fault."""
    check = doctor.check_plugin_install()
    assert check.status == doctor.SKIP
    assert doctor.exit_code([check]) == 0


def test_codex_installed_but_plugin_absent_fails(isolated_env, tmp_path):
    (tmp_path / "codex-home" / "plugins" / "cache").mkdir(parents=True)
    check = doctor.check_plugin_install()
    assert check.status == doctor.FAIL
    assert any("codex plugin add" in fix for fix in check.fixes)


def test_matching_installed_copy_is_ok(isolated_env, monkeypatch, tmp_path):
    repo = _fake_repo(tmp_path)
    _install(tmp_path, repo)
    monkeypatch.setattr(doctor, "_repo_root", lambda: repo)
    assert doctor.check_plugin_install().status == doctor.OK


def test_stale_installed_copy_warns_and_names_the_diverging_file(
        isolated_env, monkeypatch, tmp_path):
    """Codex installs a *copy*, so an edited `hooks/handler.py` in the
    checkout is not what runs until the plugin is re-added. A warning, not a
    failure: the installed copy genuinely works, it is just not the code you
    are reading. Naming the file is what separates "my edit is not live" from
    "a README typo"."""
    repo = _fake_repo(tmp_path, handler="# edited in the checkout\n")
    _install(tmp_path, repo, handler="# the old version Codex installed\n")
    monkeypatch.setattr(doctor, "_repo_root", lambda: repo)

    check = doctor.check_plugin_install()

    assert check.status == doctor.WARN
    assert any("hooks/handler.py" in d for d in check.details)
    assert any("codex plugin add" in fix for fix in check.fixes)
    assert doctor.exit_code([check]) == 0


def test_disabled_plugin_fails(isolated_env, monkeypatch, tmp_path):
    """Installed but disabled fires no hook at all — the same "nothing
    happened" symptom as a forgotten daemon, with a completely different
    fix."""
    repo = _fake_repo(tmp_path)
    _install(tmp_path, repo, enabled=False)
    monkeypatch.setattr(doctor, "_repo_root", lambda: repo)

    check = doctor.check_plugin_install()

    assert check.status == doctor.FAIL
    assert check.fixes


def test_install_check_ignores_files_codex_never_runs(isolated_env, monkeypatch,
                                                      tmp_path):
    """A staleness signal that is always on is one nobody looks at. The
    checkout's tests, byte-code caches and `.DS_Store` are not part of what
    Codex executes and must not count as divergence."""
    repo = _fake_repo(tmp_path)
    dest = _install(tmp_path, repo)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_x.py").write_text("def test_x(): pass\n")
    (repo / "skills" / "privacy" / "__pycache__").mkdir()
    (repo / "skills" / "privacy" / "__pycache__" / "x.pyc").write_bytes(b"\x00")
    (repo / "skills" / ".DS_Store").write_bytes(b"\x00")
    monkeypatch.setattr(doctor, "_repo_root", lambda: repo)

    assert doctor.check_plugin_install().status == doctor.OK
    assert not (dest / "tests").exists()


def test_install_check_without_a_source_checkout_cannot_claim_staleness(
        isolated_env, monkeypatch, tmp_path):
    """Installed as a wheel: there is no checkout to compare against, so the
    report says staleness is unchecked rather than inventing a verdict."""
    repo = _fake_repo(tmp_path)
    _install(tmp_path, repo)
    monkeypatch.setattr(doctor, "_repo_root", lambda: None)

    check = doctor.check_plugin_install()

    assert check.status == doctor.OK
    assert any("unchecked" in d for d in check.details)


def test_install_check_does_not_shell_out(isolated_env, monkeypatch, tmp_path):
    """I2: this plugin makes no network calls except 127.0.0.1, and `codex`
    is an API client that does. A diagnostic belonging to a tool whose claim
    is "nothing leaves your machine" must not launch one — and `codex` is
    frequently not on PATH where this command is most useful anyway."""
    import subprocess

    def _boom(*_a, **_k):
        raise AssertionError("the doctor must not run a subprocess")

    for name in ("run", "check_output", "Popen", "call", "check_call"):
        monkeypatch.setattr(subprocess, name, _boom)

    repo = _fake_repo(tmp_path)
    _install(tmp_path, repo)
    monkeypatch.setattr(doctor, "_repo_root", lambda: repo)
    doctor.run_checks(load_model=False, timeout=0.2)


# --------------------------------------------------------------------- #
# report, exit code, and the whole-command guarantees
# --------------------------------------------------------------------- #

def test_every_non_ok_check_carries_a_fix(isolated_env):
    """A diagnostic that does not tell you the fix is half a tool. Asserted
    as a property so a new check cannot be added without one."""
    for check in doctor.run_checks(load_model=False, timeout=0.2):
        if check.status in (doctor.WARN, doctor.FAIL):
            assert check.fixes, f"{check.name} has no remedy"


def test_exit_code_is_zero_when_only_warnings(isolated_env):
    warned = [doctor.Check("x", doctor.WARN, "degraded", fixes=["do a thing"]),
              doctor.Check("y", doctor.OK, "fine"),
              doctor.Check("z", doctor.SKIP, "n/a")]
    assert doctor.exit_code(warned) == 0


def test_exit_code_is_one_on_any_failure(isolated_env):
    checks = [doctor.Check("x", doctor.OK, "fine"),
              doctor.Check("y", doctor.FAIL, "broken", fixes=["fix it"])]
    assert doctor.exit_code(checks) == 1


def test_a_check_that_raises_becomes_a_failure_not_a_traceback(monkeypatch,
                                                               isolated_env):
    """A bug in one check must not cost the user the other six, and must not
    print an exception message — a diagnostic in a privacy tool does not emit
    strings it did not choose (I1)."""
    def _explode():
        raise RuntimeError("a message containing something private")

    monkeypatch.setattr(doctor, "check_ledger", _explode)
    checks = doctor.run_checks(load_model=False, timeout=0.2)

    ledger = _by_name(checks, "Ledger")
    assert ledger.status == doctor.FAIL
    assert "RuntimeError" in ledger.summary
    text = doctor.format_report(checks)
    assert "something private" not in text
    assert len(checks) == 7


def test_report_is_plain_text_with_no_escape_sequences(isolated_env):
    """No colour, so `NO_COLOR` is respected by construction rather than by a
    branch that could be wrong — same reasoning as `ambient.py`."""
    text = doctor.format_report(doctor.run_checks(load_model=False,
                                                  timeout=0.2))
    assert "\x1b" not in text


def test_report_never_implies_recall(isolated_env):
    text = doctor.format_report(doctor.run_checks(load_model=False,
                                                  timeout=0.2)).lower()
    for word in BANNED:
        assert word not in text


def test_main_returns_an_int_and_prints_a_report(isolated_env, capsys):
    code = doctor.main([])
    out = capsys.readouterr().out
    assert isinstance(code, int)
    assert "privacy-hud doctor" in out
    assert "Summary:" in out


def test_main_catches_argparse_systemexit(isolated_env, capsys):
    """`ambient.main`'s contract, kept: the console-script wrapper is handed
    this function's return value, so `--help` returns 0 rather than raising
    through it."""
    assert doctor.main(["--help"]) == 0
    assert doctor.main(["--nonsense"]) == 2


def test_main_on_a_broken_setup_exits_non_zero(isolated_env, capsys):
    """No daemon socket in the temp PLUGIN_DATA, so the daemon check fails."""
    assert doctor.main(["--timeout", "0.2"]) == 1
    assert "[FAIL]" in capsys.readouterr().out


def test_main_creates_nothing_in_plugin_data(isolated_env, capsys):
    """The whole command, run against an empty `PLUGIN_DATA`, must leave it
    empty. Anything else means a diagnostic wrote to the directory it was
    asked to inspect."""
    before = sorted(p.name for p in isolated_env.iterdir())
    doctor.main(["--timeout", "0.2"])
    after = sorted(p.name for p in isolated_env.iterdir())
    assert before == after == []


def test_main_does_not_touch_an_existing_ledger(isolated_env, capsys):
    """Read-only against a real ledger: same bytes, same mtime, same rows."""
    path = isolated_env / "ledger.db"
    led = Ledger(path, M)
    led.start_session("s1", cwd="/repo", model="gpt-5")
    led.conn.close()
    before_stat = path.stat()
    before_rows = sqlite3.connect(f"file:{path}?mode=ro", uri=True).execute(
        "SELECT COUNT(*) FROM events").fetchone()[0]

    doctor.main(["--timeout", "0.2"])

    after_stat = path.stat()
    after_rows = sqlite3.connect(f"file:{path}?mode=ro", uri=True).execute(
        "SELECT COUNT(*) FROM events").fetchone()[0]
    assert (before_stat.st_mtime_ns, before_stat.st_size) == \
        (after_stat.st_mtime_ns, after_stat.st_size)
    assert before_rows == after_rows


def test_healthy_setup_reports_healthy_and_exits_zero(isolated_env, monkeypatch,
                                                      tmp_path, short_sockdir,
                                                      capsys):
    """End to end, with every part of the stack standing up: the right
    PLUGIN_DATA, a populated ledger, a responsive daemon, both detector
    packages above their floors, the weights on disk, and a matching
    installed copy."""
    assigned = tmp_path / "codex-home" / "plugins" / "data" / \
        "codex-privacy-hud-codex-privacy-hud"
    assigned.mkdir(parents=True)
    monkeypatch.setenv("PLUGIN_DATA", str(assigned))
    led = Ledger(assigned / "ledger.db", M)
    led.start_session("s1", cwd="/repo", model="gpt-5")
    led.conn.close()

    sock_path = short_sockdir / "d.sock"
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)
    server, thread = _serve(sock_path, b"{}\n")

    _pin_versions(monkeypatch, transformers="5.16.1", torch="2.5.1")
    _seed_weights(tmp_path, doctor.MODEL_FILES)
    monkeypatch.setenv("HF_HOME", str(tmp_path / "hf"))
    repo = _fake_repo(tmp_path)
    _install(tmp_path, repo)
    monkeypatch.setattr(doctor, "_repo_root", lambda: repo)

    try:
        code = doctor.main([])
    finally:
        _stop(server, thread)

    out = capsys.readouterr().out
    assert code == 0
    assert "[FAIL]" not in out
    assert "[WARN]" not in out
    assert "Setup is healthy." in out
