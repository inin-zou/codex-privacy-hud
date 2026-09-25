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
import sys
import tempfile
import textwrap
import threading
import time
import tomllib
from pathlib import Path

import pytest

from privacy_hud import doctor, runtime
from privacy_hud.matrix.loader import load_matrix
from runtime_helpers import writer_ledger

M = load_matrix()

#: I5 (never imply recall) and CLAUDE.md §5 (no overclaiming) apply to this
#: command's output too.
BANNED = ("undo", "revoke", "remove from context", "your data is protected",
          "100% secure")


def _fake_mcp_server_body(tools, *, crash=False, says="", call="ok") -> str:
    """The stdlib stdio MCP server body `_write_fake_plugin` and the
    all-green end-to-end test both ship: answers `initialize` and
    `tools/list`, nothing else. Real enough to prove the handshake, small
    enough to have no dependencies — the point is the doctor's side of the
    conversation, not FastMCP's.

    `says` makes it die the way the real launcher dies: one line of cause on
    stderr, nothing on stdout, non-zero exit.

    `call` is how it answers the doctor's ledger-read probe (`tools/call`):
    "ok" a summary, "error" a tool error carrying a sentinel payload,
    "malformed" a result that is not a summary, "hang" no answer at all."""
    if crash:
        if says:
            return (f"import sys; print({says!r}, file=sys.stderr); "
                    "sys.exit(1)\n")
        return "import sys; sys.exit(3)\n"
    return f"""
import json, sys, time
TOOLS = {tools!r}
CALL = {call!r}
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": msg["id"],
            "result": {{"protocolVersion": "2024-11-05", "capabilities": {{}},
            "serverInfo": {{"name": "fake", "version": "1"}}}}}}) + "\\n")
    elif msg.get("method") == "tools/list":
        sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": msg["id"],
            "result": {{"tools": [{{"name": n, "inputSchema": {{"type": "object"}}}}
                                 for n in TOOLS]}}}}) + "\\n")
    elif msg.get("method") == "tools/call":
        if CALL == "hang":
            time.sleep(60)
        elif CALL == "error":
            result = {{"isError": True, "content": [{{"type": "text",
                "text": "SENTINEL-tool-error-payload-7d2e"}}]}}
        elif CALL == "malformed":
            result = {{"content": [{{"type": "text", "text": "[]"}}]}}
        elif CALL.startswith("value:"):
            bad = json.loads(CALL[len("value:"):])
            result = {{"content": [{{"type": "text", "text": json.dumps(
                {{"accounting_version": 1, "legacy_score": 0.0,
                  "legacy_cap": 120.0, "legacy_percent": bad,
                  "legacy_permitted_crossing_rows": 0,
                  "legacy_boundary_kinds": 0, "legacy_prevented_rows": 0,
                  "score_label": "legacy permitted-crossing score",
                  "accounting_note": "Historical accounting includes "
                  "permitted crossings and may collapse different outcomes. "
                  "It does not establish confirmed disclosure."}})}}]}}
        else:
            result = {{"content": [{{"type": "text", "text": json.dumps(
                {{"accounting_version": 0, "percent": None,
                  "score_label": "No session on record",
                  "accounting_note": "No session record is available in "
                  "this ledger. The percentage and counts are "
                  "unavailable."}})}}]}}
        if CALL != "hang":
            sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": msg["id"],
                "result": result}}) + "\\n")
    sys.stdout.flush()
"""


def _write_fake_plugin(root, *, tools, declare=True, crash=False, says="",
                       server_name="privacy-hud", call="ok"):
    """A plugin directory shaped like an installed one, whose `mcp/server.py`
    is a stdlib stdio MCP server answering `initialize` and `tools/list`.

    Real enough to prove the handshake, small enough to have no dependencies:
    the point is the doctor's side of the conversation, not FastMCP's.
    """
    import json
    (root / ".codex-plugin").mkdir(parents=True, exist_ok=True)
    manifest = {"name": "codex-privacy-hud", "version": "0.7.0",
                "description": "x", "skills": "./skills/",
                "hooks": "./hooks/hooks.json"}
    if declare:
        manifest["mcpServers"] = {server_name: {
            "command": "python3", "args": ["./mcp/server.py"], "cwd": "."}}
    (root / ".codex-plugin" / "plugin.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    (root / "mcp").mkdir(parents=True, exist_ok=True)
    (root / "mcp" / "server.py").write_text(
        _fake_mcp_server_body(tools, crash=crash, says=says, call=call),
        encoding="utf-8")


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


def _select_runtime(data_dir, monkeypatch=None):
    """Give `data_dir` a receipt v2 over the shared test bundle and return
    the activation it selects.

    Protocol 2 has no anonymous healthy answer: the doctor's daemon probe
    is a hello, and the only reply that counts as responsive is one naming
    the selected build and activation epoch. So a test with a daemon in it
    needs a selection, which is what this is. With a `monkeypatch`, the
    running first-party code is also pointed at that bundle, so the
    Runtime source check agrees with the receipt.
    """
    from privacy_hud import runtime_contract
    from runtime_helpers import shared_bundle, write_receipt_v2

    bundle = shared_bundle()
    write_receipt_v2(Path(data_dir), bundle=bundle, python=sys.executable)
    if monkeypatch is not None:
        monkeypatch.setattr(doctor, "_first_party_origin",
                            lambda: bundle / "src" / "privacy_hud")
    return runtime_contract.load_activation(Path(data_dir))


def _hello_bytes(activation, schema_version: int = 0) -> bytes:
    """The frame a matching daemon answers a hello with."""
    from privacy_hud import runtime_client

    return runtime_client.encode_frame(
        runtime_client.hello_reply(activation, schema_version))


def _pin_runtime(data_dir, monkeypatch, *, python=None, transformers="5.16.1",
                 torch="2.5.1", package="present", **overrides):
    """Write a runtime receipt and stub the probe of the interpreter it names.

    Both halves are needed and neither can be skipped. The receipt has to be a
    real file because that is what `hooks/handler.py` reads and what
    `check_daemon` consults to decide whether "no daemon" is self-correcting.
    The probe has to be stubbed because the real one spends ~1.4 s starting an
    interpreter and asking it for `transformers` — the answer would then be
    "whatever is installed on this laptop", which is exactly the kind of
    assertion this suite refuses to make.
    """
    receipt = runtime.build_receipt(
        data_dir, python=python or sys.executable,
        versions={"transformers": transformers, "torch": torch})
    receipt.update(overrides)
    runtime.write_receipt(data_dir, receipt)
    monkeypatch.setattr(doctor, "_probe_pinned_interpreter",
                        lambda r, t: ({"privacy_hud": package,
                                       "transformers": transformers,
                                       "torch": torch}, 0.4, ""))
    return receipt


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

def test_unset_plugin_data_fails_because_nothing_is_resolved(
        monkeypatch, tmp_path):
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    check = doctor.check_plugin_data()
    assert check.status == doctor.FAIL
    assert check.fixes


def test_empty_plugin_data_fails_the_same_way_unset_does(monkeypatch, tmp_path):
    """`PLUGIN_DATA=` (exported empty) is set and useless. Every resolver in
    the package already treats it as unset, so `check_plugin_data` took its
    "it is set" branch and then called `.parent` on the `None` that
    `_ledger_path()` correctly returned -- an `AttributeError` reported as
    the opaque "the check itself failed", in precisely the broken-profile
    state this check exists to name."""
    monkeypatch.setenv("PLUGIN_DATA", "")
    monkeypatch.setattr(runtime, "resolve_data_dir",
                        lambda explicit=None: (None, ["no codex"], []))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    check = doctor.check_plugin_data()
    assert check.status == doctor.FAIL
    assert "not set" in check.summary
    assert check.fixes


def test_unset_plugin_data_fails_cleanly_in_the_checks_that_need_a_data_dir(
        monkeypatch, tmp_path):
    """`check_ledger`, `check_runtime_pin` and `check_daemon` all resolve
    `PLUGIN_DATA` through `runtime.ledger_path()` (`doctor._ledger_path`,
    and `local_ui_server._ledger_path` — one function, three names), which returns
    `None` once there is no `/tmp` fallback to guess with (spec §6). Left
    unguarded, each one called `.parent`/`.exists()` on that `None` and
    crashed with `AttributeError` -- caught by `run_checks()`'s per-check
    `try/except`, but only into an opaque "the check itself failed
    (AttributeError)", which is a real regression in diagnostic quality for
    exactly the fresh-install state this file exists to explain. Each must
    instead resolve to its own clear, actionable `FAIL`.

    `runtime.resolve_data_dir` is patched directly (as
    `tests/test_no_tmp_fallback.py` does) so this is genuinely the
    "no Codex install either" state, not just "env var unset"."""
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    monkeypatch.setattr(runtime, "resolve_data_dir",
                        lambda explicit=None: (None, ["no codex"], []))

    for check_fn in (doctor.check_ledger, doctor.check_runtime_pin,
                      doctor.check_daemon):
        check = check_fn()
        assert check.status == doctor.FAIL
        assert "PLUGIN_DATA" in check.summary or any(
            "PLUGIN_DATA" in d for d in check.details)
        assert "the check itself failed" not in check.summary
        assert all("the check itself failed" not in d
                   for d in check.details)


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


@pytest.mark.parametrize("fenced", [False, True])
def test_plugin_data_uses_root_for_each_ledger_layout(
        tmp_path, monkeypatch, fenced):
    from privacy_hud import codex, runtime_storage

    codex_home = tmp_path / "codex-home"
    assigned = (
        codex_home / "plugins" / "data"
        / "codex-privacy-hud-codex-privacy-hud"
    )
    assigned.mkdir(parents=True)
    historical = assigned / codex.LEDGER_NAME

    if fenced:
        historical.mkdir()
        active = runtime_storage.active_path(assigned)
        active.parent.mkdir(parents=True, exist_ok=True)
        active.touch()
        expected = active
    else:
        historical.touch()
        expected = historical

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setenv("PLUGIN_DATA", str(assigned))

    assert doctor._ledger_path() == expected
    check = doctor.check_plugin_data()
    assert check.status == doctor.OK
    assert check.summary == doctor._display_path(assigned)
    assert check.fixes == []


@pytest.mark.parametrize("raw", [None, ""])
def test_plugin_data_unset_still_fails_with_a_discoverable_candidate(
        tmp_path, monkeypatch, raw):
    codex_home = tmp_path / "codex-home"
    assigned = (
        codex_home / "plugins" / "data"
        / "codex-privacy-hud-codex-privacy-hud"
    )
    assigned.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    if raw is None:
        monkeypatch.delenv("PLUGIN_DATA", raising=False)
    else:
        monkeypatch.setenv("PLUGIN_DATA", raw)

    assert runtime.plugin_data_dir() == assigned
    check = doctor.check_plugin_data()
    assert check.status == doctor.FAIL
    assert check.summary == "not set — nothing is written until it is"
    assert check.fixes


def test_plugin_data_does_not_need_a_resolved_ledger(
        tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.setenv("PLUGIN_DATA", str(data))

    def forbidden():
        pytest.fail("PLUGIN_DATA check must not resolve the ledger")

    monkeypatch.setattr(doctor, "_ledger_path", forbidden)
    assert doctor.check_plugin_data().status == doctor.OK


def test_plugin_data_none_resolution_fails_cleanly(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path / "data"))
    monkeypatch.setattr(runtime, "plugin_data_dir", lambda: None)

    check = doctor.check_plugin_data()
    assert check.status == doctor.FAIL
    assert "not set" in check.summary
    assert check.fixes


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
    led = writer_ledger(isolated_env / "ledger.db", M)
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
    writer_ledger(isolated_env / "ledger.db", M).conn.close()
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
    led = writer_ledger(isolated_env / "ledger.db", M)
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
# Runtime pin — the interpreter the hooks spawn the daemon from
# --------------------------------------------------------------------- #
#
# The failure this section defends against is the quiet one. A daemon spawned
# from Codex's PATH `python3` (Homebrew's, on the machine this was built on)
# has no `transformers` at all: it starts, it binds, it answers every probe in
# this file, and tier 3 is dead. Nothing else in this report would notice. So
# a pin that is absent, damaged, or pointing at an interpreter that no longer
# works has to be loud, and a pin that works has to be verified by asking that
# interpreter rather than by asking the one running pytest.


def test_no_receipt_fails_and_points_at_the_setup_step(isolated_env):
    check = doctor.check_runtime_pin(1.0)
    assert check.status == doctor.FAIL
    assert any("privacy-hud-setup" in fix or "privacy_hud.runtime" in fix
               for fix in check.fixes)


def test_malformed_receipt_fails_rather_than_guessing(isolated_env):
    """A receipt that cannot be parsed must never fall back to a plausible
    interpreter — falling back is how a blind daemon gets started."""
    runtime.receipt_path(isolated_env).write_text("{not json", encoding="utf-8")
    check = doctor.check_runtime_pin(1.0)
    assert check.status == doctor.FAIL
    assert check.fixes


def test_receipt_of_an_unknown_version_is_not_guessed_at(isolated_env):
    receipt = runtime.build_receipt(isolated_env, python=sys.executable)
    receipt["v"] = runtime.RECEIPT_VERSION + 99
    runtime.write_receipt(isolated_env, receipt)
    assert doctor.check_runtime_pin(1.0).status == doctor.FAIL


def test_deleted_interpreter_fails_loudly_instead_of_degrading(isolated_env,
                                                              monkeypatch,
                                                              tmp_path):
    """The stale-pin case: a removed venv or conda environment.

    `FAIL`, and with no probe attempted — there is nothing to probe. The
    alternative (quietly retrying against some other python) is the single
    thing this whole mechanism must not do.
    """
    _pin_runtime(isolated_env, monkeypatch,
                 python=str(tmp_path / "deleted-venv" / "bin" / "python3"))
    check = doctor.check_runtime_pin(1.0)
    assert check.status == doctor.FAIL
    assert check.fixes


def test_a_world_writable_receipt_fails_the_way_the_client_treats_it(
        isolated_env, monkeypatch):
    """The receipt names a program a hook executes, so the client refuses to
    spawn from one other users can write — the state an unset `PLUGIN_DATA`
    produces, since everything then falls back to /tmp. The report has to say
    that rather than leave the user with a daemon that never starts."""
    _pin_runtime(isolated_env, monkeypatch)
    runtime.receipt_path(isolated_env).chmod(0o666)
    check = doctor.check_runtime_pin(1.0)
    assert check.status == doctor.FAIL
    assert any("chmod 600" in fix for fix in check.fixes)


def test_pinned_interpreter_without_transformers_warns_with_the_consequence(
        isolated_env, monkeypatch):
    """Same line `Detector deps` draws: tiers 0-2 still run, so this is
    degraded-and-working, and the warning owes the user the consequence in
    their terms rather than ours."""
    _pin_runtime(isolated_env, monkeypatch, transformers=None, torch=None)
    check = doctor.check_runtime_pin(1.0)
    assert check.status == doctor.WARN
    assert any("names and addresses will not be detected" in d.lower()
               for d in check.details)
    assert check.fixes


def test_pinned_interpreter_below_the_transformers_floor_warns(isolated_env,
                                                              monkeypatch):
    _pin_runtime(isolated_env, monkeypatch, transformers="4.44.2")
    assert doctor.check_runtime_pin(1.0).status == doctor.WARN


def test_pinned_interpreter_that_cannot_import_the_package_fails(isolated_env,
                                                                monkeypatch):
    """A daemon spawned there would exit with an ImportError on every hook
    forever, which is not degraded — it is nothing working at all."""
    _pin_runtime(isolated_env, monkeypatch, package=None)
    check = doctor.check_runtime_pin(1.0)
    assert check.status == doctor.FAIL
    assert check.fixes


def test_a_probe_that_will_not_run_fails(isolated_env, monkeypatch):
    _pin_runtime(isolated_env, monkeypatch)
    monkeypatch.setattr(doctor, "_probe_pinned_interpreter",
                        lambda r, t: (None, 0.2, "exited 1"))
    assert doctor.check_runtime_pin(1.0).status == doctor.FAIL


def test_receipt_recorded_for_another_directory_warns(isolated_env,
                                                      monkeypatch, tmp_path):
    """A copied or moved plugin-data directory. The interpreter still works,
    so the daemon will start; what is uncertain is whether this receipt
    describes this setup."""
    _pin_runtime(isolated_env, monkeypatch,
                 plugin_data=str(tmp_path / "somewhere-else"))
    check = doctor.check_runtime_pin(1.0)
    assert check.status == doctor.WARN
    assert check.fixes


def test_healthy_pin_is_ok_and_states_the_unmonitored_window(isolated_env,
                                                            monkeypatch):
    """CLAUDE.md §5: the good news does not get to travel without the cost.
    The daemon starting itself means the first seconds of a session are
    answered without detection, and that has to be in the report."""
    _pin_runtime(isolated_env, monkeypatch)
    check = doctor.check_runtime_pin(1.0)
    assert check.status == doctor.OK
    joined = " ".join(check.details).lower()
    assert "unverified" in joined and "not monitored" in joined


def test_detector_deps_scopes_its_verdict_when_the_daemon_runs_elsewhere(
        isolated_env, monkeypatch, tmp_path):
    """The doctor may be run from an interpreter that is not the daemon's.

    "transformers not installed", and the "names and addresses will not be
    detected" that follows it, are then facts about *this* process — stating
    them unscoped is an overclaim in both directions, and would let the shell
    the user happened to be in decide whether a healthy setup reads as blind.
    It stays a detail line and never moves the verdict; the authoritative
    answer is the Runtime pin check's probe.
    """
    _pin_versions(monkeypatch, transformers=None, torch=None)
    _pin_runtime(isolated_env, monkeypatch,
                 python=str(tmp_path / "elsewhere" / "bin" / "python3"))
    check = doctor.check_detector_deps()

    assert check.status == doctor.WARN
    assert any("Runtime pin" in d for d in check.details)
    # The scoping must come after the consequence it scopes, or a reader stops
    # at the consequence and takes it for the product's.
    consequence = next(i for i, d in enumerate(check.details)
                       if "will not be detected" in d)
    scoping = next(i for i, d in enumerate(check.details)
                   if "Runtime pin" in d)
    assert scoping > consequence


def test_tier3_check_also_scopes_itself_to_this_interpreter(isolated_env,
                                                           monkeypatch,
                                                           tmp_path):
    """`--check-model` constructs the detector in the doctor's own process,
    and the default branch reads the doctor's own HF cache location. Both are
    statements about this interpreter, and the daemon's may differ."""
    _pin_runtime(isolated_env, monkeypatch,
                 python=str(tmp_path / "elsewhere" / "bin" / "python3"))
    check = doctor.check_tier3(load_model=False)
    assert check.status == doctor.WARN  # isolated_env has no weights
    assert any("Runtime pin" in d for d in check.details)


# --------------------------------------------------------------------- #
# Daemon — the round trip, not the socket file
# --------------------------------------------------------------------- #

def test_no_socket_fails_and_says_how_to_start_the_daemon(isolated_env):
    """No receipt either, so nothing will ever start one: still a FAIL."""
    check = doctor.check_daemon(timeout=0.5)
    assert check.status == doctor.FAIL
    assert any("privacy_hud.daemon" in fix for fix in check.fixes)


def test_absent_daemon_warns_rather_than_fails_when_a_pin_exists(isolated_env):
    """The daemon idle-exits after 30 minutes and the next hook starts it, so
    "no socket" between sessions is the correct state of a healthy setup.
    Reporting that as FAIL would teach the user to ignore this line."""
    check = doctor.check_daemon(timeout=0.5, pinned=True)
    assert check.status == doctor.WARN
    assert check.fixes


def test_absent_daemon_with_a_pin_still_names_the_unmonitored_window(
        isolated_env):
    check = doctor.check_daemon(timeout=0.5, pinned=True)
    assert any("unverified" in d for d in check.details)


def test_stale_socket_with_a_pin_warns_because_it_self_heals(
        isolated_env, monkeypatch, short_sockdir):
    """`Daemon._claim_socket_path` unlinks a socket it has probed dead, under
    the startup lock — so a leftover socket is cleared by the next spawn
    rather than needing an `rm`."""
    sock_path = short_sockdir / "stale.sock"
    server, thread = _serve(sock_path, b"{}\n")
    _stop(server, thread)  # closes the listener, leaves the file behind
    assert sock_path.exists()
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)

    check = doctor.check_daemon(timeout=0.5, pinned=True)
    assert check.status == doctor.WARN
    assert check.fixes


def test_responsive_daemon_is_ok(isolated_env, monkeypatch, short_sockdir):
    activation = _select_runtime(isolated_env)
    sock_path = short_sockdir / "d.sock"
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)
    server, thread = _serve(sock_path, _hello_bytes(activation))
    try:
        check = doctor.check_daemon(timeout=2.0)
    finally:
        _stop(server, thread)

    assert check.status == doctor.OK


def test_probe_sends_the_documented_protocol_and_no_event_at_all(
        isolated_env, monkeypatch, short_sockdir):
    """The probe must be the wire format `hooks/handler.py` owns, and it
    must carry nothing a daemon could record.

    Protocol 1's probe sent a `PreCompact` event, chosen because
    `dispatch()` returns an empty allow for it before touching the ledger.
    Protocol 2 needs no such argument: a hello establishes liveness by
    itself, so the diagnostic sends no event to the thing it diagnoses. If
    someone ever puts one back, a diagnostic starts writing to the thing
    it diagnoses — hence the assertion.
    """
    from privacy_hud import runtime_client

    activation = _select_runtime(isolated_env)
    sock_path = short_sockdir / "d.sock"
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)
    server, thread = _serve(sock_path, _hello_bytes(activation))
    try:
        doctor.check_daemon(timeout=2.0)
    finally:
        _stop(server, thread)

    assert len(server.seen) == 1
    assert runtime_client.is_valid_hello(server.seen[0])
    assert server.seen[0]["build_id"] == activation.identity.build_id
    assert server.seen[0]["activation_epoch"] == activation.epoch
    assert all(message.get("op") != "event" for message in server.seen)


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
    activation = _select_runtime(isolated_env)
    sock_path = short_sockdir / "d.sock"
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)
    server, thread = _serve(sock_path, _hello_bytes(activation))
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


def test_check_model_missing_weights_warns_without_network(tmp_path):
    """`--check-model` against an empty cache, with the offline flags
    inherited OFF: the real detector runs, reports unavailable, and nothing
    resolves or connects anywhere. A cache miss is a warning and a printed
    recipe, never a download.

    In a fresh interpreter, because the hub caches both its offline flag and
    its cache location at import: in-process, an earlier test's import
    decides which cache this one sees."""
    from privacy_hud import offline
    script = textwrap.dedent("""
        import json, socket
        attempts = []

        def refuse(*args, **kwargs):
            attempts.append(repr(args[:1]))
            raise OSError("network refused by test")

        socket.getaddrinfo = refuse
        socket.create_connection = refuse
        socket.socket.connect = lambda self, address: refuse(address)
        from privacy_hud import doctor
        check = doctor.check_tier3(load_model=True)
        print(json.dumps({"status": check.status, "fixes": check.fixes,
                          "attempts": attempts}))
    """)
    env = {**os.environ, **{name: "0" for name in offline.FORCED_ENV},
           "HF_HOME": str(tmp_path / "hf"),
           "HF_HUB_CACHE": str(tmp_path / "hf" / "hub"),
           "PYTHONPATH": str(Path(doctor.__file__).parents[1])}
    proc = subprocess.run([sys.executable, "-c", script], env=env,
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["status"] == doctor.WARN
    assert out["attempts"] == []
    assert any(offline.download_env_prefix() in fix for fix in out["fixes"])


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
    (repo / ".codex-plugin").mkdir(parents=True)
    (repo / "hooks").mkdir(parents=True)
    (repo / "skills" / "privacy").mkdir(parents=True)
    (repo / ".codex-plugin" / "plugin.json").write_text(
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
    assert len(checks) == 13


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
    led = writer_ledger(path, M)
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
    PLUGIN_DATA, a populated ledger, a pinned runtime, a responsive daemon,
    both detector packages above their floors, the weights on disk, and a
    matching installed copy."""
    assigned = tmp_path / "codex-home" / "plugins" / "data" / \
        "codex-privacy-hud-codex-privacy-hud"
    assigned.mkdir(parents=True)
    monkeypatch.setenv("PLUGIN_DATA", str(assigned))
    led = writer_ledger(assigned / "ledger.db", M)
    led.start_session("s1", cwd="/repo", model="gpt-5")
    led.conn.close()
    _pin_runtime(assigned, monkeypatch)
    # A healthy setup now also means a selected bundle the running code
    # came out of, and a daemon that answers as that build (#66).
    activation = _select_runtime(assigned, monkeypatch)

    sock_path = short_sockdir / "d.sock"
    monkeypatch.setattr(doctor, "_socket_path", lambda _d: sock_path)
    server, thread = _serve(sock_path, _hello_bytes(activation))

    _pin_versions(monkeypatch, transformers="5.16.1", torch="2.5.1")
    _seed_weights(tmp_path, doctor.MODEL_FILES)
    monkeypatch.setenv("HF_HOME", str(tmp_path / "hf"))
    repo = _fake_repo(tmp_path)
    # Declare and ship a real (fake) MCP server so the new "MCP server" check
    # also comes back OK in this all-green scenario, exactly as it would for
    # an installed copy that Codex can actually launch.
    manifest_path = repo / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["mcpServers"] = {"privacy-hud": {
        "command": "python3", "args": ["./mcp/server.py"], "cwd": "."}}
    manifest_path.write_text(json.dumps(manifest))
    (repo / "mcp").mkdir(parents=True, exist_ok=True)
    (repo / "mcp" / "server.py").write_text(
        _fake_mcp_server_body(list(doctor.MCP_TOOLS)), encoding="utf-8")
    dest = _install(tmp_path, repo)
    # `mcp/server.py` is not one of the tracked files `_install` copies (it
    # is compared for staleness no more than any other untracked file), so
    # it is copied into the installed copy by hand here.
    (dest / "mcp").mkdir(parents=True, exist_ok=True)
    (dest / "mcp" / "server.py").write_bytes(
        (repo / "mcp" / "server.py").read_bytes())
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


# --------------------------------------------------------------------- #
# MCP server
# --------------------------------------------------------------------- #

def test_check_plugin_install_survives_a_plugin_removed_mid_check(
        monkeypatch, tmp_path, isolated_env):
    """It read the cache twice and matched the second reading against the
    first: `next(entry for entry in installed if entry[2] == root)`, with no
    default. A plugin removed between the two readings raised
    `StopIteration` out of the diagnostic whose whole job is to survive a
    broken install — and `run_checks` would report it as a doctor crash
    rather than as anything about the user's setup.

    Simulated by making the second reading empty, which is what `codex
    plugin remove` in another terminal looks like from in here.
    """
    doctor._codex_home().mkdir(parents=True, exist_ok=True)
    version = doctor._declared_version(doctor._repo_root()) or "0.7.0"
    readings = [[("m", version, tmp_path)], []]
    monkeypatch.setattr(doctor, "_installed_plugin_dirs",
                        lambda: readings.pop(0) if readings else [])
    check = doctor.check_plugin_install()
    assert check.name == "Plugin install"


def test_check_mcp_server_passes_on_the_exact_tool_set(monkeypatch, tmp_path):
    """The check is the runtime half of the exposure decision: it passes only
    when the running server lists exactly the tools that cannot loosen
    protection, so a regression that re-exposes `allow_once` fails something
    a user runs, not only a unit test."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS))
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.OK


def test_check_mcp_server_fails_when_the_manifest_declares_nothing(
        monkeypatch, tmp_path):
    """Codex warns and ignores a manifest without the key; nothing inside
    Codex shows the difference."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS), declare=False)
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL
    assert check.fixes


def test_check_mcp_server_fails_on_an_extra_tool(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path,
                       tools=list(doctor.MCP_TOOLS) + ["privacy.allow_once"])
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL
    assert "privacy.allow_once" in check.summary + " ".join(check.details)


def test_check_mcp_server_fails_on_a_missing_tool(monkeypatch, tmp_path):
    """The other half of "a differing tool set" (spec, Testing item 6). An
    extra tool is the dangerous direction and has always been covered; a
    missing one means a read the `$privacy` surfaces rely on is simply not
    there, and the report has to name which."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS)[1:])
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL
    assert "missing:" in " ".join(check.details)
    assert doctor.MCP_TOOLS[0] in " ".join(check.details)


def test_check_mcp_server_fails_when_the_server_will_not_start(
        monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=[], crash=True)
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL


def test_check_mcp_server_quotes_the_reason_the_server_gave(
        monkeypatch, tmp_path):
    """The launcher writes a cause to stderr and exits. Without this the
    report said `the server did not start (ValueError)` and stopped there —
    while the answer (`no usable runtime.json (FileNotFoundError); run
    privacy-hud-setup`) sat unread in a pipe this check had already opened.

    Preserve that diagnosis through an exact startup allowlist match.
    Arbitrary stderr does not inherit the launcher's disclosure policy.
    """
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(
        tmp_path, tools=[], crash=True,
        says="privacy-hud mcp: no usable runtime.json (FileNotFoundError); "
             "run privacy-hud-setup")
    check = doctor.check_mcp_server(timeout=30)
    reason = (
        "privacy-hud mcp: no usable runtime.json (FileNotFoundError); "
        "run privacy-hud-setup"
    )
    assert check.status == doctor.FAIL
    assert check.details[0] == f"probe diagnostic: {reason}"
    assert reason in doctor.format_report([check])
    assert doctor._STDERR_WITHHELD not in doctor.format_report([check])


def test_check_mcp_server_caps_what_it_quotes(monkeypatch, tmp_path):
    """A stderr dump is withheld, not merely shortened. The diagnostic
    remains bounded and carries none of the dumped text."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    sentinel = "SENTINEL-private-exception"
    _write_fake_plugin(
        tmp_path, tools=[], crash=True, says=sentinel + "x" * 5000)
    check = doctor.check_mcp_server(timeout=30)
    report = doctor.format_report([check])
    assert check.status == doctor.FAIL
    assert check.details[0] == (
        f"probe diagnostic: {doctor._STDERR_WITHHELD}"
    )
    assert max(len(d) for d in check.details) < 400
    assert sentinel not in report
    assert "x" * 200 not in report


def test_check_mcp_server_reads_the_server_the_manifest_names(
        monkeypatch, tmp_path):
    """`next(iter(servers.values()))` probed whichever server came first. A
    manifest may legitimately grow a second one, and a check that reports on
    an arbitrary server passes and fails for reasons that have nothing to do
    with this plugin."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS),
                       server_name="somebody-elses-server")
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL
    assert "somebody-elses-server" in " ".join(check.details)
    assert doctor.MCP_SERVER_NAME in check.summary


def test_check_mcp_server_fails_when_list_succeeds_but_call_errors(
        monkeypatch, tmp_path):
    """The failure 0.7.4 and earlier shipped with MCP SDK 2.x: the tools
    listed, every ledger-backed call errored, and listing was all this
    check looked at."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS), call="error")
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL
    assert check.summary == ("server started, but the MCP ledger-read probe "
                             "failed")


def test_check_mcp_server_fails_on_malformed_tool_result(monkeypatch,
                                                         tmp_path):
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS),
                       call="malformed")
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL
    assert "ledger-read probe failed" in check.summary


@pytest.mark.parametrize("bad", [None, "0", True, -1, 1.5])
def test_check_mcp_server_fails_on_a_summary_with_malformed_values(
        monkeypatch, tmp_path, bad):
    """The right keys are not enough: a summary whose values are not
    non-negative integers is not evidence that the ledger was read."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS),
                       call="value:" + json.dumps(bad))
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL
    assert "ledger-read probe failed" in check.summary


def test_check_mcp_server_fails_when_tool_call_times_out(monkeypatch,
                                                         tmp_path):
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS), call="hang")
    started = time.monotonic()
    check = doctor.check_mcp_server(timeout=3)
    assert time.monotonic() - started < 20, "the child was not cleaned up"
    assert check.status == doctor.FAIL
    assert "ledger-read probe failed" in check.summary


def test_check_mcp_server_does_not_echo_tool_error_payload(monkeypatch,
                                                           tmp_path):
    """A tool error can carry anything; the report quotes none of it."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS), call="error")
    check = doctor.check_mcp_server(timeout=30)
    text = " ".join([check.summary, *check.details, *check.fixes])
    assert "SENTINEL-tool-error-payload-7d2e" not in text


def test_check_mcp_server_probe_does_not_write_ledger_rows(monkeypatch,
                                                           tmp_path):
    """Against the real `mcp/server.py`: the probe passes, and every table
    holds exactly what it held before -- no session, policy, event or
    coverage row for the probe's synthetic session."""
    from privacy_hud.matrix.loader import load_matrix

    from runtime_helpers import make_bundle, write_receipt_v2

    root = make_bundle(tmp_path / "plugin")
    data = tmp_path / "data"
    data.mkdir()
    led = writer_ledger(data / "ledger.db", load_matrix())
    led.start_session("real", cwd="/r", model="gpt-5")
    led.conn.close()
    write_receipt_v2(data, bundle=root, python=sys.executable)

    def counts() -> dict[str, int]:
        conn = sqlite3.connect(data / "ledger.db")
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
            return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    for t in tables}
        finally:
            conn.close()

    before = counts()
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: root)
    monkeypatch.setenv("PLUGIN_DATA", str(data))
    monkeypatch.delenv("PRIVACY_HUD_BOOTSTRAP_REEXEC", raising=False)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex-home"))
    check = doctor.check_mcp_server(timeout=60)
    assert check.status == doctor.OK, (check.summary, check.details)
    assert check.summary.endswith("ledger read succeeded")
    assert counts() == before


def test_doctor_stderr_allowlist_matches_all_launcher_fail_calls():
    import ast
    import re

    path = Path(__file__).resolve().parent.parent / "mcp" / "server.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))

    receipt = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "RECEIPT_NAME"
                for t in node.targets)
        and isinstance(node.value, ast.Constant)
    ]
    assert receipt == ["runtime.json"]

    fail = next(node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "_fail")
    prints = [
        node for node in ast.walk(fail)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "print"
    ]
    expected_print = ast.parse(
        'print(f"privacy-hud mcp: {message}", file=sys.stderr)',
        mode="eval",
    ).body
    assert len(prints) == 1
    assert ast.dump(prints[0]) == ast.dump(expected_print)

    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "_fail"
    ]
    assert len(calls) == 4

    class_expr = ast.dump(ast.parse("type(exc).__name__", mode="eval").body)
    fixed = set()
    variable = []

    for call in calls:
        assert len(call.args) == 1
        assert not call.keywords
        value = call.args[0]
        parts = value.values if isinstance(value, ast.JoinedStr) else [value]
        pieces = ["privacy-hud mcp: "]
        class_slots = 0

        for part in parts:
            if isinstance(part, ast.Constant):
                assert isinstance(part.value, str)
                pieces.append(part.value)
            else:
                assert isinstance(part, ast.FormattedValue)
                assert part.conversion == -1
                assert part.format_spec is None
                if isinstance(part.value, ast.Name):
                    assert part.value.id == "RECEIPT_NAME"
                    pieces.append("runtime.json")
                else:
                    assert ast.dump(part.value) == class_expr
                    class_slots += 1
                    pieces.append("{exception_class}")

        message = "".join(pieces)
        if class_slots:
            assert class_slots == 1
            variable.append(message)
        else:
            fixed.add(message)

    assert fixed == doctor._LAUNCHER_STDERR_LINES
    assert variable == [
        "privacy-hud mcp: no usable runtime.json ({exception_class}); "
        "run privacy-hud-setup"
    ]
    assert doctor._LAUNCHER_RECEIPT_ERROR == (
        r"privacy-hud mcp: no usable runtime\.json "
        r"\([A-Za-z_][A-Za-z0-9_]*\); run privacy-hud-setup"
    )

    for line in fixed:
        expected = (
            line if len(line) <= 200 else line[:200] + "…"
        )
        assert doctor._stderr_tail(
            line + "\n", allow_launcher=True) == expected

    for name in ("FileNotFoundError", "JSONDecodeError", "_CustomError2"):
        line = variable[0].format(exception_class=name)
        assert re.fullmatch(doctor._LAUNCHER_RECEIPT_ERROR, line)
        assert doctor._stderr_tail(line, allow_launcher=True) == line


_SENTINEL = "SENTINEL-private-exception"
_REASON = ("privacy-hud mcp: no usable runtime.json (FileNotFoundError); "
           "run privacy-hud-setup")


@pytest.mark.parametrize("text", [
    f"RuntimeError: {_SENTINEL}",
    f"SystemExit: cannot import SDK: {_SENTINEL}",
    " " + _REASON,
    _REASON + " ",
    _REASON + _SENTINEL,
    _SENTINEL + _REASON,
    _REASON + "\r" + _SENTINEL,
    _REASON + "\x1b[0m",
    _REASON.replace("FileNotFoundError", "Error: " + _SENTINEL),
    _REASON.replace("FileNotFoundError", "Érror"),
    _REASON + "\n" + _SENTINEL,
])
def test_stderr_allowlist_requires_a_complete_unmodified_line(text):
    sentinel = _SENTINEL
    assert doctor._stderr_tail(text, allow_launcher=True) == (
        doctor._STDERR_WITHHELD
    )
    exc = ValueError("fixed probe failure")
    doctor._attach_stderr(exc, text, allow_launcher=True)
    assert exc.__notes__ == [doctor._STDERR_WITHHELD]
    assert sentinel not in "\n".join(exc.__notes__)


def test_stderr_allowlist_caps_only_after_matching():
    line = (
        "privacy-hud mcp: no usable runtime.json ("
        + "E" * 5000
        + "); run privacy-hud-setup"
    )
    assert doctor._stderr_tail(line, allow_launcher=True) == line[:200] + "…"
    assert doctor._stderr_tail(
        line + " SENTINEL-private-exception", allow_launcher=True
    ) == doctor._STDERR_WITHHELD
    assert doctor._stderr_tail("") == ""
    assert doctor._stderr_tail(" \n\t\n") == ""


def _scripted_mcp_body(scenario: str, stderr_text: str) -> str:
    """A stdio server that fails at one chosen step, writing `stderr_text`
    to stderr (flushed) just before it does."""
    return f"""
import json, sys, time
SCENARIO = {scenario!r}
ERR = {stderr_text!r}
TOOLS = {sorted(doctor.MCP_TOOLS)!r}
SENTINEL = {_SENTINEL!r}

def say(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()

def err():
    sys.stderr.write(ERR + "\\n")
    sys.stderr.flush()

if SCENARIO == "pre_init":
    err()
    sys.exit(1)
for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    method = msg.get("method")
    if method == "initialize":
        say({{"jsonrpc": "2.0", "id": msg["id"], "result": {{
            "protocolVersion": "2024-11-05", "capabilities": {{}},
            "serverInfo": {{"name": "fake", "version": "1"}}}}}})
    elif method == "tools/list":
        if SCENARIO.startswith("list_"):
            err()
            if SCENARIO == "list_eof":
                sys.exit(1)
            if SCENARIO == "list_error":
                say({{"jsonrpc": "2.0", "id": msg["id"],
                     "error": {{"code": -32000, "message": SENTINEL}}}})
                continue
            time.sleep(60)
        say({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"tools": [
            {{"name": n, "inputSchema": {{"type": "object"}}}}
            for n in TOOLS]}}}})
    elif method == "tools/call":
        err()
        if SCENARIO == "call_iserror":
            say({{"jsonrpc": "2.0", "id": msg["id"], "result": {{
                "isError": True,
                "content": [{{"type": "text", "text": SENTINEL}}]}}}})
        elif SCENARIO == "call_error":
            say({{"jsonrpc": "2.0", "id": msg["id"],
                 "error": {{"code": -32000, "message": SENTINEL}}}})
        elif SCENARIO == "call_eof":
            sys.exit(1)
        else:
            time.sleep(60)
"""


def _run_scripted(monkeypatch, tmp_path, scenario, stderr_text, timeout=30):
    """Run the check against a scripted server, recording what `_mcp_probe`
    raised or returned and every `_attach_stderr` call."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS))
    (tmp_path / "mcp" / "server.py").write_text(
        _scripted_mcp_body(scenario, stderr_text), encoding="utf-8")
    caught: list[BaseException] = []
    probe_returns: list = []
    attached_exceptions: list[BaseException] = []
    real_probe = doctor._mcp_probe
    real_attach = doctor._attach_stderr

    def probe(*args, **kwargs):
        try:
            out = real_probe(*args, **kwargs)
        except BaseException as exc:            # noqa: BLE001
            caught.append(exc)
            raise
        probe_returns.append(out)
        return out

    def attach(exc, err, **kwargs):
        attached_exceptions.append(exc)
        return real_attach(exc, err, **kwargs)

    monkeypatch.setattr(doctor, "_mcp_probe", probe)
    monkeypatch.setattr(doctor, "_attach_stderr", attach)
    check = doctor.check_mcp_server(timeout=timeout)
    return check, doctor.format_report([check]), caught, probe_returns, \
        attached_exceptions


def _assert_withheld(check, report, caught):
    sentinel, reason = _SENTINEL, _REASON
    assert check.status == doctor.FAIL
    assert len(caught) == 1
    assert caught[0].__notes__ == [doctor._STDERR_WITHHELD]
    assert sentinel not in "\n".join(caught[0].__notes__)
    assert check.details[0] == (
        f"probe diagnostic: {doctor._STDERR_WITHHELD}"
    )
    assert sentinel not in report
    assert reason not in report


def test_mcp_stderr_before_initialize_is_withheld(monkeypatch, tmp_path):
    check, report, caught, _returns, _attached = _run_scripted(
        monkeypatch, tmp_path, "pre_init", f"RuntimeError: {_SENTINEL}")
    _assert_withheld(check, report, caught)
    assert type(caught[0]) is ValueError


@pytest.mark.parametrize("scenario", ["list_eof", "list_error"])
@pytest.mark.parametrize("stderr_text", [
    f"RuntimeError: {_SENTINEL}",
    f"RuntimeError: {_SENTINEL}\n{_REASON}",
])
def test_mcp_listing_eof_or_error_withholds_stderr(monkeypatch, tmp_path,
                                                   scenario, stderr_text):
    check, report, caught, _returns, _attached = _run_scripted(
        monkeypatch, tmp_path, scenario, stderr_text)
    _assert_withheld(check, report, caught)
    assert type(caught[0]) is ValueError


@pytest.mark.parametrize("stderr_text", [
    f"RuntimeError: {_SENTINEL}",
    f"RuntimeError: {_SENTINEL}\n{_REASON}",
])
def test_mcp_listing_timeout_withholds_stderr(monkeypatch, tmp_path,
                                              stderr_text):
    check, report, caught, _returns, _attached = _run_scripted(
        monkeypatch, tmp_path, "list_hang", stderr_text, timeout=3)
    _assert_withheld(check, report, caught)
    assert type(caught[0]) is TimeoutError


@pytest.mark.parametrize("scenario", ["call_iserror", "call_error",
                                      "call_eof", "call_hang"])
def test_mcp_tool_call_failure_quotes_nothing(monkeypatch, tmp_path,
                                              scenario):
    sentinel, reason = _SENTINEL, _REASON
    check, report, caught, probe_returns, attached_exceptions = \
        _run_scripted(monkeypatch, tmp_path, scenario,
                      f"RuntimeError: {sentinel}\n{reason}", timeout=3)
    assert check.status == doctor.FAIL
    assert check.summary == (
        "server started, but the MCP ledger-read probe failed"
    )
    assert probe_returns == [(sorted(doctor.MCP_TOOLS), False)]
    assert caught == []
    assert attached_exceptions == []
    assert sentinel not in report
    assert reason not in report
    assert doctor._STDERR_WITHHELD not in report
    assert "probe diagnostic:" not in report


def test_the_doctor_probes_the_server_the_real_manifest_declares():
    """The doctor's copy of the manifest key, pinned to the manifest."""
    import json as _json
    from pathlib import Path as _Path

    manifest = _json.loads(
        (_Path(__file__).resolve().parent.parent / ".codex-plugin"
         / "plugin.json").read_text(encoding="utf-8"))
    assert set(manifest["mcpServers"]) == {doctor.MCP_SERVER_NAME}


def test_the_doctors_tool_list_matches_the_servers(monkeypatch):
    """Two copies, one fact. The doctor cannot import `mcp/server.py` (not a
    package, and importing it would need the SDK), so it restates the list —
    and this is what stops the two drifting."""
    import server
    assert tuple(doctor.MCP_TOOLS) == tuple(server.EXPOSED_TOOLS)


def test_run_checks_gives_the_mcp_check_its_own_timeout_budget(
        monkeypatch, isolated_env):
    """`--timeout`/`DAEMON_TIMEOUT` is the daemon round-trip budget (2.0s);
    the MCP check needs `MCP_TIMEOUT` (20.0s) because it starts an
    interpreter and opens the ledger, which does not fit in the daemon's
    window. A registration that threads the daemon's `timeout` into
    `check_mcp_server` makes a correctly wired server look broken — exactly
    what `MCP_TIMEOUT`'s docstring warns a doctor must not do ("a doctor
    that times out on a working server teaches users to ignore it")."""
    seen = []

    def fake_check_mcp_server(timeout=doctor.MCP_TIMEOUT):
        seen.append(timeout)
        return doctor.Check("MCP server", doctor.OK, "stub")

    monkeypatch.setattr(doctor, "check_mcp_server", fake_check_mcp_server)
    doctor.run_checks(timeout=0.2)
    assert seen == [doctor.MCP_TIMEOUT]


# --------------------------------------------------------------------- #
# #54 Phase 3: the structured version-2 summary
# --------------------------------------------------------------------- #

def test_doctor_validates_v2_summary_strictly(tmp_path):
    from accounting_fakes import (
        crossed, event, prepared_ledger, start_v2, unresolved_subject,
    )

    from privacy_hud.accounting import ACCOUNTING_NOTE, ACCOUNTING_SCORE_LABEL

    led = prepared_ledger(tmp_path / "ledger.db")
    try:
        complete = start_v2(led)
        led.record_observation(crossed(complete), [event()])
        partial = start_v2(led)
        led.record_observation(crossed(partial), [event(unresolved_subject())])
        valid = json.loads(json.dumps(led.summary(complete).as_dict()))
        nullable = json.loads(json.dumps(led.summary(partial).as_dict()))
    finally:
        led.conn.close()
    assert valid["percent"] == 8 and valid["percentage_unavailable_reasons"] == []
    assert nullable["percent"] is None
    assert nullable["percentage_unavailable_reasons"] == ["unresolved_subjects"]
    assert doctor._is_summary(valid)
    assert doctor._is_summary(nullable)
    assert doctor._V2_SUMMARY_LABEL == ACCOUNTING_SCORE_LABEL
    assert doctor._V2_SUMMARY_NOTE == ACCOUNTING_NOTE

    def broken(base, **changes):
        out = dict(base)
        for key, value in changes.items():
            if value is KeyError:
                del out[key]
            else:
                out[key] = value
        return out

    invalid = [
        broken(valid, accounting_version=True),
        broken(valid, observations=True),
        broken(valid, event_rows=1.0),
        broken(valid, denials_issued=-1),
        broken(valid, confirmed_points=float("nan")),
        broken(valid, confirmed_points=-1.0),
        broken(valid, budget_cap=0.0),
        broken(valid, percent=True),
        broken(valid, percent=101),
        broken(valid, percent=None),
        broken(nullable, percent=0),
        broken(valid, reads_stopped=KeyError),
        broken(valid, extra=1),
        broken(valid, score_label="legacy permitted-crossing score"),
        broken(valid, accounting_note="Confirmed."),
        broken(valid, accounting_status="legacy"),
        broken(valid, profile_id="not-a-profile"),
        broken(nullable, percentage_unavailable_reasons=["surprise"]),
        broken(nullable, percentage_unavailable_reasons=[
            "unresolved_subjects", "unresolved_subjects"]),
        broken(nullable, percentage_unavailable_reasons=[
            "unresolved_subjects", "unresolved_actions"]),
        broken(nullable, percentage_unavailable_reasons="unresolved_subjects"),
        broken(nullable, accounting_status="unavailable"),
        broken(nullable, percentage_unavailable_reasons=[
            "accounting_unavailable", "unresolved_subjects"]),
    ]
    for case in invalid:
        assert not doctor._is_summary(case), case
