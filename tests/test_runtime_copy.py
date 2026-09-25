# tests/test_runtime_copy.py
"""#66 Pair 7: what the diagnostic surfaces say, and what they refuse to say.

Four separate questions get four separate answers here, because one of
them passing has never established the others:

* **Runtime alignment** — is the daemon that is listening the build this
  plugin selected? A daemon that answers *something* is not a daemon that
  answers *for this build*, and before #66 the doctor could not tell the
  difference: any JSON object counted as a healthy round trip.
* **Provenance** — which tree did the running first-party code come out
  of? Not "which version does `importlib.metadata` report", which is a
  fact about the dependency environment and was the thing #66 exists to
  stop being trusted.
* **Snapshot lifecycle** — a reading published by a daemon that has since
  been replaced must not outlive it, and must not be re-stamped by its
  replacement. Snapshot v2 does not authenticate its producer (§A), so
  ownership is the publisher's own bookkeeping or it is nothing.
* **Copy** — every recovery verb in `runtime_messages` has to name
  something a user can actually run.

I1 runs through all of it: a diagnostic that printed a planted payload
back would be an exfiltration path with a friendly name.
"""
from __future__ import annotations

import json
import os
import shutil
import socketserver
import sys
import threading
import time
from pathlib import Path

import pytest

from privacy_hud import (
    ambient,
    codex,
    doctor,
    hud_snapshot,
    runtime_client,
    runtime_contract as contract,
    runtime_messages,
    runtime_repair as repair,
    runtime_storage as storage,
)
from legacy_fakes import legacy_summary
from runtime_helpers import shared_bundle, short_data_dir, write_receipt_v2

# The private-installation machinery is already written once, in the Pair 5
# suite; a second copy of "a bundle, a venv and a data directory" would be a
# second thing to keep true.
from test_runtime_repair import (  # noqa: E402
    Install,
    _no_installer_on_path,
    seed_ledger,
    stop_runtime,
)
from runtime_helpers import write_receipt_v1  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
SID = "0199e2e0-b10c-4000-8000-00000000cccc"


# --------------------------------------------------------------------- #
# a listener that is not the selected daemon
# --------------------------------------------------------------------- #

class _OneShot(socketserver.StreamRequestHandler):
    """Read one frame, write whatever the server was told to write."""

    def handle(self) -> None:
        line = self.rfile.readline()
        if not line:
            return
        try:
            self.server.seen.append(json.loads(line.decode("utf-8")))
        except ValueError:
            self.server.seen.append(None)
        if self.server.reply is not None:
            self.wfile.write(self.server.reply)


def _serve(sock_path: Path, reply: bytes | None):
    server = socketserver.ThreadingUnixStreamServer(str(sock_path), _OneShot)
    os.chmod(sock_path, 0o600)
    server.reply = reply
    server.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _stop(server, thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _mismatched_reply() -> bytes:
    """What a daemon of another build sends: a protocol-2 refusal.

    Well formed, and still not this build — which is exactly the state
    the alignment check exists to name.
    """
    return json.dumps({"v": contract.PROTOCOL_VERSION, "op": "hello",
                       "ok": False, "code": "runtime_mismatch"}).encode() + b"\n"


def _matching_reply(activation: contract.Activation) -> bytes:
    return runtime_client.encode_frame(
        runtime_client.hello_reply(activation, 0))


@pytest.fixture
def selected(tmp_path, monkeypatch):
    """A short `$PLUGIN_DATA` that selects the shared test bundle.

    Short because several of these tests bind a unix socket in it; the
    receipt is written before anything asks for an activation, since an
    activation is what a receipt is.
    """
    data = short_data_dir("phcopy")
    monkeypatch.setenv("PLUGIN_DATA", str(data))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.setenv("HF_HOME", str(tmp_path / "hf"))
    monkeypatch.delenv("HF_HUB_CACHE", raising=False)
    write_receipt_v2(data, bundle=shared_bundle(), python=sys.executable)
    yield data


@pytest.fixture
def install():
    """One throwaway installation, torn down with whatever it started."""
    inst = Install()
    try:
        yield inst
    finally:
        stop_runtime(inst.data)
        shutil.rmtree(inst.root, ignore_errors=True)


def _rendered(check) -> str:
    return "\n".join([check.summary, *check.details, *check.fixes])


# --------------------------------------------------------------------- #
# the daemon round trip
# --------------------------------------------------------------------- #

def test_doctor_rejects_arbitrary_json_daemon_reply(selected):
    """Any JSON object used to read as a healthy daemon.

    The probe sent protocol 1 and accepted "a dict came back", so a
    daemon of another build — or anything else holding the socket path —
    was reported as responsive. Under protocol 2 the only healthy answer
    is a hello naming this build and this activation epoch.
    """
    sock = codex.socket_path(selected)
    server, thread = _serve(sock, b'{"ok": true, "release": "0.8.0"}\n')
    try:
        check = doctor.check_daemon(timeout=2.0, pinned=True)
    finally:
        _stop(server, thread)

    assert check.status != doctor.OK
    assert check.fixes
    assert "0.8.0" not in _rendered(check), (
        "a release string from an unvalidated peer is a string that peer "
        "chose (I1)")


def test_doctor_accepts_only_a_matching_hello(selected):
    """The other half of the same rule: a real hello is accepted, and it
    is the only thing that is."""
    activation = contract.load_activation(selected)
    sock = codex.socket_path(selected)
    server, thread = _serve(sock, _matching_reply(activation))
    try:
        check = doctor.check_daemon(timeout=2.0, pinned=True)
    finally:
        _stop(server, thread)

    assert check.status == doctor.OK
    assert server.seen and runtime_client.is_valid_hello(server.seen[0])
    assert server.seen[0]["build_id"] == activation.identity.build_id
    assert server.seen[0]["activation_epoch"] == activation.epoch
    assert all(message.get("op") != "event" for message in server.seen), (
        "a diagnostic must not send an event to the thing it diagnoses")


# --------------------------------------------------------------------- #
# provenance and alignment
# --------------------------------------------------------------------- #

def test_doctor_reports_actual_bundle_origin(selected, monkeypatch):
    """Where the code came from, not what the environment calls itself.

    `_first_party_origin` and `_installed_distribution` are substituted
    for the same reason `_module_version` is: the real answers depend on
    the machine the suite runs on, and asserting on those would pass
    everywhere and prove nothing.
    """
    bundle = shared_bundle()
    monkeypatch.setattr(doctor, "_first_party_origin",
                        lambda: bundle / "src" / "privacy_hud")
    monkeypatch.setattr(doctor, "_installed_distribution",
                        lambda: ("0.7.1", Path("/opt/env/site-packages")))

    check = doctor.check_runtime_source()
    text = _rendered(check)

    assert check.status == doctor.OK
    expected = runtime_messages.DOCTOR_RUNTIME_SOURCE_OK.format(
        release=contract.RELEASE).split("\n")[1]
    assert expected in text
    assert runtime_messages.DOCTOR_OLD_DISTRIBUTION_UNUSED in text
    assert str(bundle) in text
    assert "0.7.1" not in check.summary, (
        "the summary is provenance; an installed distribution's version is "
        "not what selected the code")


def test_doctor_says_nothing_about_a_distribution_it_did_not_find(
        selected, monkeypatch):
    """The appended sentence is conditional on evidence (§D)."""
    bundle = shared_bundle()
    monkeypatch.setattr(doctor, "_first_party_origin",
                        lambda: bundle / "src" / "privacy_hud")
    monkeypatch.setattr(doctor, "_installed_distribution", lambda: None)

    check = doctor.check_runtime_source()

    assert check.status == doctor.OK
    assert runtime_messages.DOCTOR_OLD_DISTRIBUTION_UNUSED not in _rendered(
        check)


def test_doctor_detects_running_build_mismatch(selected):
    """A daemon that is not this build fails the alignment check, in §D's
    exact words, with a repair command that is a real command."""
    sock = codex.socket_path(selected)
    server, thread = _serve(sock, _mismatched_reply())
    try:
        check = doctor.check_runtime_alignment(timeout=2.0)
    finally:
        _stop(server, thread)

    assert check.status == doctor.FAIL
    expected = runtime_messages.DOCTOR_RUNTIME_MISMATCH.format(
        plugin_release=contract.RELEASE,
        daemon_release_or_unknown=runtime_messages.UNKNOWN_DAEMON_RELEASE,
        repair_command=repair.format_repair_command(shared_bundle(), selected),
    ).split("\n")
    rendered = _rendered(check).split("\n")
    assert [line.strip() for line in expected[1:]] == [
        line.strip() for line in rendered]


def test_doctor_alignment_passes_only_on_a_matching_hello(selected):
    activation = contract.load_activation(selected)
    sock = codex.socket_path(selected)
    server, thread = _serve(sock, _matching_reply(activation))
    try:
        check = doctor.check_runtime_alignment(timeout=2.0)
    finally:
        _stop(server, thread)

    assert check.status == doctor.OK
    assert runtime_messages.DOCTOR_RUNTIME_ALIGNMENT_OK.split("\n")[1] in \
        _rendered(check)


def test_doctor_mcp_probe_has_no_ledger_mutations(selected, tmp_path,
                                                  monkeypatch):
    """The MCP check launches a server against the user's real data
    directory. It must read and never write — and it must name the data
    directory rather than the ledger's parent, which after the storage
    transition is `$PLUGIN_DATA/ledger/` and holds no settings, socket or
    receipt at all.
    """
    from test_doctor import _write_fake_plugin

    # A repaired layout: the historical pathname is the fence, so the
    # ledger's parent is `$PLUGIN_DATA/ledger/` and holds no receipt,
    # socket or settings file at all.
    (selected / "ledger.db").mkdir()
    ledger_path = codex.ledger_path(selected)
    assert ledger_path.parent != selected
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_bytes(b"not a real ledger, and not to be touched")
    before = ledger_path.read_bytes()
    before_stat = ledger_path.stat().st_mtime_ns

    plugin = tmp_path / "cache" / "mp" / "codex-privacy-hud" / "0.8.0"
    plugin.mkdir(parents=True)
    _write_fake_plugin(plugin, tools=sorted(doctor.MCP_TOOLS))
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: plugin)

    seen_env: dict[str, str] = {}
    real_probe = doctor._mcp_probe

    def recording(command, cwd, env, timeout):
        seen_env.update(env)
        return real_probe(command, cwd, env, timeout)

    monkeypatch.setattr(doctor, "_mcp_probe", recording)
    doctor.check_mcp_server(timeout=20.0)

    assert Path(seen_env["PLUGIN_DATA"]) == selected, (
        "the probe must name the plugin-data directory, not the active "
        "store's parent"
    )
    assert ledger_path.read_bytes() == before
    assert ledger_path.stat().st_mtime_ns == before_stat
    assert not (selected / "ledger" / "active.db-wal").exists()


# --------------------------------------------------------------------- #
# snapshot lifecycle
# --------------------------------------------------------------------- #

def test_repair_retires_old_snapshots_before_ready(install, monkeypatch):
    """A reading published by the daemon repair just replaced must not
    survive the cutover, and must be gone before repair reports ready.

    Snapshot v2 carries no producer identity, so a file left behind keeps
    rendering as though it described the running runtime.
    """
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    publisher = hud_snapshot.HudPublisher(install.data)
    publisher.publish(SID, summary=legacy_summary(28, 2), unverified=False)
    publisher.mark_daemon(unattributed_gaps=False)
    # Age the marker past `STALE_AFTER`: a young one means a live publisher
    # and correctly refuses the cutover (that is Pair 5's rule, tested
    # there). What is under test here is what happens to the readings once
    # the old publisher really has stopped.
    marker = hud_snapshot.hud_dir(install.data) / "_daemon.json"
    marker.write_text(json.dumps({
        **json.loads(marker.read_text(encoding="utf-8")),
        "updated_at": time.time() - 3600}), encoding="utf-8")
    assert hud_snapshot.read_snapshot(install.data, SID) is not None

    order: list[tuple[str, bool]] = []
    real_record = storage.record_stage

    def recording(data_dir, transition_id, stage, preserved):
        order.append((stage, hud_snapshot.read_snapshot(
            Path(data_dir), SID, ignore_staleness=True) is not None))
        real_record(data_dir, transition_id, stage, preserved)

    monkeypatch.setattr(storage, "record_stage", recording)
    with _no_installer_on_path(install.root / "offline-bin"):
        result = repair.repair_runtime(install.bundle, install.data,
                                       allow_degraded=True)

    stages = [stage for stage, _ in order]
    assert "snapshots_retired" in stages and "ready" in stages
    assert stages.index("snapshots_retired") < stages.index("ready")
    assert dict(order)["ready"] is False, (
        "the old reading was still readable when repair reported ready")
    assert hud_snapshot.read_snapshot(install.data, SID,
                                      ignore_staleness=True) is None

    journal = storage.read_journal(install.data)
    assert journal is not None
    retired = storage.retired_dir(install.data, journal["transition_id"])
    assert (retired / "hud" / f"{SID}.json").is_file(), (
        "retired, not deleted: the same preservation rule the ledger gets")
    assert (retired / "hud" / "_daemon.json").is_file(), (
        "the old publisher's daemon marker is a reading too")
    assert result.preserved_existing is True


def test_restart_does_not_heartbeat_inherited_reading(tmp_path):
    """A publisher re-stamps what it published, and nothing else.

    A daemon restarted in a data directory that still holds an older
    daemon's snapshot would otherwise keep that reading alive forever:
    `heartbeat` refreshed anything that parsed, which is a claim about
    numbers this process never derived.
    """
    first = hud_snapshot.HudPublisher(tmp_path)
    first.publish(SID, summary=legacy_summary(28, 2), unverified=False)
    path = hud_snapshot.snapshot_path(tmp_path, SID)
    inherited = json.loads(path.read_text(encoding="utf-8"))

    successor = hud_snapshot.HudPublisher(tmp_path)
    successor.heartbeat([SID])

    assert json.loads(path.read_text(encoding="utf-8")) == inherited

    # And the publisher that did write it still keeps its own alive.
    first.heartbeat([SID])
    assert json.loads(path.read_text(encoding="utf-8"))["updated_at"] > \
        inherited["updated_at"]


def test_snapshot_v2_goldens_remain_byte_identical():
    """#66 changes runtime selection, not the reading contract (§A).

    The patched Codex reader embeds a byte copy of this file, so a
    reformat here silently desynchronizes two surfaces that must agree.
    """
    import hashlib

    golden = (REPO / "tests" / "matrix" / "hud_reading_golden.json").read_bytes()
    schema = (REPO / "tests" / "matrix" /
              "hud_snapshot.schema.json").read_bytes()
    assert hud_snapshot.SNAPSHOT_VERSION == 2
    assert contract.SNAPSHOT_VERSIONS == (2,)
    assert hashlib.sha256(golden).hexdigest() == \
        _recorded_digest("hud_reading_golden.json")
    assert hashlib.sha256(schema).hexdigest() == \
        _recorded_digest("hud_snapshot.schema.json")


#: Digests recorded when #66 began, from `main` at 0.7.9. Regenerating one
#: of these is a decision to change a published reader contract, which #66
#: does not make.
_GOLDEN_DIGESTS = {
    "hud_reading_golden.json":
        "6d70c642b85d8901e3c5717d9ba2e5f34ecf8a614ac961c2ff958d2d4ce6fe3a",
    "hud_snapshot.schema.json":
        "c7055b4bce5d8e21e6c80786ab5210ba36cddd44d7c2f5d1dc5b2a13f2367c51",
}


def _recorded_digest(name: str) -> str:
    return _GOLDEN_DIGESTS[name]


# --------------------------------------------------------------------- #
# the ambient pane
# --------------------------------------------------------------------- #

def test_ambient_runtime_refusal_suppresses_numeric_line(selected):
    """A percentage from a runtime nothing verified is worse than no
    line: the pane says the runtime does not match and draws no number.
    """
    hud_snapshot.HudPublisher(selected).publish(
        SID, summary=legacy_summary(28, 2), unverified=False)
    activation = contract.load_activation(selected)
    pin = ambient._SessionPin(SID)

    sock = codex.socket_path(selected)
    server, thread = _serve(sock, _mismatched_reply())
    try:
        wide = ambient.safe_line(pin, 80, activation=activation)
        narrow = ambient.safe_line(ambient._SessionPin(SID), 20,
                                   activation=activation)
    finally:
        _stop(server, thread)

    assert wide == "Privacy — runtime mismatch; run $privacy repair"
    assert narrow == runtime_messages.AMBIENT_NARROW_FALLBACK
    assert "28" not in wide and "%" not in wide
    assert "%" not in narrow

    # Nothing listening at all is the ordinary between-sessions state, not
    # a mismatch: the reading still renders.
    normal = ambient.safe_line(ambient._SessionPin(SID), 80,
                               activation=activation)
    assert normal is not None and "28" in normal


def test_runtime_mismatch_does_not_fabricate_accounting_zero(selected):
    """§A: a runtime failure is not accounting version 0.

    "No session on record" means the ledger holds no reading. A daemon of
    the wrong build is a different fact about a different subject, and
    publishing the unrecorded sentinel for it would tell a user their
    session was clean.
    """
    hud_snapshot.HudPublisher(selected).publish(
        SID, summary=legacy_summary(28, 2), unverified=False)
    path = hud_snapshot.snapshot_path(selected, SID)
    before = path.read_bytes()
    activation = contract.load_activation(selected)

    sock = codex.socket_path(selected)
    server, thread = _serve(sock, _mismatched_reply())
    try:
        line = ambient.safe_line(ambient._SessionPin(SID), 80,
                                 activation=activation)
        check = doctor.check_runtime_alignment(timeout=2.0)
    finally:
        _stop(server, thread)

    assert line == "Privacy — runtime mismatch; run $privacy repair"
    assert "No session on record" not in line
    assert "No session on record" not in _rendered(check)
    assert "—%" not in line
    assert path.read_bytes() == before, (
        "a runtime check must not rewrite a reading it did not derive")
    assert json.loads(before.decode("utf-8"))["accounting_version"] == 1


# --------------------------------------------------------------------- #
# copy, and what it promises
# --------------------------------------------------------------------- #

def test_runtime_copy_contains_no_unimplemented_action(selected):
    """Every recovery verb in `runtime_messages` maps to a command.

    CLAUDE.md §5: an action user-facing copy tells a user to take is
    traced to the surface that performs it, through the call and not from
    a function existing. The block message that shipped for six weeks
    telling users to "minimize, or allow once" is what this is for.
    """
    bundle = shared_bundle()
    repair_command = repair.format_repair_command(bundle, selected)
    ambient_command = repair.format_ambient_command(bundle, selected)

    rendered = []
    for name in dir(runtime_messages):
        value = getattr(runtime_messages, name)
        if name.startswith("_") or not isinstance(value, str):
            continue
        rendered.append(value.format(
            release=contract.RELEASE, plugin_release=contract.RELEASE,
            daemon_release_or_unknown="unknown",
            repair_command=repair_command, ambient_command=ambient_command))
    text = "\n".join(rendered)

    # The two commands the copy tells a user to run are real: the repair
    # command names this bundle's installer and its repair mode, and the
    # ambient command names the bundle's own bootstrap subcommand.
    assert repair_command in text and ambient_command in text
    assert (bundle / "install.sh").is_file()
    assert "--repair-runtime" in repair_command
    assert (bundle / "scripts" / "runtime.py").is_file()
    assert ambient_command.endswith("ambient --watch")

    # Nothing else is phrased as an instruction to run something we do not
    # ship. `$privacy repair` is the skill branch; it is the only
    # `$privacy` subcommand the runtime copy names.
    named = {line.split("$privacy ", 1)[1].split()[0].rstrip(".,")
             for line in text.split("\n") if "$privacy " in line}
    assert named == {"repair"}

    # No "allow once", and no recall (I5).
    lowered = text.lower()
    for banned in ("allow once", "undo", "revoke", "remove from context",
                   "your data is protected", "100% secure"):
        assert banned not in lowered
    # No placeholder survived into rendered output (§D).
    assert "{" not in text and "}" not in text
    assert "/absolute/path/to" not in text


def test_diagnostics_do_not_persist_payload_canary(install):
    """A planted value delivered over the hook protocol reaches no
    receipt, journal, snapshot or diagnostic file (I1).

    The daemon is the real one, started by repair, and the event is
    delivered the way a hook delivers it — so this is the actual path a
    payload takes, not a reconstruction of it.
    """
    canary = "CANARY-8f31d0c4e5a6-PAYLOAD"
    seed_ledger(install.data)
    write_receipt_v1(install.data, python=install.python)
    with _no_installer_on_path(install.root / "offline-bin"):
        repair.repair_runtime(install.bundle, install.data,
                              allow_degraded=True)

    activation = contract.load_activation(install.data)
    with runtime_client.connect_runtime(install.data, activation=activation,
                                        timeout=20.0) as connection:
        connection.request(runtime_client.OP_EVENT, {"payload": {
            "hook_event_name": "PreToolUse",
            "session_id": SID,
            "tool_name": "Bash",
            "tool_input": {"command": f"echo {canary}"},
        }})

    stop_runtime(install.data)
    hits = []
    for path in sorted(install.data.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        if canary.encode("utf-8") in blob:
            hits.append(str(path.relative_to(install.data)))
    assert hits == []
