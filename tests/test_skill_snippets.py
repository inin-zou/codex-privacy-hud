# tests/test_skill_snippets.py
"""The bash in `skills/privacy/SKILL.md` runs, and says what the skill
says it says.

Those blocks are code an agent executes verbatim in a user's session, and
nothing else ever ran them: before #66 they were python heredocs that
opened `$PLUGIN_DATA/ledger.db` directly, and on a repaired installation
that pathname is a directory. They are now invocations of the bundle's
own bootstrap, extracted from the skill exactly as written and run under
bash against a seeded installation, with `python3` resolving to this
interpreter and `PLUGIN_ROOT` pointing at a real bundle — the same two
things the skill relies on in a real session.

`tests/test_issue66_contract.py` asserts that every block *runs*. This
file asserts what each one *produces*, which is the half a smoke test
cannot cover: a renamed field or a changed rendering breaks `$privacy`
the first time someone types it, and passes every other test here.

A new block in the skill must get a case here; the inventory test fails
until it does.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from privacy_hud.matrix.loader import load_matrix
from privacy_hud.origin import OriginKind, origin_phrase
from runtime_helpers import (
    release_leases,
    shared_bundle,
    short_data_dir,
    write_receipt_v2,
    writer_ledger,
)

REPO = Path(__file__).resolve().parents[1]
SKILL_MD = REPO / "skills" / "privacy" / "SKILL.md"

#: Each block is identified by the bootstrap subcommand only it runs, so
#: reordering or rewording the skill's prose does not break the lookup.
MARKERS = {
    "audit": "\n  audit ",
    "detail": "\n  detail ",
    "ui": "\n  ui ",
    "hud": "\n  hud ",
    "read": "\n  read status",
    "repair": "repair --print-command",
    "setup": "install.sh",
    "preamble": 'HUD=(python3 "$BUNDLE/scripts/runtime.py"',
}


def _bash_blocks() -> list[str]:
    text = SKILL_MD.read_text(encoding="utf-8")
    return re.findall(r"```bash\n(.*?)```", text, flags=re.S)


def _block(name: str) -> str:
    found = [b for b in _bash_blocks() if MARKERS[name] in b]
    assert len(found) == 1, (
        f"expected one SKILL.md block containing {MARKERS[name]!r}, "
        f"found {len(found)}")
    return found[0]


@pytest.fixture
def env(tmp_path):
    """A seeded installation: a real bundle, a receipt selecting it, and
    a ledger with one exposed row."""
    bundle = shared_bundle()
    data = short_data_dir("phsk")
    ledger = writer_ledger(data / "ledger.db", load_matrix(), data_dir=data)
    ledger.start_session("s1", cwd="/r", model="gpt-5")
    ledger.record("s1", turn_id="t1", kind="exposed", data_type="email",
                  source="support.log", destination="model_context",
                  value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
                  tool_name="Read", protection=None)
    ledger.conn.close()
    release_leases()
    write_receipt_v2(data, bundle=bundle, python=sys.executable)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").symlink_to(sys.executable)
    environment = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "PLUGIN_ROOT": str(bundle),
        "PLUGIN_DATA": str(data),
        "SESSION_ID": "s1",
        "EVENT_ID": "1",
        # Nothing here may read the real Codex home.
        "CODEX_HOME": str(tmp_path / "codex-home"),
    }
    environment.pop("PYTHONPATH", None)
    return environment


def _run(block: str, env: dict, timeout: float = 300.0):
    return subprocess.run(["bash", "-c", block], capture_output=True,
                          text=True, env=env, timeout=timeout)


# --------------------------------------------------------------------- #
# inventory
# --------------------------------------------------------------------- #

def test_every_bash_block_has_a_case():
    blocks = _bash_blocks()
    assert blocks, "SKILL.md declares no commands"
    matched = {id(b) for name in MARKERS for b in blocks if MARKERS[name] in b}
    unmatched = [b for b in blocks if id(b) not in matched]
    assert unmatched == [], unmatched


def test_no_block_opens_the_ledger_or_imports_the_package():
    """The two things the old blocks did, and the two reasons they broke.

    A heredoc that imported `privacy_hud` chose a package by `sys.path`,
    which is what #66 exists to stop; one that joined `ledger.db` onto
    the data directory opened the fence on a repaired installation.
    """
    for block in _bash_blocks():
        assert "ledger.db" not in block
        assert "import privacy_hud" not in block
        assert "sys.path" not in block
        assert "<<'PY'" not in block


# --------------------------------------------------------------------- #
# what each block produces
# --------------------------------------------------------------------- #

def test_audit_block_prints_the_table_and_one_resolution(env):
    out = _run(_block("audit"), env)
    assert out.returncode == 0, out.stderr
    lines = out.stdout.strip().splitlines()
    resolution = json.loads(lines[-1])
    assert resolution["session_id"] == "s1"
    assert resolution["basis"] in ("explicit", "active", "started_at")
    assert resolution["runtime_mismatch"] is False
    assert "Disclosure" in out.stdout or "legacy" in out.stdout
    assert "support.log" in out.stdout


def test_audit_block_resolves_without_an_explicit_id(env):
    """`$privacy` with no id resolves one; the skill carries that id into
    every later step rather than resolving a second time."""
    out = _run(_block("audit"), {**env, "SESSION_ID": ""})
    assert out.returncode == 0, out.stderr
    resolution = json.loads(out.stdout.strip().splitlines()[-1])
    assert resolution["session_id"] == "s1"


def test_detail_block_prints_one_row(env):
    out = _run(_block("detail"), env)
    assert out.returncode == 0, out.stderr
    assert "email" in out.stdout.lower()
    assert origin_phrase(OriginKind.PATH, "support.log") in out.stdout \
        or "support.log" in out.stdout


def test_hud_block_prints_a_state(env):
    out = _run(_block("hud"), env)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["state"] in ("shown", "hidden", "stale",
                                               "absent")


def test_read_block_prints_the_setting(env):
    out = _run(_block("read"), env)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["deny_read"] is False


def test_read_block_says_so_when_the_setting_cannot_be_written(env):
    """The word printed is what the setting still says, not what was
    asked for — so an unwritable settings file is reported, never
    silently swallowed."""
    data = Path(env["PLUGIN_DATA"])
    data.chmod(0o500)
    try:
        block = _block("read").replace("read status", "read on")
        out = _run(block, env)
        assert out.returncode == 0, out.stderr
        answer = json.loads(out.stdout)
        assert answer["deny_read"] is False, (
            "the guard is off, which is what the file still says")
        assert answer.get("error")
    finally:
        data.chmod(0o700)


def test_repair_block_prints_the_recovery_command(env):
    from privacy_hud import runtime_messages, runtime_repair

    out = _run(_block("repair"), env)
    assert out.returncode == 0, out.stderr
    expected = runtime_messages.REPAIR_COMMAND_OUTPUT.format(
        repair_command=runtime_repair.format_repair_command(
            Path(env["PLUGIN_ROOT"]).resolve(),
            Path(env["PLUGIN_DATA"])))
    assert out.stdout.strip() == expected
    assert "--repair-runtime" in out.stdout
    assert "It does not install or replace a patched Codex binary." in \
        out.stdout


def test_setup_block_names_this_bundles_installer(env):
    out = _run(_block("setup"), env)
    assert out.returncode == 0, out.stderr
    printed = out.stdout.strip()
    assert printed == f"sh {Path(env['PLUGIN_ROOT']) / 'install.sh'} --yes"
    assert Path(printed.split()[1]).is_file()
    assert "ls -d" not in _block("setup")


def test_ui_block_prints_one_loopback_url(env):
    import signal
    import threading

    proc = subprocess.Popen(["bash", "-c", _block("ui")],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env, start_new_session=True)

    def stop() -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass

    watchdog = threading.Timer(120.0, stop)
    watchdog.start()
    try:
        url = proc.stdout.readline().strip()
        assert url.startswith("http://127.0.0.1:")
        assert "session_id=s1" in url
    finally:
        watchdog.cancel()
        stop()
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()


# --------------------------------------------------------------------- #
# what the prose promises
# --------------------------------------------------------------------- #

def test_the_skill_describes_the_source_rules_that_actually_ship():
    """The two origin rule types, and no third one.

    `block_source` was withdrawn in #38; a skill that still offered it
    would be telling a user to save a rule `apply_policy` refuses.
    """
    text = SKILL_MD.read_text(encoding="utf-8")
    assert "block_path" in text and "block_command" in text
    assert "block_source" in text and "refuses the withdrawn" in text


def test_the_skill_does_not_tell_the_model_to_announce_enforcement():
    """The instruction that made the model repeat the overclaim.

    SKILL.md used to end this bullet "It is correct to tell the user the
    rule is now enforced, not merely recorded." — a direct instruction to
    assert the thing #49 item 2 is about. The model is the surface the
    user actually hears, so an honest API reply with this line still in
    the skill would have changed nothing they see.
    """
    text = SKILL_MD.read_text(encoding="utf-8")
    assert "now enforced, not merely recorded" not in text
    assert "Say the rule is **saved**" in text
