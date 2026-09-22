# tests/test_skill_snippets.py
"""The Python in `skills/privacy/SKILL.md` runs.

Those heredocs are code an agent executes verbatim in a user's session, but
nothing else ever ran them: a renamed `mcp_tools` function or a changed
`render.audit` signature would pass every other test and break `$privacy`
the first time someone typed it. So each block is extracted from the skill
file exactly as written and run under bash against a seeded ledger, with
`python3` resolving to this interpreter and `PLUGIN_ROOT` pointing at this
checkout — the same two things the skill relies on in a real session.

A new heredoc in the skill must get a case here; the inventory test fails
until it does.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.origin import OriginKind, origin_phrase

REPO = Path(__file__).resolve().parents[1]
SKILL_MD = REPO / "skills" / "privacy" / "SKILL.md"

# Each block is identified by a call only it makes, so reordering or
# rewording the skill's prose does not break the lookup.
MARKERS = {
    "resolve": "mcp_tools.resolve_audit_session(",
    "audit": "render.audit(",
    "detail": "render.detail(",
    "hud": "mcp_tools.hud_set_hidden(",
    "read": "mcp_tools.read_guard_status(",
}


def _python_blocks() -> list[str]:
    text = SKILL_MD.read_text(encoding="utf-8")
    blocks = re.findall(r"```bash\n(.*?)```", text, flags=re.S)
    return [b for b in blocks if "<<'PY'" in b]


def _block(name: str) -> str:
    found = [b for b in _python_blocks() if MARKERS[name] in b]
    assert len(found) == 1, f"expected one SKILL.md block calling {MARKERS[name]}"
    return found[0]


@pytest.fixture
def env(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    ledger = Ledger(data / "ledger.db", load_matrix())
    ledger.start_session("s1", cwd="/r", model="gpt-5")
    ledger.record("s1", turn_id="t1", kind="exposed", data_type="email",
                  source="support.log", destination="model_context",
                  value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
                  tool_name="Read", protection=None)
    ledger.conn.close()

    # `python3` in the skill's shell must be an interpreter that can import
    # the package's stdlib-only modules; pin it to the one running the tests.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").symlink_to(sys.executable)

    return {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "PLUGIN_ROOT": str(REPO),
        "PLUGIN_DATA": str(data),
        # Nothing here should read the real Codex home; make sure it cannot.
        "HOME": str(tmp_path / "home"),
        "CODEX_HOME": str(tmp_path / "codex-home"),
    }


def _run(block: str, env: dict, **extra: str) -> str:
    proc = subprocess.run(["bash", "-c", block], env={**env, **extra},
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_every_python_block_has_a_case():
    covered = set(MARKERS.values())
    uncovered = [b.splitlines()[0] for b in _python_blocks()
                 if not any(m in b for m in covered)]
    assert not uncovered, f"SKILL.md blocks with no test here: {uncovered}"
    assert len(_python_blocks()) == len(MARKERS)


def test_the_skill_describes_the_source_rules_that_actually_ship():
    """The skill is read by the model that is looking at the screen, so a
    claim in it about that screen has to be true of what `render.detail()`
    prints. It told the model there was no source-level action while the
    renderer was printing one (#40), i.e. that the button on its own screen
    did nothing. Pinned against the renderer's own labels, not retyped."""
    text = SKILL_MD.read_text(encoding="utf-8")

    for kind in (OriginKind.PATH, OriginKind.COMMAND):
        # "read from {}" / "from `{}` output", with the origin left out:
        # the skill describes the shape, a real row fills in the name.
        wording = origin_phrase("{}", kind).split("{}")[0].strip()
        assert f"Block values {wording}" in text

    for rule_type in ("block_path", "block_command"):
        assert rule_type in text

    # The withdrawn action, and the false premise it rested on.
    assert "Block this source" not in text
    assert "no rule can name a source" not in text

    # Known limit 10: origin rules match the whole value, normalised.
    # Matching requires detection on ingress and again on egress; saving
    # a rule does not establish that it will match a later call.
    #
    # This asserted `"byte-identical" in text` until #49 item 7, which is
    # the third test in this repository found enforcing a claim the code
    # contradicts. Matching keys on an HMAC of `value.strip().lower()`
    # (`mask.py:21`), so the matching set is WIDER than a byte comparison.
    # The skill is the surface that speaks for the tool at runtime, and a
    # test pinning its wording is the last place a stale claim should be
    # able to hide.
    # Short enough not to span a line wrap: SKILL.md is hand-wrapped prose,
    # and the first version of this assertion looked for a phrase that a
    # newline ran through.
    assert "whole value, normalised" in text
    assert "byte-identical" not in text


def test_resolve_block_names_the_session(env):
    out = _run(_block("resolve"), env)
    # No daemon in the test, so the skill's documented fallback applies.
    assert "session_id: s1" in out
    assert "basis: started_at" in out


def test_audit_block_prints_the_table(env):
    out = _run(_block("audit"), env,
               SESSION_ID="s1", BASIS="started_at", ALSO_ACTIVE="")
    assert "Privacy Audit" in out
    # BASIS reached the header: no daemon named the session current.
    assert "Most recently started session" in out
    assert "Email ×1        support.log  model_context  [EXPOSED]" in out


def test_detail_block_prints_one_row(env):
    with sqlite3.connect(Path(env["PLUGIN_DATA"]) / "ledger.db") as conn:
        (event_id,) = conn.execute(
            "SELECT id FROM events WHERE session_id = 's1'").fetchone()
    out = _run(_block("detail"), env, SESSION_ID="s1", EVENT_ID=str(event_id))
    assert "Email ×1\nsupport.log → model_context" in out


def test_hud_block_prints_one_state_word(env):
    out = _run(_block("hud"), env, SESSION_ID="s1")
    assert out.strip() in {"shown", "hidden", "stale", "absent"}


def test_read_block_prints_on_or_off(env):
    # The block ships with `on` filled in, the way the `hud` block does, so
    # running it verbatim turns the guard on and says so in one word. No
    # second line: this env's PLUGIN_DATA is writable.
    out = _run(_block("read"), env)
    assert out.splitlines() == ["on"]
    settings = Path(env["PLUGIN_DATA"]) / "settings.json"
    assert json.loads(settings.read_text())["deny_read"] is True


def test_read_block_says_so_when_the_setting_cannot_be_written(env, tmp_path):
    """The failure the user must not meet as a traceback: the word printed
    is what the setting still says, and the line after it says the write
    did not land."""
    data = Path(env["PLUGIN_DATA"])
    data.chmod(0o500)
    try:
        out = _run(_block("read"), {**env})
    finally:
        data.chmod(0o700)
    first, rest = out.splitlines()[0], out.splitlines()[1:]
    assert first == "off"
    assert rest and "unchanged" in rest[0]


def test_the_skill_does_not_tell_the_model_to_announce_enforcement():
    """The instruction that made the model repeat the overclaim.

    SKILL.md used to end this bullet "It is correct to tell the user the
    rule is now enforced, not merely recorded." — a direct instruction to
    assert the thing #49 item 2 is about. The model is the surface the user
    actually hears, so an honest API reply with this line still in the skill
    would have changed nothing they see.
    """
    text = (REPO / "skills" / "privacy" / "SKILL.md").read_text(encoding="utf-8")
    assert "now enforced, not merely recorded" not in text
    assert "Say the rule is **saved**" in text
