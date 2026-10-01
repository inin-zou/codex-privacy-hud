from __future__ import annotations

import os
import subprocess

import pytest

from privacy_hud import doctor

from forwarder_helpers import executable, forwarder_source

MARKER = "# codex-privacy-hud forwarder synthetic\n"
SAFETY = "# codex-privacy-hud forwarder safety: 1\n"
REMEDY = (
    "Re-run the normal installer from Privacy HUD 0.10.7 or newer "
    "with HOME set to the home that owns each reported forwarder. "
    "See README.md#install. --repair-runtime does not replace forwarders."
)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    commands = tmp_path / "commands"
    commands.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", str(commands))
    monkeypatch.chdir(tmp_path)

    def refuse(*args, **kwargs):
        raise AssertionError("forwarder diagnosis must not execute anything")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    return home, commands


def test_old_foreign_forwarder_is_warned(isolated):
    home, commands = isolated
    path = executable(
        commands / "codex", "#!/bin/sh\n" + MARKER + "exit 91\n"
    )
    before = path.read_bytes()
    check = doctor.check_codex_forwarder()
    assert check.name == "Codex forwarder"
    assert check.status == doctor.WARN
    assert check.summary == (
        "a Privacy HUD forwarder lacks the recursion-protection marker"
    )
    assert check.fixes == [REMEDY]
    assert path.read_bytes() == before


def test_home_forwarder_is_checked_when_not_on_path(isolated):
    home, commands = isolated
    executable(
        home / ".local/bin/codex",
        "#!/bin/sh\n" + MARKER + "exit 91\n",
    )
    assert doctor.check_codex_forwarder().status == doctor.WARN


def test_current_generated_forwarder_is_recognized(isolated):
    home, commands = isolated
    executable(commands / "codex", forwarder_source())
    check = doctor.check_codex_forwarder()
    assert check.status == doctor.OK
    assert check.summary == (
        "all detected Privacy HUD forwarders declare safety revision 1"
    )


def test_no_forwarder_is_not_an_install_failure(isolated):
    check = doctor.check_codex_forwarder()
    assert check.status == doctor.SKIP
    assert check.summary == "no Privacy HUD forwarder found"


def test_fifo_does_not_block(isolated):
    home, commands = isolated
    os.mkfifo(commands / "codex", 0o700)
    check = doctor.check_codex_forwarder()
    assert check.status == doctor.WARN
    assert check.summary == "a Codex candidate could not be inspected safely"


def test_marker_on_third_line_does_not_classify_official(isolated):
    home, commands = isolated
    executable(
        commands / "codex",
        "#!/bin/sh\n# unrelated launcher\n" + MARKER,
    )
    assert doctor.check_codex_forwarder().status == doctor.SKIP


def test_header_read_is_byte_bounded(isolated):
    home, commands = isolated
    executable(
        commands / "codex",
        "#!/bin/sh\n" + MARKER + "#" * 100_000 + "\n" + SAFETY,
    )
    assert doctor.check_codex_forwarder().status == doctor.WARN


def test_symlink_to_old_forwarder_is_warned(isolated, tmp_path):
    home, commands = isolated
    target = executable(
        tmp_path / "foreign/.local/bin/codex",
        "#!/bin/sh\n" + MARKER + "exit 91\n",
    )
    (commands / "codex").symlink_to(target)
    assert doctor.check_codex_forwarder().status == doctor.WARN
