"""Doctor reads settings at the data root without opening a ledger."""

from __future__ import annotations

import json

import pytest

from privacy_hud import codex, doctor, runtime
from privacy_hud.settings import SETTINGS_NAME


@pytest.fixture(autouse=True)
def isolated_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.delenv("PLUGIN_DATA", raising=False)


@pytest.mark.parametrize("fenced", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_read_guard_reads_the_root_setting(tmp_path, monkeypatch, fenced, enabled):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("PLUGIN_DATA", str(data))
    if fenced:
        # Directory fence only: no SQLite file is created or read.
        (data / codex.LEDGER_NAME).mkdir()
        nested = data / "ledger"
        nested.mkdir()
        (nested / SETTINGS_NAME).write_text(
            json.dumps({"deny_read": not enabled}), encoding="utf-8")
    (data / SETTINGS_NAME).write_text(
        json.dumps({"deny_read": enabled}), encoding="utf-8")

    check = doctor.check_read_guard()

    assert check.status == doctor.OK
    assert check.summary == (
        "on — sensitive-path reads denied" if enabled
        else "off (default) — reads are not blocked")


@pytest.mark.parametrize("body", [None, "{", '{"deny_read": "true"}'])
def test_read_guard_keeps_default_for_missing_or_invalid_settings(
        tmp_path, monkeypatch, body):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("PLUGIN_DATA", str(data))
    if body is not None:
        (data / SETTINGS_NAME).write_text(body, encoding="utf-8")

    check = doctor.check_read_guard()

    assert check.status == doctor.OK
    assert check.summary == "off (default) — reads are not blocked"


def test_read_guard_handles_unresolved_data(monkeypatch):
    monkeypatch.setattr(runtime, "plugin_data_dir", lambda: None)
    expected = doctor._plugin_data_unset_check("Read guard")

    check = doctor.check_read_guard()

    assert check.status == expected.status
    assert check.summary == expected.summary


def test_read_guard_uses_the_resolver_without_ledger_lookup(tmp_path, monkeypatch):
    data = tmp_path / "resolved"
    data.mkdir()
    (data / SETTINGS_NAME).write_text('{"deny_read": true}', encoding="utf-8")
    monkeypatch.setattr(runtime, "plugin_data_dir", lambda: data)

    def forbidden():
        pytest.fail("read-guard diagnosis must not resolve a ledger")

    monkeypatch.setattr(doctor, "_ledger_path", forbidden)

    assert doctor.check_read_guard().summary == \
        "on — sensitive-path reads denied"
