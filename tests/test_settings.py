import json

from privacy_hud.settings import Settings


def test_blocking_is_off_when_there_is_no_file(tmp_path):
    assert Settings(tmp_path).deny_read is False


def test_a_written_setting_reads_back(tmp_path):
    s = Settings(tmp_path)
    s.set_deny_read(True)
    assert Settings(tmp_path).deny_read is True
    assert json.loads((tmp_path / "settings.json").read_text())["deny_read"] is True


def test_a_change_is_seen_without_a_restart(tmp_path):
    """The daemon holds one Settings for its life. A user who turns blocking
    on inside a running session must see it apply to that session -- a
    setting that needs a restart reads as a broken setting."""
    live = Settings(tmp_path)
    assert live.deny_read is False
    Settings(tmp_path).set_deny_read(True)          # another process writes
    assert live.deny_read is True


def test_a_corrupt_file_reads_as_off(tmp_path):
    """I6: this feature never fails closed on its own configuration. A
    guard that cannot read its setting must not start blocking on a guess."""
    (tmp_path / "settings.json").write_text("{ not json")
    assert Settings(tmp_path).deny_read is False


def test_an_unreadable_file_reads_as_off(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text('{"deny_read": true}')
    path.chmod(0o000)
    try:
        assert Settings(tmp_path).deny_read is False
    finally:
        path.chmod(0o600)


def test_writing_does_not_lose_an_unrelated_key(tmp_path):
    (tmp_path / "settings.json").write_text('{"kept": 1}')
    Settings(tmp_path).set_deny_read(True)
    data = json.loads((tmp_path / "settings.json").read_text())
    assert data == {"kept": 1, "deny_read": True}
