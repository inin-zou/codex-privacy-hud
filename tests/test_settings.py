import json
import os

import pytest

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


def test_a_same_tick_rewrite_is_still_seen(tmp_path):
    """Closes the gap `test_a_change_is_seen_without_a_restart` leaves open:
    that test goes from "no file" to "file exists", which invalidates any
    cache because the cache starts empty -- it pins nothing about comparing
    `(mtime, size)` instead of `mtime` alone. This test forces the actual
    same-tick collision that motivated that choice: `live` has already
    cached a real `(mtime, size)` stamp from an existing file, a second
    write changes the value, and `os.utime` then pins the second write's
    mtime to be bit-identical to the first write's -- so only `size`
    differs, and a mtime-only cache would report no change at all.
    """
    path = tmp_path / "settings.json"
    live = Settings(tmp_path)
    Settings(tmp_path).set_deny_read(False)
    assert live.deny_read is False          # primes the cache with a real stamp
    first_mtime, first_size = path.stat().st_mtime, path.stat().st_size

    Settings(tmp_path).set_deny_read(True)  # a second process writes a change
    os.utime(path, (first_mtime, first_mtime))  # force an identical mtime
    # `{"deny_read": false}` and `{"deny_read": true}` serialize to different
    # byte counts, so the collision this forces is genuinely a
    # same-mtime-different-size one -- exactly the case (mtime, size) is for,
    # not a same-mtime-same-size case no cache key could distinguish.
    assert path.stat().st_size != first_size

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


@pytest.mark.parametrize("written", ["false", "off", "no", "true", "on", 1, 0])
def test_only_a_real_true_turns_blocking_on(tmp_path, written):
    """I6 again, from the other side: a hand-edited `settings.json` is the
    file the docs name as the toggle's home, so a user writing
    `{"deny_read": "false"}` to turn blocking OFF must not turn it on.
    `bool("false")` is True, so anything that is not the JSON literal
    `true` — a string, a number, a typo — reads as off."""
    (tmp_path / "settings.json").write_text(json.dumps({"deny_read": written}))
    assert Settings(tmp_path).deny_read is False
