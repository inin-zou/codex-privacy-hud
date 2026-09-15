# tests/test_hud_snapshot.py
"""Contract A's one writer and its Python reader (spec §4.1, §5.1).

The writer is tested for the properties readers rely on: atomicity (no reader
ever sees a partial file), schema conformance (validated with the same
stdlib validator the contract test uses), preservation of `hidden` across
`publish`, 0600/0700 modes, and a sweep that removes only what is old. The
reader is tested for the one rule that matters -- every failure is `None`.
"""
from __future__ import annotations

import json
import os
import stat
import threading
import time
from types import SimpleNamespace

import pytest

from privacy_hud import hud_snapshot as hs
from test_hud_contract import validate  # same directory; pytest adds it to sys.path

SID = "0199abcd-1111-2222-3333-444455556666"


@pytest.fixture
def data_dir(tmp_path):
    return tmp_path


def _read(data_dir, sid=SID):
    return json.loads(hs.snapshot_path(data_dir, sid).read_text())


def test_publish_writes_a_schema_valid_snapshot(data_dir):
    hs.HudPublisher(data_dir).publish(SID, percent=28, blocked=2, unverified=False)
    doc = _read(data_dir)
    assert validate(doc) == []
    assert doc["percent"] == 28 and doc["blocked"] == 2
    assert doc["hidden"] is False
    assert abs(doc["updated_at"] - time.time()) < 5


def test_publish_creates_hud_dir_0700_and_file_0600(data_dir):
    hs.HudPublisher(data_dir).publish(SID, percent=0, blocked=0, unverified=True)
    assert stat.S_IMODE(hs.hud_dir(data_dir).stat().st_mode) == 0o700
    assert stat.S_IMODE(hs.snapshot_path(data_dir, SID).stat().st_mode) == 0o600


def test_publish_preserves_hidden(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=10, blocked=0, unverified=False)
    pub.set_hidden(SID, True)
    pub.publish(SID, percent=20, blocked=1, unverified=False)
    doc = _read(data_dir)
    assert doc["hidden"] is True and doc["percent"] == 20


def test_set_hidden_on_missing_snapshot_creates_a_zero_one(data_dir):
    hs.HudPublisher(data_dir).set_hidden(SID, True)
    doc = _read(data_dir)
    assert validate(doc) == [] and doc["hidden"] is True and doc["percent"] == 0


def test_publish_is_atomic_under_a_concurrent_reader(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=0, blocked=0, unverified=False)
    stop = threading.Event()
    bad = []

    def reader():
        while not stop.is_set():
            try:
                doc = json.loads(hs.snapshot_path(data_dir, SID).read_text())
            except (ValueError, OSError) as exc:
                bad.append(repr(exc))
                continue
            if validate(doc):
                bad.append(doc)

    t = threading.Thread(target=reader)
    t.start()
    for i in range(500):
        pub.publish(SID, percent=i % 101, blocked=i, unverified=bool(i % 2))
    stop.set()
    t.join()
    assert bad == []
    assert not list(hs.hud_dir(data_dir).glob("*.tmp"))


def test_retire_removes_the_file_and_tolerates_absence(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=1, blocked=0, unverified=False)
    pub.retire(SID)
    assert not hs.snapshot_path(data_dir, SID).exists()
    pub.retire(SID)  # no raise


def test_sweep_removes_only_old_files(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish("old", percent=1, blocked=0, unverified=False)
    pub.publish("new", percent=1, blocked=0, unverified=False)
    old = hs.snapshot_path(data_dir, "old")
    past = time.time() - 5 * 3600
    os.utime(old, (past, past))
    removed = pub.sweep(now=time.time())
    assert removed == 1
    assert not old.exists() and hs.snapshot_path(data_dir, "new").exists()


@pytest.mark.parametrize("sid", ["", "../x", "a/b"])
def test_session_id_cannot_escape_hud_dir(data_dir, sid):
    with pytest.raises(ValueError):
        hs.snapshot_path(data_dir, sid)


def test_read_roundtrip(data_dir):
    hs.HudPublisher(data_dir).publish(SID, percent=63, blocked=4, unverified=True)
    snap = hs.read_snapshot(data_dir, SID)
    assert snap == hs.Snapshot(percent=63, blocked=4, unverified=True,
                               hidden=False, updated_at=snap.updated_at)


def test_read_returns_hidden_and_lets_caller_decide(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=63, blocked=0, unverified=False)
    pub.set_hidden(SID, True)
    assert hs.read_snapshot(data_dir, SID).hidden is True


@pytest.mark.parametrize("text", [
    "", "{", "[]", '{"v": 2, "percent": 1, "blocked": 0, "unverified": false, "hidden": false, "updated_at": 1}',
    '{"v": 1, "percent": 101, "blocked": 0, "unverified": false, "hidden": false, "updated_at": 1}',
    '{"v": 1, "percent": 1, "blocked": 0, "unverified": false, "hidden": false}',
])
def test_read_returns_none_on_malformed(data_dir, text):
    hs.hud_dir(data_dir).mkdir()
    hs.snapshot_path(data_dir, SID).write_text(text)
    assert hs.read_snapshot(data_dir, SID, now=2.0) is None


def test_read_returns_none_when_stale(data_dir):
    hs.HudPublisher(data_dir).publish(SID, percent=5, blocked=0, unverified=False)
    assert hs.read_snapshot(data_dir, SID, now=time.time() + 29) is not None
    assert hs.read_snapshot(data_dir, SID, now=time.time() + 31) is None


def test_read_returns_none_when_missing(data_dir):
    assert hs.read_snapshot(data_dir, SID) is None


def test_sweep_never_removes_the_daemon_marker(data_dir):
    """`_daemon.json` is the one file in `hud/` that is not a session, and
    it is what `ambient.py` reads for the unattributed-gaps line. A sweep
    that retired it because it happened to be old would silently delete the
    marker out from under a daemon that had just started and was about to
    heartbeat it."""
    pub = hs.HudPublisher(data_dir)
    pub.mark_daemon(unattributed_gaps=True)
    marker = hs.hud_dir(data_dir) / "_daemon.json"
    ancient = time.time() - 30 * 24 * 3600
    os.utime(marker, (ancient, ancient))
    assert pub.sweep(now=time.time()) == 0
    assert marker.exists()
    assert hs.read_daemon_marker(data_dir, ignore_staleness=True) is True


def test_daemon_marker_roundtrip_and_staleness(data_dir):
    pub = hs.HudPublisher(data_dir)
    assert hs.read_daemon_marker(data_dir) is None
    pub.mark_daemon(unattributed_gaps=True)
    assert hs.read_daemon_marker(data_dir) is True
    assert hs.read_daemon_marker(data_dir, now=time.time() + 31) is None


# -- heartbeat (spec §4.1) ------------------------------------------------

def _freeze(monkeypatch, when: float) -> None:
    """Make the publisher's own clock read `when`. `hud_snapshot` calls
    `time.time()` and nothing else from the module, so a stub with that one
    attribute is the whole surface."""
    monkeypatch.setattr(hs, "time", SimpleNamespace(time=lambda: when))


def test_heartbeat_refreshes_updated_at_and_nothing_else(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=28, blocked=2, unverified=True)
    pub.set_hidden(SID, True)
    before = _read(data_dir)
    old = before["updated_at"] - 25.0
    path = hs.snapshot_path(data_dir, SID)
    path.write_text(json.dumps({**before, "updated_at": old}))

    pub.heartbeat([SID])

    after = _read(data_dir)
    assert validate(after) == []
    assert after["updated_at"] > old
    assert abs(after["updated_at"] - time.time()) < 5
    assert {k: v for k, v in after.items() if k != "updated_at"} \
        == {k: v for k, v in before.items() if k != "updated_at"}
    assert after["hidden"] is True and after["percent"] == 28
    assert after["blocked"] == 2 and after["unverified"] is True


def test_heartbeat_keeps_a_quiet_session_readable_past_stale_after(
        data_dir, monkeypatch):
    """The bug, end to end: nothing happens in the session for longer than
    `STALE_AFTER`, and without a heartbeat both readers stop drawing the
    item even though the daemon is alive and the numbers are still true."""
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=7, blocked=0, unverified=False)
    later = time.time() + hs.STALE_AFTER + 1
    assert hs.read_snapshot(data_dir, SID, now=later) is None
    _freeze(monkeypatch, later)
    pub.heartbeat([SID])
    snap = hs.read_snapshot(data_dir, SID, now=later)
    assert snap is not None and snap.percent == 7


def test_heartbeat_skips_ids_with_no_file(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=1, blocked=0, unverified=False)
    pub.heartbeat([SID, "never-started", "../escape", ""])
    assert [p.name for p in hs.hud_dir(data_dir).iterdir()] == [f"{SID}.json"]


def test_heartbeat_restamps_the_daemon_marker_keeping_the_bool(
        data_dir, monkeypatch):
    pub = hs.HudPublisher(data_dir)
    pub.mark_daemon(unattributed_gaps=True)
    later = time.time() + hs.STALE_AFTER + 1
    assert hs.read_daemon_marker(data_dir, now=later) is None
    _freeze(monkeypatch, later)
    pub.heartbeat([])
    assert hs.read_daemon_marker(data_dir, now=later) is True


def test_heartbeat_reads_the_marker_back_when_it_did_not_write_it(
        data_dir, monkeypatch):
    """A publisher built after the marker (a restart within the same data
    dir, or the `$privacy` tool's own publisher) must carry the bit
    forward, not invent one."""
    hs.HudPublisher(data_dir).mark_daemon(unattributed_gaps=False)
    fresh = hs.HudPublisher(data_dir)
    later = time.time() + hs.STALE_AFTER + 1
    _freeze(monkeypatch, later)
    fresh.heartbeat([])
    assert hs.read_daemon_marker(data_dir, now=later) is False


def test_heartbeat_writes_no_marker_when_there_is_none(data_dir):
    hs.HudPublisher(data_dir).heartbeat([SID])
    assert not (hs.hud_dir(data_dir) / "_daemon.json").exists()


def test_heartbeat_interval_leaves_room_for_a_missed_beat():
    assert hs.HEARTBEAT_INTERVAL * 2 < hs.STALE_AFTER


def test_snapshot_never_contains_a_string(data_dir):
    hs.HudPublisher(data_dir).publish(SID, percent=1, blocked=1, unverified=False)
    assert not any(isinstance(v, str) for v in _read(data_dir).values())
