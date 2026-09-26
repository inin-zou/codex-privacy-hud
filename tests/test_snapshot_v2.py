"""#54 phase 1: snapshot version 2, and the HUD line both readers draw.

The snapshot carries an accounting discriminator and nullable quantities,
so an unrecorded session is published as "no reading" rather than as 0%,
and a legacy score cannot be read as confirmed accounting. Version 1
snapshots are still read, as explicitly legacy. The daemon marker keeps its
own version 1.

`tests/matrix/hud_reading_golden.json` is the snapshot-to-text golden; the
patched Codex reader embeds a byte copy of it (`test_hud_contract.py`).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from privacy_hud import ambient, hud_snapshot, render
from privacy_hud.hud_snapshot import HudPublisher, read_snapshot
from privacy_hud.matrix.loader import load_matrix
from runtime_helpers import writer_ledger

MATRIX = Path(__file__).parent / "matrix"
GOLDEN = json.loads((MATRIX / "hud_reading_golden.json").read_text(
    encoding="utf-8"))
SID = "0199e2e0-b10c-4000-8000-0000000054b2"

KEYS = ["v", "accounting_version", "percent", "confirmed_points",
        "denials_issued", "legacy_prevented_rows", "unresolved_actions",
        "unverified", "hidden", "updated_at"]


@pytest.fixture
def state(deterministic_state):
    """These contracts exercise dispatch and projections, not model inference."""
    return deterministic_state


@pytest.fixture
def data_dir(tmp_path):
    return tmp_path


@pytest.fixture
def led(tmp_path):
    ledger = writer_ledger(tmp_path / "ledger.db", load_matrix())
    yield ledger
    ledger.conn.close()


def _write(data_dir, doc=None, *, text=None, sid=SID):
    path = hud_snapshot.snapshot_path(data_dir, sid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc) if text is None else text,
                    encoding="utf-8")
    return path


def _doc(data_dir, sid=SID):
    return json.loads(hud_snapshot.snapshot_path(data_dir, sid).read_text())


def _line(data_dir, width=GOLDEN["width"], now=GOLDEN["now"]):
    snap = read_snapshot(data_dir, SID, now=now)
    return "" if snap is None else render.hud_line(snap, width)


# -- the writer -------------------------------------------------------------

def test_versions_are_separate():
    assert hud_snapshot.SNAPSHOT_VERSION == 2
    assert hud_snapshot.DAEMON_MARKER_VERSION == 1


def test_publish_writes_a_legacy_v2_snapshot(data_dir, led):
    led.start_session(SID, cwd="/w", model="m")
    HudPublisher(data_dir).publish(SID, summary=led.summary(SID),
                                   unverified=False)
    doc = _doc(data_dir)
    assert list(doc) == KEYS
    assert doc["v"] == 2 and doc["accounting_version"] == 1
    assert doc["percent"] == 0 and doc["legacy_prevented_rows"] == 0
    assert doc["confirmed_points"] is None
    assert doc["denials_issued"] is None
    assert doc["unresolved_actions"] is None


def test_publish_writes_an_unrecorded_snapshot_with_no_numbers(data_dir, led):
    HudPublisher(data_dir).publish(SID, summary=led.summary("missing"),
                                   unverified=False)
    doc = _doc(data_dir)
    assert doc["accounting_version"] == 0
    for key in ("percent", "confirmed_points", "denials_issued",
                "legacy_prevented_rows", "unresolved_actions"):
        assert doc[key] is None, key
    assert doc["unverified"] is True


def test_the_daemon_marker_stays_version_one(data_dir):
    HudPublisher(data_dir).mark_daemon(unattributed_gaps=True)
    marker = json.loads((data_dir / "hud" / "_daemon.json").read_text())
    assert marker["v"] == 1
    assert hud_snapshot.read_daemon_marker(data_dir) is True


# -- the reader -------------------------------------------------------------

@pytest.mark.parametrize("name,field", [
    ("legacy_v1_snapshot", "updated_at"),
    ("legacy", "updated_at"),
    ("accounting_v2_null", "confirmed_points"),
])
@pytest.mark.parametrize("sign", [-1, 1])
def test_oversized_integer_is_absent_and_not_rewritten(data_dir, name,
                                                      field, sign):
    doc = {**GOLDEN["cases"][name]["snapshot"], field: sign * 10**400}
    path = _write(data_dir, doc)
    before = path.read_bytes()

    assert read_snapshot(data_dir, SID, now=1010.0,
                         ignore_staleness=True) is None

    publisher = HudPublisher(data_dir)
    publisher.set_hidden(SID, True)
    publisher.heartbeat([SID])
    assert path.read_bytes() == before

def test_a_v1_snapshot_reads_as_legacy(data_dir):
    _write(data_dir, {"v": 1, "percent": 28, "blocked": 2,
                      "unverified": False, "hidden": False,
                      "updated_at": 1000.0})
    snap = read_snapshot(data_dir, SID, now=1010.0)
    assert snap.accounting_version == 1
    assert snap.percent == 28
    assert snap.legacy_prevented_rows == 2
    assert snap.denials_issued is None
    assert snap.confirmed_points is None


@pytest.mark.parametrize("index", range(len(GOLDEN["malformed"])))
def test_every_malformed_snapshot_reads_as_absent(data_dir, index):
    _write(data_dir, GOLDEN["malformed"][index])
    assert read_snapshot(data_dir, SID, now=1010.0,
                         ignore_staleness=True) is None


@pytest.mark.parametrize("index", range(len(GOLDEN["malformed_text"])))
def test_nonfinite_and_empty_text_reads_as_absent(data_dir, index):
    _write(data_dir, text=GOLDEN["malformed_text"][index])
    assert read_snapshot(data_dir, SID, now=1010.0,
                         ignore_staleness=True) is None


# -- heartbeat and hide preserve the reading --------------------------------

def test_heartbeat_and_hide_preserve_unknown(data_dir, led, monkeypatch):
    pub = HudPublisher(data_dir)
    pub.publish(SID, summary=led.summary("missing"), unverified=True)
    before = _doc(data_dir)
    pub.heartbeat([SID])
    pub.set_hidden(SID, True)
    after = _doc(data_dir)
    for key in KEYS:
        if key not in ("hidden", "updated_at"):
            assert after[key] == before[key], key
    assert after["hidden"] is True
    assert after["percent"] is None


def test_hide_on_a_missing_snapshot_writes_nothing(data_dir):
    HudPublisher(data_dir).set_hidden(SID, True)
    assert not hud_snapshot.snapshot_path(data_dir, SID).exists()


def test_hide_on_a_malformed_snapshot_writes_nothing(data_dir):
    path = _write(data_dir, text="{")
    HudPublisher(data_dir).set_hidden(SID, True)
    assert path.read_text() == "{"


# -- the HUD line -----------------------------------------------------------

@pytest.mark.parametrize("name", sorted(GOLDEN["cases"]))
def test_python_renders_every_golden_case(data_dir, name):
    case = GOLDEN["cases"][name]
    if "text" in case:
        _write(data_dir, text=case["text"])
    else:
        _write(data_dir, case["snapshot"])
    assert _line(data_dir) == case["expected"]


LEGACY = GOLDEN["cases"]["legacy"]["snapshot"]


@pytest.mark.parametrize("width,expected", [
    (120, "Privacy legacy 28% · 2 prevented rows"),
    (37, "Privacy legacy 28% · 2 prevented rows"),
    (36, "Privacy legacy 28%"),
    (18, "Privacy legacy 28%"),
    (17, "legacy 28%"),
    (10, "legacy 28%"),
    (9, "legacy"),
    (6, "legacy"),
    (5, ""),
])
def test_legacy_width_ladder_never_cuts_the_qualifier(data_dir, width,
                                                     expected):
    _write(data_dir, LEGACY)
    assert _line(data_dir, width=width) == expected


@pytest.mark.parametrize("width,expected", [
    (120, "Privacy legacy 28% · 2 prevented rows ⚠unverified"),
    (49, "Privacy legacy 28% · 2 prevented rows ⚠unverified"),
    (48, "Privacy legacy 28% ⚠unverified"),
    (30, "Privacy legacy 28% ⚠unverified"),
    (29, "legacy 28% ⚠unverified"),
    (22, "legacy 28% ⚠unverified"),
    (21, "⚠ legacy 28%"),
    (12, "⚠ legacy 28%"),
    (11, "⚠ legacy"),
    (8, "⚠ legacy"),
    (7, ""),
])
def test_unverified_legacy_width_ladder(data_dir, width, expected):
    _write(data_dir, dict(LEGACY, unverified=True))
    assert _line(data_dir, width=width) == expected


@pytest.mark.parametrize("width,expected", [
    (120, "Privacy —% · No session on record"),
    (33, "Privacy —% · No session on record"),
    (32, "Privacy —% · no record"),
    (22, "Privacy —% · no record"),
    (21, "—% · no record"),
    (14, "—% · no record"),
    (13, "⚠ —%"),
    (4, "⚠ —%"),
    (3, ""),
])
def test_unrecorded_width_ladder(data_dir, width, expected):
    _write(data_dir, GOLDEN["cases"]["unrecorded_null"]["snapshot"])
    assert _line(data_dir, width=width) == expected


def test_no_unavailable_line_draws_a_bar_or_a_green_dot(data_dir):
    _write(data_dir, GOLDEN["cases"]["unrecorded_null"]["snapshot"])
    for width in range(1, 121):
        line = _line(data_dir, width=width)
        assert "█" not in line and "░" not in line and "⬤" not in line
        assert "0%" not in line


# -- ambient ----------------------------------------------------------------

def test_ambient_draws_the_legacy_line(data_dir, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(data_dir))
    _write(data_dir, dict(LEGACY, updated_at=__import__("time").time()))
    assert ambient._line_for(SID, 120) == \
        "Privacy legacy 28% · 2 prevented rows"


def test_ambient_names_unattributed_gaps_without_a_number(data_dir,
                                                         monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(data_dir))
    HudPublisher(data_dir).mark_daemon(unattributed_gaps=True)
    assert ambient._line_for(None, 120) == \
        "Privacy —% · unattributed hook gaps"
    assert ambient._line_for(None, 26) == "Privacy —% ⚠unverified"
    assert ambient._line_for(None, 6) == "⚠ —%"
    assert ambient._line_for(None, 3) is None


# -- dispatch ---------------------------------------------------------------

def test_session_start_publishes_a_version_2_snapshot(state, tmp_path):
    """A genuine start is version-2 accounted since #54 Phase 4, and its
    snapshot says so; a legacy session's snapshot is pinned above."""
    from privacy_hud import dispatch as dispatch_mod
    dispatch_mod.dispatch(state, {
        "hook_event_name": "SessionStart", "session_id": SID,
        "cwd": "/w", "model": "gpt-5", "turn_id": "t1"})
    doc = _doc(tmp_path)
    assert doc["v"] == 2 and doc["accounting_version"] == 2
    assert doc["percent"] == 0 and doc["legacy_prevented_rows"] is None
    assert (doc["denials_issued"], doc["unresolved_actions"]) == (0, 0)


def test_the_publisher_never_reads_the_summary_through_int(state, tmp_path):
    import inspect

    from privacy_hud import dispatch as dispatch_mod
    source = inspect.getsource(dispatch_mod._publish_hud)
    assert "int(" not in source
    assert os.path.exists(tmp_path)
