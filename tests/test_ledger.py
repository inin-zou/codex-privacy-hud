import dataclasses
import json

import pytest
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.ledger import (EventRow, ExposureRow, Ledger, SessionCoverage,
                                SessionSummary)

M = load_matrix()


@pytest.fixture
def led(tmp_path):
    l = Ledger(tmp_path / "ledger.db", M)
    l.start_session("s1", cwd="/repo", model="gpt-5")
    return l


def _rec(led, **kw):
    base = dict(turn_id="t1", kind="exposed", data_type="email",
                source="support.log", destination="model_context",
                value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
                tool_name="Read", protection=None)
    base.update(kw)
    return led.record("s1", **base)


def test_first_disclosure_adds_budget(led):
    assert _rec(led) == pytest.approx(6.0)


def test_same_value_same_destination_does_not_double_count(led):
    _rec(led)
    assert _rec(led) == 0.0


def test_replaying_the_same_event_is_idempotent(led):
    for _ in range(100):
        _rec(led)
    assert led.summary("s1").exposed_items == 1


def test_new_destination_does_count(led):
    _rec(led)
    delta = _rec(led, destination="mcp_tool")
    assert delta > 0.0


def test_prevented_events_add_zero_budget(led):
    delta = _rec(led, kind="prevented", data_type="credential",
                 destination="external_net", protection="blocked")
    assert delta == 0.0
    assert led.summary("s1").prevented == 1


def test_summary_counts_distinct_destinations(led):
    _rec(led)
    _rec(led, value_hash=b"\x02" * 16, destination="mcp_tool")
    assert led.summary("s1").destinations == 2


def test_end_session_nulls_value_hashes(led):
    _rec(led)
    led.end_session("s1")
    rows = led.list_events("s1", "exposed")
    assert all(r.value_hash is None for r in rows)


def test_schema_has_no_raw_content_columns(led):
    cols = {r[1] for r in led.conn.execute("PRAGMA table_info(events)")}
    assert not cols & {"content", "prompt", "raw_value", "snippet", "text"}


# --------------------------------------------------------------------- #
# The read contract itself (see ledger.py's `SessionSummary`/`EventRow`).
# --------------------------------------------------------------------- #

def test_summary_is_frozen(led):
    """I4: a summary is a reading, not an accumulator. There is no removal
    path for disclosure, so there is no write path here either."""
    s = led.summary("s1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.percent = 99


def test_event_rows_are_frozen(led):
    _rec(led)
    row = led.list_events("s1", "exposed")[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        row.data_type = "credential"


def test_a_mistyped_field_name_is_loud_not_none(led):
    """The bug this contract exists to prevent. `detect/model.py`'s LABEL_MAP
    shipped with keys the model never emits, and tier 3 silently returned
    nothing for weeks. A dict `.get()` on a mistyped key is that failure mode;
    attribute access on a dataclass is not."""
    _rec(led)
    row = led.list_events("s1", "exposed")[0]
    with pytest.raises(AttributeError):
        row.data_typ
    # Subscripting is gone too, so the old stringly-typed spelling cannot
    # quietly come back: there is no `.get()` on these rows to return None.
    with pytest.raises(TypeError):
        row["data_type"]


def test_event_row_narrows_to_an_exposure_row_without_the_hash(led):
    """`to_exposure()` is the old `mcp_tools._project`, as a type: the two
    ledger-internal columns are absent from the result by construction, not by
    a maintained exclusion list (I1)."""
    _rec(led)
    row = led.list_events("s1", "exposed")[0]
    assert row.value_hash is not None
    exposure = row.to_exposure()
    assert not hasattr(exposure, "value_hash")
    assert not hasattr(exposure, "session_id")
    assert exposure.data_type == row.data_type


def test_no_read_contract_field_can_hold_raw_content(led):
    """I1, asserted against the types rather than only the SQL schema: the
    field NAMES are part of the guarantee, and a `text`/`content` field would
    be a violation even though it would never be a column."""
    banned = {"content", "prompt", "raw_value", "snippet", "text", "value",
              "body", "payload"}
    for cls in (SessionSummary, ExposureRow, EventRow):
        names = {f.name for f in dataclasses.fields(cls)}
        assert not names & banned, f"{cls.__name__} has a raw-content field"


def test_as_dict_never_serializes_the_salted_hash(led):
    """`EventRow` inherits `as_dict()` unchanged, and that is deliberate:
    `value_hash` is not in `_EXPOSURE_JSON_FIELDS`, so no JSON boundary can
    emit it even when handed a full ledger row."""
    _rec(led)
    row = led.list_events("s1", "exposed")[0]
    payload = row.as_dict()
    assert "value_hash" not in payload
    assert "session_id" not in payload
    json.dumps(payload)  # must be encodable, bytes would raise


# --------------------------------------------------------------------- #
# coverage: "was anyone watching?"
#
# The bug these pin: a ledger that recorded nothing is byte-identical to a
# ledger with nothing to record. `summary()` answers both with 0%, and an I7
# self-audit once passed on the strength of exactly that. Every test below asks
# whether the ledger can now tell the two apart, and — just as importantly —
# refuses to let it claim a completeness it has no evidence for.
# --------------------------------------------------------------------- #

def test_a_session_started_normally_is_verified(led):
    cov = led.coverage("s1")
    assert cov.verified
    assert cov.recorded and cov.observers == 1
    assert cov.reason == ""


def test_a_session_the_ledger_never_saw_is_not_a_clean_session(led):
    """The whole point. `summary()` answers an unknown id with a well-formed
    zero; `coverage()` must not."""
    assert led.summary("never-happened").percent == 0
    cov = led.coverage("never-happened")
    assert not cov.verified
    assert not cov.recorded
    assert "never recorded" in cov.reason


def test_a_lazily_created_session_row_is_marked_attached(led):
    led.start_session("s2", cwd="/repo", model="gpt-5", observed_start=False)
    cov = led.coverage("s2")
    assert cov.attached
    assert not cov.verified
    assert "already under way" in cov.reason


def test_session_start_wins_over_a_later_lazy_resolution(led):
    """A daemon that DID see the SessionStart must keep its stronger record
    when it later re-resolves the same session (after a SessionEnd, say)."""
    led.start_session("s1", cwd="/repo", model="gpt-5", observed_start=False)
    assert led.coverage("s1").verified


def test_a_second_observer_means_nobody_was_watching_in_between(led, tmp_path):
    """A daemon replaced mid-session leaves a gap that neither daemon can see
    on its own -- but two observer rows against one session can."""
    other = Ledger(tmp_path / "ledger.db", M)
    assert other.observer != led.observer
    other.start_session("s1", cwd="/repo", model="gpt-5", observed_start=False)

    cov = led.coverage("s1")
    assert cov.observers == 2
    assert not cov.verified
    # The replacement daemon's first sight was mid-session, so `attached` is
    # the more specific evidence and it is what the banner names. `observers`
    # is the independent signal, and it is what catches the shape `attached`
    # cannot: two daemons that each saw a SessionStart for one session id.
    assert cov.attached
    assert not SessionCoverage(recorded=True, observers=2, attached=False,
                               unobserved_hooks=False).verified
    assert "restarted" in SessionCoverage(
        recorded=True, observers=2, attached=False,
        unobserved_hooks=False).reason


def test_a_session_row_with_no_coverage_record_reads_unverified(led):
    """Absence of evidence is not evidence of coverage. A row written by a
    Ledger predating this table (or by a caller bypassing start_session) must
    not inherit a clean bill of health."""
    led.conn.execute("DELETE FROM coverage WHERE session_id='s1'")
    cov = led.coverage("s1")
    assert cov.recorded and cov.observers == 0
    assert not cov.verified


def test_unobserved_hooks_are_recorded_and_countable(led):
    assert led.unattributed_gaps() == 0
    led.note_unobserved_hooks(1_757_000_000)
    assert led.unattributed_gaps() == 1
    # One row per observer, so re-reading a latch cannot inflate the count.
    led.note_unobserved_hooks(1_757_000_001)
    assert led.unattributed_gaps() == 1


def test_an_open_session_is_unverified_by_a_gap_inside_its_window(led):
    started = led.conn.execute(
        "SELECT started_at FROM sessions WHERE session_id='s1'").fetchone()[0]
    led.note_unobserved_hooks(started + 5)

    cov = led.coverage("s1")
    assert cov.unobserved_hooks
    assert not cov.verified
    assert "no daemon listening" in cov.reason


def test_a_gap_before_a_session_started_does_not_touch_it(led):
    started = led.conn.execute(
        "SELECT started_at FROM sessions WHERE session_id='s1'").fetchone()[0]
    led.note_unobserved_hooks(started - 600)
    assert led.coverage("s1").verified


def test_the_newest_ended_session_is_unverified_by_a_gap_after_it(led):
    """This IS the incident. The session that ran during the gap has no row and
    never will, so a caller resolving "the current session" as "the newest row"
    is looking at an answer to a different question -- and must be told."""
    led.end_session("s1")
    started = led.conn.execute(
        "SELECT started_at FROM sessions WHERE session_id='s1'").fetchone()[0]
    led.note_unobserved_hooks(started + 60)

    assert not led.coverage("s1").verified


def test_an_ended_session_followed_by_a_recorded_one_is_unaffected(led):
    """The bound that keeps this from becoming noise: once a later session is on
    record, whatever was dropped afterwards belongs to that one."""
    led.end_session("s1")
    started = led.conn.execute(
        "SELECT started_at FROM sessions WHERE session_id='s1'").fetchone()[0]
    led.note_unobserved_hooks(started + 60)
    led.start_session("s2", cwd="/repo", model="gpt-5")
    led.conn.execute("UPDATE sessions SET started_at=? WHERE session_id='s2'",
                      (started + 120,))

    assert led.coverage("s1").verified


def test_coverage_holds_no_content(led):
    """I1: session ids, timestamps, an opaque observer id, and a reason from a
    closed set of literals. Nothing that could describe what a session did."""
    cols = {r[1] for r in led.conn.execute("PRAGMA table_info(coverage)")}
    assert cols == {"id", "session_id", "ts", "observer", "reason"}
    banned = {"content", "prompt", "raw_value", "snippet", "text", "value",
              "cwd", "path", "command"}
    assert not cols & banned


def test_observer_ids_are_opaque_and_per_instance(tmp_path):
    """Not a pid, not a hostname (I1) -- and distinct per Ledger, which is what
    makes "a second daemon touched this session" observable at all."""
    a = Ledger(tmp_path / "l.db", M)
    b = Ledger(tmp_path / "l.db", M)
    assert a.observer != b.observer
    assert a.observer.isalnum() and len(a.observer) == 16
    assert Ledger(tmp_path / "l.db", M, observer="pinned").observer == "pinned"


def test_coverage_is_append_only(led):
    """CLAUDE.md §4: the only permitted UPDATEs are `count` and nulling
    `value_hash`. Coverage adds no third one -- a downgrade is a new row from a
    new observer, never a rewrite of an old one."""
    before = led.conn.execute(
        "SELECT id, reason FROM coverage ORDER BY id").fetchall()
    led.start_session("s1", cwd="/repo", model="gpt-5", observed_start=False)
    led.note_unobserved_hooks(1)
    led.end_session("s1")
    after = led.conn.execute(
        "SELECT id, reason FROM coverage ORDER BY id").fetchall()
    assert [tuple(r) for r in after][:len(before)] == \
        [tuple(r) for r in before]
