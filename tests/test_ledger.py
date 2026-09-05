import dataclasses
import json

import pytest
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.ledger import EventRow, ExposureRow, Ledger, SessionSummary

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
