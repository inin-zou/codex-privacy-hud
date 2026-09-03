import pytest
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.ledger import Ledger

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
    assert led.summary("s1")["exposed_items"] == 1


def test_new_destination_does_count(led):
    _rec(led)
    delta = _rec(led, destination="mcp_tool")
    assert delta > 0.0


def test_prevented_events_add_zero_budget(led):
    delta = _rec(led, kind="prevented", data_type="credential",
                 destination="external_net", protection="blocked")
    assert delta == 0.0
    assert led.summary("s1")["prevented"] == 1


def test_summary_counts_distinct_destinations(led):
    _rec(led)
    _rec(led, value_hash=b"\x02" * 16, destination="mcp_tool")
    assert led.summary("s1")["destinations"] == 2


def test_end_session_nulls_value_hashes(led):
    _rec(led)
    led.end_session("s1")
    rows = led.list_events("s1", "exposed")
    assert all(r["value_hash"] is None for r in rows)


def test_schema_has_no_raw_content_columns(led):
    cols = {r[1] for r in led.conn.execute("PRAGMA table_info(events)")}
    assert not cols & {"content", "prompt", "raw_value", "snippet", "text"}
