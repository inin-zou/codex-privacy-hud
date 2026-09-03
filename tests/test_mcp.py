# tests/test_mcp.py
"""Tests for the pure MCP tool functions in privacy_hud.mcp_tools.

These functions are the last hop before user-facing surfaces (the UI, the
skill's printed audit). The risk that matters most here is I1: no raw
sensitive value may ever leave one of these functions — only IDs, counts,
types, destinations, timestamps, and the pre-masked `masked_example` the
ledger already stores. `test_no_raw_value_survives_json_round_trip` is the
gate for that, run against every function's return value at once.

The second risk that matters is design.md §8's consent rule: `allow_once`
must refuse to mint a token for an exposure the user has not reviewed
(`reviewed=False` -> PermissionError). Consent without information is not
consent.
"""
from __future__ import annotations

import json

import pytest

from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.mcp_tools import (
    allow_once,
    apply_policy,
    get_exposure_detail,
    get_session_summary,
    list_exposures,
    start_clean_session,
)

M = load_matrix()

# A raw value that must NEVER appear, in any form, in any function's return.
RAW_LOCAL_PART = "jordan"
RAW_SECRET = "sk-live-abcdef0123456789"


@pytest.fixture
def led(tmp_path):
    l = Ledger(tmp_path / "l.db", M)
    l.start_session("s1", cwd="/r", model="gpt-5")
    l.record("s1", turn_id="t1", kind="exposed", data_type="email",
              source="support.log", destination="model_context",
              value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
              tool_name="Read", protection=None)
    l.record("s1", turn_id="t2", kind="prevented", data_type="credential",
              source="tool input", destination="mcp_tool",
              value_hash=b"\x02" * 16, masked_example=None,
              tool_name="mcp__github__x", protection="blocked")
    l.record("s1", turn_id="t3", kind="local_access", data_type="path",
              source="terminal output", destination="local",
              value_hash=b"\x03" * 16, masked_example="/Users/.../app.log",
              tool_name="Read", protection=None)
    return l


# --------------------------------------------------------------------- #
# get_session_summary
# --------------------------------------------------------------------- #

def test_summary_returns_the_four_tiles(led):
    s = get_session_summary(led, "s1")
    assert set(s) >= {"percent", "exposed_items", "destinations", "prevented"}
    assert s["exposed_items"] == 1
    assert s["prevented"] == 1


# --------------------------------------------------------------------- #
# list_exposures
# --------------------------------------------------------------------- #

def test_list_exposures_returns_no_raw_values(led):
    rows = list_exposures(led, "s1", "Exposed")
    blob = json.dumps(rows)
    assert "@acme.com" in blob          # the masked exemplar is fine
    assert RAW_LOCAL_PART not in blob   # the raw local part is not
    assert len(rows) == 1
    assert rows[0]["data_type"] == "email"


def test_list_exposures_prevented_tab(led):
    rows = list_exposures(led, "s1", "Prevented")
    assert len(rows) == 1
    assert rows[0]["data_type"] == "credential"
    assert rows[0]["protection"] == "blocked"


def test_list_exposures_all_events_includes_every_kind(led):
    rows = list_exposures(led, "s1", "All events")
    kinds = {r["kind"] for r in rows}
    assert kinds == {"exposed", "prevented", "local_access"}
    assert len(rows) == 3


def test_list_exposures_rejects_an_unknown_tab(led):
    with pytest.raises(ValueError):
        list_exposures(led, "s1", "Nonexistent")


def test_list_exposures_rows_carry_no_value_hash_bytes(led):
    # bytes are not JSON-serializable at all -- if this key ever leaked
    # through, json.dumps above would already have raised. This test names
    # the invariant explicitly rather than relying on that side effect.
    rows = list_exposures(led, "s1", "All events")
    assert all("value_hash" not in r for r in rows)


# --------------------------------------------------------------------- #
# get_exposure_detail
# --------------------------------------------------------------------- #

def test_get_exposure_detail_by_row_id(led):
    rows = list_exposures(led, "s1", "Exposed")
    event_id = rows[0]["id"]
    detail = get_exposure_detail(led, "s1", event_id)
    assert detail["data_type"] == "email"
    assert detail["masked_example"] == "jo•••@acme.com"
    blob = json.dumps(detail)
    assert RAW_LOCAL_PART not in blob


def test_get_exposure_detail_includes_budget_cap(led):
    rows = list_exposures(led, "s1", "Exposed")
    detail = get_exposure_detail(led, "s1", rows[0]["id"])
    assert detail.get("budget_cap") == M.budget_cap


def test_get_exposure_detail_unknown_id_raises(led):
    with pytest.raises(LookupError):
        get_exposure_detail(led, "s1", 999999)


def test_get_exposure_detail_scoped_to_session(led):
    # A row id from a DIFFERENT session must not resolve, even if the
    # integer id happens to exist in the events table.
    rows = list_exposures(led, "s1", "Exposed")
    event_id = rows[0]["id"]
    with pytest.raises(LookupError):
        get_exposure_detail(led, "s2-does-not-exist", event_id)


# --------------------------------------------------------------------- #
# allow_once
# --------------------------------------------------------------------- #

def test_allow_once_requires_a_reviewed_exposure(led):
    with pytest.raises(PermissionError):
        allow_once(led, "s1", tool_name="Bash", tool_input={"command": "x"},
                   reviewed=False)


def test_allow_once_mints_a_token_when_reviewed(led):
    allow_once(led, "s1", tool_name="Bash", tool_input={"command": "x"},
               reviewed=True)
    rows = [dict(r) for r in led.conn.execute(
        "SELECT * FROM policy_tokens WHERE session_id='s1'")]
    assert len(rows) == 1
    assert rows[0]["mode"] == "allow_once"
    assert rows[0]["tool_name"] == "Bash"


def test_allow_once_does_not_mint_when_not_reviewed(led):
    with pytest.raises(PermissionError):
        allow_once(led, "s1", tool_name="Bash", tool_input={"command": "x"},
                   reviewed=False)
    rows = led.conn.execute("SELECT count(*) FROM policy_tokens").fetchone()[0]
    assert rows == 0


# --------------------------------------------------------------------- #
# apply_policy
# --------------------------------------------------------------------- #

def test_block_this_source_writes_an_enforceable_rule(led):
    apply_policy(led, "s1", rule_type="block_source", selector="support.log")
    rules = [dict(r) for r in led.conn.execute("SELECT * FROM policy")]
    assert rules[0]["rule_type"] == "block_source"
    assert rules[0]["selector"] == "support.log"


def test_protect_future_occurrences_writes_a_mask_rule(led):
    apply_policy(led, "s1", rule_type="mask", selector="email")
    assert led.conn.execute(
        "SELECT count(*) FROM policy WHERE rule_type='mask'").fetchone()[0] == 1


def test_apply_policy_scopes_the_rule_to_the_session(led):
    apply_policy(led, "s1", rule_type="block_source", selector="support.log")
    row = led.conn.execute("SELECT scope FROM policy").fetchone()
    assert "s1" in row["scope"]


def test_apply_policy_rejects_an_unknown_rule_type(led):
    with pytest.raises(ValueError):
        apply_policy(led, "s1", rule_type="not_a_real_rule", selector="x")
    assert led.conn.execute("SELECT count(*) FROM policy").fetchone()[0] == 0


# --------------------------------------------------------------------- #
# start_clean_session
# --------------------------------------------------------------------- #

def test_start_clean_session_returns_a_different_session_id(led):
    new_id = start_clean_session(led, "s1")
    assert isinstance(new_id, str)
    assert new_id != "s1"


def test_start_clean_session_ends_the_old_session(led):
    start_clean_session(led, "s1")
    row = led.conn.execute(
        "SELECT ended_at FROM sessions WHERE session_id='s1'").fetchone()
    assert row["ended_at"] is not None


def test_start_clean_session_nulls_the_old_sessions_value_hashes(led):
    start_clean_session(led, "s1")
    rows = led.conn.execute(
        "SELECT value_hash FROM events WHERE session_id='s1'").fetchall()
    assert all(r["value_hash"] is None for r in rows)


def test_start_clean_session_starts_a_fresh_session_row(led):
    new_id = start_clean_session(led, "s1")
    row = led.conn.execute(
        "SELECT session_id FROM sessions WHERE session_id=?", (new_id,)).fetchone()
    assert row is not None


# --------------------------------------------------------------------- #
# Cross-cutting: no raw sensitive value leaves ANY function, ever.
# --------------------------------------------------------------------- #

def test_no_raw_value_survives_json_round_trip(led):
    outputs = [
        get_session_summary(led, "s1"),
        list_exposures(led, "s1", "Exposed"),
        list_exposures(led, "s1", "Prevented"),
        list_exposures(led, "s1", "All events"),
    ]
    rows = list_exposures(led, "s1", "Exposed")
    outputs.append(get_exposure_detail(led, "s1", rows[0]["id"]))

    blob = json.dumps(outputs)
    for raw in (RAW_LOCAL_PART, RAW_SECRET):
        assert raw not in blob
