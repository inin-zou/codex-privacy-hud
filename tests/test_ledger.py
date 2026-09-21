import dataclasses
import json
import re
import sqlite3
from pathlib import Path

import pytest
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.ledger import (SCHEMA, EventRow, ExposureRow, Ledger,
                                SessionCoverage, SessionSummary)
from privacy_hud.mcp_tools import _POLICY_RULE_TYPES

REPO = Path(__file__).resolve().parents[1]
M = load_matrix()


@pytest.fixture
def led(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db", M)
    ledger.start_session("s1", cwd="/repo", model="gpt-5")
    return ledger


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


@pytest.mark.parametrize("source", ["schema", "architecture"])
def test_the_documented_policy_rule_types_are_the_ones_that_exist(source):
    """`mcp_tools.apply_policy`'s docstring sends a reader to the SCHEMA
    comment for the list of rule types it accepts, and architecture.md §5
    repeats the same table, so neither is decoration. Both listed
    `mask|block_source|allow_dest`: a type `apply_policy` refuses outright
    (#38) and neither of the two that ship (#40)."""
    text = SCHEMA if source == "schema" else (
        REPO / ".claude" / "docs" / "architecture.md").read_text(encoding="utf-8")
    documented = re.findall(r"rule_type +TEXT NOT NULL, +-- *(\S+)", text)
    assert documented, "no documented rule_type list found"
    for listed in documented:
        assert set(listed.split("|")) == _POLICY_RULE_TYPES


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
        _ = row.data_typ
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


# --------------------------------------------------------------------- #
# policy: rules the user wrote, and whether the engine can see them
#
# These rows are the only ones in this schema that change what happens next
# rather than describing what already happened. A rule written under a scope
# the reader never asks for is not an error anywhere — it is silence, and the
# user was told their data was protected. So both sides of that string live in
# `ledger.py` now, and the tests below pin the pair, not either half.
# --------------------------------------------------------------------- #

def test_a_rule_applies_to_the_session_that_wrote_it(led):
    led.add_policy("s1", rule_type="block_source", selector="support.log")
    assert led.policy_selectors("s1", "block_source") == {"support.log"}


def test_a_rule_does_not_leak_into_another_session(led):
    led.add_policy("s1", rule_type="mask", selector="email")
    assert led.policy_selectors("s2", "mask") == set()


def test_a_rule_of_another_type_is_not_returned(led):
    led.add_policy("s1", rule_type="mask", selector="email")
    assert led.policy_selectors("s1", "block_source") == set()


def test_only_session_scoped_rules_are_read(led):
    """No writer or action produces a `global` row, so the reader does not
    honour one: a scope the product does not offer must not change what the
    engine enforces."""
    led.conn.execute(
        "INSERT INTO policy(scope, rule_type, selector, created_at)"
        " VALUES('global','block_source','support.log',0)")
    assert led.policy_selectors("s1", "block_source") == set()


def test_duplicate_rules_collapse_to_one_selector(led):
    led.add_policy("s1", rule_type="mask", selector="email")
    led.add_policy("s1", rule_type="mask", selector="email")
    assert led.policy_selectors("s1", "mask") == {"email"}


def test_no_rules_reads_as_no_rules_not_an_error(led):
    assert led.policy_selectors("s1", "mask") == set()


def test_add_policy_writes_the_documented_scope_spelling(led):
    """The one string the writer and the reader have to agree on."""
    led.add_policy("s1", rule_type="mask", selector="email")
    assert led.conn.execute(
        "SELECT scope FROM policy").fetchone()["scope"] == "session:s1"


def test_policy_holds_no_content(led):
    """I1: a scope, a rule type, a selector the user chose, a timestamp."""
    cols = {r[1] for r in led.conn.execute("PRAGMA table_info(policy)")}
    assert cols == {"id", "scope", "rule_type", "selector", "created_at"}


# --------------------------------------------------------------------- #
# policy_tokens: one token authorizes one argument set, once
#
# The whole guarantee is a single WHERE clause, and every test below is one
# way consent could be stretched past what the user gave: a second use, a
# different argument set, a different tool, another session, or a token that
# went stale between grant and use.
# --------------------------------------------------------------------- #

ARGS = b"\xaa" * 32
OTHER_ARGS = b"\xbb" * 32


def _mint(led, session_id="s1", *, tool_name="Bash", args_hash=ARGS,
          mode="allow_once", ttl_seconds=120):
    return led.mint_token(session_id, tool_name=tool_name, args_hash=args_hash,
                          mode=mode, ttl_seconds=ttl_seconds)


def test_a_token_consumes_once_for_its_argument_set(led):
    _mint(led)
    assert led.consume_token("s1", tool_name="Bash", args_hash=ARGS) == "allow_once"


def test_a_token_does_not_consume_twice(led):
    """The retry loop this defends against is real: a blocked tool call comes
    back with identical arguments, and exactly one of those attempts was
    consented to."""
    _mint(led)
    led.consume_token("s1", tool_name="Bash", args_hash=ARGS)
    assert led.consume_token("s1", tool_name="Bash", args_hash=ARGS) is None


def test_a_second_mint_for_the_same_call_replaces_the_first(led):
    """Two consents for one call are still one pass, and the newer consent's
    mode is the one spent."""
    _mint(led, mode="allow_once")
    _mint(led, mode="minimize")
    assert led.conn.execute(
        "SELECT count(*) FROM policy_tokens").fetchone()[0] == 1
    assert led.consume_token("s1", tool_name="Bash", args_hash=ARGS) == "minimize"
    assert led.consume_token("s1", tool_name="Bash", args_hash=ARGS) is None


def test_a_mint_does_not_replace_a_token_for_another_call(led):
    _mint(led)
    _mint(led, args_hash=b"\x09" * 32)
    _mint(led, "s2")
    assert led.conn.execute(
        "SELECT count(*) FROM policy_tokens").fetchone()[0] == 3


def test_tokens_work_in_a_ledger_that_still_has_the_consumed_column(tmp_path):
    """Ledgers created before the column was dropped keep it (SCHEMA is
    CREATE TABLE IF NOT EXISTS). Its DEFAULT 0 is what lets the new INSERT
    omit it."""
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE policy_tokens (token TEXT PRIMARY KEY, session_id TEXT NOT"
        " NULL, tool_name TEXT NOT NULL, args_hash BLOB NOT NULL, mode TEXT NOT"
        " NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)")
    conn.commit()
    conn.close()
    old = Ledger(path, M)
    _mint(old)
    assert old.consume_token("s1", tool_name="Bash", args_hash=ARGS) == "allow_once"


def test_a_token_does_not_authorize_a_different_argument_set(led):
    _mint(led)
    assert led.consume_token("s1", tool_name="Bash",
                             args_hash=OTHER_ARGS) is None


def test_a_rejected_argument_set_does_not_spend_the_token(led):
    """A near miss must not burn the consent the user actually gave."""
    _mint(led)
    led.consume_token("s1", tool_name="Bash", args_hash=OTHER_ARGS)
    assert led.consume_token("s1", tool_name="Bash", args_hash=ARGS) == "allow_once"


def test_a_token_does_not_authorize_a_different_tool(led):
    _mint(led, tool_name="Bash")
    assert led.consume_token("s1", tool_name="apply_patch",
                             args_hash=ARGS) is None


def test_a_token_does_not_authorize_another_session(led):
    _mint(led, "s1")
    assert led.consume_token("s2", tool_name="Bash", args_hash=ARGS) is None


def test_an_expired_token_is_not_consumable(led):
    _mint(led, ttl_seconds=-1)
    assert led.consume_token("s1", tool_name="Bash", args_hash=ARGS) is None


def test_the_minted_mode_comes_back_verbatim(led):
    _mint(led, mode="minimize")
    assert led.consume_token("s1", tool_name="Bash", args_hash=ARGS) == "minimize"


def test_no_token_reads_as_none_rather_than_raising(led):
    assert led.consume_token("s1", tool_name="Bash", args_hash=ARGS) is None


def test_tokens_are_opaque_and_unguessable(led):
    """A bearer credential: a caller who could predict the next one could
    authorize a call the user never saw."""
    a, b = _mint(led), _mint(led)
    assert a != b
    assert len(a) == 32 and all(c in "0123456789abcdef" for c in a)


def test_consuming_removes_the_row(led):
    _mint(led)
    led.consume_token("s1", tool_name="Bash", args_hash=ARGS)
    assert led.conn.execute(
        "SELECT count(*) FROM policy_tokens").fetchone()[0] == 0


def test_policy_tokens_hold_no_arguments(led):
    """I1: the token row says a call was consented to, never what the call
    was — `args_hash` is a hash the ledger cannot invert."""
    cols = {r[1] for r in led.conn.execute("PRAGMA table_info(policy_tokens)")}
    assert cols == {"token", "session_id", "tool_name", "args_hash", "mode",
                    "expires_at"}
    banned = {"tool_input", "args", "command", "content", "prompt", "text"}
    assert not cols & banned


def test_an_older_ledger_gains_the_source_kind_column(tmp_path):
    """The schema is applied with CREATE TABLE IF NOT EXISTS, which does not
    add columns to a database that already exists. Without the migration,
    every insert against a pre-existing ledger raises OperationalError."""
    import sqlite3

    from privacy_hud.ledger import Ledger
    from privacy_hud.matrix.loader import load_matrix

    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE sessions (
          session_id TEXT PRIMARY KEY, started_at INTEGER NOT NULL,
          ended_at INTEGER, cwd TEXT, model TEXT,
          budget_score REAL NOT NULL DEFAULT 0,
          budget_cap REAL NOT NULL DEFAULT 120);
        CREATE TABLE events (
          id INTEGER PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions,
          turn_id TEXT, ts INTEGER NOT NULL, kind TEXT NOT NULL,
          data_type TEXT NOT NULL, source TEXT NOT NULL,
          destination TEXT NOT NULL, boundary TEXT NOT NULL,
          count INTEGER NOT NULL DEFAULT 1, value_hash BLOB,
          masked_example TEXT, budget_delta REAL NOT NULL DEFAULT 0,
          protection TEXT, tool_name TEXT,
          UNIQUE(session_id, value_hash, destination));
        INSERT INTO sessions(session_id, started_at) VALUES ('s1', 1);
        INSERT INTO events(session_id, ts, kind, data_type, source,
                           destination, boundary)
             VALUES ('s1', 1, 'exposed', 'email', 'Bash', 'model_context', 'B1');
    """)
    conn.commit()
    conn.close()

    led = Ledger(path, load_matrix())
    columns = {r["name"] for r in led.conn.execute("PRAGMA table_info(events)")}
    assert "source_kind" in columns
    # The row written before the migration keeps NULL: nothing knows where
    # it came from, and a guess would be worse than an absence.
    assert led.conn.execute(
        "SELECT source_kind FROM events WHERE id=1").fetchone()[0] is None
    led.conn.close()


def test_migrating_twice_is_a_no_op(tmp_path):
    from privacy_hud.ledger import Ledger
    from privacy_hud.matrix.loader import load_matrix

    path = tmp_path / "twice.db"
    Ledger(path, load_matrix()).conn.close()
    led = Ledger(path, load_matrix())
    columns = [r["name"] for r in led.conn.execute("PRAGMA table_info(events)")]
    assert columns.count("source_kind") == 1
    led.conn.close()


def test_record_stores_the_source_kind(led):
    led.start_session("s1", cwd="/w", model="m")
    led.record("s1", turn_id="t1", kind="exposed", data_type="credential",
               source=".env", destination="model_context",
               value_hash=b"\x01" * 16, masked_example=None,
               tool_name="Bash", protection=None, source_kind="path")
    row = led.conn.execute("SELECT source, source_kind FROM events").fetchone()
    assert (row["source"], row["source_kind"]) == (".env", "path")


def test_record_defaults_source_kind_to_null(led):
    led.start_session("s1", cwd="/w", model="m")
    led.record("s1", turn_id="t1", kind="exposed", data_type="email",
               source="Bash", destination="model_context",
               value_hash=b"\x02" * 16, masked_example="jo•••@acme.com",
               tool_name="Bash", protection=None)
    assert led.conn.execute(
        "SELECT source_kind FROM events").fetchone()["source_kind"] is None


# ---------------------------------------------------------------------------
# scan_gaps: the deep scans that did not run (#47 items 1 and 6).
# ---------------------------------------------------------------------------

def test_the_gap_reasons_the_engine_writes_are_the_ones_this_schema_documents():
    """`record_scan_gap` cannot validate `reason` — `ledger` is imported BY
    `engine`, so it cannot import the taxonomy back. This is the check that
    stands in for that validation, and it is the reason the docstring can
    promise the two lists agree.

    A reason the schema comment does not list is not a cosmetic mismatch: the
    comment is what a reader consults to find out what a row means, and a
    value it does not mention reads as data nobody wrote down on purpose."""
    from privacy_hud import engine

    written = {engine.GAP_OVERSIZE, engine.GAP_UNAVAILABLE,
               engine.GAP_BUSY, engine.GAP_TIMEOUT}
    line = next(ln for ln in SCHEMA.splitlines() if "oversize|" in ln)
    documented = set(line.split("--")[1].strip().split("|"))
    assert written == documented


def test_a_gap_makes_the_session_unverified_and_names_the_count(led):
    assert led.coverage("s1").verified is True
    led.record_scan_gap("s1", boundary="B3", reason="timeout")
    led.record_scan_gap("s1", boundary="B3", reason="busy")

    cov = led.coverage("s1")
    assert cov.shallow_scans == 2
    assert cov.verified is False
    assert cov.reason == "2 observations got the fast detectors only"


def test_one_gap_reads_as_singular(led):
    led.record_scan_gap("s1", boundary="B4", reason="oversize")
    assert led.coverage("s1").reason == "1 observation got the fast detectors only"


def test_gaps_are_not_deduped(led):
    """Append-only, and deliberately not `INSERT OR IGNORE` like `coverage`:
    two outbound calls that each lost their deep scan are two lost scans, and
    collapsing them would under-report exactly the burst case the admission
    control in `engine` exists to handle."""
    for _ in range(3):
        led.record_scan_gap("s1", boundary="B3", reason="busy")
    assert led.scan_gaps("s1") == 3


def test_a_gap_in_another_session_does_not_count_against_this_one(led):
    led.start_session("s2", cwd="/repo", model="gpt-5")
    led.record_scan_gap("s2", boundary="B3", reason="timeout")
    assert led.scan_gaps("s1") == 0
    assert led.coverage("s1").verified is True


def test_a_gap_row_holds_nothing_about_what_the_payload_contained(led):
    """I1, checked at the schema rather than trusted: this table records a
    scan that did not happen, and a scan that did not happen has even less
    business holding content than one that did."""
    led.record_scan_gap("s1", boundary="B3", reason="timeout")
    row = dict(led.conn.execute("SELECT * FROM scan_gaps").fetchone())
    assert set(row) == {"id", "session_id", "ts", "boundary", "reason"}
