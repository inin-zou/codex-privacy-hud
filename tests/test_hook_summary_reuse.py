from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from privacy_hud import dispatch as dispatch_mod
from privacy_hud import hud_snapshot as hs
from privacy_hud.accounting import AccountingSummary
from privacy_hud.detect.secrets import SecretDetector
from runtime_helpers import close_writer, writer_state_with_detectors


SID = "summary-reuse"
CREDENTIAL = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def st(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    state = writer_state_with_detectors(
        tmp_path, detectors=[SecretDetector()]
    )
    # Prompt confirmation must not depend on machine speed.
    state.prompt_clock = lambda: 100.0
    yield state
    close_writer(state.ledger)


def send(st, event, *, key="1" * 32, **fields):
    return dispatch_mod.dispatch(
        st,
        {
            "hook_event_name": event,
            "session_id": SID,
            **fields,
        },
        delivery_key=key,
    )


def start(st, *, legacy=False):
    if legacy:
        st.ledger.start_session(SID, cwd="/synthetic", model="test")
    assert send(st, "SessionStart") == {}


def result(st, *, key="2" * 32):
    return send(
        st,
        "PostToolUse",
        key=key,
        tool_name="Read",
        tool_use_id=key,
        tool_input={"file_path": "/synthetic/notes.txt"},
        tool_response=CREDENTIAL,
    )


def watch(st, monkeypatch):
    readings = []
    publications = []
    decisions = []
    coverage_calls = []

    original_summary = st.ledger.summary
    original_coverage = st.ledger.coverage
    original_publish = st.hud.publish
    original_output = dispatch_mod._decision_to_output

    def summary(sid):
        value = original_summary(sid)
        readings.append((sid, value))
        return value

    def coverage(sid):
        coverage_calls.append(sid)
        return original_coverage(sid)

    def publish(sid, *, summary, unverified):
        assert not st.ledger.conn.in_transaction
        publications.append((sid, summary, unverified))
        return original_publish(
            sid, summary=summary, unverified=unverified
        )

    def output(decision, *, hook_event):
        decisions.append(decision)
        return original_output(decision, hook_event=hook_event)

    monkeypatch.setattr(st.ledger, "summary", summary)
    monkeypatch.setattr(st.ledger, "coverage", coverage)
    monkeypatch.setattr(st.hud, "publish", publish)
    monkeypatch.setattr(dispatch_mod, "_decision_to_output", output)

    return readings, publications, decisions, coverage_calls


@pytest.mark.parametrize(
    ("legacy", "path"),
    [
        (False, "result"),
        (False, "hold"),
        (False, "metadata"),
        (False, "ended"),
        (True, "result"),
        (True, "hold"),
        (True, "ended"),
    ],
)
def test_one_committed_reading_supplies_decision_and_snapshot(
    st, tmp_path, monkeypatch, legacy, path
):
    start(st, legacy=legacy)
    if path == "ended":
        send(st, "SessionEnd")

    # Freeze only the snapshot writer's clock, not global time.
    monkeypatch.setattr(
        hs, "time", SimpleNamespace(time=lambda: 1234567890.0)
    )
    readings, publications, decisions, coverage_calls = watch(
        st, monkeypatch
    )

    if path == "hold":
        out = send(st, "UserPromptSubmit", prompt=CREDENTIAL)
        assert out["decision"] == "block"
    elif path == "metadata":
        assert send(st, "PreCompact") == {}
    else:
        assert result(st) == {}

    assert len(readings) == 1
    assert len(publications) == 1
    assert len(decisions) == 1
    assert coverage_calls == [SID]

    summary = readings[0][1]
    assert publications[0][1] is summary
    expected_pct = (
        summary.percent
        if isinstance(summary, AccountingSummary)
        else summary.legacy_percent
    )
    assert decisions[0].budget_percent == expected_pct

    # Compare serialized bytes with a fresh projection through the
    # unchanged publisher, including field order, hidden state and nulls.
    snapshot = hs.snapshot_path(tmp_path, SID)
    actual = snapshot.read_bytes()
    fresh = st.ledger.summary(SID)
    fresh_coverage = st.ledger.coverage(SID)
    st.hud.publish(
        SID, summary=fresh, unverified=not fresh_coverage.verified
    )
    assert snapshot.read_bytes() == actual


@pytest.mark.parametrize("keyless", [False, True])
def test_attachment_keeps_two_distinct_publications(
    st, monkeypatch, keyless
):
    if keyless:
        start(st)
        st.engines.clear()
        st.accounting_keys.clear()

    readings, publications, decisions, coverage_calls = watch(
        st, monkeypatch
    )
    out = send(st, "UserPromptSubmit", prompt=CREDENTIAL)
    assert out["decision"] == "block"

    assert len(readings) == 2
    assert len(publications) == 2
    assert len(decisions) == 1
    assert coverage_calls == [SID, SID]

    before = publications[0][1]
    after = publications[1][1]
    assert before is readings[0][1]
    assert after is readings[1][1]
    if keyless:
        # A keyless version-2 session records no counted denial: its
        # accounting is unavailable, so both readings carry zero (base
        # behavior, unchanged). They are still two separate readings.
        assert before is not after
        assert (before.denials_issued, after.denials_issued) == (0, 0)
        assert after.percentage_unavailable_reasons == (
            "accounting_unavailable",)
    else:
        assert (
            before.legacy_prevented_rows,
            after.legacy_prevented_rows,
        ) == (0, 1)


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("rollback", [False, True])
def test_observe_outer_transaction_finishes_before_summary(
    st, tmp_path, monkeypatch, legacy, rollback
):
    start(st, legacy=legacy)
    snapshot = hs.snapshot_path(tmp_path, SID)
    before = snapshot.read_bytes()
    engine = st.engines[SID]
    original_observe = engine.observe
    original_summary = st.ledger.summary
    read_transactions = []

    def summary(sid):
        read_transactions.append(st.ledger.conn.in_transaction)
        return original_summary(sid)

    def observe(*args, **kwargs):
        with st.ledger._write_transaction():
            decision = original_observe(*args, **kwargs)
            if rollback:
                raise RuntimeError("synthetic rollback")
        return decision

    monkeypatch.setattr(st.ledger, "summary", summary)
    monkeypatch.setattr(engine, "observe", observe)

    if rollback:
        with pytest.raises(RuntimeError, match="synthetic rollback"):
            result(st)
        assert snapshot.read_bytes() == before
        assert read_transactions == []
    else:
        assert result(st) == {}
        assert read_transactions == [False]


def test_dispatch_cannot_publish_an_outer_uncommitted_write(
    st, tmp_path
):
    start(st)
    snapshot = hs.snapshot_path(tmp_path, SID)
    before = snapshot.read_bytes()
    observations_before = st.ledger.conn.execute(
        "SELECT COUNT(*) FROM observations WHERE session_id=?", (SID,)
    ).fetchone()[0]

    with pytest.raises(
        RuntimeError, match="hook summary requires a committed ledger"
    ):
        with st.ledger._write_transaction():
            result(st)

    assert snapshot.read_bytes() == before
    assert st.ledger.conn.execute(
        "SELECT COUNT(*) FROM observations WHERE session_id=?", (SID,)
    ).fetchone()[0] == observations_before


def test_standalone_publication_refuses_uncommitted_state(
    st, monkeypatch
):
    start(st)
    publications = []

    def publish(*args, **kwargs):
        publications.append((args, kwargs))

    monkeypatch.setattr(st.hud, "publish", publish)

    with st.ledger._write_transaction():
        dispatch_mod._publish_hud(st, SID)

    assert publications == []


@pytest.mark.parametrize("legacy", [False, True])
def test_hold_summary_failure_keeps_block_and_does_not_publish(
    st, tmp_path, monkeypatch, legacy
):
    start(st, legacy=legacy)
    snapshot = hs.snapshot_path(tmp_path, SID)
    before = snapshot.read_bytes()
    publications = []

    def fail_summary(sid):
        assert not st.ledger.conn.in_transaction
        raise RuntimeError("synthetic summary failure")

    def publish(*args, **kwargs):
        publications.append((args, kwargs))

    monkeypatch.setattr(st.ledger, "summary", fail_summary)
    monkeypatch.setattr(st.hud, "publish", publish)

    out = send(st, "UserPromptSubmit", prompt=CREDENTIAL)
    assert out["decision"] == "block"
    assert "Ledger recording failed; this hold may be missing" in out["reason"]
    assert "synthetic summary failure" not in out["reason"]
    assert publications == []
    assert snapshot.read_bytes() == before
    assert st.engines[SID].prompt_gate.pending


def test_growing_session_projection_cost(st):
    start(st)
    conn = st.ledger.conn
    old_factory = conn.row_factory
    current = None
    statements = {"observations": 0, "events": 0}
    rows = {"observations": 0, "events": 0}
    samples = []

    def trace(sql):
        nonlocal current
        normalized = " ".join(sql.lower().split())
        if normalized.startswith(
            "select * from observations where session_id="
        ) and normalized.endswith("order by rowid"):
            current = "observations"
        elif normalized.startswith(
            "select e.*, s.resolution as subject_resolution,"
        ) and normalized.endswith("order by e.id"):
            current = "events"
        else:
            current = None
        if current is not None:
            statements[current] += 1

    def row_factory(cursor, row):
        if current is not None:
            rows[current] += 1
        return old_factory(cursor, row) if old_factory else row

    conn.set_trace_callback(trace)
    conn.row_factory = row_factory
    try:
        for n in range(1, 129):
            for name in statements:
                statements[name] = 0
                rows[name] = 0
            assert result(st, key=f"{n:032x}") == {}
            if n in (1, 8, 32, 128):
                sample = {
                    "deliveries": n,
                    "observation_selects": statements["observations"],
                    "event_selects": statements["events"],
                    "observation_rows": rows["observations"],
                    "event_rows": rows["events"],
                }
                samples.append(sample)
                print("hook-summary-cost " + json.dumps(sample, sort_keys=True))
    finally:
        conn.set_trace_callback(None)
        conn.row_factory = old_factory

    # Assert after collecting every sample, so RED also prints its curve.
    for sample in samples:
        n = sample["deliveries"]
        assert sample["observation_selects"] == 1
        assert sample["event_selects"] == 1
        assert sample["observation_rows"] == n + 1
        assert sample["event_rows"] == n
