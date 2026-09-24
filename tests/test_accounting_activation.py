"""#54 Phase 4 P4-C3: accounting activation and production key ownership.

A genuine `SessionStart` for an absent session activates version-2
accounting: the session, its frozen profile, its start coverage and its
start observation commit in one outermost write transaction under the
daemon's current writer lease, and the ledger becomes generation 5402. The
daemon's accounting key for that session is installed only after that
COMMIT. Replays, lazy attachments, ended sessions and empty probes keep
their contracts, and a new process never inherits a key it did not create.

Every ledger here is synthetic, under a temporary directory.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import time
from pathlib import Path

import pytest

from privacy_hud import codex, ledger_schema
from privacy_hud import dispatch as dispatch_mod
from privacy_hud.accounting import Evidence, ObservationRecord, ScoringProfile
from privacy_hud.ledger import Ledger, UnsupportedAccounting
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.runtime_contract import RuntimeRefusal
from runtime_helpers import (
    REPO,
    close_writer,
    write_receipt_v2,
    writer_ledger,
    writer_state,
)

M = load_matrix()
PROFILE = ScoringProfile.from_matrix(M)
OUTERMOST = "accounted session start requires an outermost transaction"
REPO_BUILD = __import__("json").loads(
    (REPO / "runtime-build.json").read_text())["build_id"]


class Crash(Exception):
    """A simulated process death at a chosen point."""


# --------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------- #

def start_observation(sid: str, /, **changes) -> ObservationRecord:
    values = dict(
        session_id=sid, delivery_key=secrets.token_hex(16),
        action_id=secrets.token_hex(16), turn_id=None, ts=int(time.time()),
        hook_event="SessionStart", phase="lifecycle",
        action_kind="lifecycle", boundary="B0", decision="none",
        evidence=Evidence.HOOK_OBSERVED, resolution_scope="none",
        potential_crossing=False, scan_gap=None)
    values.update(changes)
    return ObservationRecord(**values)


def activating_state(data_dir: Path):
    """The daemon's state, with activation of genuine starts enabled."""
    state = writer_state(data_dir)
    state.accounting_activation = True
    return state


def start(state, sid: str, **extra) -> dict:
    return dispatch_mod.dispatch(state, {
        "hook_event_name": "SessionStart", "session_id": sid, "cwd": "/w",
        "model": "gpt-5", **extra})


def restart(state, data_dir: Path):
    """Close this state's writer as a crashed process would lose it: no
    SessionEnd, no cleanup. Then build a fresh daemon state."""
    close_writer(state.ledger)
    return writer_state(data_dir)


def raw(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro",
                           uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def version(path: Path) -> int:
    conn = raw(path)
    try:
        return conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()


def schema(conn) -> list[tuple]:
    return sorted(tuple(r) for r in conn.execute(
        "SELECT type, name, sql FROM sqlite_master"))


def cells(conn) -> dict[str, list[tuple]]:
    out = {}
    for (name,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"):
        out[name] = sorted(
            (tuple((type(v).__name__, v) for v in tuple(row))
             for row in conn.execute(f'SELECT * FROM "{name}"')), key=repr)
    return out


def image(path: Path) -> tuple:
    conn = raw(path)
    try:
        return (conn.execute("PRAGMA user_version").fetchone()[0],
                schema(conn), cells(conn))
    finally:
        conn.close()


def session_row(conn, sid):
    return conn.execute("SELECT * FROM sessions WHERE session_id=?",
                        (sid,)).fetchone()


def count(conn, table: str, sid: str | None = None) -> int:
    if sid is None:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE session_id=?",
                        (sid,)).fetchone()[0]


def seed_legacy(path: Path) -> None:
    """A generation-0 ledger with a legacy session and rows."""
    led = writer_ledger(path, M)
    led.start_session("old1", cwd="/r", model="m")
    led.record("old1", turn_id="t1", kind="exposed", data_type="email",
               source="a.log", destination="model_context",
               value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
               tool_name="Read", protection=None)
    close_writer(led)


def seed_prepared(path: Path) -> None:
    """Generation 5401: a legacy session, the Phase 2 boundary, and legacy
    rows preserved in `events_legacy_v1`."""
    seed_legacy(path)
    led = writer_ledger(path, M)
    with led._write_transaction():
        led.prepare_session_boundary("boundary")
        led.start_session("boundary", cwd="", model="")
    close_writer(led)


def seed_activated_ledger(path: Path, *, lease_root: Path | None = None
                          ) -> str:
    """A valid generation-5402 ledger built without the activation API: a
    prepared ledger, one synthetic version-2 session, then the marker. The
    activated layout is the prepared layout, so this is a well-formed 5402
    store. Returns the version-2 session ID."""
    from privacy_hud.runtime_owner import acquire_writer, unselected_activation

    path.parent.mkdir(parents=True, exist_ok=True)
    owner = lease_root or (path.parent / "seed-owner")
    lease = acquire_writer(owner, activation=unselected_activation())
    try:
        led = Ledger(path, M, writer_lease=lease)
        led.start_session("old1", cwd="/r", model="m")
        led.record("old1", turn_id="t1", kind="exposed", data_type="email",
                   source="a.log", destination="model_context",
                   value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
                   tool_name="Read", protection=None)
        with led._write_transaction():
            led.prepare_session_boundary("boundary")
            led.start_session("boundary", cwd="", model="")
        sid = "v2-seeded"
        with led._write_transaction():
            led._start_v2_session(sid, cwd="", model="", profile=PROFILE)
        led.conn.execute(
            f"PRAGMA user_version = {ledger_schema.ACTIVATED_VERSION}")
        led.conn.close()
    finally:
        lease.close()
    return sid


# --------------------------------------------------------------------- #
# activation through dispatch
# --------------------------------------------------------------------- #

def test_only_absent_sessionstart_activates_v2(tmp_path):
    state = activating_state(tmp_path)
    path = tmp_path / "ledger.db"
    try:
        # A session this daemon first met lazily stays legacy.
        dispatch_mod.dispatch(state, {"hook_event_name": "UserPromptSubmit",
                                      "session_id": "lazy", "prompt": "hi"})
        start(state, "new")
        start(state, "lazy")
        conn = state.ledger.conn
        assert session_row(conn, "new")["accounting_version"] == 2
        assert session_row(conn, "lazy")["accounting_version"] == 1
        assert version(path) == ledger_schema.ACTIVATED_VERSION
        key = state.accounting_keys["new"]
        assert type(key) is bytes and len(key) == 32
        assert state.engines["new"].accounting_key is key
        assert "lazy" not in state.accounting_keys
        rows = conn.execute(
            "SELECT hook_event, phase, action_kind, boundary, decision,"
            " evidence, resolution_scope, potential_crossing, scan_gap"
            " FROM observations WHERE session_id='new'").fetchall()
        assert [tuple(r) for r in rows] == [
            ("SessionStart", "lifecycle", "lifecycle", "B0", "none",
             int(Evidence.HOOK_OBSERVED), "none", 0, None)]
        coverage = [r[0] for r in conn.execute(
            "SELECT reason FROM coverage WHERE session_id='new'")]
        assert coverage == ["session_start"]
        stored = conn.execute("SELECT cwd, model FROM sessions"
                              " WHERE session_id='new'").fetchone()
        assert tuple(stored) == (None, None)
    finally:
        state.ledger.conn.close()


def test_activation_from_5401_preserves_original_sessions(tmp_path):
    path = tmp_path / "ledger.db"
    seed_prepared(path)
    before = image(path)
    assert before[0] == ledger_schema.PREPARED_VERSION
    state = activating_state(tmp_path)
    try:
        start(state, "new")
    finally:
        state.ledger.conn.close()
    after = image(path)
    assert after[0] == ledger_schema.ACTIVATED_VERSION
    assert after[1] == before[1], "5401 activation must run no DDL"
    for table, rows in before[2].items():
        if table in ("sessions", "coverage"):
            assert set(rows) <= set(after[2][table]), table
        elif table in ("scoring_profiles", "observations"):
            continue
        else:
            assert after[2][table] == rows, table
    conn = raw(path)
    try:
        for sid in ("old1", "boundary"):
            assert session_row(conn, sid)["accounting_version"] == 1
    finally:
        conn.close()


def test_direct_upgrade_is_one_transaction(tmp_path, monkeypatch):
    path = tmp_path / "ledger.db"
    seed_legacy(path)
    before = image(path)
    statements = len(ledger_schema.migration_statements())

    def crash_at(n):
        seen = []

        def failpoint(_statement):
            seen.append(1)
            if len(seen) == n:
                raise Crash()
        return failpoint

    led = writer_ledger(path, M)
    try:
        # A crash after each migration statement.
        for n in range(1, statements + 1):
            led._migration_failpoint = crash_at(n)
            with pytest.raises(Crash):
                led.start_accounted_session(
                    "new", cwd="", model="", profile=PROFILE,
                    start_observation=start_observation("new"))
            assert image(path) == before, n
        led._migration_failpoint = None
        # A crash while recording the start observation, and while
        # validating the activated schema, before COMMIT.
        for target in ("_record_observation", "validate"):
            with monkeypatch.context() as patch:
                if target == "validate":
                    real = ledger_schema.validate_schema

                    def fail_on_5402(conn, real=real):
                        found = real(conn)
                        if found == ledger_schema.ACTIVATED_VERSION:
                            raise Crash()
                        return found
                    patch.setattr(ledger_schema, "validate_schema",
                                  fail_on_5402)
                else:
                    def boom(self, *args, **kwargs):
                        raise Crash()
                    patch.setattr(Ledger, target, boom)
                with pytest.raises(Crash):
                    led.start_accounted_session(
                        "new", cwd="", model="", profile=PROFILE,
                        start_observation=start_observation("new"))
            assert image(path) == before, target
        # After COMMIT: the complete activated generation.
        assert led.start_accounted_session(
            "new", cwd="", model="", profile=PROFILE,
            start_observation=start_observation("new")) is True
    finally:
        led.conn.close()
    after = image(path)
    assert after[0] == ledger_schema.ACTIVATED_VERSION
    conn = raw(path)
    try:
        assert ledger_schema.validate_schema(conn) == \
            ledger_schema.ACTIVATED_VERSION
        assert session_row(conn, "new")["accounting_version"] == 2
    finally:
        conn.close()


def test_start_accounted_session_returns_only_after_commit(tmp_path):
    path = tmp_path / "ledger.db"
    led = writer_ledger(path, M)
    trace: list[str] = []
    try:
        for outer in (led._write_transaction, led._read_transaction):
            with outer():
                with pytest.raises(RuntimeError) as refused:
                    led.start_accounted_session(
                        "nested", cwd="", model="", profile=PROFILE,
                        start_observation=start_observation("nested"))
                assert str(refused.value) == OUTERMOST
        assert not led.session_exists("nested")
        led.conn.set_trace_callback(trace.append)
        assert led.start_accounted_session(
            "s1", cwd="", model="", profile=PROFILE,
            start_observation=start_observation("s1")) is True
        led.conn.set_trace_callback(None)
        assert trace[-1].strip().upper() == "COMMIT"
        assert not led.conn.in_transaction
        # An existing ID returns False and changes nothing.
        before = image(path)
        assert led.start_accounted_session(
            "s1", cwd="", model="", profile=PROFILE,
            start_observation=start_observation("s1")) is False
        assert image(path) == before
    finally:
        led.conn.close()

    # Through dispatch: no key is installed while the call is in progress.
    state = activating_state(tmp_path / "d")
    seen = []
    real = Ledger.start_accounted_session

    def spy(self, session_id, **kwargs):
        seen.append(dict(state.accounting_keys))
        result = real(self, session_id, **kwargs)
        seen.append(dict(state.accounting_keys))
        return result

    try:
        Ledger.start_accounted_session = spy  # type: ignore[method-assign]
        start(state, "watched")
    finally:
        Ledger.start_accounted_session = real  # type: ignore[method-assign]
        state.ledger.conn.close()
    assert seen == [{}, {}]
    assert "watched" in state.accounting_keys


def test_activation_commit_failure_installs_no_identity(tmp_path,
                                                        monkeypatch):
    state = activating_state(tmp_path)
    path = tmp_path / "ledger.db"
    try:
        start(state, "first")
        before = image(path)
        lease = state.ledger._lease
        real = lease.assert_current

        def refuse_once_written():
            real()
            conn = state.ledger.conn
            if conn.in_transaction and conn.execute(
                    "SELECT 1 FROM sessions WHERE session_id='second'"
            ).fetchone():
                raise RuntimeRefusal("runtime_mismatch")

        monkeypatch.setattr(lease, "assert_current", refuse_once_written)
        with pytest.raises(RuntimeRefusal):
            start(state, "second")
        monkeypatch.undo()
        assert image(path) == before
        for table in (state.accounting_keys, state.engines, state.salts,
                      state.started_at):
            assert "second" not in table
        assert set(state.accounting_keys) == {"first"}
    finally:
        state.ledger.conn.close()


def test_existing_v2_start_preserves_key_profile_cap_and_time(tmp_path):
    state = activating_state(tmp_path)
    try:
        start(state, "s1")
        conn = state.ledger.conn
        key = state.accounting_keys["s1"]
        engine = state.engines["s1"]
        salt = state.salts["s1"]
        started = state.started_at["s1"]
        row = tuple(session_row(conn, "s1"))
        counts = (count(conn, "observations", "s1"),
                  count(conn, "coverage", "s1"),
                  count(conn, "scoring_profiles"))
        start(state, "s1", cwd="/other", model="other-model")
        dispatch_mod.dispatch(state, {"hook_event_name": "SessionStart",
                                      "session_id": "s1"},
                              delivery_key="f" * 32)
        assert state.accounting_keys["s1"] is key
        assert state.engines["s1"] is engine
        assert state.salts["s1"] is salt
        assert state.started_at["s1"] == started
        assert tuple(session_row(conn, "s1")) == row
        assert (count(conn, "observations", "s1"),
                count(conn, "coverage", "s1"),
                count(conn, "scoring_profiles")) == counts
    finally:
        state.ledger.conn.close()


def test_5402_writer_reopens_without_schema_changes(tmp_path):
    """The 0.9.0 writer initializes a valid activated ledger without DDL,
    a generation change or a changed cell."""
    path = tmp_path / "ledger.db"
    sid = seed_activated_ledger(path)
    before = image(path)
    assert before[0] == ledger_schema.ACTIVATED_VERSION
    led = writer_ledger(path, M)
    try:
        assert led.summary(sid).accounting_version == 2
    finally:
        led.conn.close()
    assert image(path) == before


def test_restart_marks_open_v2_unavailable_before_publication(
        tmp_path, monkeypatch):
    from legacy_fakes import legacy_summary

    from privacy_hud import hud_snapshot as hs

    state = activating_state(tmp_path)
    start(state, "open1")
    start(state, "done")
    with state.lock:
        state.ledger.end_session("done")
        dispatch_mod._discard_session_identity(state, "done")
    # An inherited reading for the open session, as an older process left it.
    state.hud.publish("open1", summary=legacy_summary(40), unverified=False)
    snapshot = hs.snapshot_path(tmp_path, "open1")
    assert snapshot.exists()
    close_writer(state.ledger)

    path = tmp_path / "ledger.db"
    observed = []
    real_sweep = hs.HudPublisher.sweep

    def sweep(self, *args, **kwargs):
        conn = raw(path)
        try:
            observed.append(session_row(conn, "open1")["accounting_status"])
        finally:
            conn.close()
        return real_sweep(self, *args, **kwargs)

    monkeypatch.setattr(hs.HudPublisher, "sweep", sweep)
    fresh = writer_state(tmp_path)
    fresh.accounting_activation = True
    try:
        assert observed == ["unavailable"]
        conn = fresh.ledger.conn
        assert session_row(conn, "open1")["accounting_status"] == \
            "unavailable"
        assert session_row(conn, "done")["accounting_status"] == "available"
        assert not snapshot.exists()
        assert "open1" not in fresh.hud._published
        assert fresh.accounting_keys == {}
        start(fresh, "open1")
        assert "open1" not in fresh.accounting_keys
        engine = fresh.engines.get("open1")
        assert engine is None or engine.accounting_key is None
        assert session_row(conn, "open1")["accounting_status"] == \
            "unavailable"
    finally:
        fresh.ledger.conn.close()


def test_crash_after_activation_commit_does_not_replace_key(tmp_path):
    state = activating_state(tmp_path)
    start(state, "s1")
    old_key = state.accounting_keys["s1"]
    fresh = restart(state, tmp_path)
    fresh.accounting_activation = True
    try:
        conn = fresh.ledger.conn
        row = session_row(conn, "s1")
        assert row["accounting_version"] == 2
        assert row["accounting_status"] == "unavailable"
        assert count(conn, "observations", "s1") == 1
        assert version(tmp_path / "ledger.db") == \
            ledger_schema.ACTIVATED_VERSION
        start(fresh, "s1")
        dispatch_mod.dispatch(fresh, {"hook_event_name": "UserPromptSubmit",
                                      "session_id": "s1", "prompt": "hi"})
        assert "s1" not in fresh.accounting_keys
        assert old_key not in fresh.accounting_keys.values()
        engine = fresh.engines.get("s1")
        assert engine is None or engine.accounting_key is None
        assert session_row(conn, "s1")["accounting_status"] == "unavailable"
    finally:
        fresh.ledger.conn.close()


def test_lazy_attachment_after_activation_is_legacy(tmp_path):
    state = activating_state(tmp_path)
    try:
        start(state, "genuine")
        dispatch_mod.dispatch(state, {"hook_event_name": "UserPromptSubmit",
                                      "session_id": "late", "prompt": "hi"})
        conn = state.ledger.conn
        assert session_row(conn, "genuine")["accounting_version"] == 2
        assert session_row(conn, "late")["accounting_version"] == 1
        assert [r[0] for r in conn.execute(
            "SELECT reason FROM coverage WHERE session_id='late'")] == \
            ["attached"]
        assert "late" not in state.accounting_keys
        assert version(tmp_path / "ledger.db") == \
            ledger_schema.ACTIVATED_VERSION
    finally:
        state.ledger.conn.close()


def test_empty_session_probe_is_read_only(tmp_path):
    state = activating_state(tmp_path)
    path = tmp_path / "ledger.db"
    try:
        start(state, "real")
        before = image(path)
        live = dict(state.live)
        for event in sorted(codex.KNOWN_EVENTS):
            for sid in ("", None, 5, ["x"]):
                payload = {"hook_event_name": event, "prompt": "hi",
                           "tool_name": "Read",
                           "tool_input": {"file_path": "/r/a"},
                           "tool_response": "contact jordan@acme.com"}
                if sid is not None:
                    payload["session_id"] = sid
                dispatch_mod.dispatch(state, payload)
        assert image(path) == before
        assert state.live == live
        assert set(state.accounting_keys) == {"real"}
    finally:
        state.ledger.conn.close()


def test_synthetic_constructor_still_requires_5401(tmp_path):
    """Regression gate: the private Phase 3 constructor keeps its
    generation-5401-only contract."""
    path = tmp_path / "ledger.db"
    seed_prepared(path)
    led = writer_ledger(path, M)
    try:
        with led._write_transaction():
            led._start_v2_session("ok", cwd="", model="", profile=PROFILE)
        led.conn.execute(
            f"PRAGMA user_version = {ledger_schema.ACTIVATED_VERSION}")
        with pytest.raises(UnsupportedAccounting):
            with led._write_transaction():
                led._start_v2_session("refused", cwd="", model="",
                                      profile=PROFILE)
        assert not led.session_exists("refused")
    finally:
        led.conn.close()


def test_existing_legacy_session_never_switches(tmp_path):
    """Regression gate: a legacy session keeps its accounting across
    replayed starts, including after activation."""
    state = activating_state(tmp_path)
    try:
        dispatch_mod.dispatch(state, {"hook_event_name": "UserPromptSubmit",
                                      "session_id": "old", "prompt": "hi"})
        start(state, "genuine")
        conn = state.ledger.conn
        before = tuple(session_row(conn, "old"))
        start(state, "old")
        start(state, "old")
        after = session_row(conn, "old")
        assert after["accounting_version"] == 1
        assert tuple(after) == before
        assert "old" not in state.accounting_keys
    finally:
        state.ledger.conn.close()


def test_unknown_sessionend_does_not_create_session(tmp_path):
    """Regression gate: an end for a session never seen writes nothing."""
    state = activating_state(tmp_path)
    path = tmp_path / "ledger.db"
    try:
        start(state, "real")
        before = image(path)
        dispatch_mod.dispatch(state, {"hook_event_name": "SessionEnd",
                                      "session_id": "ghost"})
        assert image(path) == before
        assert "ghost" not in state.live
    finally:
        state.ledger.conn.close()


def test_ended_sessionstart_never_reopens(tmp_path):
    state = activating_state(tmp_path)
    try:
        # Legacy: an ended legacy session is not reopened.
        dispatch_mod.dispatch(state, {"hook_event_name": "UserPromptSubmit",
                                      "session_id": "old", "prompt": "hi"})
        dispatch_mod.dispatch(state, {"hook_event_name": "SessionEnd",
                                      "session_id": "old"})
        start(state, "old")
        assert "old" not in state.engines
        # Version 2: ended, its identity discarded, then a replayed start.
        start(state, "v2")
        assert session_row(state.ledger.conn, "v2")[
            "accounting_version"] == 2
        with state.lock:
            state.ledger.end_session("v2")
            dispatch_mod._discard_session_identity(state, "v2")
        conn = state.ledger.conn
        row = tuple(session_row(conn, "v2"))
        observations = count(conn, "observations", "v2")
        start(state, "v2")
        for table in (state.accounting_keys, state.engines, state.salts,
                      state.started_at):
            assert "v2" not in table
        assert tuple(session_row(conn, "v2")) == row
        assert count(conn, "observations", "v2") == observations
        assert count(conn, "disclosures", "v2") == 0
    finally:
        state.ledger.conn.close()


# --------------------------------------------------------------------- #
# ownership and the runtime epoch
# --------------------------------------------------------------------- #

def test_activation_requires_current_writer_lease(tmp_path):
    path = tmp_path / "ledger.db"
    seed_prepared(path)
    before = image(path)

    # No lease: a reader.
    reader = Ledger(path, M, initialize=False)
    try:
        with pytest.raises(RuntimeRefusal):
            reader.start_accounted_session(
                "r", cwd="", model="", profile=PROFILE,
                start_observation=start_observation("r"))
    finally:
        reader.conn.close()
    assert image(path) == before

    # A stale lease: the selection changed after it was granted.
    stale = writer_ledger(path, M)
    try:
        write_receipt_v2(tmp_path, bundle=REPO, python="/usr/bin/python3",
                         build_id=REPO_BUILD)
        with pytest.raises(RuntimeRefusal):
            stale.start_accounted_session(
                "s", cwd="", model="", profile=PROFILE,
                start_observation=start_observation("s"))
    finally:
        stale.conn.close()
        (tmp_path / "runtime.json").unlink()
    assert image(path) == before

    # A closed lease.
    closed = writer_ledger(path, M)
    try:
        closed._lease.close()
        with pytest.raises(RuntimeRefusal):
            closed.start_accounted_session(
                "c", cwd="", model="", profile=PROFILE,
                start_observation=start_observation("c"))
    finally:
        closed.conn.close()
    assert image(path) == before


def test_activation_epoch_change_before_commit_rolls_back(tmp_path,
                                                         monkeypatch):
    state = activating_state(tmp_path)
    path = tmp_path / "ledger.db"
    try:
        start(state, "first")
        before = image(path)
        real = Ledger._insert_v2_session

        def then_reselect(self, session_id, **kwargs):
            real(self, session_id, **kwargs)
            write_receipt_v2(tmp_path, bundle=REPO,
                             python="/usr/bin/python3", build_id=REPO_BUILD)

        monkeypatch.setattr(Ledger, "_insert_v2_session", then_reselect)
        with pytest.raises(RuntimeRefusal):
            start(state, "second")
        assert image(path) == before
        assert "second" not in state.accounting_keys
        assert "second" not in state.engines
    finally:
        state.ledger.conn.close()


def test_accounting_activation_does_not_rotate_runtime_epoch(tmp_path):
    from privacy_hud import runtime_storage
    from privacy_hud.runtime_contract import load_activation
    from runtime_helpers import select_runtime

    root = tmp_path / "data"
    root.mkdir()
    select_runtime(root)
    receipt = (root / "runtime.json").read_bytes()
    selected = load_activation(root)
    layout = sorted(p.name for p in root.iterdir())
    state = writer_state(root, selected=selected)
    state.accounting_activation = True
    try:
        start(state, "s1")
        assert session_row(state.ledger.conn, "s1")[
            "accounting_version"] == 2
    finally:
        close_writer(state.ledger)
    assert (root / "runtime.json").read_bytes() == receipt
    assert load_activation(root).epoch == selected.epoch
    assert runtime_storage.resolved_ledger_path(root) == \
        runtime_storage.legacy_path(root)
    assert not runtime_storage.is_fenced(root)
    assert not (root / "runtime-transition.json").exists()
    new = sorted(p.name for p in root.iterdir())
    assert set(new) - set(layout) <= {
        "ledger.db", "ledger.db-wal", "ledger.db-shm", "hud",
        "runtime-writer.lock", "settings.json"}


def test_state_discards_identity_idempotently(tmp_path):
    state = activating_state(tmp_path)
    try:
        start(state, "s1")
        engine = state.engines["s1"]
        path = tmp_path / "ledger.db"
        before = image(path)
        with state.lock:
            dispatch_mod._discard_session_identity(state, "s1")
            dispatch_mod._discard_session_identity(state, "s1")
            dispatch_mod._discard_session_identity(state, "never")
        for table in (state.accounting_keys, state.engines, state.salts,
                      state.started_at):
            assert "s1" not in table
        assert engine.accounting_key is None
        assert engine._origins == {}
        assert image(path) == before
        with pytest.raises(RuntimeError):
            dispatch_mod._discard_session_identity(state, "s1")
    finally:
        state.ledger.conn.close()


def test_payload_cannot_select_accounting_version(tmp_path):
    """Payload flags select neither an accounting version nor stronger
    evidence: a lazily attached session with forged fields stays legacy,
    and a genuine start records only the observed hook."""
    state = activating_state(tmp_path)
    forged = {"accounting_version": 2, "evidence": 2047,
              "crossing_confirmed": True, "deny_enforced": True,
              "resolution_scope": "boundary", "receipt_events": [{}]}
    try:
        dispatch_mod.dispatch(state, {"hook_event_name": "UserPromptSubmit",
                                      "session_id": "lazy", "prompt": "hi",
                                      **forged})
        start(state, "genuine", **forged)
        conn = state.ledger.conn
        assert session_row(conn, "lazy")["accounting_version"] == 1
        row = conn.execute("SELECT evidence, resolution_scope FROM"
                           " observations WHERE session_id='genuine'"
                           ).fetchone()
        assert tuple(row) == (int(Evidence.HOOK_OBSERVED), "none")
    finally:
        state.ledger.conn.close()


def test_invalid_start_observation_is_refused(tmp_path):
    path = tmp_path / "ledger.db"
    led = writer_ledger(path, M)
    try:
        before = image(path)
        for changes in ({"hook_event": "SessionEnd"},
                        {"decision": "allow",
                         "evidence": Evidence.HOOK_OBSERVED
                         | Evidence.PERMISSION_ISSUED},
                        {"boundary": "B1"}, {"potential_crossing": True},
                        {"evidence": Evidence.HOOK_OBSERVED
                         | Evidence.CROSSING_CONFIRMED},
                        {"session_id": "other"}):
            with pytest.raises(ValueError):
                led.start_accounted_session(
                    "s1", cwd="", model="", profile=PROFILE,
                    start_observation=start_observation("s1", **changes))
            assert image(path) == before
    finally:
        led.conn.close()


def test_key_material_never_reaches_the_ledger(tmp_path):
    state = activating_state(tmp_path)
    try:
        start(state, "s1")
        key = state.accounting_keys["s1"]
    finally:
        close_writer(state.ledger)
    for name in os.listdir(tmp_path):
        target = tmp_path / name
        if target.is_file():
            data = target.read_bytes()
            assert key not in data and key.hex().encode() not in data, name
