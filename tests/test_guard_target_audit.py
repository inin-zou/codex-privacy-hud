"""Synthetic #44 guard-target audit; never reads a real installation."""
from __future__ import annotations

import json
import shlex
import shutil
import sqlite3
import subprocess
import types

import pytest

import server
from privacy_hud import dispatch as dispatch_mod
from privacy_hud import ledger as ledger_mod
from privacy_hud import ledger_schema, local_ui_server, mcp_tools, render
from privacy_hud.detect.paths import PathDetector
from privacy_hud.hook_evidence import CurrentHookAdapter
from runtime_helpers import close_writer, writer_state_with_detectors
from test_accounting_dispatch import egress, end, send, start
from test_browser_accounting_js import APP_JS, _HARNESS, _fetch
from test_mcp_calls import _call, _payload


@pytest.fixture
def guarded(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    state = writer_state_with_detectors(
        tmp_path, detectors=[PathDetector()]
    )
    state.hook_adapter = CurrentHookAdapter()
    state.settings = types.SimpleNamespace(deny_read=True)
    monkeypatch.setattr(
        dispatch_mod, "render_receipt",
        lambda session_id, *args, **kwargs: f"receipt {session_id}",
    )
    start(state)
    yield state
    close_writer(state.ledger)


def deny(state, path, action, *, sid="s1", delivery=None, cwd="/r"):
    output = egress(
        state, sid, "cat " + shlex.quote(path), action,
        key=delivery, cwd=cwd,
    )
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    return output


def public_rows(state, sid="s1"):
    return sorted(
        mcp_tools.list_exposures(state.ledger, sid, "Prevented"),
        key=lambda row: row.id,
    )


def target(row):
    assert row.guard_target is not None
    result = row.guard_target.as_dict()
    assert result == row.as_dict()["guard_target"]
    assert result["basis"] == "evaluated-path-v1"
    assert result["rule_id"] == row.rule_id
    assert result["meaning"] == "Path representation evaluated by Privacy HUD"
    assert "filesystem identity" in result["summary"]
    assert "host enforcement" in result["summary"]
    return result


def assert_accounting(state, count, sid="s1"):
    summary = state.ledger.summary(sid)
    assert summary.denials_issued == count
    assert summary.denials_enforced == 0
    assert summary.reads_stopped == 0
    assert summary.unresolved_actions == count
    assert summary.unresolved_subject_events == count
    # Counts resolved subjects only; guard targets must not resolve any.
    assert summary.distinct_subjects == 0
    assert summary.distinct_disclosures == 0
    assert summary.confirmed_points == 0
    rows = public_rows(state, sid)
    assert len({row.subject_id for row in rows}) == count
    for row in rows:
        assert row.subject_kind == "file"
        assert row.subject_resolution == "unresolved"
        assert row.subject_label == f"file {row.subject_id}"
        assert row.masked_example is None
        assert row.budget_delta == 0
    stored = state.ledger.conn.execute(
        "SELECT identity_hash FROM subjects WHERE session_id=?", (sid,)
    ).fetchall()
    assert all(row[0] is None for row in stored)


def assert_no_text_in_database(conn, forbidden):
    # Enumerate every table and inspect every column, including schema text.
    names = [
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    ]
    for name in names:
        quoted = '"' + name.replace('"', '""') + '"'
        for row in conn.execute(f"SELECT * FROM {quoted}"):
            for cell in row:
                if isinstance(cell, bytes):
                    text = cell.decode("utf-8", errors="replace")
                else:
                    text = str(cell)
                for secret in forbidden:
                    assert secret not in text, (name, secret)


def browser_projection(tmp_path, base, index):
    node = shutil.which("node")
    assert node is not None, "Node is required for guard-target browser acceptance"
    harness = tmp_path / f"guard-browser-{index}.js"
    # Exercise the existing page harness, selecting the requested actual row.
    harness.write_text(
        _HARNESS.replace("rows[0]", f"rows[{index}]"), encoding="utf-8"
    )
    config = {
        "base": base,
        "search": "?session_id=s1",
        "actions": ["tab:Prevented", "click-first-row"],
        "stepMs": 300,
    }
    process = subprocess.run(
        [node, str(harness), str(APP_JS), json.dumps(config)],
        capture_output=True, text=True, timeout=30,
    )
    assert process.returncode == 0, process.stderr
    output = json.loads(process.stdout)
    assert output["errors"] == []
    return output["elements"]


@pytest.mark.parametrize("surface", ["terminal", "browser"])
def test_guard_target_detail_label_uses_shared_copy(
    guarded, tmp_path, monkeypatch, surface,
):
    deny(guarded, "/synthetic-private-team/secret-alpha.pem", "label-action")
    row = public_rows(guarded)[0]
    assert row.guard_target is not None

    label = "Synthetic target label"
    original_copy = render.accounting_copy

    def shared_copy():
        return {**original_copy(), "detail_guard_target": label}

    monkeypatch.setattr(render, "accounting_copy", shared_copy)
    # The server imports this function by alias, so patch that binding too.
    monkeypatch.setattr(
        local_ui_server, "render_accounting_copy", shared_copy,
    )

    if surface == "terminal":
        text = render.detail(row)
        assert any(
            line.startswith(label + " ")
            and line.endswith(row.guard_target.summary)
            for line in text.splitlines()
        )
        return

    ui = local_ui_server.serve("s1", print_url=False)
    host, port = ui.socket.getsockname()[:2]
    base = f"http://{host}:{port}"
    try:
        status, payload = _fetch(base, "/api/copy")
        assert status == 200
        assert payload["accounting"]["detail_guard_target"] == label

        elements = browser_projection(tmp_path, base, 0)
        html = elements["detailFields"]["html"]
        assert f'<span class="field-label">{label}</span>' in html
        assert row.guard_target.summary in html
        assert '<span class="field-label">Guard target</span>' not in html
    finally:
        ui.shutdown()
        ui.server_close()


def test_hook_to_every_projection(guarded, tmp_path, monkeypatch):
    state = guarded
    first_path = "/synthetic-private-team/private-person/secret-alpha.pem"
    second_path = "/synthetic-private-team/private-person/secret-beta.pem"
    for index, path in enumerate((first_path, second_path, first_path)):
        deny(state, path, f"action-{index}")

    rows = public_rows(state)
    a, b, repeated = [target(row) for row in rows]
    assert a["target_id"] != b["target_id"]
    assert repeated["target_id"] == a["target_id"]
    assert a["same_as_event_id"] is None
    assert b["same_as_event_id"] is None
    assert repeated["same_as_event_id"] == rows[0].id
    assert f"Same evaluated target as event #{rows[0].id}" in repeated["summary"]
    assert_accounting(state, 3)

    for row in rows:
        stored = state.ledger.get_event("s1", row.id)
        detail = mcp_tools.get_exposure_detail(state.ledger, "s1", row.id)
        assert stored.guard_target == row.guard_target == detail.guard_target
        assert row.guard_target.summary in render.detail(detail)

    audit = render.audit(
        state.ledger.summary("s1"), rows, "Prevented",
        coverage=state.ledger.coverage("s1"), session_id="s1",
    )
    # The version-2 receipt is aggregate-only and lists no rows.
    for row in rows:
        assert row.guard_target.summary in audit

    # Use the SDK's real worker-thread call path.
    opened = []
    original_open = server._open_ledger

    def capture():
        ledger = original_open()
        opened.append(ledger)
        return ledger

    monkeypatch.setattr(server, "_open_ledger", capture)
    app = server.build_app()
    try:
        listed = _payload(_call(
            app, "privacy.list_exposures",
            {"session_id": "s1", "tab": "Prevented"},
        ))
        listed = sorted(listed, key=lambda row: row["id"])
        assert [row["guard_target"] for row in listed] == [
            row.as_dict()["guard_target"] for row in rows
        ]
        for row in rows:
            detail = _payload(_call(
                app, "privacy.get_exposure_detail",
                {"session_id": "s1", "event_id": row.id},
            ))
            assert detail["guard_target"] == row.as_dict()["guard_target"]
    finally:
        for ledger in opened:
            ledger.conn.close()

    ui = local_ui_server.serve("s1", print_url=False)
    host, port = ui.socket.getsockname()[:2]
    base = f"http://{host}:{port}"
    try:
        status, payload = _fetch(
            base, "/api/exposures", session_id="s1", tab="Prevented",
        )
        assert status == 200
        assert sorted(payload["rows"], key=lambda row: row["id"]) == [
            row.as_dict() for row in rows
        ]
        for index, row in enumerate(rows):
            status, detail = _fetch(
                base, "/api/detail", session_id="s1", id=row.id,
            )
            assert status == 200
            assert detail["row"]["guard_target"] == row.as_dict()["guard_target"]
            elements = browser_projection(tmp_path, base, index)
            assert row.guard_target.summary in elements["rows"]["html"]
            assert row.guard_target.summary in elements["detailFields"]["html"]
    finally:
        ui.shutdown()
        ui.server_close()

    assert_no_text_in_database(state.ledger.conn, (
        first_path, second_path,
        "secret-alpha.pem", "secret-beta.pem",
        "synthetic-private-team", "private-person",
        "cat " + first_path, "cat " + second_path,
    ))


def test_home_collapse_and_unknown_workdir_are_explicit(guarded, monkeypatch):
    monkeypatch.setenv("HOME", "/Users/synthetic-person")
    deny(guarded, "/Users/synthetic-person/keys/a.pem", "absolute")
    deny(guarded, "~/keys/a.pem", "tilde", cwd="/different-workdir")
    deny(guarded, "$HOME/keys/a.pem", "variable")
    a, b, c = [target(row) for row in public_rows(guarded)]
    assert a["target_id"] == b["target_id"]
    assert c["target_id"] != a["target_id"]
    assert b["same_as_event_id"] == public_rows(guarded)[0].id
    assert_accounting(guarded, 3)


def test_misleading_executable_does_not_become_file_identity(guarded):
    output = egress(guarded, "s1", "/r/bin/cat .env", "misleading")
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    row = public_rows(guarded)[0]
    assert target(row)["rule_id"] == "path.env"
    assert_accounting(guarded, 1)


def test_delivery_retry_keeps_original_target_and_first_link(guarded):
    key = "a" * 32
    deny(guarded, "/r/a.pem", "one", delivery=key)
    first = public_rows(guarded)[0]
    deny(guarded, "/r/a.pem", "one", delivery=key)
    assert len(public_rows(guarded)) == 1
    assert public_rows(guarded)[0].as_dict() == first.as_dict()
    deny(guarded, "/r/a.pem", "two")
    assert target(public_rows(guarded)[1])["same_as_event_id"] == first.id
    assert_accounting(guarded, 2)


def test_session_end_retains_public_links_but_clears_matching(guarded):
    deny(guarded, "/r/a.pem", "one")
    deny(guarded, "/r/a.pem", "two")
    before = [row.as_dict() for row in public_rows(guarded)]
    engine = guarded.engines["s1"]
    end(guarded)
    assert engine._guard_targets._seen == {}
    assert engine.accounting_key is None
    assert [row.as_dict() for row in public_rows(guarded)] == before
    deny(guarded, "/r/a.pem", "late")
    assert public_rows(guarded)[-1].guard_target is None
    assert_accounting(guarded, 3)


def test_new_session_never_links_to_previous_session(guarded):
    deny(guarded, "/r/a.pem", "one")
    original = target(public_rows(guarded)[0])
    start(guarded, "s2")
    deny(guarded, "/r/a.pem", "two", sid="s2")
    new = target(public_rows(guarded, "s2")[0])
    assert new["target_id"] != original["target_id"]
    assert new["same_as_event_id"] is None


def test_restart_key_loss_does_not_recreate_matching(
        tmp_path, monkeypatch, request):
    def forbidden_init(self, *args, **kwargs):
        pytest.fail("guard-target test constructed the real ModelDetector")

    monkeypatch.setattr(
        dispatch_mod.ModelDetector, "__init__", forbidden_init
    )
    # Resolve setup only after installing the constructor trap.
    guarded = request.getfixturevalue("guarded")

    deny(guarded, "/r/a.pem", "one")
    original = public_rows(guarded)[0].as_dict()
    # A replacement State owns no prior session keys.
    replacement = writer_state_with_detectors(
        tmp_path, detectors=[PathDetector()]
    )
    replacement.settings = types.SimpleNamespace(deny_read=True)
    try:
        deny(replacement, "/r/a.pem", "after-restart")
        rows = public_rows(replacement)
        assert rows[0].as_dict() == original
        assert rows[1].guard_target is None
        assert replacement.ledger.summary("s1").accounting_status == "unavailable"
        assert "s1" not in replacement.accounting_keys
        start(replacement, "s2")
        deny(replacement, "/r/a.pem", "new-session", sid="s2")
        new = target(public_rows(replacement, "s2")[0])
        assert new["target_id"] != original["guard_target"]["target_id"]
        assert new["same_as_event_id"] is None
    finally:
        close_writer(replacement.ledger)


@pytest.mark.parametrize("seed_first", [False, True])
@pytest.mark.parametrize(("stage", "error_type"), [
    ("before", ValueError),
    ("after-table", sqlite3.OperationalError),
    ("after-insert", sqlite3.Error),
    ("after-insert", RuntimeError),
])
def test_target_write_failure_preserves_denial_without_seeding_a_link(
    guarded, monkeypatch, seed_first, stage, error_type,
):
    path = "/synthetic-private-team/private-person/secret-alpha.pem"
    forbidden = (
        path, "synthetic-private-team", "private-person",
        "secret-alpha.pem", "cat " + path,
    )
    if seed_first:
        deny(guarded, path, "committed")
    conn = guarded.ledger.conn
    engine = guarded.engines["s1"]
    before = [row.as_dict() for row in public_rows(guarded)]
    seen_before = dict(engine._guard_targets._seen)
    schema_before = conn.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ).fetchall()
    targets_before = (
        conn.execute("SELECT * FROM guard_targets ORDER BY event_id").fetchall()
        if ledger_schema.guard_target_schema_present(conn) else []
    )
    observations_before = conn.execute(
        "SELECT COUNT(*) FROM observations WHERE session_id='s1'"
    ).fetchone()[0]
    real = ledger_mod.record_target
    calls = []

    def fail_target(connection, observation, result):
        calls.append(result.observation_id)
        if stage == "after-table":
            if not ledger_schema.guard_target_schema_present(connection):
                # Leave an incomplete optional schema until rollback.
                connection.execute(ledger_schema.guard_target_statements()[0])
        elif stage == "after-insert":
            real(connection, observation, result)
        # Deliberately include synthetic path text in the exception.
        raise error_type("synthetic target failure: " + path)

    delivery = "b" * 32
    with monkeypatch.context() as patch:
        patch.setattr(ledger_mod, "record_target", fail_target)
        deny(guarded, path, "dropped", delivery=delivery)

    assert len(calls) == 1
    assert not conn.in_transaction
    rows = public_rows(guarded)
    assert [row.as_dict() for row in rows[:-1]] == before
    dropped = rows[-1]
    assert dropped.guard_target is None
    assert conn.execute(
        "SELECT COUNT(*) FROM observations WHERE session_id='s1'"
    ).fetchone()[0] == observations_before + 1
    assert conn.execute(
        "SELECT decision FROM observations WHERE observation_id=?",
        (calls[0],),
    ).fetchone()[0] == "deny"
    assert conn.execute(
        "SELECT observation_id,kind FROM events WHERE id=?", (dropped.id,),
    ).fetchone()[:] == (calls[0], "prevented")
    assert_accounting(guarded, int(seed_first) + 1)
    assert engine._guard_targets._seen == seen_before
    assert conn.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ).fetchall() == schema_before
    if seed_first:
        assert conn.execute(
            "SELECT * FROM guard_targets ORDER BY event_id"
        ).fetchall() == targets_before
    else:
        assert not ledger_schema.guard_target_schema_present(conn)
    assert ledger_schema.validate_schema(conn) == 5402
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert_no_text_in_database(conn, forbidden)

    # Retrying the recorded delivery must not backfill metadata or seed a link.
    dump_before_retry = "\n".join(conn.iterdump())

    def unexpected_target_write(*args):
        pytest.fail("delivery retry attempted a guard-target write")

    with monkeypatch.context() as patch:
        patch.setattr(ledger_mod, "record_target", unexpected_target_write)
        deny(guarded, path, "dropped", delivery=delivery)
    assert "\n".join(conn.iterdump()) == dump_before_retry
    assert engine._guard_targets._seen == seen_before
    assert public_rows(guarded)[-1].guard_target is None
    assert_accounting(guarded, int(seed_first) + 1)

    deny(guarded, path, "after-failure")
    successful = public_rows(guarded)[-1]
    new = target(successful)
    assert new["same_as_event_id"] == (before[0]["id"] if seed_first else None)
    assert new["same_as_event_id"] != dropped.id
    if seed_first:
        assert new["target_id"] == before[0]["guard_target"]["target_id"]
    assert_accounting(guarded, int(seed_first) + 2)

    # The first successful write after the drop can seed future correlation.
    deny(guarded, path, "later")
    later = target(public_rows(guarded)[-1])
    assert later["target_id"] == new["target_id"]
    assert later["same_as_event_id"] == (
        before[0]["id"] if seed_first else successful.id
    )
    assert_accounting(guarded, int(seed_first) + 3)
    assert ledger_schema.validate_schema(conn) == 5402
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert_no_text_in_database(conn, forbidden)


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit])
def test_target_write_does_not_swallow_process_control(
    guarded, monkeypatch, failure_type,
):
    conn = guarded.ledger.conn
    before = "\n".join(conn.iterdump())
    real = ledger_mod.record_target

    def interrupt_after_insert(connection, observation, result):
        real(connection, observation, result)
        raise failure_type()

    with monkeypatch.context() as patch:
        patch.setattr(ledger_mod, "record_target", interrupt_after_insert)
        with pytest.raises(failure_type):
            deny(guarded, "/synthetic-private-team/secret-alpha.pem", "interrupt")
    assert not conn.in_transaction
    assert "\n".join(conn.iterdump()) == before
    assert guarded.engines["s1"]._guard_targets._seen == {}
    assert ledger_schema.validate_schema(conn) == 5402


def test_unsupported_and_permitted_calls_receive_no_target(guarded):
    guarded.settings.deny_read = False
    egress(guarded, "s1", "cat /r/a.pem", "permitted")
    guarded.settings.deny_read = True
    egress(guarded, "s1", "curl https://example.test -T /r/a.pem", "network")
    send(
        guarded, "PreToolUse", tool_name="Read",
        tool_input={"file_path": "/r/a.pem"}, tool_use_id="non-shell",
    )
    send(
        guarded, "PreToolUse", tool_name="mcp__files__read",
        tool_input={"path": "/r/a.pem"}, tool_use_id="mcp",
    )
    rows = mcp_tools.list_exposures(guarded.ledger, "s1", "All events")
    assert rows
    assert all(row.guard_target is None for row in rows)


def test_legacy_session_does_not_create_guard_metadata(guarded):
    # A late attachment creates legacy accounting.
    deny(guarded, "/r/a.pem", "legacy", sid="legacy")
    assert guarded.ledger.summary("legacy").accounting_version == 1
    rows = mcp_tools.list_exposures(guarded.ledger, "legacy", "Prevented")
    assert rows
    assert all("guard_target" not in row.as_dict() for row in rows)


def test_optional_schema_and_append_only_contract(guarded):
    conn = guarded.ledger.conn
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 5402
    assert conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name='guard_targets'"
    ).fetchone() is None
    deny(guarded, "/r/a.pem", "one")
    assert ledger_schema.validate_schema(conn) == 5402
    columns = {row[1] for row in conn.execute("PRAGMA table_info(guard_targets)")}
    assert columns == {
        "event_id", "session_id", "target_id", "rule_id",
        "basis", "same_as_event_id",
    }
    for statement in (
        "UPDATE guard_targets SET same_as_event_id=NULL",
        "DELETE FROM guard_targets",
    ):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(statement)


def test_invalid_optional_schema_is_refused(guarded):
    deny(guarded, "/r/a.pem", "one")
    conn = guarded.ledger.conn
    conn.execute("DROP TRIGGER guard_targets_no_update")
    with pytest.raises(ledger_schema.UnsupportedAccounting):
        ledger_schema.validate_schema(conn)


def test_target_metadata_vocabulary_is_closed():
    from privacy_hud.accounting import GuardTarget

    valid = {
        "target_id": "a" * 32,
        "rule_id": "path.env",
        "same_as_event_id": None,
    }
    for changes in (
        {"target_id": "/private/secret.pem"},
        {"rule_id": "private-person"},
        {"basis": "arbitrary"},
        {"same_as_event_id": True},
        {"same_as_event_id": 0},
    ):
        with pytest.raises(ValueError, match="invalid guard target"):
            GuardTarget(**{**valid, **changes})


def test_cross_session_correlation_link_is_refused(guarded, monkeypatch):
    deny(guarded, "/r/a.pem", "one")
    first = public_rows(guarded)[0]
    assert first.guard_target is not None
    start(guarded, "s2")

    suppressed = []

    def suppress_target(conn, observation, result):
        assert observation.session_id == "s2"
        assert observation.guard_target is not None
        assert not result.duplicate_delivery
        suppressed.append(result.observation_id)

    # Preserve the real keyed denial, observation, subject and event.
    # An outer ledger transaction also defers Engine's post-commit
    # correlation publication, which requires a recorded target row.
    with monkeypatch.context() as patch:
        patch.setattr(ledger_mod, "record_target", suppress_target)
        with guarded.ledger._write_transaction():
            deny(guarded, "/r/b.pem", "two", sid="s2")

    assert len(suppressed) == 1
    rows = public_rows(guarded, "s2")
    assert len(rows) == 1
    second = rows[0]
    assert second.guard_target is None
    assert 0 < first.id < second.id

    conn = guarded.ledger.conn
    assert not conn.in_transaction
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute(
        "SELECT session_id,observation_id FROM events WHERE id=?",
        (second.id,),
    ).fetchone()[:] == ("s2", suppressed[0])
    assert conn.execute(
        "SELECT 1 FROM guard_targets WHERE event_id=?", (second.id,),
    ).fetchone() is None
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    ledger_schema.validate_guard_target_schema(conn)

    statement = (
        "INSERT INTO guard_targets"
        "(event_id,session_id,target_id,rule_id,basis,same_as_event_id)"
        " VALUES(?,?,?,?,?,?)"
    )
    values = (
        second.id, "s2", first.guard_target.target_id,
        second.rule_id, "evaluated-path-v1", first.id,
    )
    # Capture the synthetic database before either attempted insert.
    dump = "\n".join(conn.iterdump())

    def assert_cross_session_refused(connection):
        with pytest.raises(
            sqlite3.IntegrityError,
            match=r"^FOREIGN KEY constraint failed$",
        ):
            connection.execute(statement, values)

    assert_cross_session_refused(conn)
    assert conn.execute(
        "SELECT 1 FROM guard_targets WHERE event_id=?", (second.id,),
    ).fetchone() is None

    # Change ONLY the link. This proves the event, session, rule, target,
    # basis, primary key and event-scope trigger all permit the insert.
    positive = (*values[:-1], None)
    conn.execute(statement, positive)
    assert conn.execute(
        "SELECT event_id,session_id,target_id,rule_id,basis,same_as_event_id"
        " FROM guard_targets WHERE event_id=?",
        (second.id,),
    ).fetchone()[:] == positive
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []

    # Mutation control: remove ONLY the composite link FK from a
    # disposable in-memory copy. Production schema/code stays untouched.
    link_fk = (
        ",\n    FOREIGN KEY (session_id, same_as_event_id, target_id)"
        "\n        REFERENCES guard_targets(session_id, event_id, target_id)"
    )
    assert dump.count(link_fk) == 1
    scratch = sqlite3.connect(":memory:", isolation_level=None)
    try:
        # Load the dump before enabling FKs: dump table order need not
        # put referenced tables first. Enforce FKs for every probe below.
        scratch.executescript(dump.replace(link_fk, "", 1))
        scratch.execute("PRAGMA foreign_keys=ON")
        assert scratch.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert scratch.execute("PRAGMA foreign_key_check").fetchall() == []

        with pytest.raises(
            ledger_schema.UnsupportedAccounting,
            match=r"^invalid optional guard-target schema$",
        ):
            ledger_schema.validate_guard_target_schema(scratch)

        # RED proof: the exact refusal assertion fails on the mutant.
        with pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"):
            assert_cross_session_refused(scratch)

        assert scratch.execute(
            "SELECT event_id,session_id,target_id,rule_id,basis,same_as_event_id"
            " FROM guard_targets WHERE event_id=?",
            (second.id,),
        ).fetchone() == values
        assert scratch.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        scratch.close()
