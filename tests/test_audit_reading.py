"""Audit selection and snapshot regressions using synthetic fenced storage."""

from pathlib import Path

import pytest

from accounting_fakes import M, crossed, event, start_v2
from privacy_hud import codex, local_ui_server, mcp_tools
from privacy_hud import ledger as ledger_module
from privacy_hud import render, runtime_commands
from runtime_helpers import activation, close_writer, writer_ledger


@pytest.fixture
def audit_store(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    (data / codex.LEDGER_NAME).mkdir()
    (data / codex.ACTIVE_DIR_NAME).mkdir()
    monkeypatch.setenv("PLUGIN_DATA", str(data))

    path = codex.ledger_path(data)
    assert path == data / codex.ACTIVE_DIR_NAME / codex.ACTIVE_DB_NAME

    writer = writer_ledger(path, M, data_dir=data)
    try:
        with writer._write_transaction():
            writer.prepare_session_boundary("older")
            start_v2(writer, "older")
        writer.record_observation(crossed("older"), [event()])
        monkeypatch.setattr(
            runtime_commands, "runtime_matches",
            lambda data_dir, *, activation: True,
        )
        yield data, writer
    finally:
        close_writer(writer)


def _get(data, path):
    """Run the real GET router synchronously; no serving thread or daemon.

    Keeping the handler on this thread lets a deterministic read hook use
    a second SQLite connection without disabling thread-affinity checks.
    """
    reader = runtime_commands.open_reader(data)
    server = None
    try:
        server = local_ui_server.UIServer(
            reader, codex.ledger_path(data), data_dir=data,
        )
        handler = object.__new__(local_ui_server._Handler)
        handler.server = server
        handler.path = path
        responses = []
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        handler.do_GET()
        assert len(responses) == 1
        return responses[0]
    finally:
        if server is not None:
            server.server_close()
        reader.conn.close()


def _invoke(surface, data):
    if surface == "cli":
        return runtime_commands.audit(
            data, activation=activation(),
            session_id="older", tab="Exposed",
        )
    status, payload = _get(
        data, "/api/exposures?session_id=older&tab=Exposed",
    )
    assert status == 200
    return payload


@pytest.mark.parametrize(
    ("daemon_available", "explicit", "expected"),
    [
        (True, None, "older"),
        (False, None, "newer"),
        (True, "newer", "newer"),
    ],
)
def test_browser_session_selection_uses_data_root(
        audit_store, monkeypatch, daemon_available, explicit, expected):
    data, writer = audit_store
    # `sessions.started_at` is frozen by a trigger, so order the two
    # sessions by the clock the ledger reads when it starts one.
    older_started = writer.conn.execute(
        "SELECT started_at FROM sessions WHERE session_id=?", ("older",),
    ).fetchone()[0]
    with monkeypatch.context() as clock:
        clock.setattr(ledger_module.time, "time",
                      lambda: float(older_started + 100))
        start_v2(writer, "newer")

    assert mcp_tools._most_recently_started(writer) == "newer"
    asked = []

    def ask_daemon(data_dir):
        root = Path(data_dir)
        asked.append(root)
        if daemon_available and root == data:
            return [{"session_id": "older", "age": 0.01}]
        return None

    monkeypatch.setattr(mcp_tools, "_ask_daemon", ask_daemon)
    path = "/api/session"
    if explicit is not None:
        path += f"?session_id={explicit}"

    status, payload = _get(data, path)
    assert status == 200
    assert payload == {"session_id": expected}
    assert asked == ([] if explicit is not None else [data])


@pytest.mark.parametrize("surface", ["cli", "browser"])
@pytest.mark.parametrize(
    "after_read", ["get_session_summary", "list_exposures"],
)
def test_audit_keeps_one_snapshot_during_writer_commit(
        audit_store, monkeypatch, surface, after_read):
    data, writer = audit_store
    before_summary = mcp_tools.get_session_summary(
        writer, "older",
    ).as_dict()
    before_rows = [
        row.as_dict()
        for row in mcp_tools.list_exposures(writer, "older", "Exposed")
    ]
    before_coverage = mcp_tools.get_session_coverage(
        writer, "older",
    ).as_dict()
    before_all = len(
        mcp_tools.list_exposures(writer, "older", "All events")
    )

    original = getattr(mcp_tools, after_read)
    committed = []

    def read_then_commit(ledger, *args, **kwargs):
        value = original(ledger, *args, **kwargs)
        if not committed:
            assert ledger.conn is not writer.conn
            writer.record_observation(
                crossed("older", scan_gap="timeout"), [event()],
            )
            assert not writer.conn.in_transaction
            committed.append(True)
        return value

    monkeypatch.setattr(mcp_tools, after_read, read_then_commit)

    rendered = []
    real_render = render.audit

    def capture(summary, rows, tab, **kwargs):
        rendered.append((
            summary.as_dict(),
            [row.as_dict() for row in rows],
            kwargs["coverage"].as_dict(),
            kwargs.get("all_events_count"),
        ))
        return real_render(summary, rows, tab, **kwargs)

    monkeypatch.setattr(render, "audit", capture)
    monkeypatch.setattr(local_ui_server, "render_audit", capture)

    _invoke(surface, data)

    assert committed == [True]
    assert len(rendered) == 1
    summary, rows, coverage, all_events_count = rendered[0]
    assert summary == before_summary
    assert rows == before_rows
    assert coverage == before_coverage
    if surface == "browser":
        assert all_events_count == before_all

    # The write really committed; a fresh reader sees the later state.
    fresh = runtime_commands.open_reader(data)
    try:
        assert fresh.summary("older").observations == (
            before_summary["observations"] + 1
        )
        assert len(mcp_tools.list_exposures(
            fresh, "older", "Exposed",
        )) == len(before_rows) + 1
        assert fresh.coverage("older").shallow_scans == (
            before_coverage["shallow_scans"] + 1
        )
    finally:
        fresh.conn.close()


@pytest.mark.parametrize("surface", ["cli", "browser"])
def test_audit_surfaces_use_public_read_boundary(
        audit_store, monkeypatch, surface):
    data, _ = audit_store
    original = mcp_tools.read_audit
    calls = []

    def tracked(ledger, session_id, tab):
        result = original(ledger, session_id, tab)
        calls.append((session_id, tab, result))
        return result

    monkeypatch.setattr(mcp_tools, "read_audit", tracked)
    _invoke(surface, data)

    assert len(calls) == 1
    session_id, tab, reading = calls[0]
    assert (session_id, tab) == ("older", "Exposed")
    assert reading.summary.observations == 1
    assert len(reading.rows) == 1
    assert reading.coverage.shallow_scans == 0
    assert reading.all_events_count == 1
