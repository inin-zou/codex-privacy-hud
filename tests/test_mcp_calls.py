"""The MCP tools, called the way a client calls them.

Every other MCP test calls `mcp_tools.*` directly or only lists the
registered names. None went through the SDK's own call path, and that path
is where the tools broke: MCP SDK 2.x runs a synchronous tool on a worker
thread (`anyio.to_thread.run_sync`), `build_app()` opened the ledger's
sqlite connection on the main thread, and sqlite's default thread affinity
turned every ledger-backed call into `UnexpectedToolError`. Tool discovery
and `privacy.read_guard_status` (settings only) kept working, which is why
nothing noticed.

The SDK is imported normally and nothing here skips: `mcp` is in the `test`
extra for exactly this reason (pyproject's comment on it).
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

import server  # `mcp/` is on sys.path via conftest
from privacy_hud import mcp_tools
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix

M = load_matrix()
REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
SERVER = REPO / "mcp" / "server.py"
SID = "s1"
FIXED_ERROR = ("Privacy HUD ledger operation failed; no successful result "
               "is available.")


def _seed(data_dir: Path) -> int:
    """A ledger with one exposed, one prevented and one local row, closed
    before the app opens its own connection. Returns the exposed row's id."""
    led = Ledger(data_dir / "ledger.db", M)
    led.start_session(SID, cwd="/r", model="gpt-5")
    led.record(SID, turn_id="t1", kind="exposed", data_type="email",
               source="support.log", destination="model_context",
               value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
               tool_name="Read", protection=None)
    led.record(SID, turn_id="t2", kind="prevented", data_type="credential",
               source="tool input", destination="mcp_tool",
               value_hash=b"\x02" * 16, masked_example=None,
               tool_name="mcp__github__x", protection="blocked")
    led.record(SID, turn_id="t3", kind="local_access", data_type="path",
               source="terminal output", destination="local",
               value_hash=b"\x03" * 16, masked_example="/Users/.../app.log",
               tool_name="Read", protection=None)
    event_id = led.conn.execute(
        "SELECT id FROM events WHERE kind='exposed'").fetchone()[0]
    led.conn.close()
    return event_id


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    """The real app over a seeded ledger. The connection the app opens is
    captured so teardown can close it: these tests call `app.call_tool`
    directly, without the server lifespan that closes it in production."""
    event_id = _seed(tmp_path)
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    opened: list[Ledger] = []
    real_open = server._open_ledger

    def capture():
        led = real_open()
        opened.append(led)
        return led

    monkeypatch.setattr(server, "_open_ledger", capture)
    app = server.build_app()
    try:
        yield app, tmp_path, event_id
    finally:
        for led in opened:
            try:
                led.conn.close()
            except sqlite3.Error:
                pass


def _call(app, name, args):
    return asyncio.run(app.call_tool(name, args))


def _payload(result):
    """The JSON a client receives for one successful call. A tool returning
    a list arrives as one text block per element (the SDK's serialization of
    a sequence), so a multi-block result is read back as a list."""
    assert result.is_error is False, result
    blocks = [json.loads(block.text) for block in result.content]
    return blocks[0] if len(blocks) == 1 else blocks


def _direct(data_dir: Path):
    return Ledger(data_dir / "ledger.db", M)


# --------------------------------------------------------------------- #
# every exposed tool, through the SDK
# --------------------------------------------------------------------- #

def _cases(data_dir: Path, event_id: int):
    return {
        "privacy.get_session_summary": {"session_id": SID},
        "privacy.list_exposures": {"session_id": SID, "tab": "All events"},
        "privacy.get_exposure_detail": {"session_id": SID,
                                        "event_id": event_id},
        "privacy.update_policy": {"session_id": SID, "rule_type": "mask",
                                  "selector": "email"},
        "privacy.read_guard_status": {},
    }


def test_the_cases_cover_every_exposed_tool(tmp_path):
    assert set(_cases(tmp_path, 1)) == set(server.EXPOSED_TOOLS)


@pytest.mark.parametrize("name", sorted(server.EXPOSED_TOOLS))
def test_every_exposed_tool_through_sdk_call_tool(app_env, name):
    app, data_dir, event_id = app_env
    got = _payload(_call(app, name, _cases(data_dir, event_id)[name]))

    direct = _direct(data_dir)
    try:
        if name == "privacy.get_session_summary":
            assert got == mcp_tools.get_session_summary(direct, SID).as_dict()
        elif name == "privacy.list_exposures":
            assert got == [r.as_dict() for r in mcp_tools.list_exposures(
                direct, SID, "All events")]
            assert len(got) == 3
        elif name == "privacy.get_exposure_detail":
            assert got == mcp_tools.get_exposure_detail(
                direct, SID, event_id).as_dict()
        elif name == "privacy.update_policy":
            assert got["saved"] is True
            assert got["enforcement"] == "conditional"
            assert "applied" not in got
            assert got["conditions"] == mcp_tools.rule_enforcement_note(
                "mask", "email").strip()
            assert direct.policy_selectors(SID, "mask") == {"email"}
        else:
            assert got == mcp_tools.read_guard_status(str(data_dir))
    finally:
        direct.conn.close()


# --------------------------------------------------------------------- #
# the threading the fix relies on, and the lock it adds
# --------------------------------------------------------------------- #

def test_sdk_sync_tool_runs_on_worker_thread():
    """Pins the SDK behaviour that exposed the defect. The fix does not
    depend on it -- the connection is serialized either way -- but if an SDK
    upgrade changes it, this is where that shows."""
    seen: dict[str, int] = {}
    app = MCPServer("probe")

    @app.tool(name="probe.where")
    def where() -> dict:
        seen["tool"] = threading.get_ident()
        return {}

    async def run():
        seen["loop"] = threading.get_ident()
        await app.call_tool("probe.where", {})

    asyncio.run(run())
    assert seen["tool"] != seen["loop"]


def test_mcp_serializes_concurrent_tool_bodies(app_env, monkeypatch):
    app, data_dir, _event_id = app_env
    state = {"active": 0, "max": 0}
    guard = threading.Lock()
    real = mcp_tools.get_session_summary

    def instrumented(ledger, session_id):
        with guard:
            state["active"] += 1
            state["max"] = max(state["max"], state["active"])
        try:
            time.sleep(0.05)
            return real(ledger, session_id)
        finally:
            with guard:
                state["active"] -= 1

    monkeypatch.setattr(mcp_tools, "get_session_summary", instrumented)

    async def many():
        return await asyncio.gather(*[
            app.call_tool("privacy.get_session_summary", {"session_id": SID})
            for _ in range(6)])

    results = asyncio.run(many())
    assert state["max"] == 1
    assert all(_payload(r)["legacy_permitted_crossing_rows"] == 1 for r in results)


def test_mcp_calls_from_another_event_loop_thread(app_env):
    app, _data_dir, _event_id = app_env
    out: dict = {}

    def elsewhere():
        try:
            out["result"] = _call(app, "privacy.get_session_summary",
                                  {"session_id": SID})
        except BaseException as exc:            # noqa: BLE001
            out["error"] = exc

    t = threading.Thread(target=elsewhere)
    t.start()
    t.join(timeout=30)
    assert "error" not in out, out.get("error")
    assert _payload(out["result"])["legacy_permitted_crossing_rows"] == 1


# --------------------------------------------------------------------- #
# failure: explicit, fixed, and the lock comes back
# --------------------------------------------------------------------- #

def test_mcp_database_error_is_explicit_and_sanitized(app_env, monkeypatch,
                                                      caplog, capsys):
    app, _data_dir, _event_id = app_env
    sentinel = "SENTINEL-raw-db-text-4f1c"
    real = mcp_tools.get_session_summary

    def failing(ledger, session_id):
        raise sqlite3.OperationalError(sentinel)

    monkeypatch.setattr(mcp_tools, "get_session_summary", failing)
    with pytest.raises(ToolError) as caught:
        _call(app, "privacy.get_session_summary", {"session_id": SID})
    assert str(caught.value).endswith(FIXED_ERROR)
    assert sentinel not in str(caught.value)
    assert caught.value.__cause__ is None or \
        sentinel not in repr(caught.value.__cause__)
    captured = capsys.readouterr()
    assert sentinel not in caplog.text
    assert sentinel not in captured.out + captured.err

    monkeypatch.setattr(mcp_tools, "get_session_summary", real)
    again = _call(app, "privacy.get_session_summary", {"session_id": SID})
    assert _payload(again)["legacy_permitted_crossing_rows"] == 1, "the lock was not released"


def test_mcp_write_contention_returns_error_without_success(app_env):
    """Another process holds the write lock past sqlite's 5s busy timeout.
    The tool must report failure, never `saved: true`, and write nothing."""
    app, data_dir, _event_id = app_env
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sqlite3, sys, time\n"
         "c = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
         "c.execute('BEGIN IMMEDIATE')\n"
         "print('locked', flush=True)\n"
         "time.sleep(8)\n"
         "c.execute('ROLLBACK')\n",
         str(data_dir / "ledger.db")],
        stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"
        with pytest.raises(ToolError) as caught:
            _call(app, "privacy.update_policy",
                  {"session_id": SID, "rule_type": "block_path",
                   "selector": "/tmp/contended"})
        assert str(caught.value).endswith(FIXED_ERROR)
    finally:
        holder.wait(timeout=30)
    direct = _direct(data_dir)
    try:
        assert direct.policy_selectors(SID, "block_path") == set()
    finally:
        direct.conn.close()


# --------------------------------------------------------------------- #
# two processes, one database
# --------------------------------------------------------------------- #

def test_mcp_and_daemon_process_can_write_same_database(app_env):
    """The daemon writes events from its own process while this server
    writes policy rows. sqlite arbitrates between processes; neither side's
    rows may be lost, and the event history is left as the daemon wrote it."""
    app, data_dir, _event_id = app_env
    writer = subprocess.Popen(
        [sys.executable, "-c",
         "import sys\n"
         "from pathlib import Path\n"
         "from privacy_hud.ledger import Ledger\n"
         "from privacy_hud.matrix.loader import load_matrix\n"
         "led = Ledger(Path(sys.argv[1]), load_matrix())\n"
         "for i in range(40):\n"
         "    led.record('s1', turn_id=f'w{i}', kind='exposed',\n"
         "               data_type='email', source='w.log',\n"
         "               destination='model_context',\n"
         "               value_hash=bytes([i + 10]) * 16,\n"
         "               masked_example='x', tool_name='Read',\n"
         "               protection=None)\n",
         str(data_dir / "ledger.db")],
        env={**os.environ, "PYTHONPATH": str(SRC)})
    for i in range(20):
        _payload(_call(app, "privacy.update_policy",
                       {"session_id": SID, "rule_type": "block_path",
                        "selector": f"/tmp/f{i}"}))
    assert writer.wait(timeout=60) == 0
    direct = _direct(data_dir)
    try:
        assert len(direct.policy_selectors(SID, "block_path")) == 20
        assert direct.conn.execute(
            "SELECT COUNT(*) FROM events WHERE source='w.log'"
        ).fetchone()[0] == 40
        assert direct.conn.execute(
            "SELECT COUNT(*) FROM events WHERE source!='w.log'"
        ).fetchone()[0] == 3
    finally:
        direct.conn.close()


# --------------------------------------------------------------------- #
# shutdown
# --------------------------------------------------------------------- #

def test_mcp_shutdown_closes_connection(tmp_path, monkeypatch):
    """The server lifespan closes the shared connection exactly once, and
    only after a tool that holds it has finished."""
    _seed(tmp_path)
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    opened: list[Ledger] = []
    real_open = server._open_ledger

    def capture():
        led = real_open()
        opened.append(led)
        return led

    monkeypatch.setattr(server, "_open_ledger", capture)
    app = server.build_app()
    led = opened[0]
    closes: list[float] = []
    real_close = led.conn.close

    class _Conn:
        """Delegates to the real connection, recording close()."""

        def __getattr__(self, name):
            return getattr(real_led_conn, name)

        def close(self):
            closes.append(time.monotonic())
            real_close()

    real_led_conn = led.conn
    led.conn = _Conn()  # type: ignore[assignment]

    finished: list[float] = []
    real_summary = mcp_tools.get_session_summary

    def slow(ledger, session_id):
        time.sleep(0.3)
        out = real_summary(ledger, session_id)
        finished.append(time.monotonic())
        return out

    monkeypatch.setattr(mcp_tools, "get_session_summary", slow)

    async def scenario():
        async with app.settings.lifespan(app):
            call = asyncio.create_task(app.call_tool(
                "privacy.get_session_summary", {"session_id": SID}))
            await asyncio.sleep(0.05)
        return await call

    result = asyncio.run(scenario())
    assert _payload(result)["legacy_permitted_crossing_rows"] == 1
    assert len(closes) == 1
    assert closes[0] >= finished[0]


# --------------------------------------------------------------------- #
# the real launcher, over stdio
# --------------------------------------------------------------------- #

def test_mcp_stdio_round_trip(tmp_path):
    """A client session against `mcp/server.py` through its launcher: the
    runtime receipt (v2) names this interpreter and a bundle, the launcher
    hands over to the bundled bootstrap, which re-execs under it in
    isolated mode, and all five tools answer. No detector is constructed and
    nothing is downloaded."""
    from runtime_helpers import make_bundle, write_receipt_v2

    event_id = _seed(tmp_path)
    bundle = make_bundle(tmp_path / "bundle")
    write_receipt_v2(tmp_path, bundle=bundle, python=sys.executable)
    env = {k: v for k, v in os.environ.items()
           if k not in ("PRIVACY_HUD_BOOTSTRAP_REEXEC", "PYTHONPATH")}
    env.update({"PLUGIN_DATA": str(tmp_path),
                "CODEX_HOME": str(tmp_path / "no-codex-home")})

    async def session():
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(bundle / "mcp" / "server.py")], env=env)
        out = {}
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                for name, args in _cases(tmp_path, event_id).items():
                    res = await s.call_tool(name, args)
                    out[name] = res
        return out

    results = asyncio.run(session())
    assert set(results) == set(server.EXPOSED_TOOLS)
    for name, res in results.items():
        assert res.is_error is False, (name, res)
    direct = _direct(tmp_path)
    try:
        assert direct.policy_selectors(SID, "mask") == {"email"}
    finally:
        direct.conn.close()
