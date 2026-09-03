# src/privacy_hud/local_ui_server.py
"""Minimal local HTTP server for the L2/L3 audit UI (Task 13, option (a)).

architecture.md §9 documents the intended UI delivery explicitly: "daemon
serves static HTML + vanilla JS on `127.0.0.1:<ephemeral>`; the `$privacy`
skill prints the URL and an ASCII table fallback." Task 10's daemon
(`daemon.py`) is a raw unix-socket JSON server per Task 9's wire protocol,
not a web server -- it does not itself do this yet. Rather than have the
`$privacy` skill print a URL to a server that does not exist (an
overclaiming violation of design.md §9's copy rules), this module builds
the small HTTP server architecture.md already committed to, scoped tightly
to exactly what design.md §5/§6 need: JSON reads for the L2 summary/tabs
and L3 detail, two policy-writing POSTs, and two static file responses.

Stdlib only (`http.server`), matching the same "every dependency here is
paid by something that must not break a user's session" spirit as
`hooks/handler.py`'s stdlib-only rule -- this file is not on the hook path,
but there is no reason to pull in a web framework for four JSON endpoints
and two static files.

Reads the SAME ledger the daemon writes to: `$PLUGIN_DATA/ledger.db`,
identical to `dispatch.new_state()` and `mcp/server.py`. SQLite's WAL mode
(already enabled by `Ledger.__init__`) makes a second, mostly-reading
connection against that file safe.

No raw sensitive value is served by any endpoint here -- every JSON
response is built from `privacy_hud.mcp_tools` functions, which is exactly
where that guarantee is enforced and tested (`tests/test_mcp.py`). This
module adds no new field beyond what those functions already return, plus
the literal ASCII text from `render.py`'s own functions (`audit`/`detail`)
for the "every view has a legible ASCII rendering" requirement (design.md
§6/P6) -- reusing `render.py`'s actual functions, not re-describing their
copy from memory (a real risk of drift the task's constraints call out
explicitly).

`privacy.allow_once` is deliberately NOT wired to a button here. See
task-13-report.md: `allow_once` needs the exact `tool_input` a blocked
`PreToolUse` call carried, and the ledger never stores `tool_input` (I1 --
it could hold raw sensitive values). That means "Allow once" is only ever
answerable from the LIVE consent flow (architecture.md §8's state machine,
reached from the block `systemMessage`'s "Run $privacy" prompt while the
blocked call's arguments are still in memory), not from this after-the-fact
audit page reading historical ledger rows. `render.detail()` itself only
ever renders "Protect future occurrences" / "Block this source" for
exactly this reason -- this UI matches that, rather than inventing a button
with no working backend behind it.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import mcp_tools
from .ledger import Ledger
from .matrix.loader import load_matrix
from .render import _ACRONYMS as _RENDER_ACRONYMS
from .render import _EMPTY_MESSAGES as _RENDER_EMPTY_MESSAGES
from .render import audit as render_audit
from .render import detail as render_detail

_UI_DIR = Path(__file__).resolve().parent.parent.parent / "ui"

_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


def _ledger_path() -> Path:
    """Same convention as `dispatch.new_state()` / `hooks/handler.py` /
    `mcp/server.py`: `$PLUGIN_DATA/ledger.db`."""
    data_dir = Path(os.environ.get("PLUGIN_DATA", "/tmp"))
    return data_dir / "ledger.db"


def _reopen_for_background_thread(ledger: Ledger) -> None:
    """`Ledger.__init__` opens its sqlite3 connection with the default
    `check_same_thread=True` -- correct for a caller that builds the
    `Ledger` and immediately uses it on the same thread, but `serve()`
    below builds it on the CALLING thread and then hands it to a
    `UIServer` whose `serve_forever()` loop -- and therefore every
    `do_GET`/`do_POST` call that touches `self.server.ledger` -- runs on a
    separate background thread. Left unfixed, the first request would
    raise `sqlite3.ProgrammingError` exactly the way `dispatch.py`'s
    `_allow_cross_thread_access` docstring describes for the daemon.

    Reopening with `check_same_thread=False` is sufficient here (unlike
    `dispatch.py`, which ALSO needs `State.lock`) because `UIServer` is
    single-threaded (`http.server.HTTPServer`, not `ThreadingHTTPServer`
    -- see that class's docstring): once `serve_forever()` starts, every
    touch of this connection happens sequentially, on that one background
    thread, with no concurrent caller to serialize against.
    """
    path = Path(ledger.conn.execute("PRAGMA database_list").fetchone()[2])
    ledger.conn.close()
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    ledger.conn = conn


def _latest_session_id(ledger: Ledger) -> str | None:
    """Best-effort default when no `session_id` is given in the request:
    the most recently started session. Not one of the six MCP tools (this
    is UI convenience, not an audit surface), and returns only an id --
    no session content."""
    row = ledger.conn.execute(
        "SELECT session_id FROM sessions ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    return row["session_id"] if row is not None else None


class _Handler(BaseHTTPRequestHandler):
    server_version = "PrivacyHUD-UI/0.1"

    # Quiet by default -- avoid spamming the terminal the skill is also
    # printing the ASCII audit into.
    def log_message(self, fmt, *args) -> None:  # noqa: D401
        pass

    # -- helpers ----------------------------------------------------------
    def _send_json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, filename: str, content_type: str) -> None:
        path = _UI_DIR / filename
        try:
            body = path.read_bytes()
        except OSError:
            self._send_json(404, {"error": f"missing static file {filename!r}"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session_id(self, query: dict) -> str | None:
        given = query.get("session_id", [None])[0]
        if given:
            return given
        return _latest_session_id(self.server.ledger)  # type: ignore[attr-defined]

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    # -- routing ------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (stdlib-mandated name)
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        ledger: Ledger = self.server.ledger  # type: ignore[attr-defined]

        if parsed.path in _STATIC:
            filename, content_type = _STATIC[parsed.path]
            self._send_static(filename, content_type)
            return

        if parsed.path == "/api/session":
            sid = self._session_id(query)
            self._send_json(200, {"session_id": sid})
            return

        if parsed.path == "/api/copy":
            # Copy pulled directly from render.py's own module-level
            # constants (not re-typed here) so the UI's empty-state and
            # type-label wording can never silently drift from the
            # approved strings design.md §9 governs.
            self._send_json(200, {
                "empty_messages": _RENDER_EMPTY_MESSAGES,
                "acronyms": _RENDER_ACRONYMS,
            })
            return

        if parsed.path == "/api/summary":
            sid = self._session_id(query)
            if not sid:
                self._send_json(404, {"error": "no session"})
                return
            self._send_json(200, mcp_tools.get_session_summary(ledger, sid))
            return

        if parsed.path == "/api/exposures":
            sid = self._session_id(query)
            tab = query.get("tab", ["Exposed"])[0]
            if not sid:
                self._send_json(404, {"error": "no session"})
                return
            try:
                rows = mcp_tools.list_exposures(ledger, sid, tab)
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return
            summary = mcp_tools.get_session_summary(ledger, sid)
            self._send_json(200, {
                "rows": rows,
                "text": render_audit(summary, rows, tab),
            })
            return

        if parsed.path == "/api/detail":
            sid = self._session_id(query)
            event_id_raw = query.get("id", [None])[0]
            if not sid or event_id_raw is None:
                self._send_json(400, {"error": "session_id and id are required"})
                return
            try:
                event_id = int(event_id_raw)
                row = mcp_tools.get_exposure_detail(ledger, sid, event_id)
            except (ValueError, LookupError) as exc:
                self._send_json(404, {"error": str(exc)})
                return
            self._send_json(200, {"row": row, "text": render_detail(row)})
            return

        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        ledger: Ledger = self.server.ledger  # type: ignore[attr-defined]
        body = self._read_json_body()

        if parsed.path == "/api/policy":
            sid = body.get("session_id")
            rule_type = body.get("rule_type")
            selector = body.get("selector")
            if not (sid and rule_type and selector):
                self._send_json(
                    400, {"error": "session_id, rule_type, selector are required"})
                return
            try:
                mcp_tools.apply_policy(ledger, sid, rule_type=rule_type,
                                        selector=selector)
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self._send_json(200, {
                "applied": True,
                # design.md §6: every action shows a confirmation of what
                # rule it wrote, in plain terms.
                "message": f"Rule added: {rule_type} {selector}. "
                           "Applies from the next tool call.",
            })
            return

        if parsed.path == "/api/clean_session":
            sid = body.get("session_id")
            if not sid:
                self._send_json(400, {"error": "session_id is required"})
                return
            new_id = mcp_tools.start_clean_session(ledger, sid)
            self._send_json(200, {"session_id": new_id})
            return

        self._send_json(404, {"error": "not found"})


class UIServer(HTTPServer):
    """Deliberately single-threaded (`http.server.HTTPServer`, not
    `ThreadingHTTPServer`): `Ledger`'s sqlite3 connection is opened with
    the default `check_same_thread=True`, which is correct and safe for a
    single-threaded server, and this is a local, single-operator audit
    tool with no concurrency requirement worth the locking machinery
    `daemon.py`'s `_allow_cross_thread_access` needs for the real,
    multi-session daemon. Requests are served one at a time; a browser
    issuing a few requests in quick succession simply queues briefly."""

    allow_reuse_address = True

    def __init__(self, ledger: Ledger):
        # Port 0: ask the OS for an ephemeral port. 127.0.0.1 only -- I2,
        # no network exposure beyond localhost.
        super().__init__(("127.0.0.1", 0), _Handler)
        self.ledger = ledger


def serve(session_id: str | None = None, *, print_url: bool = True) -> UIServer:
    """Start the UI server in a background thread and return it. `session_id`
    is used only to build the printed URL's query string (a convenience for
    the browser tab that opens it) -- every request still carries its own
    `session_id`, resolved by `_session_id()` above."""
    matrix = load_matrix()
    ledger = Ledger(_ledger_path(), matrix)
    _reopen_for_background_thread(ledger)
    server = UIServer(ledger)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    host, port = server.server_address[0], server.server_address[1]
    query = f"?session_id={session_id}" if session_id else ""
    url = f"http://{host}:{port}/{query}"
    if print_url:
        print(url)
    return server


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    session_id = argv[0] if argv else None
    server = serve(session_id)
    try:
        threading.Event().wait()  # block forever; Ctrl-C to stop
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
