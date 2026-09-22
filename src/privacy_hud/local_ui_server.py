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
where that guarantee is enforced and tested (`tests/test_mcp.py`). Those
functions return `ledger.py`'s summary variants and `LegacyExposureRow`, so
every handler below serializes with an explicit `.as_dict()` immediately
before `json.dumps` -- `ledger._EXPOSURE_JSON_FIELDS` is what pins the keys
and their order, and `ui/app.js` reads exactly those. That call is not
ceremony: without it a dataclass reaches `json.dumps` and the endpoint 500s,
which is the correct failure (loud, at the boundary) rather than a silently
reshaped payload. This module adds no new field beyond what those functions
already return, plus
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
audit page reading historical ledger rows. `render.detail()` itself never
renders an "Allow once" button for exactly this reason -- this UI matches
that, rather than inventing a button with no working backend behind it.
The withdrawn "Block this source" (`block_source`, #38) stays gone from
both surfaces for a different reason: it named a label, not a source. Its
replacement, `block_path`/`block_command` (#40), IS offered here and in
`render.detail()`, but only on a row whose `source_kind` names a real
origin -- never on a row whose `source` is a bare tool label.
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import mcp_tools, runtime, runtime_commands
from .accounting import PHASE3_SURFACE_UNSUPPORTED
from .ledger import Ledger
from .matrix.loader import load_matrix
from .render import _ACRONYMS as _RENDER_ACRONYMS
from .render import audit as render_audit
from .render import coverage_banner as render_coverage_banner
from .render import empty_message as render_empty_message
from .render import detail as render_detail
from .runtime_contract import RuntimeRefusal, load_activation
from .runtime_messages import POLICY_OUTCOME_UNKNOWN, POLICY_PREFLIGHT_REFUSAL

_UI_DIR = Path(__file__).resolve().parent.parent.parent / "ui"

#: The endpoints that read a session's accounting. A version-2 session is
#: refused on each with HTTP 409 and the fixed Phase 3 error (#54).
_ACCOUNTING_ENDPOINTS = frozenset({"/api/summary", "/api/exposures",
                                   "/api/detail"})

_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


# Both of these moved into `runtime.py` and are re-exported here under the
# names `ambient`, `mcp/server.py` and the tests already use. The move is
# what lets `doctor.py` stop importing this module: a diagnostic that must
# survive a broken install was pulling in `mcp_tools`, `render`, the matrix
# and the ledger to learn where a file is, and that import closed a real
# cycle (`doctor` -> `local_ui_server` -> `runtime` -> `doctor`), which two
# deferred imports existed only to dodge. The resolution itself is unchanged:
# `$PLUGIN_DATA` if set, else the single directory Codex assigns, else
# `None` -- there is no `/tmp` default (spec §6).
resolve_data_dir = runtime.plugin_data_dir
_ledger_path = runtime.ledger_path


def _latest_session_id(ledger: Ledger) -> str | None:
    """The most recently *started* session.

    **Not the session the user is in**, and no longer this module's default:
    with two Codex windows open it names the one that started last, whoever is
    asking. `mcp_tools.resolve_audit_session` is the resolution the request
    handler uses now (`_session_id` below) — read its docstring for why the
    daemon has to be asked and why `MAX(events.ts)` is not the fix either.

    Kept, and kept exported, because it is still the honest answer when no
    daemon can be reached — but it no longer holds a copy of the query.
    `ambient` used to import this and resolve with it directly, which is how
    one machine ended up with an ambient line and a `$privacy` audit that could
    name two different sessions; `ambient` now goes through
    `mcp_tools.resolve_audit_session` like everything else, and this is a
    one-line alias onto that function's own fallback so the two cannot drift
    back apart. Returns only an id, no session content."""
    return mcp_tools._most_recently_started(ledger)


def _rule_confirmation(rule_type: str, selector: str) -> str:
    """design.md §6: every action confirms what rule it wrote, in plain
    terms -- and what it cannot do.

    **Saved is not enforced, and this sentence is where the two stopped
    being conflated** (#49 item 2). It used to end "Applies from the next
    tool call.", which reads as a promise about every later call. It is not
    one. A rule fires when some tier produces a finding its selector
    matches. For every type outside `mcp_tools.CHEAP_DATA_TYPES` (`path`,
    `credential`), matching requires an accepted deep-scan result. A scan
    gap means an applicable deep scan supplied no accepted result (known
    limit 21); on that call this rule has no matching deep-scan finding.
    Egress uses a requested timeout based on the remaining budget and an
    inclusive completion cutoff; neither guarantees elapsed time. See
    `engine.TIER3_EGRESS_BUDGET`. At most one egress scan worker is admitted
    at a time. Admission is nonblocking; the worker retains its slot until
    it exits, including after caller abandonment. The user clicking the button
    cannot see any of that, and a warning they find afterwards cannot
    unsend what they sent in the meantime (I5).

    Matching is also on the whole value, normalised (known limit 10), so a
    model that summarizes what it read still sends it.
    """
    conditions = mcp_tools.rule_enforcement_note(rule_type, selector)
    if rule_type in ("block_path", "block_command"):
        return (f"Rule saved: block values from {selector}, for this session. "
                "It can cause Privacy HUD to issue a denial on a later "
                "outbound call when the whole normalized value matches the "
                "recorded origin. A summary or partial quotation may not "
                "match." + conditions)
    return (f"Rule saved: mask {selector}, for this session. On later "
            "outbound calls this plugin checks, matching findings can cause "
            "Privacy HUD to return rewritten input unless the call is "
            "denied." + conditions)


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
        """The session explicitly named by the request, or selected by
        resolve_audit_session. Sharing a resolver does not guarantee
        separately timed requests select the same session. The skill pins its
        selected ID in the browser URL.

        In practice the skill always puts `session_id` in the URL it prints
        and `ui/app.js` carries it on every later request, so this default is
        reached about once, by a hand-typed URL."""
        given = query.get("session_id", [None])[0]
        if given:
            return given
        ledger: Ledger = self.server.ledger  # type: ignore[attr-defined]
        ledger_path = _ledger_path()
        if ledger_path is None:
            # Unreachable in practice -- `serve()` already refused to start
            # without a resolvable data directory -- but the environment
            # this process reads is not immutable, so this stays a clean
            # "no session" rather than an AttributeError on `.parent`.
            print("privacy-hud local-ui: PLUGIN_DATA is not set and no "
                  "Codex plugin-data directory was found", file=sys.stderr)
            return None
        return mcp_tools.resolve_audit_session(
            ledger, ledger_path.parent).session_id

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
            # constants (not re-typed here) so the UI's type-label wording can
            # never silently drift from the approved strings design.md §9
            # governs.
            #
            # `empty_messages` used to be here too, and that was the bug: this
            # endpoint is session-independent and fetched once per page load,
            # so a client indexing it by tab could only ever choose the line
            # for a session whose coverage it had not consulted. The
            # empty-state line is now decided per session by
            # `render.empty_message` and delivered by `/api/exposures`. There
            # is deliberately no second source for it to fall back to.
            self._send_json(200, {"acronyms": _RENDER_ACRONYMS})
            return

        if parsed.path in _ACCOUNTING_ENDPOINTS:
            sid = self._session_id(query)
            with ledger._read_transaction():
                version = ledger._accounting_version(sid) if sid else 0
            if version == 2:
                # #54 Phase 3: the browser renders legacy and unrecorded
                # sessions only. A version-2 session gets the fixed refusal
                # and no partial data.
                self._send_json(409, {"error": PHASE3_SURFACE_UNSUPPORTED})
                return

        if parsed.path == "/api/summary":
            sid = self._session_id(query)
            if not sid:
                self._send_json(404, {"error": "no session"})
                return
            # The summary variant, then `coverage` appended after it. An
            # unknown session is an unrecorded summary with HTTP 200, not a
            # 404: "no record" is an answer. Coverage is here because the
            # tiles alone cannot say whether a legacy account is complete.
            payload = mcp_tools.get_session_summary(ledger, sid).as_dict()
            payload["coverage"] = \
                mcp_tools.get_session_coverage(ledger, sid).as_dict()
            self._send_json(200, payload)
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
            coverage = mcp_tools.get_session_coverage(ledger, sid)
            # The exact "All events" count for the tab bar, from the list
            # itself. An approximation from the summary omits kinds.
            all_events = (len(rows) if tab == "All events" else
                          len(mcp_tools.list_exposures(ledger, sid,
                                                       "All events")))
            # `rows` goes to the browser as JSON and to `render_audit` as
            # typed rows -- the same values, serialized once, on purpose.
            #
            # `empty_message` and `coverage_banner` are fields of their own
            # because the reasoning that used to be here was wrong. It said the
            # caveat "travels inside `text`, which is the block `ui/app.js`
            # puts on the page verbatim, so the browser shows the caveat" --
            # true of the block, false of the page: `ui/index.html` hides that
            # region by default, and the HTML view picked its own empty line
            # out of `/api/copy` with the coverage reading sitting unread in
            # the `/api/summary` payload beside it. So the reassuring sentence
            # was shown on exactly the sessions that could not support it.
            #
            # `/api/copy` cannot carry the decision instead: it is
            # session-independent and fetched once per page load, while
            # coverage is per session. The decision belongs to `render`, which
            # owns the approved strings -- see `render.empty_message`.
            self._send_json(200, {
                "rows": [r.as_dict() for r in rows],
                "text": render_audit(summary, rows, tab, coverage=coverage,
                                     session_id=sid,
                                     all_events_count=all_events),
                "empty_message": render_empty_message(tab, coverage,
                                                      summary=summary),
                "coverage_banner": render_coverage_banner(coverage),
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
            self._send_json(200, {"row": row.as_dict(),
                                  "text": render_detail(row)})
            return

        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        body = self._read_json_body()

        if parsed.path == "/api/policy":
            sid = body.get("session_id")
            rule_type = body.get("rule_type")
            selector = body.get("selector")
            if not (sid and rule_type and selector):
                self._send_json(
                    400, {"error": "session_id, rule_type, selector are required"})
                return
            server = self.server  # type: ignore[assignment]
            data_dir = server.data_dir  # type: ignore[attr-defined]
            if data_dir is None:
                self._send_json(503, {"error": POLICY_PREFLIGHT_REFUSAL,
                                      "code": "setup_missing"})
                return
            try:
                # The mutation goes to the daemon that owns the ledger
                # (#66 Pair 6). This process's connection is `mode=ro`.
                activation = load_activation(data_dir)
                runtime_commands.update_policy(
                    data_dir, activation=activation, session_id=sid,
                    rule_type=rule_type, selector=selector)
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return
            except RuntimeRefusal as refusal:
                # I5/§D: say what is known. Nothing was transmitted and
                # nothing was written, so "no rule was saved" is a fact
                # here, not a guess.
                self._send_json(503, {"error": POLICY_PREFLIGHT_REFUSAL,
                                      "code": refusal.code})
                return
            except runtime_commands.PolicyOutcomeUnknown:
                # Transmitted, and no reply. The rule may or may not have
                # been saved; the one thing this must not do is claim it
                # was not, and the one thing it must not try is again.
                self._send_json(503, {"error": POLICY_OUTCOME_UNKNOWN,
                                      "code": "request_failed"})
                return
            # `saved`, not `applied`: the write happened, and that is the
            # only thing this response can honestly certify. `enforcement`
            # carries the rest — see `_rule_confirmation` and #49 item 2.
            self._send_json(200, {
                "saved": True,
                "enforcement": "conditional",
                "message": _rule_confirmation(rule_type, selector),
            })
            return

        self._send_json(404, {"error": "not found"})


class UIServer(HTTPServer):
    """Serve requests sequentially with `HTTPServer`. `serve()` disables
    SQLite thread affinity before handing the connection to the background
    request thread. Once serving starts, that thread exclusively owns ledger
    access. A threaded server would also require connection serialization."""

    allow_reuse_address = True

    def __init__(self, ledger: Ledger, ledger_path: Path,
                 data_dir: Path | None = None):
        # Port 0: ask the OS for an ephemeral port. 127.0.0.1 only -- I2,
        # no network exposure beyond localhost.
        super().__init__(("127.0.0.1", 0), _Handler)
        self.ledger = ledger
        #: The reader connection above is `mode=ro` (#66), so a policy
        #: write opens its own short-lived writable one at this path.
        self.ledger_path = Path(ledger_path)
        #: Where the writer lock lives. Not `ledger_path.parent`, which
        #: stops being `$PLUGIN_DATA` once the active store moves.
        self.data_dir = (Path(data_dir) if data_dir is not None
                         else resolve_data_dir())


def serve(session_id: str | None = None, *, print_url: bool = True) -> UIServer:
    """Start the UI server in a background thread and return it. `session_id`
    is used only to build the printed URL's query string (a convenience for
    the browser tab that opens it) -- every request still carries its own
    `session_id`, resolved by `_session_id()` above."""
    ledger_path = _ledger_path()
    if ledger_path is None:
        print("privacy-hud local-ui: PLUGIN_DATA is not set and no Codex "
              "plugin-data directory was found", file=sys.stderr)
        raise SystemExit(1)
    if not ledger_path.exists():
        # A reader never creates the ledger: the daemon does, on the first
        # SessionStart. An empty file made here would be a ledger nobody
        # writes to.
        print(f"privacy-hud local-ui: no ledger at {ledger_path} yet; the "
              "daemon creates it when a Codex session starts",
              file=sys.stderr)
        raise SystemExit(1)
    matrix = load_matrix()
    ledger = Ledger(ledger_path, matrix, initialize=False,
                    check_same_thread=False)
    server = UIServer(ledger, ledger_path, resolve_data_dir())

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # `getsockname()`, not `server_address`: the latter is typed to admit
    # bytes (an AF_UNIX path), which an f-string would render as b'...'.
    host, port = server.socket.getsockname()[:2]
    query = f"?session_id={session_id}" if session_id else ""
    url = f"http://{host}:{port}/{query}"
    if print_url:
        # Flushed, not left in the buffer. This process blocks forever
        # after printing, and Python block-buffers stdout when it is not a
        # terminal -- so the one line this command exists to emit never
        # arrived for anything that read it through a pipe, which is how
        # the `$privacy` skill's step 3 backgrounds it (#66).
        print(url, flush=True)
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
