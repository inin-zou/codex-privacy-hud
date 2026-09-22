"""The browser's session label, from the real `ui/app.js` (#49 item 1b).

`test_browser_honesty.py` pins `ui/app.js` with source tripwires because the
suite had no JS runtime. These run the actual script under Node against the
real local UI server, with a minimal DOM stub standing in for the page. The
stub seeds the subtitle with whatever `ui/index.html` ships, so the static
markup is tested too, not assumed.

What is pinned: the subtitle names the selected session by its full ID and
never claims it is the viewer's current session. `Session <id>` when an ID
is known, the static `Session ID unknown` until then (or if resolution
fails), and `No session on record` when the server resolved and found none.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from privacy_hud import dispatch as dispatch_mod
from privacy_hud import local_ui_server

REPO = Path(__file__).resolve().parents[1]
APP_JS = REPO / "ui" / "app.js"
INDEX_HTML = REPO / "ui" / "index.html"
SID = "0199e2e0-b10c-4000-8000-0000000049bb"

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")

_HARNESS = r"""
const fs = require("fs");
const [appPath, configJson] = process.argv.slice(2);
const cfg = JSON.parse(configJson);
const elements = {};
const errors = [];

function makeEl(id) {
  const e = {
    id, _text: "", _html: "", htmlWrites: [], dataset: {}, style: {},
    hidden: false, value: "",
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener() {}, focus() {}, setAttribute() {},
    querySelectorAll() { return []; },
    querySelector() { return makeEl("_query"); },
    appendChild(child) { return child; },
  };
  Object.defineProperty(e, "textContent", {
    get() { return e._text; }, set(v) { e._text = String(v); } });
  Object.defineProperty(e, "innerHTML", {
    get() { return e._html; },
    set(v) { e._html = String(v); e.htmlWrites.push(String(v)); } });
  return e;
}

global.document = {
  getElementById(id) { return elements[id] || (elements[id] = makeEl(id)); },
  querySelector() { return makeEl("_query"); },
  querySelectorAll() { return []; },
  addEventListener() {},
};
global.document.getElementById("subtitle").textContent = cfg.initialSubtitle;
global.location = { search: cfg.search || "" };

const requests = [];
const realFetch = global.fetch;
global.fetch = async (url, opts) => {
  const path = String(url);
  requests.push(path);
  if (cfg.fail) throw new Error("unavailable");
  const route = (cfg.routes || {})[path.split("?")[0]];
  if (route !== undefined) {
    return { ok: true, json: async () => route };
  }
  return realFetch(cfg.base + path, opts);
};
process.on("unhandledRejection", (e) => { errors.push(String(e)); });

new Function(fs.readFileSync(appPath, "utf8"))();

setTimeout(() => {
  const subtitle = global.document.getElementById("subtitle");
  process.stdout.write(JSON.stringify({
    subtitle: subtitle.textContent,
    subtitleHtmlWrites: subtitle.htmlWrites,
    requests, errors,
  }));
}, cfg.waitMs || 2000);
"""


def _static_subtitle() -> str:
    html = INDEX_HTML.read_text(encoding="utf-8")
    match = re.search(r'id="subtitle"[^>]*>([^<]*)<', html)
    assert match, "ui/index.html has no subtitle element"
    return match.group(1)


def _run_app(*, base: str = "", search: str = "", routes: dict | None = None,
             fail: bool = False) -> dict:
    config = {"base": base, "search": search, "routes": routes or {},
              "fail": fail, "initialSubtitle": _static_subtitle()}
    with tempfile.TemporaryDirectory() as tmp:
        harness = Path(tmp) / "harness.js"
        harness.write_text(_HARNESS, encoding="utf-8")
        proc = subprocess.run(
            [NODE, str(harness), str(APP_JS), json.dumps(config)],
            capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _start(state, session_id: str, cwd: str = "/w") -> None:
    dispatch_mod.dispatch(state, {
        "hook_event_name": "SessionStart", "session_id": session_id,
        "cwd": cwd, "model": "gpt-5", "turn_id": "t1"})


@pytest.fixture
def ui(state):
    _start(state, SID)
    server = local_ui_server.serve(SID, print_url=False)
    host, port = server.socket.getsockname()[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _data_requests(requests: list[str]) -> list[str]:
    return [r for r in requests
            if r.startswith("/api/") and not r.startswith(("/api/session",
                                                          "/api/copy"))]


@needs_node
@pytest.mark.parametrize("how", ["url", "resolved"])
def test_browser_subtitle_labels_explicit_and_resolved_ids(ui, how):
    search = f"?session_id={SID}" if how == "url" else ""
    out = _run_app(base=ui, search=search)
    assert out["errors"] == []
    assert out["subtitle"] == f"Session {SID}"
    data = _data_requests(out["requests"])
    assert data, "the page made no data request"
    for request in data:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(request).query)
        assert query.get("session_id") == [SID], request
    if how == "url":
        assert not any(r.startswith("/api/session") for r in out["requests"])


@needs_node
def test_browser_subtitle_empty_and_unavailable():
    assert _static_subtitle() == "Session ID unknown"

    unavailable = _run_app(fail=True)
    assert unavailable["subtitle"] == "Session ID unknown"

    none = _run_app(routes={"/api/session": {"session_id": None}})
    assert none["subtitle"] == "No session on record"
    assert _data_requests(none["requests"]) == []


@needs_node
def test_browser_subtitle_renders_id_as_text():
    """An ID is written as text, never as markup, and never shortened."""
    odd = "<b>id</b>&" + "x" * 300
    out = _run_app(search="?" + urllib.parse.urlencode({"session_id": odd}),
                   routes={"/api/copy": {"empty_messages": {}, "acronyms": {}},
                           "/api/summary": {"percent": 0, "exposed_items": 0,
                                            "destinations": 0, "prevented": 0},
                           "/api/exposures": {"rows": [], "text": "",
                                              "empty_message": "",
                                              "coverage_banner": None}})
    assert out["subtitle"] == f"Session {odd}"
    assert all(odd not in write for write in out["subtitleHtmlWrites"])


def test_browser_ascii_names_the_selected_session(ui):
    """The ASCII view the page can reveal says which session it is, and
    still carries its coverage caveat."""
    for tab in ("Exposed", "Prevented", "All events"):
        q = urllib.parse.urlencode({"session_id": SID, "tab": tab})
        with urllib.request.urlopen(f"{ui}/api/exposures?{q}") as r:
            payload = json.load(r)
        assert payload["text"].split("\n")[1] == f"Session {SID}", tab
        assert "coverage_banner" in payload
