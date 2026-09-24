"""#54 phase 1: the real `ui/app.js` under legacy and unrecorded summaries.

Runs the page script under Node against the real local UI server, as
`test_browser_js.py` does, with a DOM stub that also records the rows,
tabs and buttons the script renders and the click handlers it registers.
A row click is replayed through the handler the script registered, so the
detail view is the one a user would see.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from privacy_hud import local_ui_server

REPO = Path(__file__).resolve().parents[1]
APP_JS = REPO / "ui" / "app.js"
INDEX_HTML = REPO / "ui" / "index.html"
SID = "0199e2e0-b10c-4000-8000-00000000054a"

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

LEGACY_NOTE = ("Historical accounting includes permitted crossings and may "
               "collapse different outcomes. It does not establish confirmed "
               "disclosure.")
UNRECORDED_NOTE = ("No session record is available in this ledger. The "
                   "percentage and counts are unavailable.")

_HARNESS = r"""
const fs = require("fs");
const [appPath, configJson] = process.argv.slice(2);
const cfg = JSON.parse(configJson);
const elements = {};
const errors = [];

function childrenFor(parent, attr) {
  const re = new RegExp(`data-${attr}="([^"]*)"`, "g");
  const found = [];
  let m;
  while ((m = re.exec(parent._html)) !== null) {
    const key = `${attr}:${m[1]}`;
    if (!parent._children[key]) {
      const child = makeEl(key);
      child.dataset[attr === "i" ? "i" : attr] = m[1];
      const id = parent._html.slice(m.index).match(/data-id="([^"]*)"/);
      if (id) child.dataset.id = id[1];
      parent._children[key] = child;
    }
    found.push(parent._children[key]);
  }
  return found;
}

function makeEl(id) {
  const e = {
    id, _text: "", _html: "", _children: {}, handlers: {}, dataset: {},
    style: {}, hidden: false, value: "",
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener(type, fn) { (e.handlers[type] = e.handlers[type] || []).push(fn); },
    focus() {}, setAttribute() {},
    querySelectorAll(sel) {
      if (sel === ".row") return childrenFor(e, "index");
      if (sel === ".tab") return childrenFor(e, "tab");
      if (sel === "button[data-i]") return childrenFor(e, "i");
      return [];
    },
    querySelector() { return makeEl("_query"); },
    appendChild(child) { return child; },
  };
  Object.defineProperty(e, "textContent", {
    get() { return e._text; }, set(v) { e._text = String(v); } });
  Object.defineProperty(e, "innerHTML", {
    get() { return e._html; },
    set(v) { e._html = String(v); e._children = {}; } });
  return e;
}

global.document = {
  getElementById(id) { return elements[id] || (elements[id] = makeEl(id)); },
  querySelector() { return makeEl("_query"); },
  querySelectorAll() { return []; },
  addEventListener() {},
};
for (const [id, init] of Object.entries(cfg.initial || {})) {
  const el = global.document.getElementById(id);
  el.textContent = init.text || "";
  el.hidden = !!init.hidden;
}
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function dump() {
  const out = {};
  for (const [id, e] of Object.entries(elements)) {
    out[id] = { text: e._text, html: e._html, hidden: e.hidden,
                display: e.style.display || null,
                clicks: (e.handlers.click || []).length };
  }
  return out;
}

(async () => {
  await sleep(cfg.waitMs || 1500);
  const steps = [];
  for (const action of cfg.actions || []) {
    if (action === "click-first-row") {
      const rows = elements.rows ? elements.rows.querySelectorAll(".row") : [];
      steps.push({ action, rows: rows.length });
      if (rows.length) for (const fn of rows[0].handlers.click || []) fn();
    }
    await sleep(800);
  }
  process.stdout.write(JSON.stringify({ elements: dump(), requests, errors, steps }));
})();
"""


def _static(id_: str) -> dict:
    html = INDEX_HTML.read_text(encoding="utf-8")
    m = re.search(rf'<[^>]*id="{id_}"([^>]*)>([^<]*)<', html)
    if not m:
        return {"text": "", "hidden": False}
    return {"text": m.group(2), "hidden": " hidden" in m.group(1)}


def _run(*, base: str = "", search: str = "", routes: dict | None = None,
         fail: bool = False, actions: list[str] | None = None) -> dict:
    initial = {i: _static(i) for i in (
        "subtitle", "accountingStatus", "accountingNote", "empty",
        "detailEmpty")}
    config = {"base": base, "search": search, "routes": routes or {},
              "fail": fail, "actions": actions or [], "initial": initial}
    with tempfile.TemporaryDirectory() as tmp:
        harness = Path(tmp) / "harness.js"
        harness.write_text(_HARNESS, encoding="utf-8")
        proc = subprocess.run(
            [NODE, str(harness), str(APP_JS), json.dumps(config)],
            capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _start(state, session_id: str) -> None:
    """A legacy-accounted session, as 0.8.x recorded one. A genuine
    SessionStart now creates a version-2 session (#54 Phase 4), so the
    legacy page is exercised on a session that existed before activation."""
    state.ledger.start_session(session_id, cwd="/w", model="gpt-5")


@pytest.fixture
def ui(state):
    _start(state, SID)
    state.ledger.record(
        SID, turn_id="t1", kind="exposed", data_type="email",
        source="/w/support.log", source_kind="path",
        destination="model_context", value_hash=b"\x01" * 16,
        masked_example="jo•••@acme.com", tool_name="Read", protection=None)
    server = local_ui_server.serve(SID, print_url=False)
    host, port = server.socket.getsockname()[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_index_html_ships_no_number_or_success_state():
    html = INDEX_HTML.read_text(encoding="utf-8")
    body = html.split("<body>", 1)[1]
    assert "0%" not in body
    assert 'id="accountingStatus"' in body
    assert 'id="accountingNote"' in body
    assert _static("detailEmpty")["hidden"]


def test_legacy_page_labels_its_tiles_and_shows_the_note(ui):
    out = _run(base=ui, search=f"?session_id={SID}")
    assert out["errors"] == []
    el = out["elements"]
    tiles = el["tiles"]["html"]
    for label in ("legacy permitted-crossing score",
                  "legacy permitted-crossing rows",
                  "legacy boundary kinds", "legacy prevented rows"):
        assert label in tiles
    assert "of budget" not in tiles
    assert el["accountingNote"]["text"] == LEGACY_NOTE
    assert not el["accountingNote"]["hidden"]
    tabs = el["tabs"]["html"]
    assert "Legacy permitted crossings 1" in tabs
    assert "Legacy prevented rows 0" in tabs
    assert "All legacy events 1" in tabs
    assert 'data-tab="Exposed"' in tabs


def test_legacy_detail_uses_legacy_labels_and_real_save_buttons(ui):
    out = _run(base=ui, search=f"?session_id={SID}",
               actions=["click-first-row"])
    assert out["steps"] == [{"action": "click-first-row", "rows": 1}]
    el = out["elements"]
    assert "LEGACY PERMITTED" in el["rows"]["html"]
    fields = el["detailFields"]["html"]
    assert "Legacy intervention" in fields
    assert "no intervention recorded" in fields
    assert "Legacy score contribution" in fields
    assert "legacy pts" in fields
    assert "Protection" not in fields
    actions = el["detailActions"]["html"]
    assert "Save mask rule for detected email" in actions
    assert "Save block rule for values read from /w/support.log" in actions
    assert "[ " not in actions
    assert el["detailActions"]["clicks"] == 0  # handlers live on buttons
    assert el["detailEmpty"]["hidden"]


def test_unrecorded_explicit_id_renders_no_numbers_rows_or_actions(ui):
    out = _run(base=ui, search="?session_id=missing-session")
    assert out["errors"] == []
    el = out["elements"]
    tiles = el["tiles"]["html"]
    assert "—%" in tiles and "percentage unavailable" in tiles
    assert "permitted-crossing rows unavailable" in tiles
    assert "0%" not in tiles
    for band in ("safe", "warn", "danger"):
        assert band not in tiles
    assert el["accountingStatus"]["text"] == "NO SESSION RECORD"
    assert el["accountingNote"]["text"] == UNRECORDED_NOTE
    tabs = el["tabs"]["html"]
    assert "Legacy permitted crossings —" in tabs
    assert el["rows"]["html"] == ""
    assert el["empty"]["text"] == (
        "No events can be shown for an unrecorded session. This is not "
        "evidence that none occurred.")
    assert el.get("detailActions", {"html": ""})["html"] == ""
    assert el["detail"]["display"] in (None, "none")


def test_no_resolved_session_renders_the_unrecorded_view_locally():
    out = _run(routes={"/api/session": {"session_id": None}})
    el = out["elements"]
    assert el["subtitle"]["text"] == "No session on record"
    assert el["accountingStatus"]["text"] == "NO SESSION RECORD"
    assert "—%" in el["tiles"]["html"]
    assert [r for r in out["requests"]
            if r.startswith(("/api/summary", "/api/exposures"))] == []


def test_a_failed_fetch_is_not_an_unrecorded_session():
    out = _run(fail=True)
    el = out["elements"]
    assert el["accountingStatus"]["text"] != "NO SESSION RECORD"
    assert "0%" not in el.get("tiles", {"html": ""})["html"]


def test_a_missing_tab_response_counts_as_unavailable_not_zero(ui):
    out = _run(base=ui, search=f"?session_id={SID}",
               routes={"/api/exposures": {"error": "unavailable"}})
    tabs = out["elements"]["tabs"]["html"]
    assert "Legacy permitted crossings —" in tabs
    assert "Legacy permitted crossings 0" not in tabs
