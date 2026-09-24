"""#54 Phase 4 P4-C7: the real `ui/app.js` in version-2 accounting mode.

Runs the page script under Node against the real local UI server (or
scripted replies), with a DOM stub that records what the script renders
and replays the click handlers it registers, as the legacy browser tests
do. Version-2 sessions are synthetic unless a test starts one through
production dispatch.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

import pytest
from accounting_fakes import (
    E, crossed, event, observation, pre, prepared_ledger, start_v2,
    value_subject,
)

from privacy_hud import local_ui_server
from privacy_hud.accounting import ACCOUNTING_NOTE
from runtime_helpers import close_writer

REPO = Path(__file__).resolve().parents[1]
APP_JS = REPO / "ui" / "app.js"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

ERROR = ("Privacy HUD accounting could not be read. No percentage or counts "
         "are available.")
ZERO_LINE = "0 confirmed points does not mean no disclosure occurred."

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
      child.dataset[attr] = m[1];
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
    style: {}, hidden: false, value: "", disabled: false,
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
global.location = { search: cfg.search || "" };

const requests = [];
const posts = [];
const realFetch = global.fetch;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
global.fetch = async (url, opts) => {
  const path = String(url);
  requests.push(path);
  if (opts && opts.method === "POST") posts.push({ path, body: JSON.parse(opts.body) });
  const route = (cfg.routes || {})[path.split("?")[0]];
  if (route !== undefined) {
    if (route && route.__delay) await sleep(route.__delay);
    const status = (route && route.__status) || 200;
    const body = route && route.__body !== undefined ? route.__body : route;
    if (route && route.__passthrough) {
      const res = await realFetch(cfg.base + path, opts);
      return res;
    }
    return { ok: status < 400, status, json: async () => body };
  }
  return realFetch(cfg.base + path, opts);
};
process.on("unhandledRejection", (e) => { errors.push(String(e)); });

new Function(fs.readFileSync(appPath, "utf8"))();

function dump() {
  const out = {};
  for (const [id, e] of Object.entries(elements)) {
    out[id] = { text: e._text, html: e._html, hidden: e.hidden,
                display: e.style.display || null };
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
    } else if (action.startsWith("tab:")) {
      const name = action.slice(4);
      const tabs = elements.tabs ? elements.tabs.querySelectorAll(".tab") : [];
      const tab = tabs.find((t) => t.dataset.tab === name);
      steps.push({ action, found: !!tab });
      if (tab) for (const fn of tab.handlers.click || []) fn();
    } else if (action.startsWith("click-action:")) {
      const i = action.slice(13);
      const buttons = elements.detailActions
        ? elements.detailActions.querySelectorAll("button[data-i]") : [];
      const button = buttons.find((b) => b.dataset.i === i);
      steps.push({ action, found: !!button });
      if (button) for (const fn of button.handlers.click || []) await fn();
    } else if (action.startsWith("wait:")) {
      await sleep(Number(action.slice(5)));
      continue;
    }
    await sleep(cfg.stepMs || 800);
  }
  process.stdout.write(JSON.stringify({ elements: dump(), requests, posts, errors, steps }));
})();
"""


def _run(*, base: str = "", search: str = "", routes: dict | None = None,
         actions: list[str] | None = None, step_ms: int = 800) -> dict:
    config = {"base": base, "search": search, "routes": routes or {},
              "actions": actions or [], "stepMs": step_ms}
    with tempfile.TemporaryDirectory() as tmp:
        harness = Path(tmp) / "harness.js"
        harness.write_text(_HARNESS, encoding="utf-8")
        proc = subprocess.run(
            [NODE, str(harness), str(APP_JS), json.dumps(config)],
            capture_output=True, text=True, timeout=90)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def unresolved_denial(sid):
    return observation(sid, decision="deny",
                       evidence=E.DENY_ISSUED | E.LOCAL_DETECTION
                       | E.HOOK_OBSERVED, potential_crossing=True)


def _seed(tmp_path: Path, *, crossing: bool = False) -> str:
    led = prepared_ledger(tmp_path / "ledger.db")
    sid = start_v2(led)
    for value in ("a@example.com", "b@example.com"):
        led.record_observation(unresolved_denial(sid), [event(
            value_subject(value), kind="prevented",
            evidence=E.DENY_ISSUED | E.LOCAL_DETECTION)])
    led.record_observation(pre(sid), [event(
        value_subject("c@example.com"), kind="permitted",
        evidence=E.PERMISSION_ISSUED | E.LOCAL_DETECTION)])
    if crossing:
        led.record_observation(crossed(sid), [event()])
    close_writer(led)
    return sid


@pytest.fixture
def v2ui(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    sid = _seed(tmp_path)
    server = local_ui_server.serve(sid, print_url=False)
    host, port = server.socket.getsockname()[:2]
    try:
        yield f"http://{host}:{port}", sid
    finally:
        server.shutdown()
        server.server_close()


def test_browser_renders_v2_accounting(v2ui):
    base, sid = v2ui
    out = _run(base=base, search=f"?session_id={sid}")
    assert out["errors"] == []
    el = out["elements"]
    tiles = el["tiles"]["html"]
    for label in ("confirmed points", "distinct disclosures",
                  "confirmed recipients", "denials issued"):
        assert label in tiles
    assert "legacy" not in tiles
    assert "Disclosure percentage: unavailable." in el["accountingNote"]["text"]
    assert ("3 unresolved actions. Percentage unavailable until the "
            "required evidence is available.") in el["accountingNote"]["text"]
    assert ZERO_LINE in el["accountingNote"]["text"]
    assert ACCOUNTING_NOTE in el["accountingNote"]["text"]
    tabs = el["tabs"]["html"]
    assert "Confirmed crossings 0" in tabs
    assert "Interventions 2" in tabs
    assert "All finding events 3" in tabs
    for band in ("safe", "warn", "danger"):
        assert band not in tiles
    assert "0%" not in tiles


def test_browser_rejects_malformed_v2_summary(v2ui):
    base, sid = v2ui
    status, good = _fetch(base, "/api/exposures", session_id=sid,
                          tab="Exposed")
    assert status == 200
    for change in ({"unresolved_actions": None},
                   {"confirmed_points": "0"}, {"denials_issued": True},
                   {"percent": 101}, {"observations": -1},
                   {"denials_issued": 1.5}):
        broken = dict(good)
        broken["summary"] = {**good["summary"], **change}
        out = _run(base=base, search=f"?session_id={sid}",
                   routes={"/api/exposures": broken})
        el = out["elements"]
        assert el["empty"]["text"] == ERROR, change
        tiles = el["tiles"]["html"]
        assert "confirmed points" not in tiles and "0" not in tiles, change
    missing = dict(good)
    missing["summary"] = {k: v for k, v in good["summary"].items()
                          if k != "denials_issued"}
    out = _run(base=base, search=f"?session_id={sid}",
               routes={"/api/exposures": missing})
    assert out["elements"]["empty"]["text"] == ERROR


def test_browser_uses_matching_rows_and_summary(v2ui):
    """Tiles and tab counts come from the summary delivered with the rows,
    not from a separately fetched /api/summary of another moment."""
    base, sid = v2ui
    status, stale = _fetch(base, "/api/summary", session_id=sid)
    stale = {**stale, "denials_issued": 9, "unresolved_actions": 9}
    out = _run(base=base, search=f"?session_id={sid}",
               routes={"/api/summary": stale})
    el = out["elements"]
    assert "9" not in el["tiles"]["html"]
    assert "2" in el["tiles"]["html"]
    assert "Interventions 2" in el["tabs"]["html"]


def test_browser_clears_detail_across_accounting_versions(v2ui):
    base, sid = v2ui
    out = _run(base=base, search=f"?session_id={sid}",
               routes={"/api/detail": {"__delay": 1200,
                                       "__passthrough": True}},
               actions=["tab:All events", "click-first-row", "wait:100",
                        "tab:Exposed"], step_ms=300)
    out2 = out["elements"]
    assert out2["detailFields"]["html"] == ""
    assert out2["detailActions"]["html"] == ""
    # The same late reply, with nothing changed meanwhile, is rendered.
    kept = _run(base=base, search=f"?session_id={sid}",
                routes={"/api/detail": {"__delay": 1200,
                                        "__passthrough": True}},
                actions=["tab:All events", "click-first-row", "wait:1600"],
                step_ms=300)
    assert "Subject" in kept["elements"]["detailFields"]["html"]


def test_opaque_source_is_not_a_policy_selector(v2ui):
    base, sid = v2ui
    out = _run(base=base, search=f"?session_id={sid}",
               actions=["tab:All events", "click-first-row"])
    el = out["elements"]
    actions = el["detailActions"]["html"]
    assert "Save mask rule for detected email" in actions
    assert "block rule" not in actions
    assert ("A source rule cannot be saved from this opaque label."
            in el["detailFields"]["html"] + actions)
    assert all(p["body"]["rule_type"] == "mask" for p in out["posts"])


def test_browser_null_percent_keeps_valid_conditional_actions(v2ui):
    base, sid = v2ui
    out = _run(base=base, search=f"?session_id={sid}",
               actions=["tab:All events", "click-first-row"])
    el = out["elements"]
    assert "Save mask rule for detected email" in el["detailActions"]["html"]
    assert el["detailEmpty"]["hidden"]
    assert "Subject" in el["detailFields"]["html"]
    assert "Occurrences in this observation" in el["detailFields"]["html"]


def test_browser_error_mode_clears_actions_and_detail(v2ui):
    base, sid = v2ui
    out = _run(base=base, search=f"?session_id={sid}",
               routes={"/api/exposures": {"__status": 409,
                                          "__body": {"error": ERROR}}},
               actions=["click-first-row"])
    el = out["elements"]
    assert el["empty"]["text"] == ERROR
    assert el["rows"]["html"] == ""
    assert el.get("detailActions", {"html": ""})["html"] == ""
    assert "confirmed points" not in el["tiles"]["html"]
    assert out["posts"] == []


def _fetch(base, path, **query):
    import urllib.parse
    import urllib.request
    url = f"{base}{path}?{urllib.parse.urlencode(query)}"
    with urllib.request.urlopen(url) as r:
        return r.status, json.load(r)


# --------------------------------------------------------------------- #
# the policy action, end to end
# --------------------------------------------------------------------- #

@pytest.fixture
def prod(monkeypatch):
    """A production-dispatch session on a short data directory, with a
    real policy daemon and the local UI beside it."""
    from privacy_hud import dispatch as dispatch_mod
    from privacy_hud.detect.paths import PathDetector
    from privacy_hud.detect.secrets import SecretDetector
    from runtime_helpers import (
        policy_daemon, select_runtime, short_data_dir, writer_state,
    )
    from test_accounting_dispatch import EmailDetector

    data_dir = short_data_dir(prefix="phv")
    select_runtime(data_dir)
    monkeypatch.setenv("PLUGIN_DATA", str(data_dir))
    state = writer_state(data_dir)
    state.detectors = [PathDetector(), SecretDetector(), EmailDetector()]
    sid = "0199e2e0-b10c-4000-8000-0000000054b2"
    try:
        dispatch_mod.dispatch(state, {"hook_event_name": "SessionStart",
                                      "session_id": sid, "cwd": "/w"})
        dispatch_mod.dispatch(state, {
            "hook_event_name": "PostToolUse", "session_id": sid,
            "tool_name": "Read", "tool_use_id": "t1",
            "tool_input": {"file_path": "/w/notes.txt"},
            "tool_response": "contact jordan@acme.test"})
        with policy_daemon(data_dir):
            server = local_ui_server.serve(sid, print_url=False)
            host, port = server.socket.getsockname()[:2]
            try:
                yield state, sid, f"http://{host}:{port}", server
            finally:
                server.shutdown()
                server.server_close()
    finally:
        state.ledger.conn.close()
        shutil.rmtree(data_dir, ignore_errors=True)


def test_v2_browser_policy_uses_matching_daemon_rpc(prod):
    state, sid, base, server = prod
    assert state.ledger.summary(sid).accounting_version == 2
    out = _run(base=base, search=f"?session_id={sid}",
               actions=["tab:All events", "click-first-row",
                        "click-action:0"])
    assert out["posts"] == [{"path": "/api/policy", "body": {
        "session_id": sid, "rule_type": "mask", "selector": "email"}}]
    assert "Rule saved: mask email" in \
        out["elements"]["ruleConfirmation"]["text"]
    rules = state.ledger.conn.execute(
        "SELECT rule_type, selector FROM policy").fetchall()
    assert ("mask", "email") in [tuple(r) for r in rules]
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        server.ledger.conn.execute(
            "INSERT INTO policy(scope,rule_type,selector,created_at)"
            " VALUES('x','mask','email',1)")


def test_v2_mask_rule_button_reaches_policy_and_engine(prod):
    from privacy_hud import dispatch as dispatch_mod

    state, sid, base, _server = prod
    _run(base=base, search=f"?session_id={sid}",
         actions=["tab:All events", "click-first-row", "click-action:0"])
    out = dispatch_mod.dispatch(state, {
        "hook_event_name": "PreToolUse", "session_id": sid,
        "tool_name": "mcp__crm__send", "tool_use_id": "t2",
        "tool_input": {"body": "to jordan@acme.test"}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "jordan@acme.test" not in json.dumps(
        out["hookSpecificOutput"]["updatedInput"])
    last = state.ledger.conn.execute(
        "SELECT decision FROM observations WHERE session_id=?"
        " ORDER BY rowid DESC LIMIT 1", (sid,)).fetchone()
    assert last[0] == "rewrite"
