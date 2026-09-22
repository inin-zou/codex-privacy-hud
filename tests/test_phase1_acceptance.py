"""Regression cases from the commits 1–2 acceptance review."""
from __future__ import annotations

import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from privacy_hud.ledger import Ledger, SCHEMA, UnsupportedAccounting


@pytest.mark.parametrize("table", ["events", "events_legacy_v1"])
@pytest.mark.parametrize("operation", ["summary", "list", "detail"])
def test_required_legacy_columns_are_not_fabricated(table, operation):
    ledger = Ledger.__new__(Ledger)
    ledger.conn = sqlite3.connect(":memory:", isolation_level=None)
    ledger.conn.row_factory = sqlite3.Row
    try:
        ledger.conn.executescript(SCHEMA)
        ledger.conn.execute(
            "INSERT INTO sessions(session_id, started_at, budget_cap)"
            " VALUES ('s', 1, 120)")
        if table == "events_legacy_v1":
            ledger.conn.execute(
                "ALTER TABLE events RENAME TO events_legacy_v1")
        ledger.conn.execute(f"ALTER TABLE {table} DROP COLUMN ts")
        with pytest.raises(UnsupportedAccounting):
            if operation == "summary":
                ledger.summary("s")
            elif operation == "list":
                ledger.list_events("s", "exposed")
            else:
                ledger.get_event("s", 1)
    finally:
        ledger.conn.close()


def test_browser_errors_and_unrecorded_detail_transitions():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    app = Path(__file__).resolve().parents[1] / "ui" / "app.js"
    script = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const elements = {};
function element(id) {
  return elements[id] ||= {
    style: {}, hidden: true, textContent: "", innerHTML: "",
    dataset: {}, addEventListener() {},
    querySelectorAll() { return []; },
    classList: { add() {}, remove() {} },
  };
}
global.document = {
  getElementById: element,
  querySelectorAll() { return []; },
  querySelector() { return null; },
};
global.location = { search: "" };
let response;
let ok;
global.fetch = async () => ({
  ok, json: async () => response,
});
let source = fs.readFileSync(process.argv[1], "utf8");
source = source.replace(
  "  async function loadAll() {",
  `  global.review = {
       loadAll, renderDetail,
       set(s, m, id) { summary = s; mode = m; sessionId = id; },
       mode() { return mode; }
     };
     async function loadAll() {`
);
source = source.replace(/  loadAll\(\)[\s\S]*?\n\}\)\(\);\s*$/, "})();");
new Function(source)();

(async () => {
  for (const [success, body] of [
    [false, {error: "unavailable"}],
    [true, {error: "unavailable"}],
    [true, {}],
    [true, null],
  ]) {
    ok = success;
    response = body;
    review.set(null, "unavailable", null);
    await assert.rejects(review.loadAll());
    assert.equal(review.mode(), "unavailable");
  }

  const summary = {
    accounting_version: 1, legacy_percent: 0,
    accounting_note: "legacy",
  };
  const row = {
    id: 1, data_type: "email", count: 1,
    source: "/w/a.log", source_kind: "path",
    destination: "model_context",
  };
  review.set(summary, "legacy", "s");
  review.renderDetail(row);
  assert.match(element("detailActions").innerHTML, /Save mask rule/);
  element("ruleConfirmation").textContent = "old confirmation";

  ok = true;
  response = {session_id: null};
  review.set(summary, "legacy", null);
  await review.loadAll();
  assert.equal(review.mode(), "unrecorded");
  assert.equal(element("detailActions").innerHTML, "");
  assert.equal(element("detailFields").innerHTML, "");
  assert.equal(element("ruleConfirmation").textContent, "");
  assert.equal(element("detailEmpty").textContent,
    "No event detail is available for an unrecorded session.");

  review.renderDetail(row);
  assert.equal(element("detailActions").innerHTML, "");
  assert.equal(element("detailFields").innerHTML, "");
  review.renderDetail(null);
  assert.equal(element("detailActions").innerHTML, "");
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
"""
    result = subprocess.run(
        [node, "-e", script, str(app)],
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
