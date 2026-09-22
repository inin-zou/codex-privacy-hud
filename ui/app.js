// ui/app.js — Privacy HUD local audit UI (design.md §5 L2, §6 L3).
//
// Vanilla JS, no build step, no framework. Talks to the four GET / two POST
// endpoints local_ui_server.py exposes, which are themselves thin wrappers
// around the same `privacy_hud.mcp_tools` functions `tests/test_mcp.py`
// verifies never leak a raw value (I1) — this file adds no logic that could
// reintroduce one; every field it renders is exactly what those JSON
// responses already contain.
//
// Row aggregation (design.md §13, open question #2 — "does All events need
// an expandable row, or is the flat timeline enough?"): this UI does NOT
// aggregate rows by (data_type, source, destination) the way the design
// mockup's "×12" counts suggest. Every other place that renders ledger rows
// today (render.py's own `audit()`/`receipt()`, dispatch.py's SessionEnd
// handler) also renders one row per ledger event with no aggregation step —
// so this UI matches that, rather than inventing a second, independent
// aggregation algorithm that could disagree with the first. A row's own
// `count` field (from the ledger's per-value dedupe) is shown as `×N`
// exactly as render.py's `_title()` does; it will often read `×1` where the
// mockup's illustrative "×12" implies multiple distinct values were folded
// together. Fixing this is a real product improvement, not a bug — it's
// listed as an open design question for a reason.
//
// Scan-gap banner (design.md §5): this used to say the
// signal did not exist — `Decision.degraded` was a per-call return value
// the daemon saw transiently and wrote to no table, so there was nothing a
// historical audit page could honestly read. That changed with #47 item 6:
// `Ledger.record_scan_gap` writes an append-only `scan_gaps` row, and
// `SessionCoverage.shallow_scans` counts them, so the coverage banner this
// page already renders now goes off for a session with a scan gap: an
// applicable deep scan supplied no accepted result. Each observed scan gap
// is recorded per observation and counted per session, including
// observations with no event row. What still does not exist is a persisted
// per-EVENT flag: no individual row is marked, which is why there is still
// no per-row "fast-path results only" marker here.
//
// "Allow once" is intentionally not a button anywhere in this file — see
// local_ui_server.py's module docstring for why (the ledger never stores
// `tool_input`, so this static, historical audit view has nothing to mint
// a consent token against; that action belongs to the live block flow).

(function () {
  "use strict";

  // API tab arguments, and what the page calls them. The arguments select
  // stored legacy classifications (#54 phase 1); the labels say so.
  const TABS = ["Exposed", "Prevented", "All events"];
  const TAB_LABELS = {
    "Exposed": "Legacy permitted crossings",
    "Prevented": "Legacy prevented rows",
    "All events": "All legacy events",
  };

  // The unrecorded state's copy, the same strings render.py and ledger.py
  // hold. Kept here because the page must render that state without a
  // server answer when no session resolves; tests/test_browser_legacy_js.py
  // pins each one.
  const UNRECORDED_STATUS = "NO SESSION RECORD";
  const UNRECORDED_NOTE = "No session record is available in this ledger. The percentage and counts are unavailable.";
  const UNRECORDED_EMPTY = "No events can be shown for an unrecorded session. This is not evidence that none occurred.";
  const UNRECORDED_DETAIL = "No event detail is available for an unrecorded session.";
  const UNRECORDED_TILES = [
    ["—%", "percentage unavailable"],
    ["—", "permitted-crossing rows unavailable"],
    ["—", "boundary kinds unavailable"],
    ["—", "prevented rows unavailable"],
  ];
  const UNAVAILABLE = "—";

  // Legacy row chips, by stored kind alone (render._LEGACY_CHIPS).
  const LEGACY_CHIPS = {
    exposed: "LEGACY PERMITTED",
    prevented: "LEGACY PREVENTED ROW",
    local_access: "LEGACY LOCAL ACCESS",
    detected: "LEGACY DETECTED",
    retention: "LEGACY RETENTION",
  };

  // Stored `protection` values as shown (render._PROTECTION_DISPLAY). A
  // denial or rewrite is what Privacy HUD returned, not what the host
  // applied.
  const PROTECTION_DISPLAY = {
    blocked: "denial recorded; host enforcement unconfirmed",
    masked: "rewrite recorded; host application unconfirmed",
    minimized: "rewrite recorded; host application unconfirmed",
    none: "no intervention recorded",
  };
  const ASSOCIATION_NOTE = "This legacy source-to-destination association does not establish delivery or a multi-hop flow.";

  const params = new URLSearchParams(location.search);
  let sessionId = params.get("session_id") || null;
  let activeTab = "Exposed";
  let tabData = {};      // tab name -> {rows, text, ...} or null when unavailable
  let summary = null;
  // "legacy" | "unrecorded" | "unavailable". A failed request is
  // "unavailable", never "unrecorded": failing to ask is not an answer.
  let mode = "unavailable";
  let copy = { acronyms: {} };
  let selectedIndex = -1;

  const $ = (id) => document.getElementById(id);

  // -- copy helpers, mirroring render.py exactly (no re-invented wording) --

  function typeLabel(dataType) {
    if (copy.acronyms && copy.acronyms[dataType]) return copy.acronyms[dataType];
    return dataType.charAt(0).toUpperCase() + dataType.slice(1);
  }

  function title(row) {
    return `${typeLabel(row.data_type)} ×${row.count}`;
  }

  function statusChip(row) {
    return { text: LEGACY_CHIPS[row.kind] || "LEGACY UNKNOWN", cls: "legacy" };
  }

  function protectionDisplay(protection) {
    return PROTECTION_DISPLAY[protection || "none"] || "legacy intervention not recognized";
  }

  function band(pct) {
    if (pct <= 33) return "safe";
    if (pct <= 66) return "warn";
    return "danger";
  }

  function sortRows(tab, rows) {
    const copyRows = rows.slice();
    if (tab === "Exposed") {
      copyRows.sort((a, b) => (b.budget_delta || 0) - (a.budget_delta || 0));
    } else if (tab === "Prevented") {
      copyRows.sort((a, b) => (b.ts || 0) - (a.ts || 0));
    } else {
      copyRows.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    }
    return copyRows;
  }

  function tabRows(tab) {
    const data = tabData[tab];
    return data && Array.isArray(data.rows) ? data.rows : null;
  }

  // -- data fetching ---------------------------------------------------

  async function fetchJSON(path) {
    const res = await fetch(path);
    const data = await res.json();
    if (!res.ok || (data && data.error)) {
      throw new Error("Privacy HUD request failed.");
    }
    return data;
  }

  async function postJSON(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return { ok: res.ok, data: await res.json() };
  }

  async function loadAll() {
    if (!sessionId) {
      const s = await fetchJSON("/api/session");
      if (!s || !(s.session_id === null ||
          (typeof s.session_id === "string" && s.session_id.length > 0))) {
        throw new Error("Privacy HUD session response is invalid.");
      }
      sessionId = s.session_id;
    }
    if (!sessionId) {
      // The server resolved and found no session: render the unrecorded
      // view here, without asking for a summary of an invented ID.
      mode = "unrecorded";
      summary = null;
      tabData = {};
      render();
      return;
    }

    copy = await fetchJSON("/api/copy");
    summary = await fetchJSON(`/api/summary?session_id=${encodeURIComponent(sessionId)}`);
    mode = summary && summary.accounting_version === 1 ? "legacy"
      : summary && summary.accounting_version === 0 ? "unrecorded"
      : "unavailable";

    for (const tab of TABS) {
      try {
        tabData[tab] = await fetchJSON(
          `/api/exposures?session_id=${encodeURIComponent(sessionId)}&tab=${encodeURIComponent(tab)}`
        );
      } catch (e) {
        tabData[tab] = null;
      }
    }

    render();
  }

  // -- rendering ---------------------------------------------------------

  function renderTiles() {
    const note = $("accountingNote");
    const status = $("accountingStatus");
    let tiles = [];
    if (mode === "legacy") {
      // The stored numbers under legacy labels (#54). The score counts
      // permitted crossings and its rows may collapse different outcomes,
      // so none of these is a confirmed-disclosure figure.
      const pct = summary.legacy_percent;
      tiles = [
        [`${pct}%`, "legacy permitted-crossing score", band(pct)],
        [String(summary.legacy_permitted_crossing_rows), "legacy permitted-crossing rows", null],
        [String(summary.legacy_boundary_kinds), "legacy boundary kinds", null],
        [String(summary.legacy_prevented_rows), "legacy prevented rows", null],
      ];
      note.textContent = summary.accounting_note || "";
      note.hidden = !summary.accounting_note;
      status.textContent = "";
      status.hidden = true;
    } else if (mode === "unrecorded") {
      tiles = UNRECORDED_TILES.map(([value, label]) => [value, label, "unavailable"]);
      note.textContent = (summary && summary.accounting_note) || UNRECORDED_NOTE;
      note.hidden = false;
      status.textContent = UNRECORDED_STATUS;
      status.hidden = false;
    } else {
      note.textContent = "";
      note.hidden = true;
      status.textContent = "";
      status.hidden = true;
    }
    $("tiles").innerHTML = tiles.map(([value, label, cls]) => `
      <div class="tile">
        <div class="value${cls ? " " + cls : ""}">${escapeHTML(value)}</div>
        <div class="label">${escapeHTML(label)}</div>
      </div>
    `).join("");
  }

  function renderTabs() {
    $("tabs").innerHTML = TABS.map((tab) => {
      const rows = mode === "legacy" ? tabRows(tab) : null;
      const n = rows ? rows.length : UNAVAILABLE;
      const active = tab === activeTab ? " active" : "";
      return `<button class="tab${active}" role="tab" data-tab="${tab}">${TAB_LABELS[tab]} ${n}</button>`;
    }).join("");
    $("tabs").querySelectorAll(".tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        activeTab = btn.dataset.tab;
        selectedIndex = -1;
        render();
      });
    });
  }

  function renderTable() {
    const data = tabData[activeTab] || null;
    const rows = mode === "legacy" && tabRows(activeTab)
      ? sortRows(activeTab, tabRows(activeTab)) : [];
    const tbody = $("rows");
    const emptyEl = $("empty");

    // The session-scope caveat. It also travels inside `data.text`, but that
    // block lives in the "View as text" region, which is hidden until asked
    // for — so on the surface people actually look at, a caveat delivered
    // only there is a caveat nobody reads. Null on a verified session: shown
    // unconditionally it is noise, and noise is how a warning gets trained
    // away.
    const coverageEl = $("coverage");
    const banner = data && data.coverage_banner;
    coverageEl.textContent = banner || "";
    coverageEl.hidden = !banner;

    // The server decides which empty line applies, because it is the side
    // that holds this session's coverage and accounting. See
    // render.empty_message. With no session resolved there is no server
    // answer, and the unrecorded line is the page's own.
    if (rows.length === 0) {
      tbody.innerHTML = "";
      emptyEl.hidden = false;
      emptyEl.textContent = mode === "unrecorded"
        ? (data && data.empty_message) || UNRECORDED_EMPTY
        : mode === "unavailable"
          ? "Could not load session accounting."
          : tabRows(activeTab) === null
            ? "Could not load events for this tab."
            : (data && data.empty_message) || "No events to show.";
    } else {
      emptyEl.hidden = true;
      tbody.innerHTML = rows.map((r, i) => {
        const chip = statusChip(r);
        return `
          <tr class="row" tabindex="0" data-index="${i}" data-id="${r.id}">
            <td>${escapeHTML(title(r))}</td>
            <td>${escapeHTML(truncateMiddle(r.source || "", 24))}</td>
            <td>${escapeHTML(r.destination || "")}</td>
            <td><span class="chip ${chip.cls}">${chip.text}</span></td>
          </tr>`;
      }).join("");

      tbody.querySelectorAll(".row").forEach((tr) => {
        tr.addEventListener("click", () => selectRow(Number(tr.dataset.index)));
        tr.addEventListener("keydown", onRowKeydown);
      });
    }

    $("ascii").textContent = (data && data.text) || "";
  }

  function truncateMiddle(s, maxLen) {
    // design.md §11: truncate from the MIDDLE so both ends stay readable.
    if (s.length <= maxLen) return s;
    if (maxLen <= 3) return s.slice(0, maxLen);
    const keep = maxLen - 3;
    const left = Math.ceil(keep / 2);
    const right = keep - left;
    const tail = right > 0 ? s.slice(-right) : "";
    return `${s.slice(0, left)}...${tail}`;
  }

  function escapeHTML(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function onRowKeydown(e) {
    const rows = tabRows(activeTab) || [];
    if (e.key === "ArrowDown") {
      e.preventDefault();
      selectedIndex = Math.min(selectedIndex + 1, rows.length - 1);
      focusRow(selectedIndex);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      selectedIndex = Math.max(selectedIndex - 1, 0);
      focusRow(selectedIndex);
    } else if (e.key === "Enter") {
      e.preventDefault();
      selectRow(Number(e.currentTarget.dataset.index));
    }
  }

  function focusRow(index) {
    const el = document.querySelector(`.row[data-index="${index}"]`);
    if (el) el.focus();
  }

  async function selectRow(index) {
    selectedIndex = index;
    document.querySelectorAll(".row").forEach((el) => el.classList.remove("selected"));
    const el = document.querySelector(`.row[data-index="${index}"]`);
    if (el) el.classList.add("selected");

    const rows = sortRows(activeTab, tabRows(activeTab) || []);
    const row = rows[index];
    if (!row) return;

    const detailResp = await fetchJSON(
      `/api/detail?session_id=${encodeURIComponent(sessionId)}&id=${row.id}`
    );
    if (detailResp.error) return;
    renderDetail(detailResp.row);
  }

  function renderDetail(row) {
    $("detail").style.display = "block";
    // Clear whatever an earlier row left: fields, actions and the last
    // rule confirmation never carry over.
    $("ruleConfirmation").textContent = "";
    const emptyEl = $("detailEmpty");
    if (!row || mode !== "legacy") {
      $("detailTitle").textContent = "";
      $("detailFlow").textContent = "";
      $("detailFields").innerHTML = "";
      $("detailActions").innerHTML = "";
      emptyEl.textContent = UNRECORDED_DETAIL;
      emptyEl.hidden = false;
      return;
    }
    emptyEl.textContent = "";
    emptyEl.hidden = true;
    $("detailTitle").textContent = title(row);
    $("detailFlow").textContent = ASSOCIATION_NOTE;

    const fields = [
      ["Recorded association", `${row.source || ""} → ${row.destination || ""}`],
    ];
    if (row.first_seen != null) {
      fields.push(["First seen", formatTime(row.first_seen)]);
    }
    fields.push(["Legacy intervention", protectionDisplay(row.protection)]);
    if (row.masked_example) {
      fields.push(["Example", row.masked_example]);
    }
    if (row.budget_delta != null) {
      let contrib = `+${row.budget_delta} legacy pts`;
      if (row.budget_cap) contrib += ` of ${row.budget_cap}`;
      fields.push(["Legacy score contribution", contrib]);
    }
    const note = summary && summary.accounting_note;
    $("detailFields").innerHTML = fields.map(([label, value]) => `
      <div class="field-row">
        <span class="field-label">${escapeHTML(label)}</span>
        <span>${escapeHTML(String(value))}</span>
      </div>
    `).join("") + (note ? `<p class="accounting-note">${escapeHTML(note)}</p>` : "");

    // Each button saves a rule through /api/policy → apply_policy →
    // Ledger.add_policy, and says so. Whether a later call matches it, and
    // whether the host applies what Privacy HUD returns, is in the server's
    // confirmation, shown only after the response.
    const actions = [
      { text: `Save mask rule for detected ${row.data_type}`,
        rule_type: "mask", selector: row.data_type },
    ];
    // A source-level rule is offered only when the row names a real origin
    // (#40): source_kind is null when `source` is a bare tool label.
    if (row.source_kind === "path") {
      actions.push({ text: `Save block rule for values read from ${row.source}`,
                     rule_type: "block_path", selector: row.source });
    } else if (row.source_kind === "command") {
      actions.push({ text: `Save block rule for values from \`${row.source}\` output`,
                     rule_type: "block_command", selector: row.source });
    }
    const pct = mode === "legacy" ? summary.legacy_percent : null;
    const actionsEl = $("detailActions");
    // `escapeHTML` because an action's text carries `row.source`, a real
    // file path or command since #40 -- so a file named
    // `<img src=x onerror=...>.env` would otherwise run script in this page,
    // and script in this tab can reach the network, which the daemon itself
    // never does (I2).
    actionsEl.innerHTML = actions.map((a, i) =>
      `<button class="action" data-i="${i}">${escapeHTML(a.text)}</button>`
    ).join("") + (pct != null && band(pct) === "danger"
      // Not an action: a clean context is a new Codex conversation, which
      // nothing on this page can start (#23).
      ? `<p class="clean-context-note">Want a clean context? Start a new conversation in Codex. What this session already sent to the model stays sent.</p>`
      : "");

    actionsEl.querySelectorAll("button[data-i]").forEach((btn) => {
      const a = actions[Number(btn.dataset.i)];
      btn.addEventListener("click", async () => {
        if (mode !== "legacy") return;
        const requestedSession = sessionId;
        const { ok, data } = await postJSON("/api/policy", {
          session_id: requestedSession,
          rule_type: a.rule_type,
          selector: a.selector,
        });
        if (mode !== "legacy" || sessionId !== requestedSession) return;
        $("ruleConfirmation").textContent = ok
          ? data.message
          : `Could not save rule: ${data.error || "unknown error"}`;
      });
    });
  }

  function formatTime(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour12: false });
  }

  function render() {
    $("subtitle").textContent = sessionId ? `Session ${sessionId}`
      : mode === "unrecorded" ? "No session on record" : "Session ID unknown";
    renderTiles();
    renderTabs();
    renderTable();
    // An unrecorded session has no row to show: an open detail panel is
    // replaced by the empty-detail line, never left on a stale row.
    if (mode === "unrecorded") {
      selectedIndex = -1;
      const wasOpen = $("detail").style.display === "block";
      renderDetail(null);
      if (!wasOpen) $("detail").style.display = "none";
    }
  }

  $("closeDetail").addEventListener("click", () => {
    $("detail").style.display = "none";
  });

  $("toggleAscii").addEventListener("click", () => {
    const el = $("ascii");
    el.style.display = el.style.display === "block" ? "none" : "block";
  });

  loadAll().catch(() => {
    mode = "unavailable";
    summary = null;
    tabData = {};
    selectedIndex = -1;
    render();
    renderDetail(null);
    $("detail").style.display = "none";
  });
})();
