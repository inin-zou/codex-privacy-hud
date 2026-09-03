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
// "Deep scan unavailable" banner (design.md §5): `Decision.degraded`
// (engine.py) is never persisted to the ledger — it's a per-call return
// value the daemon sees transiently and never writes to any table. There is
// therefore no ledger-backed signal this after-the-fact audit page could
// read to show that banner honestly, so it is intentionally never shown
// here rather than fabricated. See task-13-report.md.
//
// "Allow once" is intentionally not a button anywhere in this file — see
// local_ui_server.py's module docstring for why (the ledger never stores
// `tool_input`, so this static, historical audit view has nothing to mint
// a consent token against; that action belongs to the live block flow).

(function () {
  "use strict";

  const TABS = ["Exposed", "Prevented", "All events"];

  const params = new URLSearchParams(location.search);
  let sessionId = params.get("session_id") || null;
  let activeTab = "Exposed";
  let tabData = {};      // tab name -> {rows, text}
  let summary = null;
  let copy = { empty_messages: {}, acronyms: {} };
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
    if (row.protection === "masked" || row.protection === "minimized") {
      return { text: "MASKED", cls: "masked" };
    }
    if (row.kind === "exposed") return { text: "EXPOSED", cls: "exposed" };
    if (row.kind === "prevented") return { text: "PREVENTED", cls: "prevented" };
    if (row.kind === "local_access") return { text: "LOCAL", cls: "local" };
    return { text: (row.kind || "unknown").toUpperCase(), cls: "" };
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

  // -- data fetching ---------------------------------------------------

  async function fetchJSON(path) {
    const res = await fetch(path);
    return res.json();
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
      sessionId = s.session_id;
    }
    if (!sessionId) {
      $("subtitle").textContent = "No session found.";
      return;
    }

    copy = await fetchJSON("/api/copy");
    summary = await fetchJSON(`/api/summary?session_id=${encodeURIComponent(sessionId)}`);

    for (const tab of TABS) {
      tabData[tab] = await fetchJSON(
        `/api/exposures?session_id=${encodeURIComponent(sessionId)}&tab=${encodeURIComponent(tab)}`
      );
    }

    render();
  }

  // -- rendering ---------------------------------------------------------

  function renderTiles() {
    const pct = summary.percent || 0;
    const tiles = [
      [`${pct}%`, "disclosure", band(pct)],
      [String(summary.exposed_items || 0), "exposed items", null],
      [String(summary.destinations || 0), "destinations", null],
      [String(summary.prevented || 0), "prevented", null],
    ];
    $("tiles").innerHTML = tiles.map(([value, label, cls]) => `
      <div class="tile">
        <div class="value${cls ? " " + cls : ""}">${value}</div>
        <div class="label">${label}</div>
      </div>
    `).join("");
  }

  function renderTabs() {
    $("tabs").innerHTML = TABS.map((tab) => {
      const n = (tabData[tab] && tabData[tab].rows) ? tabData[tab].rows.length : 0;
      const active = tab === activeTab ? " active" : "";
      return `<button class="tab${active}" role="tab" data-tab="${tab}">${tab} ${n}</button>`;
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
    const data = tabData[activeTab] || { rows: [], text: "" };
    const rows = sortRows(activeTab, data.rows);
    const tbody = $("rows");
    const emptyEl = $("empty");

    if (rows.length === 0) {
      tbody.innerHTML = "";
      emptyEl.hidden = false;
      emptyEl.textContent = (copy.empty_messages && copy.empty_messages[activeTab]) || "No events to show.";
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

    $("ascii").textContent = data.text || "";
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
    const rows = tabData[activeTab].rows;
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

    const rows = sortRows(activeTab, tabData[activeTab].rows);
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
    $("detailTitle").textContent = title(row);
    $("detailFlow").textContent = `${row.source || ""} → ${row.destination || ""}`;

    const fields = [];
    if (row.first_seen != null) {
      fields.push(["First seen", formatTime(row.first_seen)]);
    }
    fields.push(["Protection", row.protection || "none"]);
    if (row.masked_example) {
      fields.push(["Example", row.masked_example]);
    }
    if (row.budget_delta != null) {
      let contrib = `+${row.budget_delta} pts`;
      if (row.budget_cap) contrib += ` of ${row.budget_cap}`;
      fields.push(["Budget", contrib]);
    }
    $("detailFields").innerHTML = fields.map(([label, value]) => `
      <div class="field-row">
        <span class="field-label">${escapeHTML(label)}</span>
        <span>${escapeHTML(String(value))}</span>
      </div>
    `).join("");

    const actions = [
      { text: "Protect future occurrences", rule_type: "mask", selector: row.data_type },
      { text: "Block this source", rule_type: "block_source", selector: row.source },
    ];
    const pct = summary.percent || 0;
    const actionsEl = $("detailActions");
    actionsEl.innerHTML = actions.map((a, i) =>
      `<button class="action" data-i="${i}">[ ${a.text} ]</button>`
    ).join("") + (band(pct) === "danger"
      ? `<button class="action" data-clean="1">[ Start a clean session ]</button>`
      : "");

    actionsEl.querySelectorAll("button[data-i]").forEach((btn) => {
      const a = actions[Number(btn.dataset.i)];
      btn.addEventListener("click", async () => {
        const { ok, data } = await postJSON("/api/policy", {
          session_id: sessionId,
          rule_type: a.rule_type,
          selector: a.selector,
        });
        $("ruleConfirmation").textContent = ok
          ? data.message
          : `Could not apply rule: ${data.error || "unknown error"}`;
      });
    });

    const cleanBtn = actionsEl.querySelector("button[data-clean]");
    if (cleanBtn) {
      cleanBtn.addEventListener("click", async () => {
        const { ok, data } = await postJSON("/api/clean_session", { session_id: sessionId });
        if (ok) {
          $("ruleConfirmation").textContent =
            `New session started: ${data.session_id}. This audit now reflects the new session.`;
          sessionId = data.session_id;
          await loadAll();
        }
      });
    }

    $("ruleConfirmation").textContent = "";
  }

  function formatTime(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour12: false });
  }

  function render() {
    $("subtitle").textContent = "Current session";
    renderTiles();
    renderTabs();
    renderTable();
  }

  $("closeDetail").addEventListener("click", () => {
    $("detail").style.display = "none";
  });

  $("toggleAscii").addEventListener("click", () => {
    const el = $("ascii");
    el.style.display = el.style.display === "block" ? "none" : "block";
  });

  loadAll();
})();
