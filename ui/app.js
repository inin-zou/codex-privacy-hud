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

  // #54 Phase 4: version-2 accounting. Its words come from the server's
  // static catalog (`/api/copy` -> `render.accounting_copy`); only the
  // failure line is also here, because a page that could not read
  // accounting may not have that catalog either.
  const ACCOUNTING_ERROR = "Privacy HUD accounting could not be read. No percentage or counts are available.";
  const V2_COUNT_KEYS = [
    "observations", "event_rows", "finding_occurrences", "distinct_subjects",
    "exposure_events", "intervention_events", "distinct_disclosures",
    "concrete_recipients", "permission_actions", "denials_issued",
    "denials_enforced", "reads_stopped", "rewrite_actions_issued",
    "rewrite_actions_enforced", "unresolved_actions",
    "unresolved_subject_events", "unresolved_recipient_events",
  ];
  const V2_KEYS = V2_COUNT_KEYS.concat([
    "accounting_version", "accounting_status", "profile_id",
    "confirmed_points", "budget_cap", "percent",
    "percentage_unavailable_reasons", "score_label", "accounting_note",
    "coverage",
  ]);
  const V2_REASONS = [
    "accounting_unavailable", "unresolved_actions", "unresolved_subjects",
    "unresolved_recipients", "coverage_incomplete",
  ];
  // Evidence names -> chip keys in the catalog, in the chips' fixed order.
  const V2_CHIPS = [
    ["deny_issued", "chip_denial_issued"],
    ["deny_enforced", "chip_denial_enforced"],
    ["rewrite_issued", "chip_rewrite_issued"],
    ["rewrite_enforced", "chip_rewrite_applied"],
    ["rejected_before_crossing", "chip_rejected_before_crossing"],
    ["crossing_confirmed", "chip_exposed"],
    ["permission_issued", "chip_permitted"],
    ["execution_observed", "chip_local_access"],
    ["local_detection", "chip_detected"],
    ["persistence_observed", "chip_retention"],
  ];

  const params = new URLSearchParams(location.search);
  let sessionId = params.get("session_id") || null;
  let activeTab = "Exposed";
  let tabData = {};      // tab name -> {rows, text, ...} or null when unavailable
  let summary = null;
  // "legacy" | "unrecorded" | "v2" | "unavailable". A failed request is
  // "unavailable", never "unrecorded": failing to ask is not an answer.
  let mode = "unavailable";
  // Bumped whenever what is displayed changes (tab, session, reload): a
  // detail reply that arrives after it no longer belongs to the page.
  let viewGeneration = 0;
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

  // -- version-2 accounting --------------------------------------------

  function isCount(v) {
    return typeof v === "number" && Number.isInteger(v) && v >= 0;
  }

  function isFiniteNumber(v) {
    return typeof v === "number" && Number.isFinite(v);
  }

  // The exact version-2 summary contract. No field is defaulted: a missing,
  // mistyped, non-finite or inconsistent value is a failed reading, never a
  // zero.
  function validV2Summary(s) {
    if (!s || typeof s !== "object" || Array.isArray(s)) return false;
    const keys = Object.keys(s);
    if (keys.length !== V2_KEYS.length || !V2_KEYS.every((k) => keys.includes(k))) return false;
    if (s.accounting_version !== 2) return false;
    if (s.accounting_status !== "available" && s.accounting_status !== "unavailable") return false;
    if (typeof s.profile_id !== "string") return false;
    if (!V2_COUNT_KEYS.every((k) => isCount(s[k]))) return false;
    if (!isFiniteNumber(s.confirmed_points) || s.confirmed_points < 0) return false;
    if (!isFiniteNumber(s.budget_cap) || s.budget_cap <= 0) return false;
    const reasons = s.percentage_unavailable_reasons;
    if (!Array.isArray(reasons) || !reasons.every((r) => V2_REASONS.includes(r))
        || new Set(reasons).size !== reasons.length) return false;
    if (s.percent === null) {
      if (reasons.length === 0) return false;
    } else if (!isCount(s.percent) || s.percent > 100 || reasons.length !== 0) {
      return false;
    }
    if (typeof s.score_label !== "string" || typeof s.accounting_note !== "string") return false;
    return !!s.coverage && typeof s.coverage === "object";
  }

  function validV2Tab(data) {
    return !!data && Array.isArray(data.rows)
      && data.rows.every((r) => r && r.accounting_version === 2 && isCount(r.id))
      && validV2Summary(data.summary);
  }

  // The summary read with the active tab's rows: tiles, counts and rows are
  // one reading, never an older /api/summary beside newer rows.
  function v2Summary() {
    const data = tabData[activeTab];
    return mode === "v2" && data && validV2Tab(data) ? data.summary : null;
  }

  function accountingCopy() {
    return (copy && copy.accounting) || null;
  }

  function points(value) {
    return value.toFixed(2).replace(/0+$/, "").replace(/\.$/, "");
  }

  function v2Lines(s, A) {
    const lines = [s.percent === null ? A.percentage_unavailable
      : A.percentage_available.replace("{P}", String(s.percent))];
    for (const reason of s.percentage_unavailable_reasons) {
      if (reason === "accounting_unavailable") lines.push(A.reason_accounting_unavailable);
      else if (reason === "unresolved_actions") {
        lines.push(s.unresolved_actions === 1 ? A.reason_unresolved_action
          : A.reason_unresolved_actions.replace("{N}", String(s.unresolved_actions)));
      } else if (reason === "unresolved_subjects") lines.push(A.reason_unresolved_subjects);
      else if (reason === "unresolved_recipients") lines.push(A.reason_unresolved_recipients);
    }
    if (s.confirmed_points === 0 && s.unresolved_actions > 0) lines.push(A.zero_confirmed);
    lines.push(A.accounting_note);
    return lines;
  }

  function v2Chips(row, A) {
    const names = Array.isArray(row.evidence) ? row.evidence : [];
    return V2_CHIPS.filter(([name]) => {
      if (!names.includes(name)) return false;
      if (name === "crossing_confirmed") return row.boundary !== "B0";
      if (name === "execution_observed") return row.boundary === "B0";
      return true;
    }).map(([, key]) => A[key]);
  }

  function v2Failed() {
    return mode === "v2" && (!v2Summary() || !accountingCopy());
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
      : summary && summary.accounting_version === 2 ? "v2"
      : "unavailable";
    viewGeneration += 1;

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
    const s = v2Summary();
    const A = accountingCopy();
    if (mode === "v2" && s && A) {
      // No percentage bar or band: the percentage is a line of its own,
      // and "unavailable" when the evidence does not support one.
      tiles = [
        [points(s.confirmed_points), A.tile_points, null],
        [String(s.distinct_disclosures), A.tile_disclosures, null],
        [String(s.concrete_recipients), A.tile_recipients, null],
        [String(s.denials_issued), A.tile_denials, null],
      ];
      note.textContent = v2Lines(s, A).join("\n");
      note.hidden = false;
      status.textContent = "";
      status.hidden = true;
    } else if (mode === "legacy") {
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
    const s = v2Summary();
    const A = accountingCopy();
    const v2 = mode === "v2" && s && A;
    const v2Counts = v2 ? {
      "Exposed": s.exposure_events, "Prevented": s.intervention_events,
      "All events": s.event_rows } : {};
    const v2Labels = v2 ? {
      "Exposed": A.tab_exposed, "Prevented": A.tab_prevented,
      "All events": A.tab_all } : {};
    $("tabs").innerHTML = TABS.map((tab) => {
      const rows = mode === "legacy" ? tabRows(tab) : null;
      const n = v2 ? v2Counts[tab] : rows ? rows.length : UNAVAILABLE;
      const label = v2 ? v2Labels[tab] : TAB_LABELS[tab];
      const active = tab === activeTab ? " active" : "";
      return `<button class="tab${active}" role="tab" data-tab="${tab}">${escapeHTML(label)} ${n}</button>`;
    }).join("");
    $("tabs").querySelectorAll(".tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        activeTab = btn.dataset.tab;
        selectedIndex = -1;
        viewGeneration += 1;
        render();
        if (mode === "v2") clearDetail(v2Failed() ? ACCOUNTING_ERROR : "");
      });
    });
  }

  function clearDetail(message) {
    $("ruleConfirmation").textContent = "";
    $("detailTitle").textContent = "";
    $("detailFlow").textContent = "";
    $("detailFields").innerHTML = "";
    $("detailActions").innerHTML = "";
    const emptyEl = $("detailEmpty");
    emptyEl.textContent = message || "";
    emptyEl.hidden = !message;
  }

  function currentRows() {
    if (mode === "v2") {
      if (!v2Summary()) return [];
      return tabRows(activeTab).slice().sort((a, b) => a.id - b.id);
    }
    return mode === "legacy" && tabRows(activeTab)
      ? sortRows(activeTab, tabRows(activeTab)) : [];
  }

  function renderTable() {
    const data = tabData[activeTab] || null;
    const rows = currentRows();
    const A = accountingCopy();
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
      emptyEl.textContent = v2Failed()
        ? ACCOUNTING_ERROR
        : mode === "unrecorded"
        ? (data && data.empty_message) || UNRECORDED_EMPTY
        : mode === "unavailable"
          ? "Could not load session accounting."
          : tabRows(activeTab) === null
            ? "Could not load events for this tab."
            : (data && data.empty_message) || "No events to show.";
    } else {
      emptyEl.hidden = true;
      tbody.innerHTML = mode === "v2" ? rows.map((r, i) => {
        const chips = v2Chips(r, A).map((c) =>
          `<span class="chip">${escapeHTML(c)}</span>`).join(" ");
        return `
          <tr class="row" tabindex="0" data-index="${i}" data-id="${r.id}">
            <td>${escapeHTML(`${typeLabel(r.data_type)} ×${r.occurrences}`)}</td>
            <td>${escapeHTML(truncateMiddle(r.source_label || "", 24))}</td>
            <td>${escapeHTML(r.recipient_label || "")}</td>
            <td>${chips}${r.guard_target
              ? `<div>${escapeHTML(`Event #${r.id}: ${r.guard_target.summary}`)}</div>`
              : ""}</td>
          </tr>`;
      }).join("") : rows.map((r, i) => {
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

    $("ascii").textContent = v2Failed() ? "" : (data && data.text) || "";
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
    const rows = currentRows();
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

    const rows = currentRows();
    const row = rows[index];
    if (!row) return;

    const generation = viewGeneration;
    const requestedSession = sessionId;
    let detailResp;
    try {
      detailResp = await fetchJSON(
        `/api/detail?session_id=${encodeURIComponent(sessionId)}&id=${row.id}`
      );
    } catch (e) {
      if (generation === viewGeneration && mode === "v2") clearDetail(ACCOUNTING_ERROR);
      return;
    }
    // A reply for a view that has since changed restores nothing.
    if (generation !== viewGeneration || sessionId !== requestedSession) return;
    if (detailResp.error) return;
    renderDetail(detailResp.row);
  }

  function renderDetailV2(row) {
    const A = accountingCopy();
    if (v2Failed() || !row || row.accounting_version !== 2) {
      clearDetail(ACCOUNTING_ERROR);
      return;
    }
    clearDetail("");
    $("detailTitle").textContent = `${typeLabel(row.data_type)} ×${row.occurrences}`;
    $("detailFlow").textContent = A.row_note;
    const fields = [
      [A.detail_subject, row.subject_label],
      [A.detail_recipient, row.recipient_label],
      [A.detail_source, row.source_label],
      [A.detail_boundary, row.boundary],
      [A.detail_observation, row.observation_id],
      [A.detail_action, row.action_id],
      [A.detail_evidence, v2Chips(row, A).join(" · ") || "none"],
      [A.detail_occurrences_in_this_observation, String(row.occurrences)],
      [A.detail_confirmed_contribution, points(row.budget_delta)],
      [A.detail_masked_example, row.masked_example || A.not_stored],
    ];
    if (row.guard_target) {
      fields.push([A.detail_guard_target, row.guard_target.summary]);
    }
    if (row.scan_gap) fields.push([A.detail_scan_gap, row.scan_gap]);
    $("detailFields").innerHTML = fields.map(([label, value]) => `
      <div class="field-row">
        <span class="field-label">${escapeHTML(label)}</span>
        <span>${escapeHTML(String(value))}</span>
      </div>
    `).join("") + `<p class="accounting-note">${escapeHTML(A.accounting_note)}</p>`
      + `<p class="accounting-note">${escapeHTML(A.opaque_source)}</p>`;

    // Only the conditional mask rule: an opaque subject or recipient label
    // is never a source-rule selector.
    const actions = [
      { text: `Save mask rule for detected ${row.data_type}`,
        rule_type: "mask", selector: row.data_type },
    ];
    const actionsEl = $("detailActions");
    actionsEl.innerHTML = actions.map((a, i) =>
      `<button class="action" data-i="${i}">${escapeHTML(a.text)}</button>`
    ).join("");
    actionsEl.querySelectorAll("button[data-i]").forEach((btn) => {
      const a = actions[Number(btn.dataset.i)];
      btn.addEventListener("click", async () => {
        if (mode !== "v2" || v2Failed()) return;
        const requestedSession = sessionId;
        const generation = viewGeneration;
        const { ok, data } = await postJSON("/api/policy", {
          session_id: requestedSession,
          rule_type: a.rule_type,
          selector: a.selector,
        });
        if (mode !== "v2" || sessionId !== requestedSession
            || generation !== viewGeneration) return;
        $("ruleConfirmation").textContent = ok
          ? data.message
          : `Could not save rule: ${data.error || "unknown error"}`;
      });
    });
  }

  function renderDetail(row) {
    $("detail").style.display = "block";
    if (mode === "v2") {
      renderDetailV2(row);
      return;
    }
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
    if (v2Failed()) {
      // A failed reading shows no stale detail and offers no action.
      selectedIndex = -1;
      clearDetail(ACCOUNTING_ERROR);
      $("detail").style.display = "none";
    }
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
