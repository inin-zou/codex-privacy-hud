# src/privacy_hud/render.py
"""Renderer: the ambient HUD line, the session audit table, the exposure
detail view, and the end-of-session receipt.

Authoritative source for every layout and every string: `.claude/docs/design.md`
§3 (visual tokens), §4 (L1 HUD + width ladder), §5 (L2 audit), §6 (L3 detail),
§9 (copy rules), §10 (receipt). Where this module's judgement calls diverge
from a literal reading of design.md, the divergence is called out in the
docstring of the function that makes it — design.md wins in every case; the
callout exists so the gap is visible, not so it is defensible.

These functions RETURN strings. No I/O, no logging, no printing. Colour
(design.md §3's `safe`/`warn`/`danger` tokens) is applied by the terminal
client from `Matrix.band()`, not by this module — see `hud_line`'s docstring
for why band-only content changes would be redundant here anyway.

No raw sensitive values are ever handled here: rows carry `masked_example`
values the ledger already stored pre-masked (mask.py), and this module never
reconstructs or unmasks anything (I1).
"""
from __future__ import annotations

from datetime import datetime

from .matrix.loader import load_matrix

# Loaded once, at import time, the same way tests/test_ledger.py loads it —
# deterministic, no I/O beyond reading the packaged tables.toml. Used only to
# validate that a percent maps to a real band; see `_check_band`.
_MATRIX = load_matrix()

_FILLED = "█"
_EMPTY = "░"
_DOT = "⬤"

_ACRONYMS = {"ssn": "SSN", "ip": "IP", "url": "URL"}

_EMPTY_MESSAGES = {
    "Exposed": "No sensitive data has crossed a trust boundary this session.",
    "Prevented": "Nothing has been blocked or minimized yet.",
    "All events": "No privacy events recorded. The engine is running.",
}


def _check_band(pct) -> None:
    """Validate `pct` maps to a real band (design.md §3's safe/warn/danger).

    The result is discarded — colour is the terminal client's job, and
    design.md §4's state table shows the "Red band" HUD line is byte-identical
    to "Normal" except for colour, so there is no plain-text content decision
    to make here. This call exists purely so an out-of-range percent (a bug
    upstream, since budget.percent() already clamps to [0, 100]) fails loud
    instead of silently rendering nonsense. Never wrap this in a bare except —
    UnknownKey must propagate.
    """
    _MATRIX.band(pct)


def _type_label(data_type: str) -> str:
    return _ACRONYMS.get(data_type, data_type.capitalize())


def _title(data_type: str, count: int) -> str:
    return f"{_type_label(data_type)} ×{count}"


def _fmt_time(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _truncate_middle(s: str, max_len: int) -> str:
    """Truncate from the MIDDLE so both ends stay readable (design.md §11):
    `support/.../app.log`, never `support/logs/produc...`."""
    if len(s) <= max_len:
        return s
    if max_len <= 3:
        return s[:max_len]
    keep = max_len - 3
    left = (keep + 1) // 2
    right = keep - left
    tail = s[-right:] if right > 0 else ""
    return f"{s[:left]}...{tail}"


def _bar(pct: int, cells: int) -> str:
    """Render a `cells`-wide bar for `pct`.

    The 10-cell bar (design.md §4) fills proportionally: `round(pct/10)`
    cells out of 10. The compressed 5-cell bar used in the 28-39 col bucket
    is NOT a linear rescale of that — design.md's own example renders 28%
    as `███░░` (3 of 5 filled), which a linear rescale (`round(28/100*5)` =
    1) does not reproduce. The rendering that does reproduce it is "cap the
    same fill count the 10-cell bar would use at the smaller cell count":
    `min(round(pct/10), cells)`. That is what this implements.
    """
    filled10 = max(0, min(10, round(pct / 10)))
    filled = filled10 if cells == 10 else min(filled10, cells)
    return _FILLED * filled + _EMPTY * (cells - filled)


def hud_line(percent: int, width: int, blocked: int = 0) -> str:
    """The ambient L1 HUD line (design.md §4).

    Width-degradation ladder: >=52, 40-51, 28-39, <28 columns. Never exceeds
    `width` — a hard invariant, enforced below by falling back to a narrower
    bucket's format (and, as a last resort, truncating) if the natural format
    for the given bucket doesn't fit, which can happen when `blocked` is a
    large number of digits.

    The "Engine degraded" (`⚠unverified`) and "Disabled" (render nothing)
    states from design.md §4's state table are not reachable through this
    signature — it takes only `percent`, `width`, `blocked`, per the fixed
    interface in the task-11 brief, with no channel for a degraded flag or
    an enabled/disabled flag. That is a real gap between design.md and the
    frozen interface; the caller must decide not to call `hud_line` at all
    for the disabled state, and has no way to ask for the unverified suffix
    through this function.
    """
    pct = int(percent)
    _check_band(pct)  # fail loud on an out-of-range percent; never swallow
    prefix = f"⚠ {blocked} blocked · " if blocked else ""

    def full():
        bar = _bar(pct, 10)
        return f"PRIVACY  {prefix}Disclosure {bar} {pct:>2}%  ›"

    def mid():
        bar = _bar(pct, 10)
        return f"PRIVACY {prefix}{bar} {pct:>2}% ›"

    def compact():
        bar = _bar(pct, 5)
        short_prefix = f"⚠{blocked} " if blocked else ""
        return f"PRIV {short_prefix}{bar} {pct:>2}% ›"

    def dot():
        return f"{_DOT} {pct:>2}%"

    if width >= 52:
        ladder = (full, mid, compact, dot)
    elif width >= 40:
        ladder = (mid, compact, dot)
    elif width >= 28:
        ladder = (compact, dot)
    else:
        ladder = (dot,)

    for fn in ladder:
        line = fn()
        if len(line) <= width:
            return line

    # Last resort: even `dot()` didn't fit (pathologically narrow width).
    # Never exceed the given width regardless.
    line = dot()
    return line[:max(width, 0)]


def _status_chip(row: dict) -> str:
    protection = row.get("protection")
    if protection in ("masked", "minimized"):
        return "[MASKED]"
    kind = row.get("kind")
    if kind == "exposed":
        return "[EXPOSED]"
    if kind == "prevented":
        return "[PREVENTED]"
    if kind == "local_access":
        return "[LOCAL]"
    return f"[{(kind or 'unknown').upper()}]"


def _tile(value: str, label: str) -> list[str]:
    inner = max(len(value), len(label))
    top = "┌" + "─" * (inner + 2) + "┐"
    val = "│ " + value.center(inner) + " │"
    lab = "│ " + label.center(inner) + " │"
    bot = "└" + "─" * (inner + 2) + "┘"
    return [top, val, lab, bot]


def _tiles_block(summary: dict) -> str:
    pct = int(summary.get("percent", 0))
    _check_band(pct)  # same fail-loud validation as hud_line
    tiles = [
        (f"{pct}%", "disclosure"),
        (str(summary.get("exposed_items", 0)), "exposed items"),
        (str(summary.get("destinations", 0)), "destinations"),
        (str(summary.get("prevented", 0)), "prevented"),
    ]
    blocks = [_tile(v, l) for v, l in tiles]
    return "\n".join(" ".join(b[i] for b in blocks) for i in range(4))


def _tab_bar(exposed_n: int, prevented_n: int, all_n: int, tab: str) -> str:
    segs = [("Exposed", exposed_n), ("Prevented", prevented_n),
            ("All events", all_n)]
    texts = [f"{name} {n}" for name, n in segs]
    sep = "      "
    line = " " + sep.join(texts)
    underline = " "
    for i, ((name, _n), text) in enumerate(zip(segs, texts)):
        underline += ("─" if name == tab else " ") * len(text)
        if i < len(segs) - 1:
            underline += " " * len(sep)
    return line + "\n" + underline


def _table(rows: list[dict]) -> str:
    headers = ["SENSITIVE DATA", "SOURCE", "DESTINATION", "STATUS"]
    data = []
    for r in rows:
        title = _title(r["data_type"], r["count"])
        source = _truncate_middle(r.get("source", ""), 24)
        dest = r.get("destination", "")
        status = _status_chip(r)
        data.append([title, source, dest, status])
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in data)) if data
        else len(headers[i])
        for i in range(len(headers))
    ]

    def fmt(cells):
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths))

    lines = [fmt(headers)]
    lines.extend(fmt(d) for d in data)
    return "\n".join(lines)


def audit(summary: dict, rows: list[dict], tab: str) -> str:
    """The L2 session audit (design.md §5).

    `rows` is whatever the caller has already selected for `tab` — this
    function does not re-filter by kind, since `Ledger.list_events` already
    scopes to one kind at a time and the caller is what decides which
    kind(s) went into `rows` for "Exposed" / "Prevented" / "All events".
    It does apply each tab's documented sort order (design.md §5):
    Exposed by budget contribution descending, Prevented most-recent-first,
    All events chronological.

    The header subtitle in design.md's mockup reads "Current session · 41
    min" — this function's fixed interface (`summary, rows, tab`, no
    duration) has no channel for the minute count, so the subtitle here
    omits it. `receipt()` is the function that receives `minutes` and shows
    session duration.

    The "All events" tab count in the tab bar is exact when `tab == "All
    events"` (`len(rows)`, since that's exactly what's being rendered);
    for the other two tabs it is `exposed_items + prevented` as a
    best-effort approximation, because `summary` (per the given `Ledger.
    summary` interface) does not carry a total event count and this
    function only ever sees one tab's rows at a time.
    """
    exposed_n = summary.get("exposed_items", 0)
    prevented_n = summary.get("prevented", 0)
    all_n = len(rows) if tab == "All events" else exposed_n + prevented_n

    ordered = list(rows)
    if tab == "Exposed":
        ordered.sort(key=lambda r: r.get("budget_delta", 0.0), reverse=True)
    elif tab == "Prevented":
        ordered.sort(key=lambda r: r.get("ts", 0), reverse=True)
    else:
        ordered.sort(key=lambda r: r.get("ts", 0))

    lines = ["Privacy Audit", "Current session", ""]
    lines.append(_tiles_block(summary))
    lines.append("")
    lines.append(_tab_bar(exposed_n, prevented_n, all_n, tab))
    lines.append("")

    # Deep-scan degradation covers two situations (task-11 brief): the model
    # being unavailable, and a payload too large for the bounded synchronous
    # scan (Task 8's degraded flag). Both surface identically here as a
    # `degraded` flag on the affected row.
    degraded_n = sum(1 for r in ordered if r.get("degraded"))
    if degraded_n:
        plural = "" if degraded_n == 1 else "s"
        lines.append(
            f"⚠ Deep scan unavailable for {degraded_n} event{plural} "
            "— fast-path results only."
        )
        lines.append("")

    if not ordered:
        lines.append(_EMPTY_MESSAGES.get(tab, "No events to show."))
    else:
        lines.append(_table(ordered))

    return "\n".join(lines)


def detail(row: dict) -> str:
    """The L3 exposure detail view (design.md §6).

    `Already disclosed data cannot be recalled from this session.` is
    required, permanent, and unconditional — it is appended below
    regardless of any other field in `row`, and there is no code path that
    can omit it.

    Fields rendered: title, flow line, First seen, Last seen (only when
    `row["last_seen"]` is present and later than first-seen), Protection,
    Example (only when a masked exemplar exists — credentials get none per
    mask.py, and this must never print "Example None"), and Budget
    contribution.

    Two divergences from a literal reading of design.md, both forced by the
    fixed `detail(row: dict) -> str` interface (no summary/matrix/band
    passed in):
    - Budget contribution is shown as `+N pts` from `row["budget_delta"]`.
      design.md's mockup shows `+9 pts of 120`, but the 120 is the session's
      budget_cap, which this function has no access to; the "of {cap}" tail
      is included only if the row itself carries an optional "budget_cap"
      key, since fabricating 120 as a hardcoded constant here would silently
      go stale the moment tables.toml's budget_cap is retuned.
    - `Start a clean session` (design.md §6) is offered only when disclosure
      is in the red band — a session-level fact this function cannot see
      from a single row. Only the two source-scoped actions
      (`Protect future occurrences`, `Block this source`) are rendered.
    - The per-action confirmation line ("Rule added: ...") describes what
      happens after a button is pressed; there is no click state in a pure
      render of `row`, so it is not rendered here.
    """
    lines = [_title(row["data_type"], row["count"])]

    hops = row.get("hops")
    if hops:
        lines.append(" → ".join(hops))
    else:
        lines.append(f"{row.get('source', '')} → {row.get('destination', '')}")
    lines.append("")

    first_ts = row.get("first_seen", row.get("ts"))
    if first_ts is not None:
        lines.append(f"{'First seen':<12} {_fmt_time(first_ts)}")
    last_ts = row.get("last_seen")
    if last_ts is not None and first_ts is not None and last_ts > first_ts:
        lines.append(f"{'Last seen':<12} {_fmt_time(last_ts)}")

    protection = row.get("protection") or "none"
    lines.append(f"{'Protection':<12} {protection}")

    masked = row.get("masked_example")
    if masked:
        lines.append(f"{'Example':<12} {masked}")

    delta = row.get("budget_delta")
    if delta is not None:
        contrib = f"+{delta:g} pts"
        cap = row.get("budget_cap")
        if cap:
            contrib += f" of {cap:g}"
        lines.append(f"{'Budget':<12} {contrib}")

    lines += [
        "",
        "[ Protect future occurrences ]",
        "[ Block this source ]",
        "",
        "Already disclosed data cannot be recalled from this session.",
    ]
    return "\n".join(lines)


def receipt(session_id: str, summary: dict, rows: list[dict], minutes: int) -> str:
    """The end-of-session privacy receipt (design.md §10).

    `No file contents, prompts, or raw values were stored.` is the
    receipt's real payload and always the last line — it is verifiable
    against the ledger schema (ledger.py's SCHEMA has no content/prompt/
    raw_value/snippet/text column), and this function makes no claim
    beyond what that schema actually guarantees.

    design.md's mockup shows `Retained   transcript written to
    ~/.codex/sessions/...` — this function is not given a transcript path
    (it isn't part of `summary`, `rows`, or any other parameter), so rather
    than fabricate one, the Retained line states the true, generic fact:
    the session transcript is persisted by Codex, outside this ledger.
    """
    pct = int(summary.get("percent", 0))
    _check_band(pct)

    lines = [
        f"PRIVACY RECEIPT · {session_id} · {minutes} min",
        "",
        f"{'Disclosure':<16} {pct}% of budget",
        f"{'Exposed':<16} {summary.get('exposed_items', 0)} flows across "
        f"{summary.get('destinations', 0)} destinations",
        f"{'Prevented':<16} {summary.get('prevented', 0)} events",
        f"{'Retained':<16} session transcript, persisted by Codex outside "
        "this ledger.",
        "",
    ]

    for r in rows:
        title = _title(r["data_type"], r["count"])
        source = _truncate_middle(r.get("source", ""), 20)
        dest = r.get("destination", "")
        suffix = "  (masked)" if r.get("protection") == "masked" else ""
        lines.append(f"  {title:<22}{source:<18}→ {dest}{suffix}")

    lines += ["", "No file contents, prompts, or raw values were stored."]
    return "\n".join(lines)
