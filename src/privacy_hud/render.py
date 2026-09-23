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

**The third HUD state.** design.md §4's state table has always specified an
"Engine degraded" render (`⚠unverified`), and this module could not produce it:
`hud_line`'s three integers had no channel for it, so `0%` meant both "nothing
sensitive was disclosed" and "I have no idea what was disclosed". That gap is
now closed by opt-in keyword arguments — `hud_line(..., unverified=)`,
`audit(..., coverage=)`, `receipt(..., coverage=)` — each defaulting to the
previous behaviour so no existing call site or golden string moved. The decision
itself is never made here: `ledger.SessionCoverage` is the evidence, this module
only draws it. Do not "simplify" the third state away; see `ledger.py`'s
docstring for the audit it silently passed.

**Coverage and identity are two questions, and one glyph answers only one.**
`⚠unverified` / the `⚠ Session record incomplete` banner mean *this session's
record has a known hole*. Which session the numbers belong to is a separate
question with a separate answer — `audit(..., resolved=)`, which moves the
header subtitle and nothing else (`_subtitle`). Never route "I am not sure
which session this is" through the coverage marker: that would collapse the
three states back into two and undo the paragraph above.

**Input is typed.** `audit`, `detail` and `receipt` take `ledger.py`'s
summary variants (`LegacySessionSummary` or `UnrecordedSessionSummary`) and
`LegacyExposureRow`, not dicts. These functions are almost entirely `row[...]`/`.get(...)`
lookups, which made them the single most exposed consumer of the old
string-keyed contract: a mistyped key was either a `KeyError` in the middle of
the audit the user just asked for, or a `.get()` returning `None` that rendered
as an empty table cell nobody would notice was wrong. `row.data_typo` is an
`AttributeError` at the call site instead, and the field list is somewhere a
reader can check.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING

from .accounting import (
    PHASE3_SURFACE_UNSUPPORTED,
    AccountingExposureRow,
    AccountingSummary,
)
from .ledger import (
    LEGACY_ACCOUNTING_NOTE,
    LEGACY_SCORE_LABEL,
    UNRECORDED_ACCOUNTING_NOTE,
    UNRECORDED_SCORE_LABEL,
    ExposureRow,
    LegacyExposureRow,
    LegacySessionSummary,
    SessionCoverage,
    SessionSummary,
    UnsupportedAccounting,
)
from .matrix.loader import load_matrix

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .hud_snapshot import Snapshot
    # Type-only, and deliberately so: `audit()` reads three attributes off a
    # `ResolvedSession` and needs none of `mcp_tools`' behaviour. A runtime
    # import would give this module — which is meant to be a pure function of
    # ledger types — a dependency on the layer above it, for an annotation.
    from .mcp_tools import ResolvedSession

# Loaded once, at import time, the same way tests/test_ledger.py loads it —
# deterministic, no I/O beyond reading the packaged tables.toml. Used only to
# validate that a percent maps to a real band; see `_check_band`.
_MATRIX = load_matrix()

_FILLED = "█"
_EMPTY = "░"
_DOT = "⬤"

_ACRONYMS = {"ssn": "SSN", "ip": "IP", "url": "URL"}

#: Each line states what the LEDGER holds for that tab, and stops there.
#:
#: They used to state what the world holds — "No sensitive data has crossed a
#: trust boundary this session", "No privacy events recorded. The engine is
#: running." Neither survives `SessionCoverage`'s own account of itself:
#: `verified` means "nothing on record contradicts a complete account …
#: deliberately weaker than complete", and the same docstring lists what stays
#: invisible regardless — a hook Codex never fired, a hook whose 2 s client
#: timeout expired, a hosted tool that bypasses local hooks. So the type that
#: gates the reassuring line documents that it cannot carry it, and no
#: coverage reading makes those two sentences true.
#:
#: "The engine is running" is dropped rather than reworded. It answered a real
#: question — design.md §5's "an empty audit is otherwise indistinguishable
#: from a broken plugin" — with the wrong evidence: a ledger is history and
#: cannot vouch for a live process. `_EMPTY_VERIFIED` answers what the record
#: can answer; liveness belongs to something that checks liveness, which is
#: `privacy-hud-doctor`.
_EMPTY_MESSAGES = {
    "Exposed": "No exposure recorded this session.",
    "Prevented": "Nothing recorded as blocked or minimized yet.",
    "All events": "No privacy events recorded for this session.",
}

#: Appended when coverage was asked for and came back verified. This is the
#: honest half of what "The engine is running" was reaching for: it reports
#: what the coverage check found, and then says what that does not amount to.
#: A caller that passes no coverage gets the bare line above — "not asked"
#: and "asked, and verified" are different answers, and only the second earns
#: this sentence.
#:
#: It deliberately gives no examples of what can go unseen. The first draft
#: did, and got one wrong: it said a hook "whose client timed out" leaves no
#: trace, which `daemon.py`'s own probe disproves — 10 concurrent ingress
#: calls at the real 2.0 s timeout, 7 clients gave up, all 10 rows in the
#: ledger once the daemon drained, because the worker finishes its
#: `Ledger.record` whether or not anyone is still waiting for the reply. That
#: wrong example came straight from `SessionCoverage`'s docstring, which
#: lists the same case and contradicts the implementation. Enumerating is how
#: a caveat acquires a claim of its own.
_EMPTY_VERIFIED = (
    " Coverage found no gaps in this session's record, which is not proof "
    "that every event was seen."
)

#: The one empty-state line for a session whose record is not verified — it
#: replaces all three of the above, on every tab.
#:
#: Each `_EMPTY_MESSAGES` entry asserts something about the world ("No sensitive
#: data has crossed…", "…The engine is running."), and none of those assertions
#: survives an incomplete record. The third is the sentence design.md §5 added
#: specifically so "an empty audit is otherwise indistinguishable from a broken
#: plugin" — which is right, and which is exactly why printing it when the
#: plugin WAS broken for this session is the worst available outcome: it spends
#: the reader's trust to vouch for the one case it cannot vouch for. So on this
#: path the empty table says what is true about the ledger and makes no claim
#: about the session.
_EMPTY_UNVERIFIED = (
    "No events recorded for this tab. With this session's record incomplete, "
    "that is not evidence that none occurred."
)


#: The one empty-state line for an unrecorded session, on every tab. It
#: takes precedence over coverage: with no session row there are no rows to
#: have missed, and no evidence either way about what happened.
_EMPTY_UNRECORDED = (
    "No events can be shown for an unrecorded session. This is not evidence "
    "that none occurred."
)


def _refuse_v2(summary: SessionSummary | None = None,
               rows: Sequence[ExposureRow] = ()) -> None:
    """These terminal renderers describe legacy and unrecorded sessions only
    (#54 Phase 3). A version-2 summary or row is refused with the fixed
    Phase 3 error before any legacy field is read, never rendered through a
    legacy or unrecorded branch."""
    if isinstance(summary, AccountingSummary) or any(
            isinstance(row, AccountingExposureRow) for row in rows):
        raise UnsupportedAccounting(PHASE3_SURFACE_UNSUPPORTED)


def _legacy_rows(rows: Sequence[ExposureRow]) -> list[LegacyExposureRow]:
    """`rows`, after `_refuse_v2` has refused any version-2 row."""
    _refuse_v2(rows=rows)
    return [row for row in rows if isinstance(row, LegacyExposureRow)]


def empty_message(tab: str, coverage: SessionCoverage | None, *,
                  summary: SessionSummary | None = None) -> str:
    """The one empty-state line for `tab` under `coverage`.

    Public, and the only way any surface may choose this string. `audit()`
    calls it; `local_ui_server` serves its result to the browser rather than
    shipping the raw dict for `ui/app.js` to index. That is the whole point:
    the browser used to pick from `_EMPTY_MESSAGES` itself, with the coverage
    reading sitting unread in the same payload, so the reassuring line was
    shown on exactly the sessions it could not be shown on. Two surfaces each
    deciding is how they came to disagree; one function decides now.

    Four answers, and the first wins:

    - `summary` is unrecorded → `_EMPTY_UNRECORDED`, on every tab.
    - coverage says not verified → `_EMPTY_UNVERIFIED`, the same line on every
      tab, because an incomplete record is a caveat about the session and not
      about one tab's contents.
    - coverage verified → the tab's line plus what the record supports.
    - `None` → the tab's line alone, which is what a caller with no coverage
      reading is entitled to and no more.
    """
    _refuse_v2(summary)
    if summary is not None and summary.accounting_version == 0:
        return _EMPTY_UNRECORDED
    if coverage is not None and not coverage.verified:
        return _EMPTY_UNVERIFIED
    line = _EMPTY_MESSAGES.get(tab, "No events to show.")
    return line + _EMPTY_VERIFIED if coverage is not None else line


def coverage_banner(coverage: SessionCoverage | None) -> str | None:
    """The session-scope caveat, or `None` when there is nothing to caveat.

    `audit()` puts this inside the text block it returns. The browser needs it
    as a field of its own, because the block goes into a region
    `ui/index.html` hides by default — so on the surface people actually look
    at, a caveat that travels inside the ASCII is a caveat nobody reads.

    `None` on a verified reading, and on no reading at all. A caveat shown
    unconditionally is noise, and `Ledger.coverage`'s own comment says where
    that ends: "noise is how a warning gets trained away."
    """
    if coverage is None or coverage.verified:
        return None
    return _coverage_banner(coverage)


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


def hud_core(percent: int) -> str:
    """The segment of the HUD that two renderers must agree on, byte for byte.

    `<10-cell bar> <percent right-aligned to 2>%` — e.g. `███░░░░░░░ 28%`.
    `hud_line()` (this module) embeds it in the ambient pane's framing, and
    the Codex status-line patch (`privacy_status.rs`, `render_core`) embeds it
    after the word `Privacy`. `tests/matrix/hud_golden.json` pins every
    rounding tie so the Rust port's `round_ties_even` and Python's `round()`
    cannot drift apart unnoticed. The band check is here, not only in
    `hud_line`, because this is now the narrowest public entry to the bar.
    """
    pct = int(percent)
    _check_band(pct)
    return f"{_bar(pct, 10)} {pct:>2}%"


def _rows_phrase(n: int) -> str:
    """`N prevented rows`: a legacy row count, never a count of calls."""
    return f"{n} prevented row{'' if n == 1 else 's'}"


def _hud_candidates(reading: "Snapshot") -> tuple[str, ...]:
    """Every complete HUD line for `reading`, widest first.

    Each candidate is whole: a percentage is never separated from the word
    that qualifies it, and an unavailable reading never shows a number, a
    bar or a band dot.
    """
    if reading.accounting_version == 0:
        return ("Privacy —% · No session on record",
                "Privacy —% · no record",
                "—% · no record",
                "⚠ —%")
    if reading.accounting_version == 1:
        pct = int(reading.percent or 0)
        _check_band(pct)
        rows = reading.legacy_prevented_rows or 0
        count = f" · {_rows_phrase(rows)}" if rows else ""
        if reading.unverified:
            return (f"Privacy legacy {pct}%{count} ⚠unverified",
                    f"Privacy legacy {pct}% ⚠unverified",
                    f"legacy {pct}% ⚠unverified",
                    f"⚠ legacy {pct}%",
                    "⚠ legacy")
        return (f"Privacy legacy {pct}%{count}",
                f"Privacy legacy {pct}%",
                f"legacy {pct}%",
                "legacy")
    # Accounting 2 is reserved for new accounting and read only so a reader
    # already deployed can draw it; no phase 1 writer publishes it.
    parts = []
    if reading.percent is None:
        parts.append("Privacy —%")
        parts.append(f"{reading.unresolved_actions} unresolved")
    else:
        pct = int(reading.percent)
        _check_band(pct)
        parts.append(f"Privacy {pct}%")
    parts.append(f"{reading.denials_issued} denials issued")
    line = " · ".join(parts)
    return (line + " ⚠unverified" if reading.unverified else line,)


def hud_line(reading: "Snapshot", width: int) -> str:
    """The ambient L1 HUD line (design.md §4) for one snapshot reading.

    Takes the whole reading, not a percentage: whether a number may be drawn
    at all, and what it is called, depend on the accounting variant (#54
    phase 1). A legacy reading draws `Privacy legacy 28% · 2 prevented
    rows`; an unrecorded one draws `Privacy —% · No session on record` and
    no number. Hidden draws nothing. Freshness and validity are the
    reader's job (`hud_snapshot.read_snapshot`).

    The line is the first candidate that fits `width` in full, and nothing
    when none does: a percentage is never cut away from its qualifier, and
    `⚠unverified` is never truncated off a number it qualifies.
    `hud_core`'s numeric bar is not drawn here.
    """
    if reading.hidden:
        return ""
    for line in _hud_candidates(reading):
        if len(line) <= width:
            return line
    return ""


#: The line for a pane with no resolved session while the daemon marker
#: reports hook events no daemon recorded. Not "No session on record":
#: failing to resolve an id does not establish that there is none.
_UNATTRIBUTED_CANDIDATES = (
    "Privacy —% · unattributed hook gaps",
    "Privacy —% ⚠unverified",
    "⚠ —%",
)


def unattributed_gap_line(width: int) -> str:
    """The nonnumeric warning for unattributed hook gaps, or `""`."""
    for line in _UNATTRIBUTED_CANDIDATES:
        if len(line) <= width:
            return line
    return ""


#: Legacy row chips, by stored `kind` alone. `protection` does not override
#: the kind: a `masked` label records that Privacy HUD returned rewritten
#: input, not that the host applied it, so it cannot turn a permitted
#: crossing into something else.
_LEGACY_CHIPS = {
    "exposed": "LEGACY PERMITTED",
    "prevented": "LEGACY PREVENTED ROW",
    "local_access": "LEGACY LOCAL ACCESS",
    "detected": "LEGACY DETECTED",
    "retention": "LEGACY RETENTION",
}
_LEGACY_CHIP_UNKNOWN = "LEGACY UNKNOWN"


def _status_chip(row: ExposureRow) -> str:
    _refuse_v2(rows=(row,))
    return f"[{_LEGACY_CHIPS.get(row.kind, _LEGACY_CHIP_UNKNOWN)}]"


def _tile(value: str, label: str) -> list[str]:
    inner = max(len(value), len(label))
    top = "┌" + "─" * (inner + 2) + "┐"
    val = "│ " + value.center(inner) + " │"
    lab = "│ " + label.center(inner) + " │"
    bot = "└" + "─" * (inner + 2) + "┘"
    return [top, val, lab, bot]


#: The unrecorded tiles: no number, and each label says what is missing.
_UNRECORDED_TILES = (
    ("—%", "percentage unavailable"),
    ("—", "permitted-crossing rows unavailable"),
    ("—", "boundary kinds unavailable"),
    ("—", "prevented rows unavailable"),
)


def _tiles_block(summary: SessionSummary) -> str:
    """Four tiles. A legacy summary keeps its stored numbers under legacy
    labels (#54): the score counts permitted crossings, and its rows may
    collapse different outcomes, so none of them is a confirmed-disclosure
    figure. An unrecorded summary has no numbers at all."""
    _refuse_v2(summary)
    if isinstance(summary, LegacySessionSummary):
        pct = int(summary.legacy_percent)
        _check_band(pct)  # same fail-loud validation as hud_line
        tiles: Sequence[tuple[str, str]] = (
            (f"{pct}%", LEGACY_SCORE_LABEL),
            (str(summary.legacy_permitted_crossing_rows),
             "legacy permitted-crossing rows"),
            (str(summary.legacy_boundary_kinds), "legacy boundary kinds"),
            (str(summary.legacy_prevented_rows), "legacy prevented rows"),
        )
    else:
        tiles = _UNRECORDED_TILES
    # Two rows of two: the legacy and unavailable labels are too long for
    # four abreast inside design.md §5's 100-column floor.
    blocks = [_tile(value, label) for value, label in tiles]
    rows = [blocks[:2], blocks[2:]]
    return "\n".join("\n".join(" ".join(b[i] for b in row) for i in range(4))
                     for row in rows)


def _note(note: str) -> str:
    """An accounting note for a terminal view. A note longer than design.md
    §5's 100-column floor is broken between its sentences, never inside
    one."""
    return note if len(note) <= 100 else note.replace(". ", ".\n")


#: Display labels for the three tabs. The API arguments stay "Exposed",
#: "Prevented" and "All events"; what they select are stored legacy
#: classifications, and the labels say so.
TAB_LABELS = {
    "Exposed": "Legacy permitted crossings",
    "Prevented": "Legacy prevented rows",
    "All events": "All legacy events",
}

_UNAVAILABLE = "—"


def _tab_bar(exposed_n: int | None, prevented_n: int | None,
             all_n: int | None, tab: str) -> str:
    """The tab bar. A count that is not known prints `—`, never 0."""
    segs = [("Exposed", exposed_n), ("Prevented", prevented_n),
            ("All events", all_n)]
    texts = [f"{TAB_LABELS[name]} {_UNAVAILABLE if n is None else n}"
             for name, n in segs]
    sep = "      "
    line = " " + sep.join(texts)
    underline = " "
    for i, ((name, _n), text) in enumerate(zip(segs, texts, strict=True)):
        underline += ("─" if name == tab else " ") * len(text)
        if i < len(segs) - 1:
            underline += " " * len(sep)
    return line + "\n" + underline


def _table(rows: Sequence[ExposureRow]) -> str:
    headers = ["SENSITIVE DATA", "SOURCE", "DESTINATION", "STATUS"]
    data = []
    for r in _legacy_rows(rows):
        title = _title(r.data_type, r.count)
        source = _truncate_middle(r.source, 24)
        dest = r.destination
        status = _status_chip(r)
        data.append([title, source, dest, status])
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in data)) if data
        else len(headers[i])
        for i in range(len(headers))
    ]

    def fmt(cells):
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths, strict=True))

    lines = [fmt(headers)]
    lines.extend(fmt(d) for d in data)
    return "\n".join(lines)


def _coverage_banner(coverage: SessionCoverage) -> str:
    """design.md §5's "Never silently present partial results as complete",
    applied to the whole session rather than to one event's deep scan.

    Shaped like the deep-scan banner it sits beside (`⚠ … — …`) on purpose: the
    two say the same kind of thing at different scopes, and a reader who has
    learned to read one should not have to learn a second visual language for
    the other.

    I5 audit of this string, since it is the one place a reader might hope for
    good news: it states what the ledger holds and stops. "not a full account"
    is a fact about the record. Nothing here says the unrecorded events can be
    listed, retrieved, replayed or recovered, because they cannot be — the
    ledger is the only record and what it did not write down is gone.

    Two lines rather than one because the longest `reason` would otherwise push
    a single line past 100 columns and wrap mid-sentence in a terminal — and a
    caveat that wraps is a caveat that reads as a glitch.
    """
    return (f"⚠ Session record incomplete — {coverage.reason}.\n"
            "  Figures below are not a full account of this session.")


#: Used only when the skill's resolution names one live session.
_SUBTITLE_CURRENT = "Current session"

#: Subtitle per `mcp_tools.ResolvedSession.basis`, for the bases whose copy
#: does not depend on anything else. `explicit` and `active` are decided in
#: `_subtitle` because they need the id and the `certain` flag respectively.
_SUBTITLE_BY_BASIS = {
    "started_at": "Most recently started session",
    "none": "No session on record",
}


def _subtitle(resolved: "ResolvedSession | None", *,
              session_id: str | None = None) -> str:
    """The audit header's second line: which session this table is about.

    **Why this cannot be the constant it used to be.** "Current session" is a
    claim, and exactly one of `resolve_audit_session`'s four bases actually
    supports it. The daemon naming a single live session does: running
    `$privacy` fires a hook in the asking session, so "most recently active"
    *is* "current", by construction. The others do not. A `started_at`
    resolution is the most recently *started* session — the answer the daemon
    could not be asked for, and the wrong one the moment a second Codex window
    exists. An `explicit` id is whichever session the user named, which may be
    one they closed an hour ago. Printing "Current session" over any of those
    is the same overclaim CLAUDE.md §5 forbids in the README, one layer down:
    the skill already prints `ResolvedSession.note` above this table saying the
    resolution was uncertain, and a header that goes on asserting certainty
    directly contradicts the line above it.

    A supplied `session_id` labels the selected session without a
    resolution claim. With neither an ID nor a resolution, the subtitle is
    `Session ID unknown`.

    I5: every branch names a session and stops. Nothing here suggests anything
    can be taken back. I1: an id, which `ResolvedSession` already establishes
    is metadata, not content.
    """
    if session_id:
        return f"Session {session_id}"
    if resolved is None:
        return "Session ID unknown"
    if resolved.basis == "explicit":
        return (f"Session {resolved.session_id}" if resolved.session_id
                else "Session ID unknown")
    if resolved.basis == "active":
        # `certain` is False here only when other sessions were active in the
        # same moment; the daemon's ranking still stands, it just cannot be
        # called "current" without qualification.
        return (_SUBTITLE_CURRENT if resolved.certain
                else "Most recently active session")
    return _SUBTITLE_BY_BASIS.get(resolved.basis, "Session ID unknown")


def audit(summary: SessionSummary, rows: Sequence[ExposureRow],
          tab: str, *,
          coverage: SessionCoverage | None = None,
          resolved: "ResolvedSession | None" = None,
          session_id: str | None = None,
          all_events_count: int | None = None) -> str:
    """The L2 session audit (design.md §5).

    `rows` is whatever the caller has already selected for `tab` — this
    function does not re-filter by kind. It does apply each tab's documented
    sort order (design.md §5): Exposed by budget contribution descending,
    Prevented most-recent-first, All events chronological.

    **Accounting.** A legacy summary renders its stored numbers under legacy
    labels with the legacy accounting note below the tiles. An unrecorded
    summary renders "No session on record", unavailable tiles, its own note,
    `—` for every tab count and the unrecorded empty line: no number, band,
    bar or row.

    **Tab counts.** The two kind tabs count from the summary. "All events"
    is `len(rows)` on its own tab and `all_events_count` otherwise; with
    neither it prints `—`. It used to be approximated as exposed plus
    prevented, which omits local-access, detected and retention rows.

    **`coverage` is a `ledger.SessionCoverage`, or `None` for "not asked".**
    It is not read here: both things it decides are decided by the two module
    functions this passes it to — `coverage_banner()` for the banner above the
    table, `empty_message()` for the line inside it. The browser asks the
    same two questions of the same functions.

    **`resolved` is an `mcp_tools.ResolvedSession`, or `None` for "not
    asked".** It changes exactly one thing: the header subtitle. See
    `_subtitle`. Without `resolved`, a supplied `session_id` renders
    `Session <id>`; otherwise the subtitle is `Session ID unknown`.
    """
    _refuse_v2(summary, rows)
    legacy_rows = _legacy_rows(rows)
    legacy = isinstance(summary, LegacySessionSummary)
    exposed_n: int | None = None
    prevented_n: int | None = None
    all_n: int | None = None
    if isinstance(summary, LegacySessionSummary):
        exposed_n = summary.legacy_permitted_crossing_rows
        prevented_n = summary.legacy_prevented_rows
        all_n = len(rows) if tab == "All events" else all_events_count

    ordered = legacy_rows if legacy else []
    if tab == "Exposed":
        ordered.sort(key=lambda r: r.budget_delta, reverse=True)
    elif tab == "Prevented":
        ordered.sort(key=lambda r: r.ts, reverse=True)
    else:
        ordered.sort(key=lambda r: r.ts)

    lines = ["Privacy Audit", _subtitle(resolved, session_id=session_id), ""]
    if not legacy:
        lines += [UNRECORDED_SCORE_LABEL, ""]
    lines.append(_tiles_block(summary))
    lines.append(_note(LEGACY_ACCOUNTING_NOTE if legacy
                       else UNRECORDED_ACCOUNTING_NOTE))
    lines.append("")
    lines.append(_tab_bar(exposed_n, prevented_n, all_n, tab))
    lines.append("")

    # Session-scope first, event-scope second: "we were not watching" is a
    # bigger caveat than "one event got the fast path only".
    banner = coverage_banner(coverage)
    if banner is not None:
        lines.append(banner)
        lines.append("")

    # A `degraded` row had a scan gap: an applicable deep scan supplied no
    # accepted result (`engine.GAP_*` has the histories). This counts the
    # supplied rows that carry the flag; the session's own count, which also
    # covers observations with no event row, is `coverage.shallow_scans`.
    degraded_n = sum(1 for r in ordered if r.degraded)
    if degraded_n:
        plural = "" if degraded_n == 1 else "s"
        lines.append(
            f"⚠ {degraded_n} event{plural} had scan gaps "
            "— fast-path results only."
        )
        lines.append("")

    if not ordered:
        lines.append(empty_message(tab, coverage, summary=summary))
    else:
        lines.append(_table(ordered))

    return "\n".join(lines)


#: How each stored `protection` value is shown. A display mapping only:
#: persisted values are never changed. `blocked` and `masked`/`minimized`
#: record what Privacy HUD returned; no current hook reports whether the
#: host applied it. `None` (SQL NULL) and `"none"` read the same.
_PROTECTION_DISPLAY = {
    "blocked": "denial recorded; host enforcement unconfirmed",
    "masked": "rewrite recorded; host application unconfirmed",
    "minimized": "rewrite recorded; host application unconfirmed",
    "none": "no intervention recorded",
}
_PROTECTION_UNKNOWN = "legacy intervention not recognized"

_ASSOCIATION_NOTE = (
    "This legacy source-to-destination association does not establish "
    "delivery or a multi-hop flow.")

#: The terminal detail view does not save policy. The buttons that do are in
#: the local audit browser (`ui/app.js` → `/api/policy` → `apply_policy`).
_POLICY_SURFACE = ("Policy rules can be saved in the local audit browser "
                   "opened by $privacy.")

_IRREVERSIBLE = "Already disclosed data cannot be recalled from this session."

_LABEL_W = 26


def protection_display(protection: str | None) -> str:
    """The display text for a stored legacy `protection` value."""
    return _PROTECTION_DISPLAY.get(protection or "none", _PROTECTION_UNKNOWN)


def detail(row: ExposureRow) -> str:
    """The L3 legacy row detail view (design.md §6).

    `Already disclosed data cannot be recalled from this session.` is
    required, permanent, and unconditional — it is appended below
    regardless of any other field in `row`, and there is no code path that
    can omit it.

    Every field keeps its legacy meaning and says so: the source and
    destination are a recorded association, not an established delivery;
    the intervention is what Privacy HUD returned, not what the host
    applied; the contribution is to the legacy score. The legacy accounting
    note follows the fields.

    This view prints no action labels. Plain text does not save a rule, and
    bracketed labels here read as buttons. The sentence it prints instead
    names the surface that does save one.

    The "of {cap}" tail is included only when the row itself carries a
    `budget_cap`; fabricating a constant here would go stale the moment
    tables.toml's budget_cap is retuned.

    A version-2 row is refused with the fixed Phase 3 error (#54).
    """
    _refuse_v2(rows=(row,))
    assert isinstance(row, LegacyExposureRow)
    lines = [_title(row.data_type, row.count)]

    flow = (" → ".join(row.hops) if row.hops
            else f"{row.source} → {row.destination}")
    lines.append(f"{'Recorded association':<{_LABEL_W}} {flow}")
    lines.append(_ASSOCIATION_NOTE)
    lines.append("")

    first_ts = row.first_seen if row.first_seen is not None else row.ts
    if first_ts is not None:
        lines.append(f"{'First seen':<{_LABEL_W}} {_fmt_time(first_ts)}")
    last_ts = row.last_seen
    if last_ts is not None and first_ts is not None and last_ts > first_ts:
        lines.append(f"{'Last seen':<{_LABEL_W}} {_fmt_time(last_ts)}")

    lines.append(f"{'Legacy intervention':<{_LABEL_W}} "
                 f"{protection_display(row.protection)}")

    if row.masked_example:
        lines.append(f"{'Example':<{_LABEL_W}} {row.masked_example}")

    if row.budget_delta is not None:
        contrib = f"+{row.budget_delta:g} legacy pts"
        if row.budget_cap:
            contrib += f" of {row.budget_cap:g}"
        lines.append(f"{'Legacy score contribution':<{_LABEL_W}} {contrib}")

    lines += ["", _note(LEGACY_ACCOUNTING_NOTE), "", _POLICY_SURFACE, "",
              _IRREVERSIBLE]
    return "\n".join(lines)


_RECEIPT_FINAL = ("This ledger stores metadata, not file contents, prompts, "
                  "or raw values.")


def receipt(session_id: str, summary: SessionSummary,
            rows: Sequence[ExposureRow], minutes: int | None, *,
            coverage: SessionCoverage | None = None) -> str:
    """The end-of-session privacy receipt (design.md §10).

    The last line is the receipt's verifiable payload: the ledger schema
    has no content, prompt, raw_value, snippet or text column.

    An unrecorded session gets a fixed receipt with no duration, number,
    count, retention claim or table. A legacy receipt prints the stored
    numbers under legacy labels, with the legacy accounting note. The
    duration is printed only when `minutes` is known; `None` omits it rather
    than inventing `0 min`. Rows carry no `(masked)` suffix: the stored
    label records what Privacy HUD returned, not what the host applied.

    `coverage` (a `ledger.SessionCoverage`, or `None` for "not asked") adds a
    banner at the top of a legacy receipt when the record is not verified.

    A version-2 summary or row is refused with the fixed Phase 3 error
    before the unrecorded branch, including for an empty session (#54).
    """
    _refuse_v2(summary, rows)
    legacy_rows = _legacy_rows(rows)
    if not isinstance(summary, LegacySessionSummary):
        return "\n".join([
            f"PRIVACY RECEIPT · {session_id}",
            "",
            UNRECORDED_SCORE_LABEL,
            "Percentage unavailable.",
            _note(UNRECORDED_ACCOUNTING_NOTE),
            "No event rows can be listed for this session.",
            "",
            _RECEIPT_FINAL,
        ])

    pct = int(summary.legacy_percent)
    _check_band(pct)

    lines = []
    if coverage is not None and not coverage.verified:
        lines += [_coverage_banner(coverage), ""]
    header = f"PRIVACY RECEIPT · {session_id}"
    if minutes is not None:
        header += f" · {minutes} min"
    lines += [
        header,
        "",
        f"{LEGACY_SCORE_LABEL}: {pct}% ({summary.legacy_score:g} pts of "
        f"{summary.legacy_cap:g})",
        "legacy permitted-crossing rows: "
        f"{summary.legacy_permitted_crossing_rows}",
        f"legacy boundary kinds: {summary.legacy_boundary_kinds}",
        f"legacy prevented rows: {summary.legacy_prevented_rows}",
        _note(LEGACY_ACCOUNTING_NOTE),
        "Transcript retention is outside this ledger's account.",
        "",
    ]

    for r in legacy_rows:
        title = _title(r.data_type, r.count)
        source = _truncate_middle(r.source, 20)
        lines.append(f"  {title:<22}{source:<18}→ {r.destination}")

    lines += ["", _RECEIPT_FINAL]
    return "\n".join(lines)
