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
`SessionSummary` and `ExposureRow` (or an `EventRow`, which is one — see that
class), not dicts. These functions are almost entirely `row[...]`/`.get(...)`
lookups, which made them the single most exposed consumer of the old
string-keyed contract: a mistyped key was either a `KeyError` in the middle of
the audit the user just asked for, or a `.get()` returning `None` that rendered
as an empty table cell nobody would notice was wrong. `row.data_typo` is an
`AttributeError` at the call site instead, and the field list is somewhere a
reader can check.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime
from typing import TYPE_CHECKING

from .ledger import ExposureRow, SessionCoverage, SessionSummary
from .matrix.loader import load_matrix
from .origin import OriginKind, origin_phrase

if TYPE_CHECKING:  # pragma: no cover - typing only
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
#: honest half of what "The engine is running" was reaching for: it says the
#: record has no hole in it, in `SessionCoverage`'s own words, and then says
#: what that still does not amount to. A caller that passes no coverage gets
#: the bare line above — "not asked" and "asked, and verified" are different
#: answers, and only the second earns this sentence.
_EMPTY_VERIFIED = (
    " Nothing on record contradicts a complete account of it, which is weaker "
    "than a complete account: a hook that never fired, or whose client timed "
    "out, leaves no trace anywhere."
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


def empty_message(tab: str, coverage: SessionCoverage | None) -> str:
    """The one empty-state line for `tab` under `coverage`.

    Public, and the only way any surface may choose this string. `audit()`
    calls it; `local_ui_server` serves its result to the browser rather than
    shipping the raw dict for `ui/app.js` to index. That is the whole point:
    the browser used to pick from `_EMPTY_MESSAGES` itself, with the coverage
    reading sitting unread in the same payload, so the reassuring line was
    shown on exactly the sessions it could not be shown on. Two surfaces each
    deciding is how they came to disagree; one function decides now.

    Three answers, not two — "not asked" and "asked, and verified" are
    different states and only the second earns `_EMPTY_VERIFIED`:

    - coverage says not verified → `_EMPTY_UNVERIFIED`, the same line on every
      tab, because an incomplete record is a caveat about the session and not
      about one tab's contents.
    - coverage verified → the tab's line plus what the record supports.
    - `None` → the tab's line alone, which is what a caller with no coverage
      reading is entitled to and no more.
    """
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


def hud_line(percent: int, width: int, blocked: int = 0, *,
             unverified: bool = False) -> str:
    """The ambient L1 HUD line (design.md §4).

    Width-degradation ladder: >=52, 40-51, 28-39, <28 columns. Never exceeds
    `width` — a hard invariant, enforced below by falling back to a narrower
    bucket's format (and, as a last resort, truncating) if the natural format
    for the given bucket doesn't fit, which can happen when `blocked` is a
    large number of digits.

    **`unverified` closes design.md §4's "Engine degraded" gap.** Until it
    existed, this function's three integers gave `0%` two irreconcilable
    meanings — "nothing sensitive was disclosed" and "I have no idea what was
    disclosed" — and for a privacy tool those must be distinguishable. It is
    keyword-only with a False default so every existing three-positional call
    site, and every golden string pinned against one, is byte-for-byte
    unchanged; a caller opts in by knowing something this function cannot see
    (`Ledger.coverage`). design.md §4's state table owns the copy: the suffix is
    `⚠unverified`, spelled exactly that way, not paraphrased here.

    The remaining state, "Disabled" (render nothing), is still not reachable
    through this signature and deliberately so: it is the absence of a line, not
    a line, so the caller must decide not to call `hud_line` at all —
    `ambient._line_for()` returning `None` is that decision. Do not conflate the
    two. "Disabled" means there is nothing to report on; `unverified` means
    there is something to report on and the report has a hole in it.

    **The marker survives the whole ladder, including truncation.** Below 28
    columns the word does not fit, so the warning glyph *replaces* the band dot
    rather than being appended after the percentage. That looks like a downgrade
    and is the opposite: a marker appended to `⬤ 28%` is the first thing a
    truncating `[:width]` would cut, and what it would leave behind is a
    clean-looking number — precisely the failure this parameter exists to
    prevent. Losing the band colour that the dot carries is the cheaper loss,
    because a percentage we cannot vouch for must not be the last thing
    standing.
    """
    pct = int(percent)
    _check_band(pct)  # fail loud on an out-of-range percent; never swallow
    prefix = f"⚠ {blocked} blocked · " if blocked else ""
    # design.md §4's state table, character for character:
    #   normal      `... ███░░░░░░░ 28%  ›`   (two spaces before the chevron)
    #   unverified  `... ███░░░░░░░ 28% ⚠unverified ›`
    # The two-space gap is what the marker occupies, so the unverified line is
    # not the normal line plus something — it is the normal line with the gap
    # spent. That is why this is one string and not a suffix appended to it.
    full_tail = " ⚠unverified ›" if unverified else "  ›"
    tail = " ⚠unverified ›" if unverified else " ›"

    def full():
        return f"PRIVACY  {prefix}Disclosure {hud_core(pct)}{full_tail}"

    def mid():
        return f"PRIVACY {prefix}{hud_core(pct)}{tail}"

    def compact():
        bar = _bar(pct, 5)
        short_prefix = f"⚠{blocked} " if blocked else ""
        return f"PRIV {short_prefix}{bar} {pct:>2}%{tail}"

    def dot():
        # The glyph, not a suffix — see the docstring's truncation argument.
        return f"{'⚠' if unverified else _DOT} {pct:>2}%"

    ladder: tuple[Callable[[], str], ...]
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
    # Never exceed the given width regardless. Truncating from the right is
    # safe for the unverified state only because `dot()` puts the warning
    # glyph FIRST — see the docstring; do not "tidy" that into a suffix.
    line = dot()
    return line[:max(width, 0)]


def _status_chip(row: ExposureRow) -> str:
    if row.protection in ("masked", "minimized"):
        return "[MASKED]"
    if row.kind == "exposed":
        return "[EXPOSED]"
    if row.kind == "prevented":
        return "[PREVENTED]"
    if row.kind == "local_access":
        return "[LOCAL]"
    return f"[{(row.kind or 'unknown').upper()}]"


def _tile(value: str, label: str) -> list[str]:
    inner = max(len(value), len(label))
    top = "┌" + "─" * (inner + 2) + "┐"
    val = "│ " + value.center(inner) + " │"
    lab = "│ " + label.center(inner) + " │"
    bot = "└" + "─" * (inner + 2) + "┘"
    return [top, val, lab, bot]


def _tiles_block(summary: SessionSummary) -> str:
    pct = int(summary.percent)
    _check_band(pct)  # same fail-loud validation as hud_line
    tiles = [
        (f"{pct}%", "disclosure"),
        (str(summary.exposed_items), "exposed items"),
        (str(summary.destinations), "destinations"),
        (str(summary.prevented), "prevented"),
    ]
    blocks = [_tile(value, label) for value, label in tiles]
    return "\n".join(" ".join(b[i] for b in blocks) for i in range(4))


def _tab_bar(exposed_n: int, prevented_n: int, all_n: int, tab: str) -> str:
    segs = [("Exposed", exposed_n), ("Prevented", prevented_n),
            ("All events", all_n)]
    texts = [f"{name} {n}" for name, n in segs]
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
    for r in rows:
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


#: What the audit header says when the caller did not say which session this
#: is. Matches design.md §5's mockup ("Current session · 41 min", minus the
#: duration this function has no channel for) and is what every call site
#: rendered before `resolved=` existed.
_SUBTITLE_CURRENT = "Current session"

#: Subtitle per `mcp_tools.ResolvedSession.basis`, for the bases whose copy
#: does not depend on anything else. `explicit` and `active` are decided in
#: `_subtitle` because they need the id and the `certain` flag respectively.
_SUBTITLE_BY_BASIS = {
    "started_at": "Most recently started session",
    "none": "No session on record",
}


def _subtitle(resolved: "ResolvedSession | None") -> str:
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

    `None` — the caller did not resolve, or had no reason to — keeps the
    previous constant, the same compatibility rule `coverage=None` follows.
    That is not a claim this function is making on its own behalf; it is the
    string every existing call site already renders, and changing it would
    rewrite goldens for callers that did not opt in.

    I5: every branch names a session and stops. Nothing here suggests anything
    can be taken back. I1: an id, which `ResolvedSession` already establishes
    is metadata, not content.
    """
    if resolved is None:
        return _SUBTITLE_CURRENT
    if resolved.basis == "explicit":
        return f"Session {resolved.session_id}"
    if resolved.basis == "active":
        # `certain` is False here only when other sessions were active in the
        # same moment; the daemon's ranking still stands, it just cannot be
        # called "current" without qualification.
        return (_SUBTITLE_CURRENT if resolved.certain
                else "Most recently active session")
    return _SUBTITLE_BY_BASIS.get(resolved.basis, _SUBTITLE_CURRENT)


def audit(summary: SessionSummary, rows: Sequence[ExposureRow], tab: str, *,
          coverage: SessionCoverage | None = None,
          resolved: "ResolvedSession | None" = None) -> str:
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
    session duration. The first half of that subtitle is no longer a constant
    either: see `resolved` below and `_subtitle`.

    The "All events" tab count in the tab bar is exact when `tab == "All
    events"` (`len(rows)`, since that's exactly what's being rendered);
    for the other two tabs it is `exposed_items + prevented` as a
    best-effort approximation, because `summary` (per the given `Ledger.
    summary` interface) does not carry a total event count and this
    function only ever sees one tab's rows at a time.

    **`coverage` is a `ledger.SessionCoverage`, or `None` for "not asked".**
    When it says the session's record is not verified, two things change, and
    the second matters more than the first:

    1. A banner appears above the table (`_coverage_banner`).
    2. The empty-state line is REPLACED. `_EMPTY_MESSAGES` makes three positive
       claims — "No sensitive data has crossed a trust boundary this session",
       "Nothing has been blocked or minimized yet", "No privacy events
       recorded. The engine is running." — and an unverified session cannot
       support any of them. That last one is the exact sentence the incident in
       `ledger.py`'s docstring printed while the engine had, in fact, not been
       running for the session being audited. An empty table plus a banner is
       not enough; the sentence in the middle of the empty table has to stop
       asserting the thing that is not known.

    `None` (the default) renders exactly what this function always rendered, so
    a caller that has no coverage reading cannot accidentally acquire a clean
    bill of health it did not ask for — but note that "no reading" and "a
    reading of verified" are different, and only `Ledger.coverage()` can supply
    the latter.

    **`resolved` is an `mcp_tools.ResolvedSession`, or `None` for "not
    asked".** It changes exactly one thing: the header subtitle, which used to
    read the literal `"Current session"` for every session this function was
    ever handed. That was an unsupported claim whenever the session had been
    resolved by falling back to the ledger's most-recently-*started* row —
    which is precisely the case where `$privacy` prints a note above this table
    saying it could not be sure. See `_subtitle` for the copy and the argument.
    `None` keeps the old constant, on the same compatibility rule as
    `coverage=None`: opting in is the only way to see the new strings.
    """
    exposed_n = summary.exposed_items
    prevented_n = summary.prevented
    all_n = len(rows) if tab == "All events" else exposed_n + prevented_n

    ordered = list(rows)
    if tab == "Exposed":
        ordered.sort(key=lambda r: r.budget_delta, reverse=True)
    elif tab == "Prevented":
        ordered.sort(key=lambda r: r.ts, reverse=True)
    else:
        ordered.sort(key=lambda r: r.ts)

    lines = ["Privacy Audit", _subtitle(resolved), ""]
    lines.append(_tiles_block(summary))
    lines.append("")
    lines.append(_tab_bar(exposed_n, prevented_n, all_n, tab))
    lines.append("")

    # Session-scope first, event-scope second: "we were not watching" is a
    # bigger caveat than "one event got the fast path only", and reading them
    # in the other order invites treating the first as a footnote to it.
    # Through `coverage_banner()` rather than testing `coverage.verified`
    # here: the browser asks the same question, and one of the two asking it
    # separately is how the reassuring empty state came to be shown on
    # sessions that could not support it.
    banner = coverage_banner(coverage)
    if banner is not None:
        lines.append(banner)
        lines.append("")

    # Deep-scan degradation covers two situations (task-11 brief): the model
    # being unavailable, and a payload too large for the bounded synchronous
    # scan (Task 8's degraded flag). Both surface identically here as a
    # `degraded` flag on the affected row.
    degraded_n = sum(1 for r in ordered if r.degraded)
    if degraded_n:
        plural = "" if degraded_n == 1 else "s"
        lines.append(
            f"⚠ Deep scan unavailable for {degraded_n} event{plural} "
            "— fast-path results only."
        )
        lines.append("")

    if not ordered:
        lines.append(empty_message(tab, coverage))
    else:
        lines.append(_table(ordered))

    return "\n".join(lines)


def detail(row: ExposureRow) -> str:
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
    fixed one-row interface (no summary/matrix/band passed in):
    - Budget contribution is shown as `+N pts` from `row.budget_delta`.
      design.md's mockup shows `+9 pts of 120`, but the 120 is the session's
      budget_cap, which this function has no access to; the "of {cap}" tail
      is included only when the row itself carries a `budget_cap` (which is
      why that field is optional and `None` when unknown, rather than
      defaulted), since fabricating 120 as a hardcoded constant here would
      silently go stale the moment tables.toml's budget_cap is retuned.
    - `Protect future occurrences` is always rendered; a second action line,
      `Block values read from {source}` or `` Block values from `{source}`
      output ``, follows it only when `row.source_kind` is `"path"` or
      `"command"` -- i.e. only when `source` names a real origin rather than
      a bare tool label (#40). The red-band note pointing at a new Codex
      conversation (design.md §6) depends on the session's band, which this
      function cannot see from a single row. design.md's `Block this source`
      (`block_source`) stays withdrawn (#38): it named a label, not a
      source, and `block_path`/`block_command` are the replacement, not a
      revival of it.
    - The per-action confirmation line ("Rule added: ...") describes what
      happens after a button is pressed; there is no click state in a pure
      render of `row`, so it is not rendered here.

    Takes the same `ExposureRow` the tab tables take, with its L3 fields
    (`first_seen`, `last_seen`, `hops`, `budget_cap`) populated — that is what
    `mcp_tools.get_exposure_detail` returns. Each of those is optional and
    `None` when unknown, and each line below is still conditional on exactly
    that, so a bare list row renders the shorter view rather than raising.
    """
    lines = [_title(row.data_type, row.count)]

    if row.hops:
        lines.append(" → ".join(row.hops))
    else:
        lines.append(f"{row.source} → {row.destination}")
    lines.append("")

    first_ts = row.first_seen if row.first_seen is not None else row.ts
    if first_ts is not None:
        lines.append(f"{'First seen':<12} {_fmt_time(first_ts)}")
    last_ts = row.last_seen
    if last_ts is not None and first_ts is not None and last_ts > first_ts:
        lines.append(f"{'Last seen':<12} {_fmt_time(last_ts)}")

    lines.append(f"{'Protection':<12} {row.protection or 'none'}")

    if row.masked_example:
        lines.append(f"{'Example':<12} {row.masked_example}")

    if row.budget_delta is not None:
        contrib = f"+{row.budget_delta:g} pts"
        if row.budget_cap:
            contrib += f" of {row.budget_cap:g}"
        lines.append(f"{'Budget':<12} {contrib}")

    lines += ["", "[ Protect future occurrences ]"]
    # An unrecognised `source_kind` offers nothing, rather than a button
    # whose rule would never match (#40). The wording comes from
    # `origin.origin_phrase`, which the engine's deny message also uses, so
    # the button and the refusal it leads to cannot describe the same
    # origin in two different ways.
    if row.source_kind == "path":
        lines.append(f"[ Block values {origin_phrase(row.source, OriginKind.PATH)} ]")
    elif row.source_kind == "command":
        lines.append(
            f"[ Block values {origin_phrase(row.source, OriginKind.COMMAND)} ]")

    lines += [
        "",
        "Already disclosed data cannot be recalled from this session.",
    ]
    return "\n".join(lines)


def receipt(session_id: str, summary: SessionSummary,
            rows: Sequence[ExposureRow], minutes: int, *,
            coverage: SessionCoverage | None = None) -> str:
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

    `coverage` (a `ledger.SessionCoverage`, or `None` for "not asked") adds one
    banner line at the top when the record is not verified. A receipt is the
    artifact a user keeps and quotes, so it is the single worst place for a
    disclosure figure that reads complete and is not — a receipt is a claim
    about a whole session, and a session with an unrecorded stretch has no
    complete claim to make. The banner goes ABOVE the header rather than beside
    the figures because it qualifies all of them at once.
    """
    pct = int(summary.percent)
    _check_band(pct)

    lines = []
    if coverage is not None and not coverage.verified:
        lines += [_coverage_banner(coverage), ""]
    lines += [
        f"PRIVACY RECEIPT · {session_id} · {minutes} min",
        "",
        f"{'Disclosure':<16} {pct}% of budget",
        f"{'Exposed':<16} {summary.exposed_items} flows across "
        f"{summary.destinations} destinations",
        f"{'Prevented':<16} {summary.prevented} events",
        f"{'Retained':<16} session transcript, persisted by Codex outside "
        "this ledger.",
        "",
    ]

    for r in rows:
        title = _title(r.data_type, r.count)
        source = _truncate_middle(r.source, 20)
        suffix = "  (masked)" if r.protection == "masked" else ""
        lines.append(f"  {title:<22}{source:<18}→ {r.destination}{suffix}")

    lines += ["", "No file contents, prompts, or raw values were stored."]
    return "\n".join(lines)
