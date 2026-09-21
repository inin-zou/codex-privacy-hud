# tests/test_render.py
"""Renderer tests. See design.md §3-6, §9, §10 for the authoritative copy
and layouts these functions must reproduce.

The banned-word test is the gate: this is a privacy tool, and it must never
claim more than it can back up (design.md §9)."""
import json
from dataclasses import replace
from pathlib import Path

from privacy_hud.ledger import ExposureRow, SessionCoverage, SessionSummary
from privacy_hud.matrix.loader import UnknownKey
from privacy_hud.mcp_tools import ResolvedSession
from privacy_hud.render import hud_line, audit, detail, receipt, hud_core

import pytest

# Extended past the brief's list per task-11 instructions: "dangerous" and
# "critical" are scanner-vocabulary adjectives we reject even though the
# facts alone are alarming enough (design.md §7).
BANNED = ("undo", "revoke", "remove from context", "your data is protected",
          "100% secure", "threat", "dangerous", "critical")
GOLDEN = json.loads((Path(__file__).parent / "matrix" / "hud_golden.json").read_text())
# `ExposureRow`/`SessionSummary` rather than the dicts these used to be: the
# renderer's input is typed (see ledger.py's read-contract dataclasses). Same
# field values, same assertions — only the carrier changed.
ROW = ExposureRow(id=1, turn_id="t1", ts=1757000000, kind="exposed",
                  data_type="email", count=12, source="support.log",
                  source_kind=None, destination="model context", boundary="B1",
                  masked_example="jo•••@acme.com", budget_delta=9.0,
                  protection=None, tool_name="Read")
SUMMARY = SessionSummary(percent=28, exposed_items=4, destinations=2,
                         prevented=17)
EMPTY_SUMMARY = SessionSummary(percent=0, exposed_items=0, destinations=0,
                               prevented=0)


def test_hud_bar_has_ten_cells_and_percent():
    line = hud_line(28, width=80)
    assert line.count("█") + line.count("░") == 10
    assert "28%" in line


def test_hud_degrades_under_narrow_terminals():
    assert len(hud_line(28, width=30)) <= 30
    assert "28%" in hud_line(28, width=20)


def test_hud_never_exceeds_given_width_across_the_ladder():
    # design.md §4 ladder: >=52, 40-51, 28-39, <28.
    for width in (80, 52, 51, 40, 39, 28, 27, 12, 4, 1):
        assert len(hud_line(63, width=width)) <= width


def test_hud_blocked_prefix_does_not_break_the_width_budget():
    for width in (80, 45, 30, 15):
        assert len(hud_line(28, width=width, blocked=999)) <= width


def test_hud_clean_session_renders_zero_percent():
    line = hud_line(0, width=80)
    assert "0%" in line
    assert line.count("█") == 0


def test_detail_always_carries_the_irreversibility_notice():
    assert "cannot be recalled from this session" in detail(ROW)


def test_detail_never_shows_a_raw_value_only_the_masked_example():
    out = detail(ROW)
    assert ROW.masked_example in out


def test_detail_omits_example_line_when_no_exemplar_exists():
    # Credentials get no exemplar at all (mask.py) — the detail view must
    # not print "Example None".
    row = replace(ROW, data_type="credential", masked_example=None)
    out = detail(row)
    assert "None" not in out


def test_detail_offers_no_source_action_for_a_bare_tool_label():
    # `source_kind is None` means `source` is a tool name, not an origin:
    # there is nothing a rule could name, so no button is offered (#40).
    assert "Block values" not in detail(ROW)


def test_detail_golden_for_a_path_origin_row():
    row = replace(ROW, source=".env", source_kind="path")
    assert detail(row).endswith(
        "\n[ Mask detected email in future calls ]\n"
        "[ Block values read from .env ]\n"
        "\nAlready disclosed data cannot be recalled from this session.")


def test_detail_golden_for_a_command_origin_row():
    """The command branch feeds a DIFFERENT rule_type (`block_command`) to
    `apply_policy`, and until this golden existed nothing rendered it: a
    slip here would show the user a confirmation for a rule the engine
    never matches. The wording is the engine's too -- a command origin is
    named as output, not as a file that was read (`origin.origin_phrase`)."""
    row = replace(ROW, source="git log", source_kind="command")
    assert detail(row).endswith(
        "\n[ Mask detected email in future calls ]\n"
        "[ Block values from `git log` output ]\n"
        "\nAlready disclosed data cannot be recalled from this session.")


def test_no_view_contains_forbidden_copy():
    views = [hud_line(28, 80), audit(SUMMARY, [ROW], "Exposed"),
             detail(ROW), receipt("s1", SUMMARY, [ROW], 41)]
    for v in views:
        for word in BANNED:
            assert word not in v.lower()


def test_receipt_states_that_nothing_raw_was_stored():
    assert "No file contents, prompts, or raw values were stored." in \
        receipt("s1", SUMMARY, [ROW], 41)


# These three used to pin the opposite of what they now pin, and that is the
# point worth keeping. They asserted "The engine is running." and "No
# sensitive data has crossed a trust boundary this session." — so the copy
# that #49 item 3 is about was not merely present, it was enforced, and any
# attempt to soften it failed CI. A test can hold a claim in place as firmly
# as it can hold a behaviour; what decides which it is doing is whether the
# claim was ever traced to something that could support it. Neither of those
# two could be: `SessionCoverage` documents that `verified` means "nothing on
# record contradicts a complete account … deliberately weaker than complete",
# and a ledger cannot vouch for a live process at all.

def test_an_empty_tab_states_what_the_ledger_holds_and_stops():
    out = audit(EMPTY_SUMMARY, [], "All events")
    assert "No privacy events recorded for this session." in out
    assert "The engine is running." not in out


def test_an_empty_exposed_tab_does_not_claim_nothing_crossed():
    out = audit(EMPTY_SUMMARY, [], "Exposed")
    assert "No exposure recorded this session." in out
    assert "has crossed a trust boundary" not in out


def test_empty_prevented_tab_says_nothing_recorded_as_blocked_yet():
    out = audit(EMPTY_SUMMARY, [], "Prevented")
    assert "Nothing recorded as blocked or minimized yet." in out


def test_audit_degraded_banner_covers_deep_scan_gaps():
    row = replace(ROW, degraded=True)
    out = audit(SUMMARY, [row], "Exposed")
    assert "fast-path results only." in out


def test_audit_no_degraded_banner_when_nothing_is_degraded():
    out = audit(SUMMARY, [ROW], "Exposed")
    assert "fast-path results only." not in out


# --------------------------------------------------------------------- #
# The third state: design.md §4's "Engine degraded" / `⚠unverified`.
#
# What every test below is really defending: `0%` must not mean both "nothing
# sensitive was disclosed" and "I have no idea what was disclosed". The first
# is a finding; the second is an admission, and a privacy tool that renders
# them identically has a hole where its central number should be.
# --------------------------------------------------------------------- #

INCOMPLETE = SessionCoverage(recorded=True, observers=1, attached=True,
                             unobserved_hooks=False)
COMPLETE = SessionCoverage(recorded=True, observers=1, attached=False,
                           unobserved_hooks=False)


def test_hud_unverified_is_off_by_default():
    """The parameter is keyword-only with a False default so no existing call
    site — and no golden pinned against one — moves a byte."""
    assert hud_line(28, 80) == hud_line(28, 80, 0)
    assert "unverified" not in hud_line(28, 80)


def test_hud_unverified_marker_is_designs_exact_wording():
    # design.md §4's state table, not a paraphrase.
    assert hud_line(28, 80, unverified=True) == \
        "PRIVACY  Disclosure ███░░░░░░░ 28% ⚠unverified ›"


def test_hud_unverified_zero_percent_is_distinguishable_from_a_clean_zero():
    clean = hud_line(0, 80)
    unknown = hud_line(0, 80, unverified=True)
    assert clean != unknown
    assert "unverified" in unknown and "unverified" not in clean


def test_hud_unverified_survives_every_rung_of_the_ladder():
    """The marker may never be the thing that gets dropped to make the line
    fit: a narrower line that still says "unverified" beats a wider one that
    silently claims a number it cannot back."""
    for width in (80, 52, 51, 40, 39, 28, 27, 12, 4, 1):
        line = hud_line(28, width, unverified=True)
        assert len(line) <= width
        assert "⚠" in line, (width, line)


def test_hud_unverified_never_exceeds_width_with_a_block_prefix_too():
    for width in (80, 52, 45, 39, 30, 15, 4, 1):
        assert len(hud_line(28, width, blocked=999, unverified=True)) <= width


def test_hud_unverified_replaces_the_band_dot_below_28_columns():
    # Appending the marker would put it first in line for truncation, and what
    # truncation would leave is a clean-looking number.
    assert hud_line(28, 27, unverified=True) == "⚠ 28%"
    assert hud_line(28, 27) == "⬤ 28%"


def test_audit_banner_appears_only_when_coverage_says_it_should():
    assert "Session record incomplete" in audit(SUMMARY, [ROW], "Exposed",
                                                 coverage=INCOMPLETE)
    assert "Session record incomplete" not in audit(SUMMARY, [ROW], "Exposed",
                                                     coverage=COMPLETE)
    assert "Session record incomplete" not in audit(SUMMARY, [ROW], "Exposed")


def test_audit_stops_claiming_the_engine_was_running_when_it_was_not():
    """The regression this pins is the whole task. design.md §5 added "The
    engine is running." so an empty audit could not be mistaken for a broken
    plugin — which makes printing it for a session the engine missed the single
    most expensive sentence in the product."""
    out = audit(EMPTY_SUMMARY, [], "All events", coverage=INCOMPLETE)
    assert "The engine is running." not in out
    assert "not evidence that none occurred" in out


def test_audit_empty_state_stops_asserting_nothing_crossed_a_boundary():
    out = audit(EMPTY_SUMMARY, [], "Exposed", coverage=INCOMPLETE)
    assert "No sensitive data has crossed a trust boundary" not in out
    assert "not evidence that none occurred" in out


def test_audit_unverified_line_never_exceeds_a_terminal_width_assumption():
    # The banner is one line and is not width-degraded (the L2 audit is a
    # block view, not the ambient line) -- but it must not be so long that it
    # wraps into unreadability. 100 columns is the floor design.md's own §5
    # mockup assumes.
    for line in audit(SUMMARY, [ROW], "Exposed",
                       coverage=INCOMPLETE).splitlines():
        assert len(line) <= 100


def test_receipt_qualifies_its_figures_when_the_record_is_incomplete():
    out = receipt("s1", SUMMARY, [ROW], 41, coverage=INCOMPLETE)
    assert out.splitlines()[0].startswith("⚠ Session record incomplete")
    assert receipt("s1", SUMMARY, [ROW], 41, coverage=COMPLETE) == \
        receipt("s1", SUMMARY, [ROW], 41)


def test_unverified_copy_never_implies_the_lost_events_can_be_recovered():
    """I5, applied to the new strings specifically. "Unverified" is a statement
    about the ledger, never a promise about what can be got back."""
    forbidden = ("recover", "restore", "retriev", "replay", "undo", "re-scan",
                 "rescan", "will be recorded", "try again")
    views = [
        hud_line(28, 80, unverified=True),
        audit(EMPTY_SUMMARY, [], "All events", coverage=INCOMPLETE),
        audit(SUMMARY, [ROW], "Exposed", coverage=INCOMPLETE),
        receipt("s1", SUMMARY, [ROW], 41, coverage=INCOMPLETE),
    ]
    for view in views:
        low = view.lower()
        for word in BANNED + forbidden:
            assert word not in low, (word, view)


def test_every_coverage_reason_renders_a_banner_with_no_empty_clause():
    """Each `reason` is interpolated into one sentence, so an empty one would
    render `incomplete — . What follows`. Every reachable unverified shape must
    produce a phrase."""
    shapes = [
        SessionCoverage(recorded=False, observers=0, attached=False,
                        unobserved_hooks=False),
        SessionCoverage(recorded=True, observers=0, attached=False,
                        unobserved_hooks=False),
        SessionCoverage(recorded=True, observers=1, attached=True,
                        unobserved_hooks=False),
        SessionCoverage(recorded=True, observers=2, attached=False,
                        unobserved_hooks=False),
        SessionCoverage(recorded=True, observers=1, attached=False,
                        unobserved_hooks=True),
    ]
    for shape in shapes:
        assert not shape.verified
        assert shape.reason
        assert "—  ." not in audit(EMPTY_SUMMARY, [], "Exposed",
                                    coverage=shape)


# --------------------------------------------------------------------- #
# The audit header's second line: WHOSE session these numbers are.
#
# It was the literal "Current session" for every session this function was
# ever handed, including the ones reached by falling back to the ledger's
# most-recently-started row — the exact case where `$privacy` prints a note
# above the table saying it could not be sure. A header that keeps asserting
# certainty directly under a line retracting it is worse than either alone.
#
# Deliberately NOT the `⚠unverified` / `Session record incomplete` channel:
# that one means "this session's record has a known hole", and a marker that
# also meant "I am not sure which session this is" would mean neither.
# --------------------------------------------------------------------- #

def _subtitle_of(out: str) -> str:
    return out.splitlines()[1]


def test_subtitle_says_current_only_when_the_daemon_named_one_live_session():
    """The one basis that supports the claim, and the reason it does: running
    `$privacy` fires a hook in the asking session, so "most recently active"
    *is* "current" by construction."""
    resolved = ResolvedSession("s1", "active")
    assert resolved.certain
    assert _subtitle_of(audit(SUMMARY, [ROW], "Exposed",
                              resolved=resolved)) == "Current session"


def test_subtitle_stops_claiming_current_for_the_no_daemon_fallback():
    """`started_at` is the answer the daemon could not be asked for, and the
    wrong one the moment a second Codex window exists."""
    out = audit(SUMMARY, [ROW], "Exposed",
                resolved=ResolvedSession("s1", "started_at"))
    assert _subtitle_of(out) == "Most recently started session"
    assert "Current session" not in out


def test_subtitle_names_the_session_for_an_explicit_deep_link():
    """`$privacy <id>` may name a session the user closed an hour ago."""
    out = audit(SUMMARY, [ROW], "Exposed",
                resolved=ResolvedSession("sess-abc", "explicit"))
    assert _subtitle_of(out) == "Session sess-abc"
    assert "Current session" not in out


def test_subtitle_hedges_when_two_sessions_were_active_at_once():
    """Ambiguity is a real state in this design: the daemon's ranking still
    stands, it just cannot be called "current" without qualification."""
    resolved = ResolvedSession("s1", "active", ("s2",))
    assert not resolved.certain
    out = audit(SUMMARY, [ROW], "Exposed", resolved=resolved)
    assert _subtitle_of(out) == "Most recently active session"
    assert "Current session" not in out


def test_subtitle_for_an_empty_ledger_claims_no_session_at_all():
    out = audit(EMPTY_SUMMARY, [], "Exposed",
                resolved=ResolvedSession(None, "none"))
    assert _subtitle_of(out) == "No session on record"


def test_every_basis_gets_its_own_subtitle():
    """A basis silently sharing another's copy would make the header say
    something true of a different resolution — the failure this replaces."""
    subtitles = [
        _subtitle_of(audit(SUMMARY, [ROW], "Exposed", resolved=r))
        for r in (ResolvedSession("s1", "explicit"),
                  ResolvedSession("s1", "active"),
                  ResolvedSession("s1", "active", ("s2",)),
                  ResolvedSession("s1", "started_at"),
                  ResolvedSession(None, "none"))
    ]
    assert len(set(subtitles)) == len(subtitles)


def test_no_resolution_renders_exactly_what_it_always_did():
    """The compatibility rule `coverage=` already follows, stated as a test:
    opting in is the only way to see the new strings, so no existing caller
    and no existing golden moved."""
    for tab in ("Exposed", "Prevented", "All events"):
        assert audit(SUMMARY, [ROW], tab, resolved=None) == \
            audit(SUMMARY, [ROW], tab)
        assert _subtitle_of(audit(SUMMARY, [ROW], tab)) == "Current session"


def test_the_subtitle_is_not_the_coverage_channel():
    """Two questions, two answers. A session whose record is incomplete but
    whose identity is certain keeps saying "Current session" — and a session
    resolved by fallback but fully recorded still gets no coverage banner."""
    incomplete_but_certain = audit(SUMMARY, [ROW], "Exposed",
                                   coverage=INCOMPLETE,
                                   resolved=ResolvedSession("s1", "active"))
    assert _subtitle_of(incomplete_but_certain) == "Current session"
    assert "Session record incomplete" in incomplete_but_certain

    complete_but_unsure = audit(SUMMARY, [ROW], "Exposed", coverage=COMPLETE,
                                resolved=ResolvedSession("s1", "started_at"))
    assert _subtitle_of(complete_but_unsure) == "Most recently started session"
    assert "Session record incomplete" not in complete_but_unsure
    assert "unverified" not in complete_but_unsure


def test_no_subtitle_implies_recall_or_editorializes():
    """I5 / design.md §9, applied to the new strings specifically."""
    for r in (ResolvedSession("s1", "explicit"),
              ResolvedSession("s1", "active"),
              ResolvedSession("s1", "active", ("s2",)),
              ResolvedSession("s1", "started_at"),
              ResolvedSession(None, "none")):
        low = audit(SUMMARY, [ROW], "Exposed", resolved=r).lower()
        for word in BANNED:
            assert word not in low, (word, r.basis)


def test_hud_core_matches_golden_for_every_case():
    for g in GOLDEN:
        assert hud_core(g["percent"]) == g["core"], g


def test_hud_core_is_the_segment_hud_line_embeds():
    for pct in (0, 28, 63, 100):
        assert hud_core(pct) in hud_line(pct, 80)
        assert hud_core(pct) in hud_line(pct, 45)      # mid rung too


def test_hud_core_rejects_out_of_band_percent():
    with pytest.raises(UnknownKey):
        hud_core(101)
