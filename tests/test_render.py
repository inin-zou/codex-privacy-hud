# tests/test_render.py
"""Renderer tests. See design.md §3-6, §9, §10 for the authoritative copy
and layouts these functions must reproduce.

The banned-word test is the gate: this is a privacy tool, and it must never
claim more than it can back up (design.md §9)."""
from privacy_hud.render import hud_line, audit, detail, receipt

# Extended past the brief's list per task-11 instructions: "dangerous" and
# "critical" are scanner-vocabulary adjectives we reject even though the
# facts alone are alarming enough (design.md §7).
BANNED = ("undo", "revoke", "remove from context", "your data is protected",
          "100% secure", "threat", "dangerous", "critical")
ROW = {"data_type": "email", "count": 12, "source": "support.log",
       "destination": "model context", "kind": "exposed",
       "masked_example": "jo•••@acme.com", "ts": 1757000000,
       "protection": None, "budget_delta": 9.0}
SUMMARY = {"percent": 28, "exposed_items": 4, "destinations": 2, "prevented": 17}


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
    assert ROW["masked_example"] in out


def test_detail_omits_example_line_when_no_exemplar_exists():
    # Credentials get no exemplar at all (mask.py) — the detail view must
    # not print "Example None".
    row = dict(ROW, data_type="credential", masked_example=None)
    out = detail(row)
    assert "None" not in out


def test_no_view_contains_forbidden_copy():
    views = [hud_line(28, 80), audit(SUMMARY, [ROW], "Exposed"),
             detail(ROW), receipt("s1", SUMMARY, [ROW], 41)]
    for v in views:
        for word in BANNED:
            assert word not in v.lower()


def test_receipt_states_that_nothing_raw_was_stored():
    assert "No file contents, prompts, or raw values were stored." in \
        receipt("s1", SUMMARY, [ROW], 41)


def test_empty_exposed_tab_explains_the_engine_is_running():
    out = audit({"percent": 0, "exposed_items": 0, "destinations": 0,
                 "prevented": 0}, [], "All events")
    assert "The engine is running." in out


def test_empty_exposed_tab_says_nothing_crossed_a_boundary():
    out = audit({"percent": 0, "exposed_items": 0, "destinations": 0,
                 "prevented": 0}, [], "Exposed")
    assert "No sensitive data has crossed a trust boundary this session." in out


def test_empty_prevented_tab_says_nothing_blocked_yet():
    out = audit({"percent": 0, "exposed_items": 0, "destinations": 0,
                 "prevented": 0}, [], "Prevented")
    assert "Nothing has been blocked or minimized yet." in out


def test_audit_degraded_banner_covers_deep_scan_gaps():
    row = dict(ROW, degraded=True)
    out = audit(SUMMARY, [row], "Exposed")
    assert "fast-path results only." in out


def test_audit_no_degraded_banner_when_nothing_is_degraded():
    out = audit(SUMMARY, [ROW], "Exposed")
    assert "fast-path results only." not in out
