# tests/test_ambient.py
"""Tests for the Level 1 ambient HUD companion process (design.md §4).

Two things are being defended here.

The first is that `ambient` is a *transport*, not a second renderer: whatever
it prints must be byte-identical to what `render.hud_line()` would produce for
the same ledger, so the width ladder and the copy rules stay owned by exactly
one module. `test_once_prints_exactly_what_render_would_produce` is the gate.

The second is that this process can never hurt the terminal it renders into
(I6's spirit). It runs unattended in a pane beside a live Codex session, so
every failure mode — no data dir, no ledger file, no sessions, a corrupt
database, a corrupt row — must exit 0 with nothing on stdout and no traceback,
and must NOT call `hud_line` at all (design.md §4's "Disabled" state, which
`hud_line`'s own docstring says its signature cannot express). The
`no_hud_line` fixture turns that last requirement into an assertion instead of
an inspection.
"""
from __future__ import annotations

import json

import pytest

from privacy_hud import ambient, mcp_tools
from privacy_hud import hud_snapshot as hs
from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.render import hud_line

M = load_matrix()

BANNED = ("undo", "revoke", "remove from context", "your data is protected",
          "100% secure", "threat", "protected", "secure")


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """A `$PLUGIN_DATA` directory plus a pinned terminal width.

    `shutil.get_terminal_size()` consults `COLUMNS` before it asks the tty, so
    pinning the env var is how these tests get a deterministic width without
    reaching into the module under test."""
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    monkeypatch.setenv("COLUMNS", "80")
    return tmp_path


@pytest.fixture
def no_hud_line(monkeypatch):
    """Make any call to `hud_line` a test failure, and record that it wasn't.

    The "Disabled" state is defined by what does NOT happen: `hud_line`
    validates its percent against the band table and fails loud on garbage, so
    "we called it with a made-up 0" and "we correctly declined to call it" are
    otherwise indistinguishable from stdout alone."""
    calls = []

    def _fail(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("hud_line must not be called in the disabled state")

    monkeypatch.setattr(ambient, "hud_line", _fail)
    return calls


@pytest.fixture
def daemon_says(monkeypatch):
    """Stub the one socket call session resolution makes, and count it.

    Same seam `tests/test_mcp.py` uses (`mcp_tools._ask_daemon`), for the same
    reason: these tests are about the POLICY — which session this pane shows,
    and how often it asks — not about socket plumbing, which
    `tests/test_daemon.py` exercises against a real daemon. Returns the call
    log, so "did not ask at all" is assertable and not merely unobserved.
    """
    calls = []

    def _install(sessions):
        def _fake(data_dir):
            calls.append(data_dir)
            return sessions
        monkeypatch.setattr(mcp_tools, "_ask_daemon", _fake)
        return calls

    return _install


def _ledger(data_dir) -> Ledger:
    return Ledger(data_dir / "ledger.db", M)


def _expose(led, session_id, value_hash, *, data_type="email",
            destination="model_context"):
    led.record(session_id, turn_id="t1", kind="exposed", data_type=data_type,
               source="support.log", destination=destination,
               value_hash=value_hash, masked_example="jo•••@acme.com",
               tool_name="Read", protection=None)


def _prevent(led, session_id, value_hash):
    led.record(session_id, turn_id="t2", kind="prevented",
               data_type="credential", source="tool input",
               destination="mcp_tool", value_hash=value_hash,
               masked_example=None, tool_name="mcp__github__x",
               protection="blocked")


def _publish_snapshot(data_dir, session_id):
    """Stand in for the daemon (Task 4): turn `session_id`'s current ledger
    row into contract A's snapshot file (`hud_snapshot.py`), the same way
    `daemon.py` does on every ledger change. `ambient` now reads only that
    file, never the ledger, so a test that builds ledger state directly has
    no daemon to publish it and must do this itself. Returns the summary that
    was published, for assertions."""
    led = _ledger(data_dir)
    summary = led.summary(session_id)
    coverage = led.coverage(session_id)
    led.conn.close()
    hs.HudPublisher(data_dir).publish(
        session_id, percent=summary.legacy_percent, blocked=summary.legacy_prevented_rows,
        unverified=not coverage.verified)
    return summary


def _seed(data_dir, session_id="s1", *, exposures=1, prevented=0,
          started_at=None) -> dict:
    """Create a ledger with known contents, publish the matching snapshot
    (see `_publish_snapshot`), and return that session's summary."""
    led = _ledger(data_dir)
    led.start_session(session_id, cwd="/repo", model="gpt-5")
    if started_at is not None:
        # `start_session` stamps `int(time.time())`, so two sessions created in
        # the same second tie under `ORDER BY started_at DESC`. Pinning the
        # timestamps is what makes "most recently started" deterministic.
        led.conn.execute("UPDATE sessions SET started_at=? WHERE session_id=?",
                          (started_at, session_id))
    for i in range(exposures):
        _expose(led, session_id, bytes([i + 1]) * 16)
    for i in range(prevented):
        _prevent(led, session_id, bytes([100 + i]) * 16)
    led.conn.close()
    return _publish_snapshot(data_dir, session_id)


# --------------------------------------------------------------------- #
# --once: the rendered line
# --------------------------------------------------------------------- #

def test_once_prints_exactly_what_render_would_produce(data_dir, capsys):
    summary = _seed(data_dir, exposures=2, prevented=3)

    assert ambient.main(["--once"]) == 0

    out = capsys.readouterr().out
    assert out == hud_line(summary.legacy_percent, 80, summary.legacy_prevented_rows) + "\n"


def test_no_flags_behaves_as_once(data_dir, capsys):
    summary = _seed(data_dir, exposures=2, prevented=3)

    assert ambient.main([]) == 0

    out = capsys.readouterr().out
    assert out == hud_line(summary.legacy_percent, 80, summary.legacy_prevented_rows) + "\n"


def test_prevented_count_is_the_blocked_input(data_dir, capsys):
    _seed(data_dir, exposures=1, prevented=2)

    ambient.main(["--once"])

    # design.md §4's "Active block" state: `⚠ N blocked · ...`.
    assert "⚠ 2 blocked" in capsys.readouterr().out


def test_clean_session_renders_zero_percent(data_dir, capsys):
    _seed(data_dir, exposures=0)

    ambient.main(["--once"])

    out = capsys.readouterr().out
    assert "0%" in out
    assert "█" not in out


def test_line_carries_no_session_content(data_dir, capsys):
    # I1: a percentage and a bar. Never a session id, a source path, or a
    # masked exemplar — none of which belong on an ambient glance surface.
    _seed(data_dir, "session-abc123", exposures=1, prevented=1)

    ambient.main(["--once"])

    out = capsys.readouterr().out
    assert "session-abc123" not in out
    assert "support.log" not in out
    assert "acme.com" not in out


def test_no_forbidden_copy_on_any_path(data_dir, capsys):
    # I5 / design.md §9, applied to both the rendered line and the
    # nothing-to-show notice.
    _seed(data_dir, exposures=1, prevented=1)
    ambient.main(["--once"])
    rendered = capsys.readouterr()

    (data_dir / "ledger.db").unlink()
    ambient.main(["--once"])
    disabled = capsys.readouterr()

    for text in (rendered.out, rendered.err, disabled.out, disabled.err):
        for word in BANNED:
            assert word not in text.lower()


# --------------------------------------------------------------------- #
# Session resolution
# --------------------------------------------------------------------- #

def test_falls_back_to_the_most_recently_started_session_with_no_daemon(
        data_dir, capsys):
    # The bug this guards: a stray session (a test run, an earlier pane)
    # shadowing the user's real one. With no daemon to ask, "most recently
    # started" is still the honest answer and `resolve_audit_session` returns
    # it — the same line this surface has always drawn.
    _seed(data_dir, "older", exposures=4, started_at=1_000)
    newer = _seed(data_dir, "newer", exposures=1, started_at=2_000)

    ambient.main(["--once"])

    out = capsys.readouterr().out
    assert out == hud_line(newer.legacy_percent, 80, newer.legacy_prevented_rows) + "\n"


def test_session_id_override_is_honored(data_dir, capsys):
    older = _seed(data_dir, "older", exposures=4, started_at=1_000)
    _seed(data_dir, "newer", exposures=1, started_at=2_000)

    ambient.main(["--session-id", "older", "--once"])

    out = capsys.readouterr().out
    assert out == hud_line(older.legacy_percent, 80, older.legacy_prevented_rows) + "\n"
    # And it is genuinely a different line than the default resolution.
    assert older.legacy_percent != 0


def test_the_daemons_live_session_beats_the_most_recently_started_one(
        data_dir, capsys, daemon_says):
    """The self-contradiction this closes.

    `$privacy` has resolved through `mcp_tools.resolve_audit_session` since the
    two-windows bug was fixed; this pane was still calling
    `local_ui_server._latest_session_id`. On one machine that is an ambient
    line and an audit naming *different* sessions — worse than the original
    bug, because two surfaces that disagree teach the user to trust neither.
    """
    older = _seed(data_dir, "older", exposures=4, started_at=1_000)
    newer = _seed(data_dir, "newer", exposures=1, started_at=2_000)
    daemon_says([{"session_id": "older", "age": 0.02}])

    ambient.main(["--once"])

    out = capsys.readouterr().out
    assert out == hud_line(older.legacy_percent, 80, older.legacy_prevented_rows) + "\n"
    assert out != hud_line(newer.legacy_percent, 80, newer.legacy_prevented_rows) + "\n"


def test_the_pane_and_the_audit_name_the_same_session(data_dir, capsys,
                                                      daemon_says):
    """Stated as one assertion rather than two, because agreement between the
    two surfaces IS the property — not each one's answer on its own."""
    _seed(data_dir, "older", exposures=4, started_at=1_000)
    _seed(data_dir, "newer", exposures=1, started_at=2_000)
    daemon_says([{"session_id": "older", "age": 0.02}])

    led = _ledger(data_dir)
    audited = mcp_tools.resolve_audit_session(led, data_dir).session_id
    led.conn.close()

    assert ambient._SessionPin().current() == audited == "older"


def test_an_explicit_pin_never_asks_the_daemon(data_dir, capsys, daemon_says):
    """`--session-id` is an answer, not a question. It must keep working with
    no daemon, and must not be overridden by one that disagrees."""
    older = _seed(data_dir, "older", exposures=4, started_at=1_000)
    _seed(data_dir, "newer", exposures=1, started_at=2_000)
    asked = daemon_says([{"session_id": "newer", "age": 0.01}])

    ambient.main(["--session-id", "older", "--once"])

    out = capsys.readouterr().out
    assert out == hud_line(older.legacy_percent, 80, older.legacy_prevented_rows) + "\n"
    assert asked == []


def test_unknown_session_id_renders_nothing(data_dir, capsys, no_hud_line):
    # A well-formed zero for a session we have never heard of would be a
    # reassuring number we cannot back (CLAUDE.md §5).
    _seed(data_dir, "s1", exposures=2)

    assert ambient.main(["--session-id", "typo", "--once"]) == 0
    assert capsys.readouterr().out == ""
    assert no_hud_line == []


# --------------------------------------------------------------------- #
# The "Disabled" state: every failure degrades to silence, exit 0
# --------------------------------------------------------------------- #

def test_missing_data_dir_renders_nothing(tmp_path, monkeypatch, capsys,
                                          no_hud_line):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path / "never-provisioned"))
    monkeypatch.setenv("COLUMNS", "80")

    assert ambient.main(["--once"]) == 0
    assert capsys.readouterr().out == ""
    assert no_hud_line == []


def test_missing_ledger_file_renders_nothing(data_dir, capsys, no_hud_line):
    assert not (data_dir / "ledger.db").exists()

    assert ambient.main(["--once"]) == 0
    assert capsys.readouterr().out == ""
    assert no_hud_line == []


def test_polling_never_creates_a_ledger(data_dir):
    # sqlite3.connect() creates missing files; a glance-only surface must not
    # leave an empty ledger.db behind wherever PLUGIN_DATA happens to point.
    ambient.main(["--once"])

    assert not (data_dir / "ledger.db").exists()


def test_ledger_with_zero_sessions_renders_nothing(data_dir, capsys,
                                                   no_hud_line):
    _ledger(data_dir).conn.close()  # schema, but nothing recorded yet

    assert ambient.main(["--once"]) == 0
    assert capsys.readouterr().out == ""
    assert no_hud_line == []


def test_corrupt_database_renders_nothing(data_dir, capsys, no_hud_line):
    (data_dir / "ledger.db").write_bytes(b"this is not a sqlite database")

    assert ambient.main(["--once"]) == 0
    assert capsys.readouterr().out == ""
    assert no_hud_line == []


def test_out_of_range_percent_renders_nothing_rather_than_a_wrong_number(
        data_dir, capsys, no_hud_line):
    # A corrupt snapshot -- e.g. a percent outside 0..100, from a future or
    # buggy writer -- must render nothing rather than a clamped, plausible-
    # looking bar. `read_snapshot` is what enforces this now (hud_snapshot.py):
    # `_line_for` never sees the bad value to clamp or guess at.
    _seed(data_dir, "s1", exposures=1)
    p = hs.snapshot_path(data_dir, "s1")
    doc = json.loads(p.read_text())
    doc["percent"] = 150
    p.write_text(json.dumps(doc))

    assert ambient.main(["--once"]) == 0
    assert capsys.readouterr().out == ""
    assert no_hud_line == []


def test_a_raising_data_dir_degrades_quietly(data_dir, monkeypatch, capsys):
    def _boom():
        raise OSError("data dir unreadable")

    monkeypatch.setattr(ambient, "resolve_data_dir", _boom)

    assert ambient.main(["--once"]) == 0
    assert capsys.readouterr().out == ""


def test_disabled_notice_goes_to_stderr_not_stdout(data_dir, capsys):
    # stdout stays byte-clean so `--once` composes into a prompt or another
    # status bar; the human who typed the command still gets an answer.
    ambient.main(["--once"])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() != ""


# --------------------------------------------------------------------- #
# Width degradation
# --------------------------------------------------------------------- #

@pytest.mark.parametrize("columns", [80, 52, 51, 40, 39, 28, 27, 12])
def test_line_never_exceeds_the_terminal_width(data_dir, monkeypatch, capsys,
                                               columns):
    summary = _seed(data_dir, exposures=3, prevented=1)
    monkeypatch.setenv("COLUMNS", str(columns))

    ambient.main(["--once"])

    line = capsys.readouterr().out.rstrip("\n")
    assert len(line) <= columns
    assert line == hud_line(summary.legacy_percent, columns, summary.legacy_prevented_rows)


def test_narrow_terminal_degrades_to_the_dot_form(data_dir, monkeypatch,
                                                  capsys):
    _seed(data_dir, exposures=3)
    monkeypatch.setenv("COLUMNS", "20")

    ambient.main(["--once"])

    line = capsys.readouterr().out.rstrip("\n")
    assert line.startswith("⬤")
    assert len(line) <= 20


# --------------------------------------------------------------------- #
# --watch
# --------------------------------------------------------------------- #

def _stub_sleep(monkeypatch, iterations: int):
    """Let the watch loop run `iterations` frames, then Ctrl-C it.

    Bounding the loop through `time.sleep` rather than through a test-only
    parameter keeps the production code free of test hooks and exercises the
    real KeyboardInterrupt exit path at the same time. Nothing sleeps for real.
    """
    calls = []

    def _fake(seconds):
        calls.append(seconds)
        if len(calls) >= iterations:
            raise KeyboardInterrupt
    monkeypatch.setattr(ambient.time, "sleep", _fake)
    return calls


def test_watch_redraws_in_place_and_exits_zero_on_ctrl_c(data_dir, monkeypatch,
                                                         capsys):
    summary = _seed(data_dir, exposures=2, prevented=1)
    calls = _stub_sleep(monkeypatch, 3)

    assert ambient.main(["--watch"]) == 0

    out = capsys.readouterr().out
    line = hud_line(summary.legacy_percent, 80, summary.legacy_prevented_rows)
    # Three frames, each preceded by carriage-return + erase-to-end-of-line, so
    # the pane holds one line instead of scrolling a log.
    assert out == ("\r\x1b[K" + line) * 3 + "\n"
    assert calls == [ambient.DEFAULT_INTERVAL] * 3


def test_watch_default_interval_is_two_seconds(data_dir, monkeypatch, capsys):
    _seed(data_dir, exposures=1)
    calls = _stub_sleep(monkeypatch, 1)

    ambient.main(["--watch"])
    capsys.readouterr()

    assert calls == [2.0]


def test_watch_accepts_an_explicit_interval(data_dir, monkeypatch, capsys):
    _seed(data_dir, exposures=1)
    calls = _stub_sleep(monkeypatch, 2)

    ambient.main(["--watch", "5"])
    capsys.readouterr()

    assert calls == [5.0, 5.0]


def test_watch_interval_is_floored(data_dir, monkeypatch, capsys):
    # `--watch 0` would otherwise busy-wait on the same disk the daemon writes.
    _seed(data_dir, exposures=1)
    calls = _stub_sleep(monkeypatch, 1)

    ambient.main(["--watch", "0"])
    capsys.readouterr()

    assert calls == [ambient.MIN_INTERVAL]


def test_watch_honors_the_session_id_override(data_dir, monkeypatch, capsys):
    older = _seed(data_dir, "older", exposures=4, started_at=1_000)
    _seed(data_dir, "newer", exposures=1, started_at=2_000)
    _stub_sleep(monkeypatch, 1)

    ambient.main(["--watch", "--session-id", "older"])

    out = capsys.readouterr().out
    assert out == "\r\x1b[K" + hud_line(older.legacy_percent, 80,
                                        older.legacy_prevented_rows) + "\n"


def test_watch_clears_the_line_when_there_is_nothing_to_show(
        data_dir, monkeypatch, capsys, no_hud_line):
    # A HUD that was showing a percentage must blank rather than freeze on a
    # stale number, and must not print the stderr notice on every frame.
    _stub_sleep(monkeypatch, 2)

    assert ambient.main(["--watch"]) == 0

    captured = capsys.readouterr()
    assert captured.out == "\r\x1b[K\r\x1b[K\n"
    assert captured.err == ""
    assert no_hud_line == []


def test_watch_leaves_the_cursor_on_a_fresh_line(data_dir, monkeypatch,
                                                 capsys):
    # Every frame ends mid-line by design; Ctrl-C owes the shell a newline.
    _seed(data_dir, exposures=1)
    _stub_sleep(monkeypatch, 1)

    ambient.main(["--watch"])

    assert capsys.readouterr().out.endswith("\n")


# --------------------------------------------------------------------- #
# Resolution cadence: often enough to follow a new session, rarely enough
# that the pane means one thing at a time and the hook socket stays quiet.
# --------------------------------------------------------------------- #

def test_watch_resolves_once_not_once_per_redraw(data_dir, monkeypatch,
                                                 capsys, daemon_says):
    """The load half of `_SessionPin`'s argument. The daemon's socket is the
    hook hot path; a two-second redraw loop must not be on it."""
    _seed(data_dir, "s1", exposures=1)
    asked = daemon_says([{"session_id": "s1", "age": 0.01}])
    _stub_sleep(monkeypatch, 5)

    ambient.main(["--watch"])
    capsys.readouterr()

    assert len(asked) == 1


def test_watch_does_not_hop_between_sessions_between_redraws(
        data_dir, monkeypatch, capsys, daemon_says):
    """The other half, and the one a user would actually see. Two busy windows
    change which session is "most recently active" every few seconds; a pane
    resolved per frame would flip between their numbers mid-glance."""
    first = _seed(data_dir, "s1", exposures=1, started_at=1_000)
    _seed(data_dir, "s2", exposures=4, started_at=2_000)
    live = [{"session_id": "s1", "age": 0.01}]

    def _fake(data_dir_arg):
        answer = list(live)
        live[:] = [{"session_id": "s2", "age": 0.01}]  # the other window acts
        return answer
    monkeypatch.setattr(mcp_tools, "_ask_daemon", _fake)
    _stub_sleep(monkeypatch, 3)

    ambient.main(["--watch"])

    line = hud_line(first.legacy_percent, 80, first.legacy_prevented_rows)
    assert capsys.readouterr().out == ("\r\x1b[K" + line) * 3 + "\n"


def test_the_pin_re_resolves_after_the_interval(data_dir, daemon_says):
    """Pinning forever would freeze the pane on a session that ended hours
    ago — the stale-number failure `run_watch` blanks the line to avoid."""
    _seed(data_dir, "s1", exposures=1)
    asked = daemon_says([{"session_id": "s1", "age": 0.01}])

    pin = ambient._SessionPin(interval=0.0)
    assert pin.current() == "s1"
    assert pin.current() == "s1"

    assert len(asked) == 2


def test_no_session_yet_is_not_cached(data_dir, daemon_says):
    """A pane started before Codex must pick the session up on the next
    redraw, not `RESOLVE_INTERVAL` seconds later."""
    _ledger(data_dir).conn.close()  # schema, no sessions
    daemon_says(None)

    pin = ambient._SessionPin()
    assert pin.current() is None

    _seed(data_dir, "s1", exposures=1)
    assert pin.current() == "s1"


def test_resolution_failure_is_silence_not_a_traceback(data_dir, monkeypatch,
                                                       capsys):
    """I6's spirit reaches the new code path too: this runs unattended in a
    pane beside a live session, and every failure there is silence."""
    _seed(data_dir, "s1", exposures=1)

    def _boom(ledger, data_dir_arg, **kwargs):
        raise RuntimeError("resolution exploded")
    monkeypatch.setattr(mcp_tools, "resolve_audit_session", _boom)

    assert ambient.main(["--once"]) == 0
    assert capsys.readouterr().out == ""


# --------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------- #

def test_main_returns_an_int_exit_code_for_help(capsys):
    # The console script (`privacy-hud-ambient = privacy_hud.ambient:main`)
    # needs main to return, not raise SystemExit through itself.
    assert ambient.main(["--help"]) == 0
    assert "privacy-hud-ambient" in capsys.readouterr().out


def test_once_and_watch_are_mutually_exclusive(capsys):
    assert ambient.main(["--once", "--watch"]) == 2


# --------------------------------------------------------------------- #
# The third state: `⚠unverified` (design.md §4's "Engine degraded").
#
# "Disabled" (nothing rendered) and a real reading were never the whole space.
# The state that was missing is the one where a line IS drawn and says the
# figure on it is not a complete account — because `0%` meaning "nothing was
# disclosed" and `0%` meaning "nothing was recorded" must not look the same.
# --------------------------------------------------------------------- #

def test_a_clean_session_carries_no_unverified_marker(data_dir, capsys):
    _seed(data_dir, exposures=1)

    ambient.main(["--once"])

    assert "unverified" not in capsys.readouterr().out


def test_a_session_observed_late_is_marked_unverified(data_dir, capsys):
    """The daemon's first sight of this session was a mid-session event, so the
    ledger has no account of what came before. The line still draws — silence
    would hide the gap as effectively as a clean 0% did."""
    led = _ledger(data_dir)
    led.start_session("late", cwd="/repo", model="gpt-5", observed_start=False)
    led.conn.close()
    _publish_snapshot(data_dir, "late")

    ambient.main(["--once"])

    out = capsys.readouterr().out
    assert "⚠unverified" in out
    assert out == hud_line(0, 80, 0, unverified=True) + "\n"


def test_the_newest_session_is_unverified_when_hooks_were_dropped_after_it(
        data_dir, capsys):
    """The reproduced incident. A short session ran while no daemon was
    listening and left no row at all; the newest row in the ledger is the
    session BEFORE it, and showing that row's clean number as the current
    reading is the lie this fixes."""
    led = _ledger(data_dir)
    led.start_session("earlier", cwd="/repo", model="gpt-5")
    led.end_session("earlier")
    started = led.conn.execute(
        "SELECT started_at FROM sessions WHERE session_id='earlier'"
    ).fetchone()[0]
    led.note_unobserved_hooks(started + 60)
    led.conn.close()
    _publish_snapshot(data_dir, "earlier")

    ambient.main(["--once"])

    assert "⚠unverified" in capsys.readouterr().out


def test_a_ledger_holding_only_a_recorded_gap_still_says_something(
        data_dir, capsys):
    """Zero sessions plus a recorded gap is not an idle install — it is an
    install that watched hook events go by and recorded none of them. Rendering
    nothing here is exactly how the incident stayed invisible.

    The daemon is what turns `Ledger.unattributed_gaps()` into the
    `_daemon.json` marker `ambient` now reads (`hud_snapshot.read_daemon_
    marker`); this test has no daemon, so it writes the marker directly."""
    led = _ledger(data_dir)
    led.note_unobserved_hooks(1_757_000_000)
    led.conn.close()
    hs.HudPublisher(data_dir).mark_daemon(unattributed_gaps=True)

    assert ambient.main(["--once"]) == 0

    out = capsys.readouterr().out
    assert out == hud_line(0, 80, 0, unverified=True) + "\n"


def test_a_ledger_with_no_sessions_and_no_gap_still_renders_nothing(
        data_dir, capsys, no_hud_line):
    """The other half of the pair above: an untouched ledger is still
    "Disabled". A caveat that fires on an idle install is a caveat that gets
    trained away."""
    _ledger(data_dir).conn.close()

    assert ambient.main(["--once"]) == 0
    assert capsys.readouterr().out == ""
    assert no_hud_line == []


@pytest.mark.parametrize("columns", [80, 52, 51, 40, 39, 28, 27, 12])
def test_the_unverified_line_also_respects_the_width_ladder(
        data_dir, monkeypatch, capsys, columns):
    monkeypatch.setenv("COLUMNS", str(columns))
    led = _ledger(data_dir)
    led.start_session("late", cwd="/repo", model="gpt-5", observed_start=False)
    led.conn.close()
    _publish_snapshot(data_dir, "late")

    ambient.main(["--once"])

    line = capsys.readouterr().out.rstrip("\n")
    assert len(line) <= columns
    assert "⚠" in line


def test_unverified_copy_is_still_free_of_forbidden_words(data_dir, capsys):
    led = _ledger(data_dir)
    led.start_session("late", cwd="/repo", model="gpt-5", observed_start=False)
    led.conn.close()
    _publish_snapshot(data_dir, "late")

    ambient.main(["--once"])
    captured = capsys.readouterr()

    for text in (captured.out, captured.err):
        for word in BANNED:
            assert word not in text.lower()


# --------------------------------------------------------------------- #
# Contract A: `_line_for` reads the HUD snapshot file, never sqlite.
# --------------------------------------------------------------------- #

def test_line_is_hud_line_of_the_snapshot(data_dir, monkeypatch):
    hs.HudPublisher(data_dir).publish("s1", percent=28, blocked=2, unverified=False)
    monkeypatch.setattr(ambient, "_resolve_session_id", lambda: "s1")
    assert ambient.safe_line(width=80) == hud_line(28, 80, 2)


def test_unverified_flag_reaches_the_line(data_dir, monkeypatch):
    hs.HudPublisher(data_dir).publish("s1", percent=0, blocked=0, unverified=True)
    monkeypatch.setattr(ambient, "_resolve_session_id", lambda: "s1")
    assert ambient.safe_line(width=80) == hud_line(0, 80, 0, unverified=True)


def test_hidden_snapshot_renders_nothing(data_dir, monkeypatch, no_hud_line):
    pub = hs.HudPublisher(data_dir)
    pub.publish("s1", percent=28, blocked=0, unverified=False)
    pub.set_hidden("s1", True)
    monkeypatch.setattr(ambient, "_resolve_session_id", lambda: "s1")
    assert ambient.safe_line(width=80) is None


def test_stale_snapshot_renders_nothing(data_dir, monkeypatch, no_hud_line):
    hs.HudPublisher(data_dir).publish("s1", percent=28, blocked=0, unverified=False)
    p = hs.snapshot_path(data_dir, "s1")
    doc = json.loads(p.read_text()); doc["updated_at"] -= 60; p.write_text(json.dumps(doc))
    monkeypatch.setattr(ambient, "_resolve_session_id", lambda: "s1")
    assert ambient.safe_line(width=80) is None


def test_no_session_but_daemon_reports_gaps_renders_unverified_zero(data_dir, monkeypatch):
    hs.HudPublisher(data_dir).mark_daemon(unattributed_gaps=True)
    monkeypatch.setattr(ambient, "_resolve_session_id", lambda: None)
    assert ambient.safe_line(width=80) == hud_line(0, 80, 0, unverified=True)


def test_no_session_and_no_gaps_renders_nothing(data_dir, monkeypatch, no_hud_line):
    hs.HudPublisher(data_dir).mark_daemon(unattributed_gaps=False)
    monkeypatch.setattr(ambient, "_resolve_session_id", lambda: None)
    assert ambient.safe_line(width=80) is None


def test_ambient_never_opens_sqlite(data_dir, monkeypatch):
    import sqlite3
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: (_ for _ in ()).throw(AssertionError("sqlite opened")))
    hs.HudPublisher(data_dir).publish("s1", percent=1, blocked=0, unverified=False)
    monkeypatch.setattr(ambient, "_resolve_session_id", lambda: "s1")
    assert ambient.safe_line(width=80) == hud_line(1, 80, 0)
