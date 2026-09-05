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

import pytest

from privacy_hud import ambient
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


def _seed(data_dir, session_id="s1", *, exposures=1, prevented=0,
          started_at=None) -> dict:
    """Create a ledger with known contents; return that session's summary."""
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
    summary = led.summary(session_id)
    led.conn.close()
    return summary


# --------------------------------------------------------------------- #
# --once: the rendered line
# --------------------------------------------------------------------- #

def test_once_prints_exactly_what_render_would_produce(data_dir, capsys):
    summary = _seed(data_dir, exposures=2, prevented=3)

    assert ambient.main(["--once"]) == 0

    out = capsys.readouterr().out
    assert out == hud_line(summary.percent, 80, summary.prevented) + "\n"


def test_no_flags_behaves_as_once(data_dir, capsys):
    summary = _seed(data_dir, exposures=2, prevented=3)

    assert ambient.main([]) == 0

    out = capsys.readouterr().out
    assert out == hud_line(summary.percent, 80, summary.prevented) + "\n"


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

def test_defaults_to_the_most_recently_started_session(data_dir, capsys):
    # The bug this guards: a stray session (a test run, an earlier pane)
    # shadowing the user's real one. Resolution lives in exactly one place
    # (`local_ui_server._latest_session_id`); this asserts ambient uses it.
    _seed(data_dir, "older", exposures=4, started_at=1_000)
    newer = _seed(data_dir, "newer", exposures=1, started_at=2_000)

    ambient.main(["--once"])

    out = capsys.readouterr().out
    assert out == hud_line(newer.percent, 80, newer.prevented) + "\n"


def test_session_id_override_is_honored(data_dir, capsys):
    older = _seed(data_dir, "older", exposures=4, started_at=1_000)
    _seed(data_dir, "newer", exposures=1, started_at=2_000)

    ambient.main(["--session-id", "older", "--once"])

    out = capsys.readouterr().out
    assert out == hud_line(older.percent, 80, older.prevented) + "\n"
    # And it is genuinely a different line than the default resolution.
    assert older.percent != 0


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
        data_dir, capsys):
    # A corrupt score puts the percent outside every band; `hud_line`'s
    # `_check_band` fails loud on that by design. The HUD must swallow the
    # failure into silence — never clamp it into a plausible-looking bar.
    _seed(data_dir, "s1", exposures=1)
    led = _ledger(data_dir)
    led.conn.execute("UPDATE sessions SET budget_score=-50 WHERE session_id='s1'")
    led.conn.close()

    assert ambient.main(["--once"]) == 0
    assert capsys.readouterr().out == ""


def test_a_raising_ledger_path_degrades_quietly(data_dir, monkeypatch, capsys):
    def _boom():
        raise OSError("data dir unreadable")

    monkeypatch.setattr(ambient, "_ledger_path", _boom)

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
    assert line == hud_line(summary.percent, columns, summary.prevented)


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
    line = hud_line(summary.percent, 80, summary.prevented)
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
    assert out == "\r\x1b[K" + hud_line(older.percent, 80,
                                        older.prevented) + "\n"


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
# CLI surface
# --------------------------------------------------------------------- #

def test_main_returns_an_int_exit_code_for_help(capsys):
    # The console script (`privacy-hud-ambient = privacy_hud.ambient:main`)
    # needs main to return, not raise SystemExit through itself.
    assert ambient.main(["--help"]) == 0
    assert "privacy-hud-ambient" in capsys.readouterr().out


def test_once_and_watch_are_mutually_exclusive(capsys):
    assert ambient.main(["--once", "--watch"]) == 2
