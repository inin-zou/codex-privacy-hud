# tests/test_codex_integration.py
"""Acceptance test for the patched Codex status line (spec §4.1, Task 8/9).

Everything else in this suite tests one side of contract A: the Python writer
(`test_hud_snapshot.py`), the golden rendering (`tests/matrix/hud_golden.json`)
and the Rust reader (the patch's own `#[cfg(test)]` module). None of them can
answer the question the patch exists for -- *does the item actually appear in
a running Codex TUI, keyed by the id that Codex calls the thread id?* Spec
§4.1 assumes the hook's `session_id` and the TUI's thread id are the same
string; if they ever diverge the item silently shows nothing, and every unit
test still passes. So this test drives a real patched binary through a
pseudo-terminal:

    boot the TUI -> read the thread id off its own status line
                 -> HudPublisher.publish(that id, ...)
                 -> assert `Privacy ███░░░░░░░ 28% ⚠2` appears
                 -> HudPublisher.set_hidden(that id, True)
                 -> assert the line repaints without the item

It never submits a prompt, so no model call is made, no hook fires and
nothing is billed. It needs credentials only because Codex refuses to start
its TUI without them.

Marked `slow` and skipped unless a patched binary is pointed at explicitly:

    PRIVACY_HUD_CODEX_BIN=dist/codex python3 -m pytest tests/test_codex_integration.py

The pty mechanics (window size, the two boot prompts, the ANSI shapes Codex
emits) were established against a stock 0.153.0 build before this test was
written; the comments below record why each of them is here.
"""
from __future__ import annotations

import fcntl
import os
import pty
import re
import select
import shutil
import signal
import struct
import sys
import termios
import time
from pathlib import Path

import pytest

from privacy_hud.hud_snapshot import HudPublisher

#: A patched `codex` binary -- `scripts/build-patched-codex.sh 0.154.0`.
CODEX_BIN = os.environ.get("PRIVACY_HUD_CODEX_BIN", "")
#: Codex will not reach its TUI without credentials, and this test has no way
#: to mint them. The real file is copied into a throwaway CODEX_HOME so the
#: run cannot touch the user's own Codex state.
REAL_AUTH = Path.home() / ".codex" / "auth.json"

ROWS, COLS = 40, 120
#: Cloning a fresh CODEX_HOME, the update check and the first paint.
BOOT_TIMEOUT = 30.0
#: The item re-reads the snapshot once per second (`READ_INTERVAL`).
ITEM_TIMEOUT = 5.0
#: Long enough to be sure every frame painted before a change has been read.
SETTLE = 1.5

#: CSI (including `ESC[0 q`, which carries an intermediate space), OSC, charset
#: selection and keypad-mode escapes. Codex emits all four; leaving any of them
#: in would break up the very text we match on.
ANSI = re.compile(
    rb"\x1b\[[0-9;?]*[ ]?[A-Za-z@]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|\x1b[=>]"
)
UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
#: What the patch renders for percent=28, blocked=2, unverified=False.
EXPECTED = "Privacy ███░░░░░░░ 28% ⚠2"


def _skip_reason() -> str | None:
    if sys.platform == "win32":
        return "no pty on Windows"
    if not CODEX_BIN:
        return ("PRIVACY_HUD_CODEX_BIN is unset: point it at a patched codex "
                "binary (scripts/build-patched-codex.sh <ver>)")
    if not (os.path.isfile(CODEX_BIN) and os.access(CODEX_BIN, os.X_OK)):
        return f"PRIVACY_HUD_CODEX_BIN={CODEX_BIN!r} is not an executable file"
    if not REAL_AUTH.is_file():
        return (f"{REAL_AUTH} not found: Codex needs credentials to start its "
                "TUI, even with no prompt")
    return None


_SKIP = _skip_reason()
pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(_SKIP is not None, reason=_SKIP or ""),
]


def _config_toml(workdir: Path) -> str:
    """A CODEX_HOME config that puts the item on the status line and keeps the
    boot path prompt-free. Both spellings of the working directory are trusted
    because macOS hands out `/var/...` temp paths that resolve to
    `/private/var/...`, and Codex keys the trust table by the resolved one."""
    paths = {str(workdir), os.path.realpath(workdir)}
    projects = "".join(
        f'\n[projects."{path}"]\ntrust_level = "trusted"\n' for path in sorted(paths)
    )
    return (
        'model = "gpt-5.4"\n'
        "\n[tui]\n"
        'status_line = ["session-id", "privacy"]\n'
        + projects
    )


class Tui:
    """A Codex process on the far end of a pseudo-terminal.

    Everything read is appended to one buffer and matched with the escape
    sequences stripped, so a match means "this was painted at some point",
    not "this is on screen now" -- which is what we want, since a repaint can
    overwrite the evidence between two reads.
    """

    def __init__(self, argv: list[str], *, cwd: str, env: dict) -> None:
        self.buf = b""
        self._answered: set[str] = set()
        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # pragma: no cover - the child never returns
            try:
                os.chdir(cwd)
                os.execvpe(argv[0], argv, env)
            except BaseException:
                pass
            os._exit(127)
        # Codex lays out against the terminal size, and the default pty is
        # 0x0: without this the status line is never drawn at all.
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", ROWS, COLS, 0, 0))
        except OSError:
            self.close()
            raise

    # -- reading -----------------------------------------------------------

    def text(self) -> str:
        return ANSI.sub(b"", self.buf).decode("utf-8", "replace")

    def clear(self) -> None:
        self.buf = b""

    def _read_once(self, timeout: float) -> bool:
        """One select+read. False on EOF or error, True otherwise (including
        a timeout with nothing to read)."""
        try:
            ready, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
        except (OSError, ValueError):
            return False
        if not ready:
            return True
        try:
            chunk = os.read(self.fd, 65536)
        except OSError:
            return False
        if not chunk:
            return False
        self.buf += chunk
        self._answer_prompts()
        return True

    def read_until(self, predicate, timeout: float) -> str | None:
        """The accumulated text once `predicate` accepts it, else None."""
        deadline = time.monotonic() + timeout
        while True:
            text = self.text()
            if predicate(text):
                return text
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            if not self._read_once(min(0.25, remaining)):
                return None

    def drain(self, seconds: float) -> None:
        """Read and discard nothing -- just let pending frames arrive, so a
        later `clear()` really does drop everything painted before now."""
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._read_once(min(0.25, remaining)):
                return

    # -- the two prompts a first run can hit -------------------------------

    def _write(self, data: bytes) -> None:
        try:
            os.write(self.fd, data)
        except OSError:
            pass

    def _answer(self, key: bytes) -> None:
        # A keypress delivered before the prompt has finished painting is
        # dropped, and Enter sent in the same write as the choice sometimes
        # races the selection; the pauses are what made this reliable.
        time.sleep(0.5)
        self._write(key)
        time.sleep(0.3)
        self._write(b"\r")

    def _answer_prompts(self) -> None:
        text = self.text()
        if "Update now" in text and "update" not in self._answered:
            self._answered.add("update")
            self._answer(b"2")  # "Skip"
        if "trust the contents" in text and "trust" not in self._answered:
            # config.toml normally pre-empts this; kept as a belt-and-braces
            # answer in case the resolved cwd is spelled differently again.
            self._answered.add("trust")
            self._answer(b"1")  # "Yes, allow Codex to work in this folder"

    # -- teardown ----------------------------------------------------------

    def _reap(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            try:
                pid, _ = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                return True
            if pid == self.pid:
                return True
            if time.monotonic() >= deadline:
                return False
            # Keep draining: a child blocked writing into a full pty buffer
            # would never see the signal.
            self._read_once(0.1)

    def close(self) -> None:
        """Always safe to call, and safe to call twice."""
        try:
            for _ in range(2):
                self._write(b"\x03")
                time.sleep(0.5)
            if not self._reap(2.0):
                for sig in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.kill(self.pid, sig)
                    except ProcessLookupError:
                        break
                    if self._reap(2.0):
                        break
        finally:
            try:
                os.close(self.fd)
            except OSError:
                pass


@pytest.fixture
def codex_tui(tmp_path):
    """A patched Codex booted in a throwaway CODEX_HOME and cwd, with its own
    PRIVACY_HUD_DATA. Nothing outside `tmp_path` is written; Codex is free to
    drop whatever else it likes (nux flags, history, logs) into its home."""
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    data_dir = tmp_path / "hud-data"
    data_dir.mkdir()

    # These are the user's real credentials. `copyfile` + `chmod` creates the
    # file with the process umask first -- typically 0644 -- and narrows it
    # afterwards, so there is a window in which anyone on the machine can read
    # it. Create it 0600 from the first syscall instead, and O_EXCL so a
    # pre-existing file (a symlink somebody planted in a shared tmpdir) is an
    # error rather than a write-through.
    auth = codex_home / "auth.json"
    fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(REAL_AUTH.read_bytes())
    (codex_home / "config.toml").write_text(_config_toml(work), encoding="utf-8")

    env = dict(
        os.environ,
        CODEX_HOME=str(codex_home),
        PRIVACY_HUD_DATA=str(data_dir),
        TERM="xterm-256color",
        COLUMNS=str(COLS),
        LINES=str(ROWS),
    )

    tui = Tui([CODEX_BIN], cwd=str(work), env=env)
    try:
        yield tui, data_dir
    finally:
        tui.close()
        # pytest keeps the last three tmp_path trees, so without this the
        # user's real credentials would sit in /tmp for three more runs.
        # The explicit unlink first: even if rmtree trips over something
        # Codex left behind, the copy of auth.json is gone.
        auth.unlink(missing_ok=True)
        shutil.rmtree(codex_home, ignore_errors=True)


def _tail(tui: Tui, n: int = 1200) -> str:
    return "\n---- last screen text ----\n" + tui.text()[-n:]


def test_patched_status_line_follows_the_snapshot(codex_tui):
    tui, data_dir = codex_tui

    # 1. Boot, and take the thread id off Codex's own `session-id` item. This
    #    is the spec §4.1 assumption under test: the daemon writes its
    #    snapshot under the hook's session_id, and the item looks it up under
    #    the TUI's thread id.
    booted = tui.read_until(
        lambda t: "Ask Codex" in t and UUID.search(t) is not None, BOOT_TIMEOUT
    )
    assert booted is not None, f"codex never reached its prompt{_tail(tui)}"
    thread_id = UUID.search(booted).group(0)

    # 2. Publish a reading for that id; the item must pick it up within one
    #    READ_INTERVAL.
    publisher = HudPublisher(data_dir)
    tui.clear()
    publisher.publish(thread_id, percent=28, blocked=2, unverified=False)
    shown = tui.read_until(lambda t: EXPECTED in t, ITEM_TIMEOUT)
    assert shown is not None, (
        f"{EXPECTED!r} never appeared for thread {thread_id}. Either the item "
        f"is not configured, or Codex's thread id is not the key the snapshot "
        f"is filed under.{_tail(tui)}"
    )

    # 3. Contract B: `hidden` removes the item, and keeps it removed.
    #
    #    What is asserted here is an absence, because that is all the terminal
    #    can honestly report: ratatui paints by cell diff, so the repaint that
    #    erases the item need not re-emit anything recognisable -- not the
    #    thread id, not the whole line -- and an idle TUI paints nothing at all
    #    afterwards (the first real run of this test proved exactly that: the
    #    erase landed inside SETTLE and the following five seconds were empty
    #    bytes). So liveness is proved by provoking a repaint -- one character
    #    typed into the composer and deleted again echoes back -- and the
    #    absence is made meaningful by publishing a *new* reading while hidden:
    #    the item re-reads once a second, so if `hidden` were ignored the new
    #    number would be painted inside the window.
    publisher.set_hidden(thread_id, True)
    tui.drain(SETTLE)  # flush the last frame that could still show the item
    tui.clear()
    publisher.publish(thread_id, percent=29, blocked=2, unverified=False)
    tui._write(b"x")
    tui.drain(1.0)
    tui._write(b"\x7f")  # backspace: leave the composer as we found it
    tui.drain(ITEM_TIMEOUT)
    after = tui.text()
    assert "x" in after, (
        "codex did not echo a keystroke after hiding -- it probably died"
        f"{_tail(tui)}"
    )
    assert "Privacy " not in after, (
        f"the item survived `hidden`:\n{after[-1200:]}"
    )

    # 4. And `hidden = False` brings it back, carrying the reading published
    #    while it was hidden -- the two toggles compose, and `set_hidden`
    #    touched nothing but the flag.
    publisher.set_hidden(thread_id, False)
    tui.clear()
    back = tui.read_until(lambda t: "Privacy ███░░░░░░░ 29% ⚠2" in t, ITEM_TIMEOUT)
    assert back is not None, (
        f"the item did not return after `hidden` was cleared{_tail(tui)}"
    )


def test_statusline_picker_lists_the_privacy_item(codex_tui):
    """`/statusline` is the in-session switch the spec promises (§5.3): the
    picker enumerates `StatusLineItem`, so `privacy` must be in it, described,
    and previewed with the placeholder bar. Typing filters the picker, which
    also keeps this independent of where the item sits in the list."""
    tui, _data_dir = codex_tui
    booted = tui.read_until(
        lambda t: "Ask Codex" in t and UUID.search(t) is not None, BOOT_TIMEOUT
    )
    assert booted is not None, f"codex never reached its prompt{_tail(tui)}"

    tui.clear()
    tui._write(b"/statusline")
    tui.drain(0.5)
    tui._write(b"\r")
    opened = tui.read_until(lambda t: "status line" in t.lower(), ITEM_TIMEOUT)
    assert opened is not None, f"/statusline did not open a picker{_tail(tui)}"

    tui._write(b"privacy")
    listed = tui.read_until(
        lambda t: "privacy" in t and "Privacy HUD plugin" in t, ITEM_TIMEOUT
    )
    assert listed is not None, (
        f"the picker never showed the privacy item{_tail(tui)}"
    )
    tui._write(b"\x1b")  # Esc: close without changing the configuration
    tui.drain(0.5)
