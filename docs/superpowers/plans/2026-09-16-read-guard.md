# Read Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop a tool call from reading a known-sensitive path, before the bytes reach the model — off by default, on when the user turns it on.

**Architecture:** `detect/paths.py` gains a predicate over one path, reusing the patterns it already owns. A new `settings.py` holds the toggle in `$PLUGIN_DATA/settings.json`, read through an mtime cache. `dispatch` stops early-returning on a local `PreToolUse` whose origin is a path and builds an `Observation`; the `Engine` denies it when the toggle is on, writing a `prevented` row, and mentions the feature once per session when it is off.

**Tech Stack:** Python 3.11+, stdlib only (`json`, `re`, `pathlib`), pytest, ruff, mypy.

**Spec:** `docs/superpowers/specs/2026-09-16-read-guard-design.md` — read it first; this plan argues from it.

## Global Constraints

- **I1** — no raw sensitive data persisted. This feature reads paths, never file contents.
- **I3** — detection is not disclosure. Tier 0's behaviour must not change; a blocked read is `prevented`, an ordinary one `local_access`.
- **I4** — the budget is monotonic and `prevented` contributes exactly 0.
- **I5** — never imply recall. Forbidden in user-facing text: "undo", "revoke", "remove from context", "your data is protected", "100% secure".
- **I6** — fail open on ingress. No daemon, or an unreadable setting, means no blocking — this feature never fails closed on its own configuration.
- **I2** — stdlib only in `src/`; `tests/test_network_isolation.py` enforces the import allowlist.
- **Never catch bare `Exception`.** Catch the one a call raises (`OSError`, `json.JSONDecodeError`), where it is raised.
- **Copy rules (design.md §9):** no severity adjectives, no protection claims the code cannot back.
- **Commit messages carry no attribution trailers** (CLAUDE.md §1). A `commit-msg` hook enforces it; never `--no-verify`.
- **Gates before every commit:** `python -m pytest -q`, `ruff check .`, `python -m mypy`.
- **Run the suite the way CI does** — CI installs no `transformers`, so tier 3 finds nothing there. A test that needs a finding must use a cheap tier (a credential, a path), never an email or a person name. To reproduce CI locally: `mkdir -p /tmp/no-tf && printf 'raise ImportError("simulated CI")\n' > /tmp/no-tf/transformers.py && PYTHONPATH=/tmp/no-tf python -m pytest -q`.
- **Branch:** `feat/read-guard`, already created, spec already committed on it.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/privacy_hud/detect/paths.py` | Add `is_sensitive_path(path) -> bool`. Owns the patterns; knows nothing about settings or hooks. |
| `src/privacy_hud/settings.py` (new) | Read/write `$PLUGIN_DATA/settings.json` behind an mtime cache. Knows no setting's meaning. |
| `src/privacy_hud/dispatch.py` | Build a local-read `Observation` when the origin is a path. |
| `src/privacy_hud/engine.py` | The deny, the `prevented` row, the once-per-session notice. |
| `src/privacy_hud/matrix/tables.toml` | `"PreToolUse/local" = "local_access"`. |
| `src/privacy_hud/mcp_tools.py`, `mcp/server.py`, `skills/privacy/SKILL.md`, `src/privacy_hud/doctor.py` | Show and flip the toggle. |
| `docs/known-limits.md`, `README.md`, `README.zh-CN.md` | The three limits. |

---

### Task 1: `is_sensitive_path`

**Files:**
- Modify: `src/privacy_hud/detect/paths.py`
- Test: `tests/detect/test_paths.py`

**Interfaces:**
- Consumes: the existing `PATTERNS` in that module.
- Produces: `is_sensitive_path(path: str) -> bool`, and `TEMPLATE_SUFFIXES`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/detect/test_paths.py`:

```python
from privacy_hud.detect.paths import is_sensitive_path


@pytest.mark.parametrize("path", [
    ".env",
    "./.env",
    "config/.env",
    ".env.local",
    ".env.production",
    "~/.ssh/id_rsa",
    "deploy/id_ed25519",
    "certs/server.pem",
    "keystore.p12",
    "~/.aws/credentials",
    "credentials.json",
    "~/.ssh/config",
])
def test_a_known_sensitive_path_is_recognised(path):
    assert is_sensitive_path(path) is True


@pytest.mark.parametrize("path", [
    # Templates are committed to repositories to be read. Blocking one stops
    # ordinary work, and the user's only escape is turning the whole guard
    # off -- so the guard is narrower than the detector here, on purpose.
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    "config/.env.example",
    # Ordinary files.
    "src/main.py",
    "README.md",
    "Makefile",
    "",
])
def test_an_ordinary_or_template_path_is_not(path):
    assert is_sensitive_path(path) is False


def test_the_detector_still_flags_a_template(): 
    """The guard being narrower than tier 0 is deliberate, not a gap.

    A `.env.example` that really does hold a key must still be NOTICED --
    noticing costs 2.0 budget points, while blocking costs a command that
    does not run. If someone later "fixes" the asymmetry by narrowing
    PATTERNS, this fails first.
    """
    assert D.scan("cat .env.example", {}) != []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/detect/test_paths.py -q`
Expected: `ImportError: cannot import name 'is_sensitive_path'`.

- [ ] **Step 3: Write the implementation**

Add to `src/privacy_hud/detect/paths.py`:

```python
#: Suffixes that make a path a template rather than the file it stands in
#: for: `.env.example` is committed to the repository precisely so it can be
#: read. `PATTERNS` matches them (`\.env(\.[\w-]+)?` covers `.env.example`),
#: and for DETECTION that is right -- a template that really does hold a key
#: should still be noticed, and noticing costs 2.0 budget points. Blocking
#: one costs a command that does not run and a user whose only escape is
#: turning the guard off, so the guard is narrower than the detector here.
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")


def is_sensitive_path(path: str) -> bool:
    """Whether reading `path` is worth stopping (`#36`'s deny list).

    Narrower than `PathDetector.scan`, and deliberately so -- see
    `TEMPLATE_SUFFIXES`. Takes one path, not a blob of text: the caller has
    already resolved which file a tool call would read (`origin.py`), so
    this does not go looking for paths inside a string.
    """
    if not path:
        return False
    if path.endswith(TEMPLATE_SUFFIXES):
        return False
    return any(pattern.search(path) for pattern in PATTERNS)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/detect/test_paths.py -q`
Expected: PASS.

Note: `PATTERNS[0]` is anchored on `(?:^|[\s/=\"'])`, so a bare `.env` at the very start of the string matches, as does `config/.env`. If a case fails, fix the predicate (e.g. by searching `"/" + path`), not the pattern — the pattern is shared with the detector and changing it changes detection.

- [ ] **Step 5: Run the gates and commit**

```bash
python -m pytest -q && ruff check . && python -m mypy
git add src/privacy_hud/detect/paths.py tests/detect/test_paths.py
git commit -m "Say whether one path is worth stopping a read of

Reuses the patterns tier 0 already owns rather than starting a second
list that would drift from the first, and narrows them by one rule: a
template (.env.example and friends) is not blocked. Detection still
flags templates -- noticing one that really holds a key costs 2.0 budget
points, while blocking it costs a command that does not run."
```

---

### Task 2: the toggle

**Files:**
- Create: `src/privacy_hud/settings.py`
- Test: `tests/test_settings.py`
- Modify: `src/privacy_hud/mcp_tools.py`, `mcp/server.py`, `src/privacy_hud/doctor.py`, `skills/privacy/SKILL.md`

**Interfaces:**
- Consumes: `$PLUGIN_DATA` (the directory `dispatch.new_state` is given).
- Produces: `Settings(data_dir)` with `.deny_read` (property, mtime-cached) and `.set_deny_read(bool)`; `mcp_tools.read_guard_status(data_dir)` and `mcp_tools.read_guard_set(data_dir, enabled)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_settings.py`:

```python
import json

from privacy_hud.settings import Settings


def test_blocking_is_off_when_there_is_no_file(tmp_path):
    assert Settings(tmp_path).deny_read is False


def test_a_written_setting_reads_back(tmp_path):
    s = Settings(tmp_path)
    s.set_deny_read(True)
    assert Settings(tmp_path).deny_read is True
    assert json.loads((tmp_path / "settings.json").read_text())["deny_read"] is True


def test_a_change_is_seen_without_a_restart(tmp_path):
    """The daemon holds one Settings for its life. A user who turns blocking
    on inside a running session must see it apply to that session -- a
    setting that needs a restart reads as a broken setting."""
    live = Settings(tmp_path)
    assert live.deny_read is False
    Settings(tmp_path).set_deny_read(True)          # another process writes
    assert live.deny_read is True


def test_a_corrupt_file_reads_as_off(tmp_path):
    """I6: this feature never fails closed on its own configuration. A
    guard that cannot read its setting must not start blocking on a guess."""
    (tmp_path / "settings.json").write_text("{ not json")
    assert Settings(tmp_path).deny_read is False


def test_an_unreadable_file_reads_as_off(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text('{"deny_read": true}')
    path.chmod(0o000)
    try:
        assert Settings(tmp_path).deny_read is False
    finally:
        path.chmod(0o600)


def test_writing_does_not_lose_an_unrelated_key(tmp_path):
    (tmp_path / "settings.json").write_text('{"kept": 1}')
    Settings(tmp_path).set_deny_read(True)
    data = json.loads((tmp_path / "settings.json").read_text())
    assert data == {"kept": 1, "deny_read": True}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_settings.py -q`
Expected: `ModuleNotFoundError: No module named 'privacy_hud.settings'`.

- [ ] **Step 3: Write the implementation**

Create `src/privacy_hud/settings.py`:

```python
"""User preferences that outlive a session.

The first of its kind in this plugin. Everything else under `PLUGIN_DATA`
is either machine configuration written by setup (`runtime.json`), the
ledger, or per-session scratch -- so this gets its own file rather than
sharing one: a reinstall rewrites `runtime.json`, and a user's protection
setting must not be lost when the interpreter is re-recorded.

Not in Codex's `config.toml`, for three reasons. The standard library reads
TOML but cannot write it, so a toggle there means a new dependency (I2
forbids it) or `sed` against the user's own config. The setting is this
plugin's policy, not a Codex setting -- `[tui].status_line` holds a Codex
identifier we add to, while `deny_read` is a concept Codex knows nothing
about. And `install.sh --purge` already removes `PLUGIN_DATA`.

The cost is that the file is invisible, which `$privacy read status` and a
`privacy-hud-doctor` line are here to pay.
"""
from __future__ import annotations

import json
from pathlib import Path

SETTINGS_NAME = "settings.json"

#: Every setting, with the value that applies when the file does not say.
#: Defaults are the permissive answer on purpose (I6): a guard that cannot
#: read its own configuration must not start blocking on a guess.
DEFAULTS: dict[str, object] = {"deny_read": False}


class Settings:
    """`$PLUGIN_DATA/settings.json`, re-read when it changes on disk.

    The daemon builds one of these for its life, but a user flips the
    toggle from a *different* process (the `$privacy` skill, through the
    MCP server). Caching the parsed file against its mtime is what lets a
    change land inside a running session without a restart, while still
    not re-reading a file on every hook.
    """

    def __init__(self, data_dir) -> None:
        self.path = Path(data_dir) / SETTINGS_NAME
        self._cached: dict | None = None
        self._mtime: float | None = None

    def _load(self) -> dict:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            self._cached, self._mtime = {}, None
            return self._cached
        if self._cached is None or mtime != self._mtime:
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                # A malformed file is not a reason to start blocking reads.
                data = {}
            self._cached = data if isinstance(data, dict) else {}
            self._mtime = mtime
        return self._cached

    @property
    def deny_read(self) -> bool:
        return bool(self._load().get("deny_read", DEFAULTS["deny_read"]))

    def set_deny_read(self, enabled: bool) -> None:
        """Write the flag, keeping every other key the file holds."""
        data = dict(self._load())
        data["deny_read"] = bool(enabled)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2) + "\n",
                             encoding="utf-8")
        self.path.chmod(0o600)
        self._cached, self._mtime = None, None
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_settings.py -q`
Expected: PASS. If `test_a_change_is_seen_without_a_restart` is flaky, the two writes landed in the same mtime tick — compare `(mtime, size)` rather than mtime alone and say so in the docstring.

- [ ] **Step 5: Wire the operator surface**

Add to `src/privacy_hud/mcp_tools.py`, beside `hud_status`/`hud_set_hidden` (follow their shape exactly — they are the precedent for "a toggle the user flips from the skill"):

```python
def read_guard_status(data_dir) -> dict:
    """Whether reads of known-sensitive paths are blocked (`#36`).

    `settings.json` is not a file the user can see from Codex, so this and
    `privacy-hud-doctor` are how they find out what it says.
    """
    from .settings import Settings
    return {"deny_read": Settings(data_dir).deny_read}


def read_guard_set(data_dir, enabled: bool) -> dict:
    from .settings import Settings
    Settings(data_dir).set_deny_read(enabled)
    return read_guard_status(data_dir)
```

Expose both through `mcp/server.py` as `privacy.read_guard_status` and `privacy.read_guard_set`, with docstrings in the style of the neighbouring tools.

Document `$privacy read on|off|status` in `skills/privacy/SKILL.md`, in the same section and shape as the existing `$privacy hud on|off|status` (find that heading and mirror it). State plainly that `on` blocks reads of known-sensitive paths, that the default is off, and that a blocked read never runs.

Add a `privacy-hud-doctor` check that prints the current value. Follow the `Check` shape the other checks return; `OK` in both states — an off guard is a choice, not a fault.

- [ ] **Step 6: Run the gates and commit**

```bash
python -m pytest -q && ruff check . && python -m mypy
git add -A
git commit -m "Hold the read guard's toggle where the plugin can write it

settings.json under PLUGIN_DATA, re-read when it changes so a user who
turns it on mid-session sees it apply to that session. Absent, corrupt or
unreadable all read as off: a guard that cannot read its own setting must
not start blocking on a guess (I6).

Not config.toml -- the standard library cannot write TOML, and this is
the plugin's policy rather than a Codex setting. Its own file rather than
runtime.json, which a reinstall rewrites.

$privacy read on|off|status and a doctor line are what make an invisible
file answerable."
```

---

### Task 3: let a local read reach the engine

**Files:**
- Modify: `src/privacy_hud/dispatch.py` (the `PreToolUse` local early return, ~line 445), `src/privacy_hud/matrix/tables.toml`, `src/privacy_hud/engine.py` (Ruling 1's wording in the module docstring)
- Test: `tests/test_dispatch_hud.py`, `tests/matrix/test_loader.py`

**Interfaces:**
- Consumes: `origin.extract_origin` (already imported by `dispatch`), `OriginKind.PATH`.
- Produces: an `Observation(direction="local", destination="local", origin=...)` for a local `PreToolUse` whose origin is a path; `"PreToolUse/local" = "local_access"` in the taxonomy.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_dispatch_hud.py`:

```python
def test_a_local_read_of_a_path_reaches_the_ledger(state):
    """Before #36 a local PreToolUse returned early and was never scored.
    The read itself is now an observation, so that the engine can decide
    about it -- with the guard off it is simply allowed and recorded."""
    _hook(state, "SessionStart")
    assert _hook(state, "PreToolUse", tool_name="Bash",
                 tool_input={"command": "cat .env"}) == {}
    row = state.ledger.conn.execute(
        "SELECT kind, source, source_kind FROM events").fetchone()
    assert row is not None, "a local read now produces a row"
    assert (row["kind"], row["source"], row["source_kind"]) == \
        ("local_access", ".env", "path")


@pytest.mark.parametrize("command", ["env", "python -c \"open('.env')\""])
def test_a_local_command_with_no_path_still_returns_early(state, command):
    """A COMMAND origin or none at all must not build an Observation: there
    is nothing to decide, and `Engine.observe` would raise UnknownKey."""
    _hook(state, "SessionStart")
    assert _hook(state, "PreToolUse", tool_name="Bash",
                 tool_input={"command": command}) == {}
    assert state.ledger.conn.execute(
        "SELECT count(*) FROM events").fetchone()[0] == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_dispatch_hud.py -q -k local`
Expected: the first fails (`row is None` — the early return still swallows it); the second passes already.

- [ ] **Step 3: Write the implementation**

In `tables.toml`, beside `"PostToolUse/local"`:

```toml
"PreToolUse/local"         = "local_access"
```

In `dispatch._build_observation`'s `PreToolUse` branch, replace the `destination == "local"` early return with:

```python
            if destination == "local":
                # #36: a local read is no longer nothing to score. When the
                # origin names a file, the engine decides whether reading it
                # is allowed -- the one interception point that acts BEFORE
                # the bytes exist, rather than recording them after.
                #
                # Everything else local still returns early: a COMMAND
                # origin or none at all leaves nothing to decide, and
                # `Engine.observe` would raise UnknownKey for a row the
                # taxonomy does not define (I2: never silently caught).
                origin = extract_origin(tool_name, tool_input)
                if origin is None or origin.kind is not OriginKind.PATH:
                    return None
                return Observation(
                    session_id=session_id, turn_id=turn_id, hook_event=event,
                    direction="local", source=origin.value,
                    destination="local", text=command, tool_name=tool_name,
                    tool_input=tool_input, origin=origin)
            text = command
```

Import `OriginKind` beside the existing `extract_origin` import.

Amend Ruling 1 in `engine.py`'s module docstring: it currently reads "a `local` destination always classifies as `local_access`, never `exposed`, regardless of the caller-supplied `direction`". Add the exception this task creates — a denied local read classifies as `prevented`, through the existing `"PreToolUse/blocked"` entry — and say why: without it a blocked read and an ordinary one are the same row, and the audit cannot show that anything was stopped.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_dispatch_hud.py tests/matrix -q`
Expected: PASS. If `tests/matrix/test_matrix_covers_the_code.py` fails, read what it pins — it checks the taxonomy against the code's use of it, and the new entry must satisfy it rather than be excluded from it.

- [ ] **Step 5: Run the gates and commit**

```bash
python -m pytest -q && ruff check . && python -m mypy
git add -A
git commit -m "Score a local read instead of returning early

A local PreToolUse whose origin names a file now becomes an Observation,
so the engine can decide about the read before it runs -- the one
boundary in this plugin that acts before the bytes exist. With the guard
off it is allowed and recorded as local_access, which is what it always
was; the row is new only because nothing used to produce one.

A COMMAND origin or none still returns early: nothing to decide, and the
taxonomy defines no row for it.

Ruling 1 gains its first exception, in engine.py's docstring: a denied
local read is prevented, not local_access, or the audit cannot show that
anything was stopped."
```

---

### Task 4: the deny, and the notice

**Files:**
- Modify: `src/privacy_hud/engine.py`
- Test: `tests/test_engine.py`

**Interfaces:**
- Consumes: `Settings.deny_read` (Task 2), `is_sensitive_path` (Task 1), the local `Observation` (Task 3).
- Produces: `READ_BLOCK_TEMPLATE`, `READ_NOTICE_TEMPLATE`, and `Engine(..., settings=...)`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_engine.py` (the `eng` fixture builds an `Engine`; give it a settings double — a tiny object with a `deny_read` attribute is enough, and it keeps the engine's dependency an interface rather than a file):

```python
class _Settings:
    def __init__(self, deny_read=False):
        self.deny_read = deny_read


def _read(path=".env"):
    return _obs(hook_event="PreToolUse", direction="local", source=path,
                destination="local", text=f"cat {path}", tool_name="Bash",
                origin=Origin(path, OriginKind.PATH))


def test_a_sensitive_read_is_denied_when_the_guard_is_on(eng):
    eng.settings = _Settings(deny_read=True)
    d = eng.observe(_read(".env"))
    assert d.action == "deny"
    assert "would read  .env" in (d.system_message or "")


def test_the_same_read_is_allowed_when_the_guard_is_off(eng):
    eng.settings = _Settings(deny_read=False)
    assert eng.observe(_read(".env")).action == "allow"


def test_an_ordinary_read_is_allowed_with_the_guard_on(eng):
    eng.settings = _Settings(deny_read=True)
    assert eng.observe(_read("src/main.py")).action == "allow"


def test_a_template_is_allowed_with_the_guard_on(eng):
    eng.settings = _Settings(deny_read=True)
    assert eng.observe(_read(".env.example")).action == "allow"


def test_a_denied_read_is_prevented_and_costs_nothing(eng):
    eng.settings = _Settings(deny_read=True)
    before = eng.ledger.summary("s1").percent
    eng.observe(_read(".env"))
    assert eng.ledger.summary("s1").percent == before          # I4
    kinds = [r["kind"] for r in eng.ledger.conn.execute("SELECT kind FROM events")]
    assert kinds and set(kinds) == {"prevented"}               # I3


def test_the_notice_is_shown_once_per_session(eng):
    """It exists to make the feature discoverable, not to narrate every
    read: a line on every `cat .env` is noise, and noise gets ignored."""
    eng.settings = _Settings(deny_read=False)
    first = eng.observe(_read(".env"))
    second = eng.observe(_read("config/.env"))
    assert "$privacy read on" in (first.system_message or "")
    assert second.system_message is None


def test_no_notice_for_an_ordinary_read(eng):
    eng.settings = _Settings(deny_read=False)
    assert eng.observe(_read("src/main.py")).system_message is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_engine.py -q -k "read or guard or notice"`
Expected: FAIL — every read is allowed with no message; `Engine` has no `settings`.

- [ ] **Step 3: Write the implementation**

Add the templates beside the others in `engine.py`:

```python
# The one thing this plugin can say without qualification: the call is
# stopped before it runs, so there is nothing to recall (I5 is satisfied by
# the fact, not by careful wording).
READ_BLOCK_TEMPLATE = (
    "PRIVACY HUD blocked a read\n\n"
    "  {tool}  would read  {path}\n\n"
    "  Reads of known-sensitive paths are blocked. This one did not run,\n"
    "  so nothing from it reached the model.\n\n"
    "  Run `$privacy read off` to allow them again."
)

# Shown once per session, not once per path: this is how the feature is
# discovered, and a line on every read would be noise.
READ_NOTICE_TEMPLATE = (
    "PRIVACY HUD: this session read {path} — a path it can stop before it\n"
    "reaches the model. Turn that on with `$privacy read on`."
)
```

Give `Engine.__init__` a `settings` parameter (defaulting to an object whose `deny_read` is False, so every existing caller and test keeps working), and a `self._read_notice_shown = False` beside the taint map — same per-session lifetime.

In `observe`, before the egress policy block:

```python
        if obs.hook_event == "PreToolUse" and obs.direction == "local":
            # #36's one interception point that acts before the bytes exist.
            path = obs.origin.value if obs.origin else ""
            if is_sensitive_path(path):
                if self.settings.deny_read:
                    action = "deny"
                    read_block = path
                elif not self._read_notice_shown:
                    self._read_notice_shown = True
                    notice = READ_NOTICE_TEMPLATE.format(path=path)
```

and make the message-building block render `READ_BLOCK_TEMPLATE` for a denied read (it takes `tool` and `path`, not the egress templates' `label`/`destination`) and carry `notice` as the `system_message` of an allowed observation. Keep the existing egress path untouched: a local observation must not reach `Matrix.default_action()` or the consent-token branch.

Wire the real `Settings` in `dispatch.new_state`/`_get_or_start_engine`, so the daemon's engines get one built on `PLUGIN_DATA`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_engine.py tests/test_dispatch_hud.py -q`
Expected: PASS.

- [ ] **Step 5: End-to-end, through the real hook path**

Add to `tests/test_origin_rules_e2e.py` (it already has `state`/`ui`/`_hook` and stubs tier 3):

```python
def test_a_sensitive_read_is_stopped_once_the_guard_is_on(state, tmp_path):
    from privacy_hud.settings import Settings

    _hook(state, "SessionStart")
    allowed = _hook(state, "PreToolUse", tool_name="Bash",
                    tool_input={"command": "cat .env"})
    assert allowed == {} or not _is_deny(allowed)

    Settings(tmp_path).set_deny_read(True)

    denied = _hook(state, "PreToolUse", tool_name="Bash",
                   tool_input={"command": "cat .env"})
    assert _is_deny(denied)
    assert "did not run" in \
        denied["hookSpecificOutput"]["permissionDecisionReason"]
```

(`tmp_path` is the same directory the `state` fixture passes as `PLUGIN_DATA`; if the fixture uses a different one, read the setting's path from the state rather than assuming.)

- [ ] **Step 6: Run the gates and commit**

```bash
python -m pytest -q && ruff check . && python -m mypy
git add -A
git commit -m "Stop a read of a known-sensitive path when the guard is on

The engine now decides about a local read: with the guard on, a path the
patterns recognise is denied and recorded as prevented, worth 0 (I4), and
the command never runs. With it off the read is allowed and the session
says once -- not once per path -- that the guard exists.

A template is never blocked, an ordinary file is never blocked, and an
unrecognised read is not reached at all: dispatch never builds an
observation for it."
```

---

### Task 5: say what it does and does not do

**Files:**
- Modify: `docs/known-limits.md`, `README.md`, `README.zh-CN.md`, `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json`, `pyproject.toml`
- Test: `tests/test_versions.py` (must stay green)

- [ ] **Step 1: Add the three limits**

Append to `docs/known-limits.md`, numbered 14-16, and keep the existing blunt register:

14. **Only reads it can recognise are stopped.** `cat .env` is; `python -c "open('.env')"` is not. This is limit 6's root cause seen from the other side — the engine reads the text of a tool call, not what the call will do — and the two should point at each other.
15. **A template file is never blocked**, even one that really holds a key. `.env.example` is committed to be read, and blocking it stops ordinary work while the user's only escape is turning the guard off. Detection still flags it, so such a file still shows up in the audit.
16. **Nothing is blocked until you turn it on.** The default records the read and mentions the guard once per session; it stops nothing. `$privacy read status` says which state you are in.

- [ ] **Step 2: Update both READMEs**

Add the three limits to the short list in `README.md` (it now runs to 13, so these become 14-16) and correct the "All thirteen limits in full" line in the documentation table.

For `README.zh-CN.md`, have Codex write the Chinese — house practice, zh-CN prose is not translated inline. Pass it the current Chinese list items and the new English ones, ask for only the rewritten lines, and apply them verbatim:

```bash
codex exec --skip-git-repo-check 'Output ONLY the Chinese lines requested...'
```

Also update its documentation-table cell (currently `十三条限制的完整说明`).

- [ ] **Step 3: Bump the version**

`0.5.0` → `0.6.0` in `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json`, `pyproject.toml`. A new MCP tool and a new skill command are user-visible, and Codex caches an installed plugin by version.

- [ ] **Step 4: Run the gates and commit**

```bash
python -m pytest -q && ruff check . && python -m mypy
git add -A
git commit -m "State what the read guard stops and what it does not

Three limits: only recognised reads are stopped, a template is never
blocked, and nothing is blocked until you turn it on. The first points at
limit 6, which is the same gap seen from the other side.

Version 0.6.0: a new MCP tool and a new skill command are user-visible."
```

---

## Self-review

**Spec coverage.** Default-warn and the opt-in toggle → Tasks 2 and 4; the settings file and its failure modes → Task 2; the engine-not-dispatch decision, the taxonomy entry and Ruling 1 → Task 3; reusing the detector's patterns with the template carve-out → Task 1; copy → Task 4; the three limits → Task 5; error handling → Task 1 (empty path), Task 2 (corrupt/unreadable), Task 3 (no origin), Task 4 (guard off).

**Type consistency.** `is_sensitive_path(str) -> bool`, `Settings(data_dir).deny_read -> bool`, `Origin(value, kind)` and `OriginKind.PATH` are used with those exact shapes in every task that touches them. The engine depends on a `settings` object with one attribute, not on the concrete class, which is what lets Task 4's tests pass a double.

**Known risk, called out rather than designed around.** Task 3 makes every local Bash read build an `Observation` and run the detector stack, where before it returned immediately. That is more work on a hot path. Tier 3 is already gated by boundary (`engine.py` skips the deep scan for local reads), so the added cost is tiers 0-1 over the command text — measure it if the daemon's latency moves, and say so in the report rather than optimising blind.
