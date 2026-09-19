# MCP Server Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Codex actually load the plugin's MCP server, exposing only tools that cannot loosen protection, and stop the block message naming actions no surface performs.

**Architecture:** `mcp/server.py` becomes a stdlib-only launcher that re-executes itself under the interpreter `runtime.json` records, then builds a FastMCP app registering five read/tighten-only tools. `.codex-plugin/plugin.json` declares it inline; `install.sh` installs the `[mcp]` extra; `privacy-hud-doctor` proves it loads by completing a real MCP handshake and comparing the tool list.

**Tech Stack:** Python 3.11+ (stdlib only in the launcher), the `mcp` SDK (optional extra), SQLite, pytest.

**Spec:** `docs/superpowers/specs/2026-09-17-mcp-server-design.md`

## Global Constraints

- **I1 — no raw sensitive data persisted or printed.** Error text names an exception class or a fixed phrase; never a payload, never a `tool_input`.
- **I2 — no network except `127.0.0.1`.** No new distribution beyond `mcp`, which is already in `tests/test_network_isolation.py::ALLOWED_DISTRIBUTIONS`. Nothing under `src/` or `hooks/` gains a non-stdlib import.
- **I6 — fail open on ingress, closed on egress.** Unchanged by this work.
- **stdout is the JSON-RPC channel.** `mcp/server.py` writes nothing to stdout on any failure path. Every diagnostic goes to stderr with a non-zero exit.
- **No attribution trailers in commit messages** (`.claude/CLAUDE.md` §1). A commit message ends with its body.
- **Exposed tool set, exactly these five, sorted:** `privacy.get_exposure_detail`, `privacy.get_session_summary`, `privacy.list_exposures`, `privacy.read_guard_status`, `privacy.update_policy`.
- **Withheld, and they stay withheld:** `privacy.allow_once`, `privacy.hud_toggle`, `privacy.read_guard_set`.
- **Version `0.7.0`** in `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json` and `pyproject.toml`, which move together (`tests/test_versions.py`).
- **Every new test is run once against a deliberately broken implementation before it is committed**, and the task report says what was broken and that the test failed. A test that has only ever passed proves nothing.
- **Run the suite both ways before declaring a task done:**
  `python -m pytest -q` and
  `mkdir -p /tmp/no-tf && printf 'raise ImportError("simulated CI")\n' > /tmp/no-tf/transformers.py && PYTHONPATH=/tmp/no-tf python -m pytest -q`
- **zh-CN prose is written by Codex, never translated inline** (house practice). If `codex exec` cannot be run, stop and report rather than writing the Chinese yourself.

---

### Task 1: Withdraw `allow_dest`, fix the block copy, pin the subcommand rule

**Files:**
- Modify: `src/privacy_hud/mcp_tools.py` — `_POLICY_RULE_TYPES` and `apply_policy`
- Modify: `src/privacy_hud/engine.py` — `BLOCK_TEMPLATE`, `ORIGIN_BLOCK_TEMPLATE`
- Modify: `src/privacy_hud/ledger.py:98` — the `rule_type` schema comment
- Test: `tests/test_mcp.py`, `tests/test_copy_promises.py` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `mcp_tools._ALLOW_DEST_WITHDRAWN` (a `str` message constant) and the shortened templates. Task 3 relies on `apply_policy` raising `ValueError` for `allow_dest`.

- [ ] **Step 1: Write the failing test for `allow_dest`**

Append to `tests/test_mcp.py`:

```python
def test_allow_dest_is_refused_like_block_source(ledger):
    """`allow_dest` was accepted, written, and reported applied — and the
    engine never read it. `Engine.observe` compares `rule_type` against
    exactly `mask`, `block_path` and `block_command`, so an `allow_dest`
    row decided nothing while `{"applied": True}` said otherwise. That is
    #38's defect wearing a different name, and `apply_policy`'s own
    docstring calls it worse than an error."""
    with pytest.raises(ValueError, match="allow_dest"):
        mcp_tools.apply_policy(ledger, SID, rule_type="allow_dest",
                               selector="external_net")
    assert ledger.policy_selectors(SID, "allow_dest") == set()
```

If `tests/test_mcp.py` has no `ledger` fixture or `SID` constant, read the top of that file and use whatever it already provides; do not add a second fixture.

- [ ] **Step 2: Run it and watch it fail**

Run: `python -m pytest tests/test_mcp.py::test_allow_dest_is_refused_like_block_source -q`
Expected: FAIL — `DID NOT RAISE ValueError`.

- [ ] **Step 3: Withdraw `allow_dest`**

In `src/privacy_hud/mcp_tools.py`, change the rule-type set:

```python
_POLICY_RULE_TYPES = {"mask", "block_path", "block_command"}
```

Add, beside `_BLOCK_SOURCE_WITHDRAWN`:

```python
#: Why `allow_dest` is refused rather than written. It named a destination
#: to stop treating as sensitive, and nothing ever enforced it: `Engine.observe`
#: reads `mask` (its own matrix defaults behind it) and the two origin rule
#: types, and compares `rule_type` against nothing else. So a row went in, the
#: caller was told `{"applied": True}`, and every later call was decided
#: exactly as if the rule did not exist. `2026-09-03-decisions.md` recorded it
#: as a placeholder -- "untouched because nothing mints it yet" -- and wiring
#: the MCP server is what would have started minting it. Refused for #38's
#: reason, in #38's words: a policy row the engine can never match is worse
#: than an error, because it looks like protection was applied when nothing
#: was. An allow rule failing to apply is the safe direction; saying it
#: applied is not.
_ALLOW_DEST_WITHDRAWN = (
    "allow_dest is not available: no code path has ever enforced it, so a "
    "rule written that way decides nothing while reporting success (#38's "
    "reason) — there is no replacement, because nothing minted it")
```

In `apply_policy`, beneath the existing `block_source` branch:

```python
    if rule_type == "allow_dest":
        raise ValueError(_ALLOW_DEST_WITHDRAWN)
```

In `src/privacy_hud/ledger.py:98`, the schema comment becomes:

```
  rule_type  TEXT NOT NULL,               -- mask|block_path|block_command
```

- [ ] **Step 4: Run it and watch it pass**

Run: `python -m pytest tests/test_mcp.py -q`
Expected: PASS. If another test asserted `allow_dest` was accepted, it was asserting the defect — update it to expect the refusal and say so in its docstring.

- [ ] **Step 5: Write the failing copy test**

Create `tests/test_copy_promises.py`:

```python
# tests/test_copy_promises.py
"""Copy that tells a user to run something must name something that exists.

The block message shipped for six weeks ending `Run $privacy to review,
minimize, or allow once.` `$privacy` has never had either. It was in the
2026-09-03 plan verbatim, so every task review compared the code against a
brief that already contained the defect.

This catches the mechanical half: a `$privacy <subcommand>` that
`skills/privacy/SKILL.md` does not document. It cannot catch the half that
bit us -- "minimize" was a verb in a sentence, not a subcommand, and no
pattern reads what a sentence promises. `.claude/CLAUDE.md` §5 carries that
half as a review rule.
"""
from __future__ import annotations

import re
from pathlib import Path

from privacy_hud import engine

REPO = Path(__file__).resolve().parent.parent
SKILL = REPO / "skills" / "privacy" / "SKILL.md"

#: `$privacy` followed by a word, in or out of backticks. The bare form
#: (`Run $privacy to review.`) names no subcommand and is not a claim about
#: one, so `to` and friends are filtered by the documented-set check below
#: only when they look like subcommands -- see `_SUBCOMMANDS`.
_MENTION = re.compile(r"\$privacy\s+([a-z][a-z-]*)")

#: Prose connectives that follow a bare `$privacy`, not subcommands.
_PROSE = {"to", "and", "or", "in", "for", "again", "itself", "prints"}


def _documented_subcommands() -> set[str]:
    """The first word of every `### `$privacy <...>`` heading in SKILL.md."""
    found = set()
    for line in SKILL.read_text(encoding="utf-8").splitlines():
        match = re.match(r"###\s+`\$privacy\s+([a-z][a-z-]*)", line)
        if match:
            found.add(match.group(1))
    return found


def _templates() -> dict[str, str]:
    return {name: value for name, value in vars(engine).items()
            if name.endswith("_TEMPLATE") and isinstance(value, str)}


def test_every_privacy_subcommand_named_in_copy_exists():
    documented = _documented_subcommands()
    assert documented, "SKILL.md no longer declares subcommands the way this parses"
    offenders = []
    for name, text in _templates().items():
        for word in _MENTION.findall(text):
            if word in _PROSE or word in documented:
                continue
            offenders.append(f"{name}: `$privacy {word}`")
    assert not offenders, (
        "user-facing copy names a $privacy subcommand SKILL.md does not "
        "document:\n  " + "\n  ".join(offenders))


def test_the_block_templates_promise_no_action_without_a_surface():
    """The two words that shipped false. `minimize` has no surface at all;
    `allow once` has `mcp_tools.allow_once`, deliberately exposed nowhere
    (see the design doc) -- and it could not work through MCP even if it
    were, because the consent call would carry the credential that caused
    the block and be blocked itself."""
    for name in ("BLOCK_TEMPLATE", "ORIGIN_BLOCK_TEMPLATE"):
        text = _templates()[name]
        assert "minimize" not in text, f"{name} still offers minimize"
        assert "allow once" not in text, f"{name} still names allow once"
```

- [ ] **Step 6: Run it and watch it fail**

Run: `python -m pytest tests/test_copy_promises.py -q`
Expected: both tests FAIL — the first on `BLOCK_TEMPLATE: $privacy to` unless `to` is filtered (it is, via `_PROSE`), the second on `BLOCK_TEMPLATE still offers minimize`.

If the first test passes at this point, that is correct: it is the guard for the *next* defect, not this one. Record that in the task report.

- [ ] **Step 7: Fix the copy**

In `src/privacy_hud/engine.py`, `BLOCK_TEMPLATE`'s last line:

```python
BLOCK_TEMPLATE = (
    "PRIVACY HUD blocked a tool call\n\n"
    "  {tool}  would send  {label}\n"
    "  from {source} to {destination}.\n\n"
    "  Run $privacy to review."
)
```

`ORIGIN_BLOCK_TEMPLATE` drops the allow-once clause:

```python
ORIGIN_BLOCK_TEMPLATE = (
    "PRIVACY HUD blocked a tool call\n\n"
    "  {tool}  would send  {label}\n"
    "  {origin_phrase}.\n\n"
    "  A source rule you wrote for this session denies this call.\n"
    "  The rule ends with the session."
)
```

Update the comment above `ORIGIN_BLOCK_TEMPLATE`: the paragraph explaining why it does not end in "Run `$privacy` to review or adjust policy" still stands, but the sentence about an allow-once token not overriding a standing rule now explains why the clause was *removed* — the fact is true, and naming allow once implied the user had it.

- [ ] **Step 8: Run both files and watch them pass**

Run: `python -m pytest tests/test_copy_promises.py tests/test_engine.py tests/test_mcp.py -q`
Expected: PASS. Any engine test asserting the old block string is asserting the defect — update it and say so in its docstring.

- [ ] **Step 9: Prove the copy test can fail**

Temporarily append `" Run $privacy minimize."` to `BLOCK_TEMPLATE`, run
`python -m pytest tests/test_copy_promises.py -q`, confirm
`test_every_privacy_subcommand_named_in_copy_exists` FAILS naming
`BLOCK_TEMPLATE: $privacy minimize`, then revert. Record it in the report.

- [ ] **Step 10: Full suite, both ways, then commit**

```bash
python -m pytest -q
mkdir -p /tmp/no-tf && printf 'raise ImportError("simulated CI")\n' > /tmp/no-tf/transformers.py && PYTHONPATH=/tmp/no-tf python -m pytest -q
ruff check .
git add src/privacy_hud/mcp_tools.py src/privacy_hud/engine.py src/privacy_hud/ledger.py tests/test_mcp.py tests/test_copy_promises.py
git commit -m "Refuse allow_dest, and stop the block message offering what nothing does"
```

---

### Task 2: The stdlib launcher

**Files:**
- Modify: `mcp/server.py` — module scope becomes stdlib-only; add the launcher
- Test: `tests/test_mcp_launcher.py` (create)

**Interfaces:**
- Consumes: Task 1's changes only incidentally (same repo).
- Produces: `RECEIPT_NAME = "runtime.json"`, `RECEIPT_VERSION = 1`, `REEXEC_MARKER = "PRIVACY_HUD_MCP_REEXEC"`, and `_reexec_under_pinned_interpreter() -> None` in `mcp/server.py`. Task 5's doctor check launches this file.

- [ ] **Step 1: Write the failing launcher tests**

Create `tests/test_mcp_launcher.py`:

```python
# tests/test_mcp_launcher.py
"""`mcp/server.py` has to get itself into the plugin's own interpreter.

Codex will not run `${PLUGIN_ROOT}/...` as an MCP `command` -- the manifest
may name a bare executable on the host PATH or a `./` path inside the plugin
root, and the venv is neither. So Codex launches host `python3`, which has
neither `privacy_hud` nor `mcp` importable, and this file re-executes itself
under the interpreter `privacy-hud-setup` recorded in `runtime.json`.

`hooks/handler.py` already does this to spawn the daemon. The checks are
restated rather than imported (they are inlined in `_spawn_daemon`, on the
path every tool call runs); `test_the_receipt_checks_match_the_hook_client`
is what keeps the two copies honest.

Everything here runs the real file in a subprocess, because what is being
tested is what `execve` does to a process, which cannot be observed in-process.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SERVER = REPO / "mcp" / "server.py"
MARKER = "PRIVACY_HUD_MCP_REEXEC"


def _fake_interpreter(tmp_path: Path) -> Path:
    """An executable that reports how it was invoked and exits, standing in
    for the venv python. It prints to STDOUT on purpose: reaching it is the
    success signal, and on the real path stdout is where JSON-RPC goes."""
    path = tmp_path / "fake-python"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "print(json.dumps({'argv': sys.argv[1:],\n"
        "                  'pythonpath': os.environ.get('PYTHONPATH', ''),\n"
        "                  'marker': os.environ.get('PRIVACY_HUD_MCP_REEXEC', '')}))\n",
        encoding="utf-8")
    path.chmod(0o755)
    return path


def _receipt(tmp_path: Path, python: Path, *, pythonpath="/pinned/site-packages",
             version=1, mode=0o600) -> Path:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    receipt = data / "runtime.json"
    receipt.write_text(json.dumps({
        "v": version, "python": str(python), "pythonpath": pythonpath,
        "plugin_data": str(data), "env": {}}), encoding="utf-8")
    receipt.chmod(mode)
    return data


def _run(data_dir, *, env_extra=None):
    env = {k: v for k, v in os.environ.items() if k != MARKER}
    env["PLUGIN_DATA"] = str(data_dir) if data_dir is not None else ""
    if data_dir is None:
        del env["PLUGIN_DATA"]
    env.pop("PYTHONPATH", None)
    env.update(env_extra or {})
    return subprocess.run([sys.executable, str(SERVER)], env=env,
                          capture_output=True, text=True, timeout=60)


def test_it_re_execs_under_the_recorded_interpreter(tmp_path):
    data = _receipt(tmp_path, _fake_interpreter(tmp_path))
    result = _run(data)
    payload = json.loads(result.stdout)
    assert payload["argv"] == [str(SERVER)]
    assert payload["marker"] == "1", "the guard must be set before execve"


def test_the_recorded_pythonpath_is_prepended(tmp_path):
    data = _receipt(tmp_path, _fake_interpreter(tmp_path))
    result = _run(data, env_extra={"PYTHONPATH": "/already/here"})
    payload = json.loads(result.stdout)
    assert payload["pythonpath"].split(os.pathsep) == [
        "/pinned/site-packages", "/already/here"]


def test_it_does_not_re_exec_twice(tmp_path):
    """The marker is the only thing standing between a misconfigured
    receipt and a fork bomb of execve calls."""
    data = _receipt(tmp_path, _fake_interpreter(tmp_path))
    result = _run(data, env_extra={MARKER: "1"})
    assert result.stdout == "", "already pinned: it must fall through, not exec"


@pytest.mark.parametrize("break_it, expected", [
    ("no_plugin_data", "PLUGIN_DATA"),
    ("no_receipt", "runtime.json"),
    ("wrong_version", "runtime.json"),
    ("world_writable", "writable"),
    ("not_executable", "executable"),
])
def test_every_failure_is_quiet_on_stdout_and_loud_on_stderr(
        tmp_path, break_it, expected):
    """stdout is the JSON-RPC channel. A single stray byte there
    desynchronises the protocol, so a failure that prints to stdout is worse
    than the failure it reports."""
    fake = _fake_interpreter(tmp_path)
    if break_it == "no_plugin_data":
        data = None
    elif break_it == "no_receipt":
        data = tmp_path / "empty"
        data.mkdir()
    elif break_it == "wrong_version":
        data = _receipt(tmp_path, fake, version=99)
    elif break_it == "world_writable":
        data = _receipt(tmp_path, fake, mode=0o666)
    else:
        notexec = tmp_path / "not-exec"
        notexec.write_text("", encoding="utf-8")
        notexec.chmod(0o644)
        data = _receipt(tmp_path, notexec)
    result = _run(data)
    assert result.returncode != 0
    assert result.stdout == "", f"wrote to stdout: {result.stdout!r}"
    assert expected in result.stderr


def test_the_receipt_checks_match_the_hook_client():
    """Two stdlib-only readers of the same file. The repo's precedent for
    that (EGRESS_EVENTS, the socket name) is to restate and pin, so this is
    the pin: the constants, and the fact that both refuse a receipt another
    user can write -- the check that makes `runtime.json` not an
    arbitrary-exec hole."""
    server = SERVER.read_text(encoding="utf-8")
    handler = (REPO / "hooks" / "handler.py").read_text(encoding="utf-8")
    for source in (server, handler):
        assert 'RECEIPT_NAME = "runtime.json"' in source
        assert "RECEIPT_VERSION = 1" in source
        assert re.search(r"st_uid\s*!=\s*os\.getuid\(\)", source)
        assert "0o022" in source
```

- [ ] **Step 2: Run them and watch them fail**

Run: `python -m pytest tests/test_mcp_launcher.py -q`
Expected: every test FAILS. Today `mcp/server.py` imports `privacy_hud` at module scope, so under a plain interpreter without the package importable it dies with `ModuleNotFoundError` — which is exactly the failure this task removes.

- [ ] **Step 3: Make module scope stdlib-only**

In `mcp/server.py`, replace the three package imports at module scope:

```python
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import-time cost is the whole point of not importing these
    from privacy_hud.ledger import Ledger
```

Move the package imports into the functions that use them:

```python
def _ledger_path() -> Path:
    """`$PLUGIN_DATA/ledger.db`, resolved the same way every other reader
    does (`local_ui_server.resolve_data_dir`). No `/tmp` default (spec §6)."""
    from privacy_hud.local_ui_server import resolve_data_dir
    data_dir = resolve_data_dir()
    if data_dir is None:
        raise SystemExit("privacy-hud mcp: PLUGIN_DATA is not set and no "
                          "Codex plugin-data directory was found")
    return data_dir / "ledger.db"


def _open_ledger() -> "Ledger":
    from privacy_hud.ledger import Ledger
    from privacy_hud.matrix.loader import load_matrix
    return Ledger(_ledger_path(), load_matrix())
```

and inside `build_app()`, after the `FastMCP` import:

```python
    from privacy_hud import mcp_tools
```

- [ ] **Step 4: Add the launcher**

Insert after the constants, before `_ledger_path`:

```python
#: `$PLUGIN_DATA/runtime.json` — written by `privacy-hud-setup`, read by
#: `hooks/handler.py` to launch the daemon and by this file to launch itself.
#: Restated rather than imported: `handler.py` inlines these checks inside
#: `_spawn_daemon`, on the path every tool call runs, and extracting them to
#: share would change the hook client for this file's benefit. The repo's
#: precedent for a fact two stdlib-only ends must share is to restate it and
#: pin both copies with one test —
#: `tests/test_mcp_launcher.py::test_the_receipt_checks_match_the_hook_client`.
RECEIPT_NAME = "runtime.json"
RECEIPT_VERSION = 1

#: Set in the child's environment before `execve`, so an entry that finds it
#: already set does not exec again. Without it, a receipt naming an
#: interpreter that re-enters this file loops until the process table gives up.
REEXEC_MARKER = "PRIVACY_HUD_MCP_REEXEC"


def _fail(message: str):
    """One line to stderr, non-zero exit, nothing on stdout.

    stdout is the JSON-RPC channel for stdio MCP: a single stray byte there
    desynchronises the framing, so an error printed to stdout is worse than
    the error it reports. I1: `message` names a cause, never a payload.
    """
    print(f"privacy-hud mcp: {message}", file=sys.stderr)
    raise SystemExit(1)


def _reexec_under_pinned_interpreter() -> None:
    """Replace this process with the interpreter `runtime.json` records.

    Codex constrains an MCP `command` to a bare executable on the host PATH
    or a `./` path inside the plugin root, and rejects `${PLUGIN_ROOT}` there
    — unlike `hooks.json`, where `$PLUGIN_ROOT` expands. The plugin's venv is
    neither, so the manifest launches host `python3` and this is how the
    process reaches an interpreter that can import `privacy_hud` and `mcp`.

    Re-exec, not `sys.path`: `mcp` depends on `pydantic`, whose core is a
    compiled extension built for one interpreter version. Borrowing the
    venv's `site-packages` from a different host `python3` is a binary
    mismatch waiting for the two versions to differ.

    Returns only when already running under the pinned interpreter. Otherwise
    `execve` replaces the process and this never returns.
    """
    if os.environ.get(REEXEC_MARKER):
        return
    data_dir = os.environ.get("PLUGIN_DATA")
    if not data_dir:
        _fail("PLUGIN_DATA is not set; Codex did not launch this, or the "
              "plugin is not installed")
    try:
        with open(os.path.join(data_dir, RECEIPT_NAME)) as handle:
            # This file names a program about to be executed, so who can
            # write it matters — `handler.py` carries the same check and the
            # same reasoning. `fstat` on the open handle, not `stat` on the
            # path: the check must describe the bytes actually read.
            info = os.fstat(handle.fileno())
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                _fail(f"{RECEIPT_NAME} is writable by others; refusing to "
                      "execute the interpreter it names")
            receipt = json.load(handle)
        if not isinstance(receipt, dict) or receipt.get("v") != RECEIPT_VERSION:
            raise ValueError("unusable receipt")
        python = receipt["python"]
        if not isinstance(python, str) or not python:
            raise ValueError("unusable receipt")
    except (OSError, ValueError, KeyError) as exc:
        _fail(f"no usable {RECEIPT_NAME} ({type(exc).__name__}); "
              "run privacy-hud-setup")
    if not os.access(python, os.X_OK) or os.path.isdir(python):
        _fail("the recorded interpreter is not executable; run privacy-hud-setup")

    env = dict(os.environ)
    env[REEXEC_MARKER] = "1"
    pythonpath = receipt.get("pythonpath")
    if isinstance(pythonpath, str) and pythonpath:
        parts = [pythonpath] + [p for p in env.get("PYTHONPATH", "").split(
            os.pathsep) if p]
        seen, ordered = set(), []
        for part in parts:
            if part not in seen:
                seen.add(part)
                ordered.append(part)
        env["PYTHONPATH"] = os.pathsep.join(ordered)
    os.execve(python, [python, os.path.abspath(__file__)], env)
```

`SystemExit` inherits from `BaseException`, not `Exception`, so a `_fail` raised inside the `try` is not swallowed by its `except` clause. Do not widen that tuple.

- [ ] **Step 5: Call it first in `main`**

```python
def main() -> int:
    _reexec_under_pinned_interpreter()
    app = build_app()
    app.run(transport="stdio")
    return 0
```

- [ ] **Step 6: Run the launcher tests and watch them pass**

Run: `python -m pytest tests/test_mcp_launcher.py -q`
Expected: PASS.

- [ ] **Step 7: Prove they can fail**

Three separate breaks, each reverted after:
1. Delete the `if os.environ.get(REEXEC_MARKER): return` guard → `test_it_does_not_re_exec_twice` FAILS.
2. Change `_fail` to `print(...)` without `file=sys.stderr` → `test_every_failure_is_quiet_on_stdout_and_loud_on_stderr` FAILS on stdout.
3. Drop the `st_uid`/`0o022` check → the `world_writable` parameter FAILS.

Record each in the task report.

- [ ] **Step 8: Full suite, both ways, then commit**

```bash
python -m pytest -q
PYTHONPATH=/tmp/no-tf python -m pytest -q
ruff check . && python -m mypy
git add mcp/server.py tests/test_mcp_launcher.py
git commit -m "Launch the MCP server under the interpreter the receipt pins"
```

`python -m mypy` reports one pre-existing error in `doctor.py:1640`. That one is expected; any other is yours.

---

### Task 3: The exposed tool surface

**Files:**
- Modify: `mcp/server.py` — `build_app`
- Test: `tests/test_mcp_surface.py` (create)

**Interfaces:**
- Consumes: Task 2's `build_app()`, Task 1's `apply_policy` refusal.
- Produces: `mcp/server.py::EXPOSED_TOOLS`, a `tuple[str, ...]` of the five names, sorted. Task 5's doctor check imports nothing from here — it compares against its own copy — but the two must agree, which Task 5's test asserts.

- [ ] **Step 1: Write the failing surface test**

Create `tests/test_mcp_surface.py`:

```python
# tests/test_mcp_surface.py
"""Which tools the model can call, and why three are missing.

An MCP tool is called by the MODEL, subject only to Codex's per-tool
approval — which a user can set to approve automatically and which
`permission_mode = bypassPermissions` skips. So a tool that can loosen what
the plugin enforces is a switch handed to the actor being enforced against.

This is not a claim that the model cannot disable the plugin: it has a shell
with the user's permissions and can write `settings.json` directly. The rule
is narrower. The plugin does not *hand* it a sanctioned switch, because a
helpful agent that gets blocked reaches for the documented remedy.
"""
from __future__ import annotations

import pytest

import server  # `mcp/` is on sys.path via conftest; module scope needs no SDK

WITHHELD = ("privacy.allow_once", "privacy.hud_toggle",
            "privacy.read_guard_set")


def _registered(app) -> set[str]:
    """The names FastMCP holds, through whichever accessor this SDK version
    offers.

    Pinned in one helper on purpose: the accessor is the SDK's business and
    has moved between versions, and a test file that reaches into it in four
    places breaks in four places. If none of these exist, the SDK changed —
    fix it here, and only here.
    """
    for get in (lambda: app.list_tools(), lambda: app._tool_manager.list_tools()):
        try:
            tools = get()
        except (AttributeError, TypeError):
            continue
        if hasattr(tools, "__await__"):  # an async accessor
            import asyncio
            tools = asyncio.run(tools)
        return {t.name for t in tools}
    raise AssertionError("no FastMCP accessor for the registered tools")


def test_the_server_exposes_exactly_the_five(monkeypatch, tmp_path):
    pytest.importorskip("mcp", reason="the MCP SDK is an optional extra")
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    assert _registered(server.build_app()) == set(server.EXPOSED_TOOLS)


def test_no_withheld_tool_is_registered(monkeypatch, tmp_path):
    pytest.importorskip("mcp", reason="the MCP SDK is an optional extra")
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    assert not _registered(server.build_app()) & set(WITHHELD)


def test_no_withheld_tool_is_listed_as_exposed():
    """The half of the rule that needs no SDK, so CI — which installs no
    optional extras — still enforces it. The two tests above skip there;
    this one is what actually guards the decision on every Python."""
    assert not set(server.EXPOSED_TOOLS) & set(WITHHELD)
    assert len(server.EXPOSED_TOOLS) == 5


def test_allow_once_would_block_itself(state):
    """Why `privacy.allow_once` is not merely withheld but unworkable here.

    To mint a matching token it must carry the blocked call's whole
    `tool_input`. The only default block is a credential on egress, so that
    `tool_input` holds the credential — and an MCP call IS egress
    (`codex.is_mcp_tool`), with no exemption for the plugin's own tools. The
    consent call is blocked by the thing it exists to consent to.

    If this ever stops holding, the design decision behind `EXPOSED_TOOLS`
    needs revisiting — do not delete this test to make it green.
    """
    import json as _json

    from privacy_hud import dispatch

    sid = "0199abcd-1111-2222-3333-444455556666"
    dispatch.dispatch(state, {"hook_event_name": "SessionStart",
                              "session_id": sid, "cwd": "/w", "model": "m"})
    secret = "sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm"
    blocked = {"command": f"curl https://api.example.com -H 'auth: {secret}'"}
    reply = dispatch.dispatch(state, {
        "hook_event_name": "PreToolUse", "session_id": sid, "cwd": "/w",
        "model": "m", "turn_id": "t1",
        "tool_name": "mcp__privacy-hud__privacy.allow_once",
        "tool_input": {"session_id": sid, "tool_name": "Bash",
                       "tool_input": blocked, "reviewed": True}})
    assert "deny" in _json.dumps(reply)
```

`state` is the fixture in `tests/test_dispatch_hud.py`; move it into `tests/conftest.py` only if it is not already there, and leave its existing users untouched.

`mcp/` is not a package, so `from server import ...` needs `mcp/` on `sys.path`. Add to `tests/conftest.py`:

```python
import sys
from pathlib import Path

# `mcp/server.py` is a script, not a module in a package — deliberately, so a
# top-level `mcp` package cannot shadow the real `mcp` distribution. Tests
# reach it by putting its directory on the path, not by importing `mcp.server`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp"))
```

- [ ] **Step 2: Run them and watch them fail**

Run: `python -m pytest tests/test_mcp_surface.py -q`
Expected: the first three FAIL — `EXPOSED_TOOLS` does not exist, and eight tools are registered. `test_allow_once_would_block_itself` PASSES: it pins behaviour that already holds and is the evidence behind the decision, not a change this task makes. Say so in the report.

Then run it once with the SDK hidden, to confirm the guard that matters in CI is not among the skips:

```bash
mkdir -p /tmp/no-mcp && printf 'raise ImportError("simulated CI")\n' > /tmp/no-mcp/mcp.py
PYTHONPATH=/tmp/no-mcp python -m pytest tests/test_mcp_surface.py -q
```

Expected: two skipped, and `test_no_withheld_tool_is_listed_as_exposed` still FAILS. If it skips too, the importorskip is at module scope again and CI enforces nothing.

- [ ] **Step 3: Narrow `build_app`**

Add above `build_app` in `mcp/server.py`:

```python
#: The tools the model may call, sorted. A tool belongs here only if calling
#: it cannot weaken what the plugin enforces:
#:
#:   * the four reads answer questions and change nothing;
#:   * `update_policy` only tightens — since #38 and this change its rule
#:     types are `mask`, `block_path` and `block_command`, no path removes a
#:     rule (known limit 13), and its selectors are a data type, a path or a
#:     program name, never a value, so the call carries no secret.
#:
#: Withheld, and not by oversight: `privacy.allow_once` (mints a token that
#: unblocks the call it names), `privacy.read_guard_set` (can turn the read
#: guard off) and `privacy.hud_toggle` (can hide the indicator). The last two
#: stay reachable through `$privacy read|hud on|off`, which a user types.
#: `allow_once` keeps no surface at all: see
#: `tests/test_mcp_surface.py::test_allow_once_would_block_itself`.
#:
#: `privacy-hud-doctor` compares the running server's tools against its own
#: copy of this list, so a regression fails a check a user runs.
EXPOSED_TOOLS = (
    "privacy.get_exposure_detail",
    "privacy.get_session_summary",
    "privacy.list_exposures",
    "privacy.read_guard_status",
    "privacy.update_policy",
)
```

Delete the `@app.tool` registrations for `privacy.allow_once`, `privacy.hud_toggle` and `privacy.read_guard_set` from `build_app`. Leave `mcp_tools.allow_once`, `mcp_tools.hud_set_hidden` and `mcp_tools.read_guard_set` untouched — the skill and the UI still use two of them, and `allow_once` stays for the consent flow the design doc defers.

Update the module docstring's "Exposes eight tools" paragraph to describe five and the rule, pointing at `EXPOSED_TOOLS`.

- [ ] **Step 4: Run them and watch them pass**

Run: `python -m pytest tests/test_mcp_surface.py tests/test_mcp.py -q`
Expected: PASS.

- [ ] **Step 5: Prove the surface test can fail**

Re-add the `privacy.hud_toggle` registration, run
`python -m pytest tests/test_mcp_surface.py -q`, confirm both surface tests
FAIL, then remove it again. Record it.

- [ ] **Step 6: Full suite, both ways, then commit**

```bash
python -m pytest -q
PYTHONPATH=/tmp/no-tf python -m pytest -q
ruff check .
git add mcp/server.py tests/test_mcp_surface.py tests/conftest.py
git commit -m "Expose only the MCP tools that cannot loosen protection"
```

---

### Task 4: Manifest, install extra, version 0.7.0

**Files:**
- Modify: `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json`, `pyproject.toml`
- Modify: `install.sh:254`
- Test: `tests/test_codex_facts.py`, `tests/test_install_sh.py`

**Interfaces:**
- Consumes: Task 3's `EXPOSED_TOOLS`.
- Produces: the `mcpServers` object in `.codex-plugin/plugin.json`, which Task 5's doctor check reads.

- [ ] **Step 1: Write the failing manifest test**

Append to `tests/test_codex_facts.py`:

```python
def test_the_manifest_declares_the_mcp_server_in_the_shape_codex_parses():
    """Codex warns and IGNORES an `mcpServers` value it cannot use, leaving
    the plugin loaded with hooks and skills intact — the same silent shape as
    the hooks trust gate. A typo here is invisible from inside Codex, so the
    shape is pinned here and proved live by `privacy-hud-doctor`.

    The field set comes from the 0.154.0 binary's `AgentPluginMcpServer`
    parser: a stdio server takes `command`, `args`, `env` and `cwd`, and
    nothing else. `command` must be a bare executable name or a contained
    `./` path — `${PLUGIN_ROOT}` is rejected there, which is why this runs
    host `python3` and `mcp/server.py` re-execs itself (see that file).
    """
    import json
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    manifest = json.loads(
        (repo / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    servers = manifest["mcpServers"]
    assert set(servers) == {"privacy-hud"}
    entry = servers["privacy-hud"]
    assert entry == {"command": "python3", "args": ["./mcp/server.py"],
                     "cwd": "."}
    assert (repo / "mcp" / "server.py").is_file()
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python -m pytest tests/test_codex_facts.py -q`
Expected: FAIL with `KeyError: 'mcpServers'`.

- [ ] **Step 3: Declare it, and bump the version**

`.codex-plugin/plugin.json` becomes:

```json
{
  "name": "codex-privacy-hud",
  "version": "0.7.0",
  "description": "Local-first disclosure ledger and privacy enforcement for Codex sessions",
  "skills": "./skills/",
  "hooks": "./hooks/hooks.json",
  "mcpServers": {
    "privacy-hud": {
      "command": "python3",
      "args": ["./mcp/server.py"],
      "cwd": "."
    }
  }
}
```

Set `0.7.0` in `.agents/plugins/marketplace.json` (the `codex-privacy-hud` entry) and in `pyproject.toml`.

Do **not** add a `.mcp.json` file. Declaring both forms lets one silently overwrite the other.

- [ ] **Step 4: Install the extra**

`install.sh:254` becomes:

```sh
  "$SHARE/venv/bin/pip" -q install "privacy-hud[detectors,mcp] @ git+https://github.com/$REPO"
```

- [ ] **Step 5: Write the failing install test**

Append to `tests/test_install_sh.py`, following the file's existing style for reading `install.sh`:

```python
def test_the_install_brings_the_mcp_extra():
    """Without it the server dies at `from mcp.server.fastmcp import FastMCP`
    and Codex reports nothing. The install runs before the model prompt, so a
    user who declines the model still gets the server."""
    source = (REPO / "install.sh").read_text(encoding="utf-8")
    assert "privacy-hud[detectors,mcp]" in source
    assert "privacy-hud[detectors]" not in source.replace(
        "privacy-hud[detectors,mcp]", "")
```

- [ ] **Step 6: Run the three files and watch them pass**

Run: `python -m pytest tests/test_codex_facts.py tests/test_versions.py tests/test_install_sh.py -q`
Expected: PASS.

- [ ] **Step 7: Prove the manifest test can fail**

Rename the key to `mcp_servers` (the `config.toml` spelling, and a plausible mistake), confirm the test FAILS, then restore. Record it.

- [ ] **Step 8: Full suite, both ways, then commit**

```bash
python -m pytest -q
PYTHONPATH=/tmp/no-tf python -m pytest -q
ruff check .
git add .codex-plugin/plugin.json .agents/plugins/marketplace.json pyproject.toml install.sh tests/test_codex_facts.py tests/test_install_sh.py
git commit -m "Declare the MCP server in the plugin manifest and install its extra"
```

---

### Task 5: The doctor proves it loads

**Files:**
- Modify: `src/privacy_hud/doctor.py` — add `check_mcp_server`, register it
- Test: `tests/test_doctor.py`

**Interfaces:**
- Consumes: Task 3's `EXPOSED_TOOLS` (by value, restated), Task 4's manifest key.
- Produces: `doctor.check_mcp_server(timeout: float = MCP_TIMEOUT) -> Check` and `doctor.MCP_TOOLS: tuple[str, ...]`.

- [ ] **Step 1: Read what exists first**

Read `src/privacy_hud/doctor.py::check_plugin_install` (around line 1466) and find how it resolves the installed plugin directory under `~/.codex/plugins/cache/`. If that resolution is inlined, extract it as `_installed_plugin_root() -> Path | None` and have `check_plugin_install` call it too, so there is one answer to "where did Codex put us". Do not duplicate the logic.

- [ ] **Step 2: Write the failing doctor tests**

Append to `tests/test_doctor.py`:

```python
def test_check_mcp_server_passes_on_the_exact_tool_set(monkeypatch, tmp_path):
    """The check is the runtime half of the exposure decision: it passes only
    when the running server lists exactly the tools that cannot loosen
    protection, so a regression that re-exposes `allow_once` fails something
    a user runs, not only a unit test."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS))
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.OK


def test_check_mcp_server_fails_when_the_manifest_declares_nothing(
        monkeypatch, tmp_path):
    """Codex warns and ignores a manifest without the key; nothing inside
    Codex shows the difference."""
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=list(doctor.MCP_TOOLS), declare=False)
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL
    assert check.fixes


def test_check_mcp_server_fails_on_an_extra_tool(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path,
                       tools=list(doctor.MCP_TOOLS) + ["privacy.allow_once"])
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL
    assert "privacy.allow_once" in check.summary + " ".join(check.details)


def test_check_mcp_server_fails_when_the_server_will_not_start(
        monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "_installed_plugin_root", lambda: tmp_path)
    _write_fake_plugin(tmp_path, tools=[], crash=True)
    check = doctor.check_mcp_server(timeout=30)
    assert check.status == doctor.FAIL


def test_the_doctors_tool_list_matches_the_servers(monkeypatch):
    """Two copies, one fact. The doctor cannot import `mcp/server.py` (not a
    package, and importing it would need the SDK), so it restates the list —
    and this is what stops the two drifting."""
    import server
    assert tuple(doctor.MCP_TOOLS) == tuple(server.EXPOSED_TOOLS)
```

Add the helper near the top of `tests/test_doctor.py`:

```python
def _write_fake_plugin(root, *, tools, declare=True, crash=False):
    """A plugin directory shaped like an installed one, whose `mcp/server.py`
    is a stdlib stdio MCP server answering `initialize` and `tools/list`.

    Real enough to prove the handshake, small enough to have no dependencies:
    the point is the doctor's side of the conversation, not FastMCP's.
    """
    import json
    (root / ".codex-plugin").mkdir(parents=True, exist_ok=True)
    manifest = {"name": "codex-privacy-hud", "version": "0.7.0",
                "description": "x", "skills": "./skills/",
                "hooks": "./hooks/hooks.json"}
    if declare:
        manifest["mcpServers"] = {"privacy-hud": {
            "command": "python3", "args": ["./mcp/server.py"], "cwd": "."}}
    (root / ".codex-plugin" / "plugin.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    (root / "mcp").mkdir(parents=True, exist_ok=True)
    body = "import sys; sys.exit(3)\n" if crash else f"""
import json, sys
TOOLS = {tools!r}
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": msg["id"],
            "result": {{"protocolVersion": "2024-11-05", "capabilities": {{}},
            "serverInfo": {{"name": "fake", "version": "1"}}}}}}) + "\\n")
    elif msg.get("method") == "tools/list":
        sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": msg["id"],
            "result": {{"tools": [{{"name": n, "inputSchema": {{"type": "object"}}}}
                                 for n in TOOLS]}}}}) + "\\n")
    sys.stdout.flush()
"""
    (root / "mcp" / "server.py").write_text(body, encoding="utf-8")
```

- [ ] **Step 3: Run them and watch them fail**

Run: `python -m pytest tests/test_doctor.py -q -k mcp`
Expected: FAIL — `module 'privacy_hud.doctor' has no attribute 'check_mcp_server'`.

- [ ] **Step 4: Implement the check**

Add to `src/privacy_hud/doctor.py`:

```python
#: How long the MCP probe waits for a server that has to start an interpreter
#: and open the ledger. Generous: a slow answer is a slow answer, and a
#: doctor that times out on a working server teaches users to ignore it.
MCP_TIMEOUT = 20.0

#: The tools the server is expected to expose, restated from
#: `mcp/server.py::EXPOSED_TOOLS`. Two copies because `mcp/` is not a package
#: and importing it here would drag in the optional SDK — the copies are
#: pinned together by
#: `tests/test_doctor.py::test_the_doctors_tool_list_matches_the_servers`.
MCP_TOOLS = (
    "privacy.get_exposure_detail",
    "privacy.get_session_summary",
    "privacy.list_exposures",
    "privacy.read_guard_status",
    "privacy.update_policy",
)


def _mcp_tool_names(command, cwd, env, timeout) -> list[str]:
    """Speak enough MCP over stdio to list a server's tools.

    Raw JSON-RPC rather than the `mcp` client SDK: one thing this check must
    be able to report is that the SDK is missing, which it cannot do if
    importing the SDK is how it runs.
    """
    import subprocess

    proc = subprocess.Popen(
        command, cwd=str(cwd), env=env, text=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    request = "".join(json.dumps(m) + "\n" for m in (
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "privacy-hud-doctor",
                                   "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
    try:
        out, _err = proc.communicate(request, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise TimeoutError("the server did not answer in time") from None
    for line in out.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue  # a server that logs to stdout, which ours never does
        if message.get("id") == 2 and "result" in message:
            return sorted(t["name"] for t in message["result"].get("tools", []))
    raise ValueError("the server answered nothing this check could read")


def check_mcp_server(timeout: float = MCP_TIMEOUT) -> Check:
    """Does Codex's copy of the plugin declare an MCP server, and does it run?

    This check exists because failure here is silent. Codex warns and ignores
    an `mcpServers` value it cannot parse, and a server that dies at launch
    leaves the plugin loaded with its hooks and skills intact — so from
    inside Codex, "wired" and "quietly not wired" look identical. The same
    shape as the hooks trust gate, and the reason `$privacy read status` and
    this check's neighbours exist.

    It launches the server the way Codex does — host `python3`, the installed
    plugin as `cwd`, `PLUGIN_ROOT` and `PLUGIN_DATA` in the environment — and
    compares the tools it lists against `MCP_TOOLS`. The comparison is
    `==`, not "contains": a tool that can loosen protection appearing here
    is exactly what this must catch.
    """
    root = _installed_plugin_root()
    if root is None:
        return Check("MCP server", WARN,
                     "Codex has no installed copy of this plugin to check",
                     fixes=["codex plugin install codex-privacy-hud"])
    manifest_path = root / ".codex-plugin" / "plugin.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return Check("MCP server", FAIL,
                     f"cannot read the installed manifest ({type(exc).__name__})",
                     fixes=["Reinstall: ./install.sh"])
    servers = manifest.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        return Check(
            "MCP server", FAIL,
            "the installed manifest declares no MCP server",
            details=[f"read from {manifest_path}",
                     "Codex caches a plugin by version, so a manifest change "
                     "does not reach an existing install until you reinstall."],
            fixes=["Reinstall: ./install.sh"])
    entry = next(iter(servers.values()))
    command = [entry.get("command", "python3"), *entry.get("args", [])]
    data_dir = _ledger_path()
    env = dict(os.environ)
    env["PLUGIN_ROOT"] = str(root)
    if data_dir is not None:
        env["PLUGIN_DATA"] = str(data_dir.parent)
    try:
        names = _mcp_tool_names(command, root, env, timeout)
    except (OSError, ValueError, TimeoutError) as exc:
        return Check("MCP server", FAIL,
                     f"the server did not start ({type(exc).__name__})",
                     details=["Codex reports nothing when this happens: the "
                              "plugin loads, and the tools are simply absent."],
                     fixes=["Reinstall: ./install.sh",
                            "Then: privacy-hud-doctor"])
    if names != sorted(MCP_TOOLS):
        extra = sorted(set(names) - set(MCP_TOOLS))
        missing = sorted(set(MCP_TOOLS) - set(names))
        return Check(
            "MCP server", FAIL,
            "the server exposes a different set of tools than it should",
            details=([f"unexpected: {', '.join(extra)}"] if extra else [])
                    + ([f"missing: {', '.join(missing)}"] if missing else []),
            fixes=["A tool that can loosen protection must not be exposed — "
                   "see mcp/server.py::EXPOSED_TOOLS"])
    return Check("MCP server", OK,
                 f"declared and answering — {len(names)} read/tighten-only tools")
```

Register it in the `checks` list, after `("Plugin install", check_plugin_install)`:

```python
        ("MCP server", lambda: check_mcp_server(timeout)),
```

Reuse the module's existing `json` and `os` imports; add `subprocess` at module scope only if it is already imported there, otherwise keep the function-local import shown above.

- [ ] **Step 5: Run them and watch them pass**

Run: `python -m pytest tests/test_doctor.py -q`
Expected: PASS.

- [ ] **Step 6: Prove the tool-set test can fail**

Change `MCP_TOOLS` to include `"privacy.allow_once"`, run
`python -m pytest tests/test_doctor.py -q -k mcp`, confirm
`test_check_mcp_server_fails_on_an_extra_tool` and
`test_the_doctors_tool_list_matches_the_servers` FAIL, then revert. Record it.

- [ ] **Step 7: Run the doctor against the real installation**

```bash
~/.local/share/codex-privacy-hud/venv/bin/privacy-hud-doctor
```

The plugin installed in Codex is 0.5.0 while this branch is 0.7.0, so the
MCP check is expected to report that the installed manifest declares no MCP
server, with the reinstall fix. **That is the correct result, not a
failure** — record its exact output in the task report. Do not run
`./install.sh`: reinstalling is the user's call, and this branch is not
merged.

- [ ] **Step 8: Full suite, both ways, then commit**

```bash
python -m pytest -q
PYTHONPATH=/tmp/no-tf python -m pytest -q
ruff check . && python -m mypy
git add src/privacy_hud/doctor.py tests/test_doctor.py
git commit -m "Prove the MCP server loads, and exposes only what it should"
```

---

### Task 6: The review rule, and the docs

**Files:**
- Modify: `.claude/CLAUDE.md` — §5
- Modify: `README.md`, `README.zh-CN.md`
- Modify: `.claude/docs/architecture.md` §9, `.claude/docs/PRD.md` §7.5

**Interfaces:**
- Consumes: every earlier task.
- Produces: nothing code-facing.

- [ ] **Step 1: Add the review rule to CLAUDE.md §5**

Append to `.claude/CLAUDE.md` §5, after the existing bullets:

```markdown
- **Every action user-facing copy tells a user to take must be traced, before merge, to the surface that performs it.** Traced through the call, not inferred from a function existing. The block message shipped for six weeks telling users to "minimize, or allow once" through `$privacy`, which does neither; `mcp_tools.allow_once` existed, and that was mistaken for the action being available. `tests/test_copy_promises.py` catches a `$privacy` subcommand that does not exist. It cannot catch a verb in a sentence, which is what shipped, so the final whole-branch review checks this by name.
```

- [ ] **Step 2: Update `architecture.md` §9 and `PRD.md` §7.5**

In `.claude/docs/architecture.md` §9, the tool list becomes the five, with one sentence of the rule:

```markdown
Local stdio MCP server, declared in `.codex-plugin/plugin.json` as `mcpServers`
and launched by Codex as host `python3 ./mcp/server.py`; the script re-executes
itself under the interpreter `runtime.json` pins, because Codex does not expand
`${PLUGIN_ROOT}` in an MCP `command`.

It exposes only tools that cannot loosen what the plugin enforces, because an
MCP tool is called by the model: `privacy.get_session_summary`,
`privacy.list_exposures`, `privacy.get_exposure_detail`,
`privacy.read_guard_status`, `privacy.update_policy`. `privacy.allow_once`,
`privacy.read_guard_set` and `privacy.hud_toggle` are deliberately not exposed
(`mcp/server.py::EXPOSED_TOOLS`).
```

Also in `architecture.md`, the `policy` schema comment drops `allow_dest`.

In `.claude/docs/PRD.md` §7.5, replace the tool list with the same five and a pointer to the rule.

- [ ] **Step 3: Update `README.md`**

Find the sentence at `README.md:108` ("That gives Codex the `$privacy` skill, the hooks, and the MCP server, and …"). It becomes true as written; add, in the section that describes what the plugin provides, one short paragraph naming the five tools and the rule:

```markdown
The MCP tools are read-only or tightening — a session summary, the exposure
list, one exposure's detail, the read-guard state, and writing a policy rule.
Turning the read guard off, hiding the HUD, and allowing a blocked call once
are not among them: an MCP tool is called by the model, and a switch that
loosens protection is not one to hand to the thing being enforced against.
Those stay behind `$privacy`, which you type.
```

- [ ] **Step 4: Have Codex write the zh-CN prose**

zh-CN prose is written by Codex, never translated inline. Run:

```bash
codex exec "Rewrite these passages of README.zh-CN.md as natural Chinese technical writing, not a translation. Keep every code block, path, command and status-line string verbatim. Keep the known limits exactly as strong as the English. Here is the English source: <paste the English paragraphs changed in Step 3, plus the read-guard section and known limit 14 as they currently stand in README.md>. Here is the current Chinese: <paste the corresponding passages of README.zh-CN.md>."
```

Apply what it returns. Besides this task's own changes, this covers the zh-CN read-guard section and limit 14, which were written inline in #42 against house practice.

If `codex exec` is unavailable or fails, **stop and report it**. Do not write the Chinese yourself.

- [ ] **Step 5: Check the structure survived**

```bash
python -m pytest -q
ruff check .
grep -c '^' README.zh-CN.md
```

Confirm the zh-CN file still has its headings, tables and code blocks intact, and that no English paragraph was dropped rather than rewritten.

- [ ] **Step 6: Commit**

```bash
git add .claude/CLAUDE.md .claude/docs/architecture.md .claude/docs/PRD.md README.md README.zh-CN.md
git commit -m "Say what the MCP server exposes, and why three tools are missing"
```

---

## Final gates, before the branch is offered

- [ ] `python -m pytest -q` — record the count
- [ ] `PYTHONPATH=/tmp/no-tf python -m pytest -q` — record the count
- [ ] `ruff check .` — clean
- [ ] `python -m mypy` — only the pre-existing `doctor.py:1640` error
- [ ] `git log --format=%B main..HEAD | grep -iE 'co-authored-by|generated with|claude-session'` returns nothing
- [ ] Every user-visible string added or changed on this branch, listed with the surface that performs each action it names (the §5 rule, applied to this branch)
