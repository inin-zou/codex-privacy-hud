# Native Privacy Status Line Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put a `privacy` item into Codex's own status line, fed by a snapshot file the daemon writes, delivered as a separately built Codex binary that an installer places beside the official one and an uninstaller removes without trace.

**Architecture:** Six units joined by three contracts (spec §3). The daemon writes `$PLUGIN_DATA/hud/<session_id>.json` (contract A); a ~300-line patch to Codex adds `StatusLineItem::Privacy` that reads it; `ambient.py` becomes a second reader of the same file; `install.sh` writes a manifest (contract C) that `--uninstall` reverses. Every task below writes the contract test first, then the code, and the Python side is complete and shippable before any Rust is touched.

**Tech Stack:** Python 3.11+ stdlib (the plugin has zero runtime dependencies; keep it so), pytest, Rust 1.95.0 via rustup (Codex's `rust-toolchain.toml`), ratatui-based Codex TUI at tag `rust-v0.154.0`, POSIX `sh` for the installer and forwarder, GitHub Actions on `macos-14`/`macos-13`.

**Spec:** `docs/superpowers/specs/2026-09-15-patched-codex-status-line-design.md`

## Global Constraints

- **I1:** no session content, value, path or file name ever leaves the daemon. Contract A has no string fields. `render_privacy` output contains only digits, the bar glyphs, `Privacy`, `⚠`, `unverified`.
- **I2:** the runtime makes no network calls. Only `install.sh` downloads anything, once, with consent.
- **I3:** `percent` is `Ledger.summary().percent` verbatim. Never recomputed.
- **I6:** a hook never fails because of the HUD. Every `HudPublisher` call site is wrapped in `try/except Exception`.
- **Silence over wrong numbers:** every reader failure (missing, stale > 30 s, malformed, `v != 1`, `hidden`, percent outside 0–100) renders nothing.
- **`⚠unverified` means coverage has a hole.** It is never used for any other state.
- **No `/tmp` fallback anywhere.** Unset `PLUGIN_DATA` means "write nothing".
- **Bar rounding is Python's `round()`** (round-half-to-even). Rust uses `f64::round_ties_even`. `25` fills 2 cells, `35` fills 4.
- **Patch budget:** ≤ 300 lines. Four upstream files touched plus one new file.
- **The user's official `codex` binary is never modified.** The forwarder at `~/.local/bin/codex` falls through to it whenever no matching build exists.
- **Commit messages:** subject line ≤ 72 chars, body explains why. No trailers of any kind (repo policy).
- Run the suite with `python3 -m pytest -q` from the repo root. It must stay green after every task.

---

## File map

| path | responsibility | task |
|---|---|---|
| `tests/matrix/hud_snapshot.schema.json` | contract A, machine-readable | 1 |
| `tests/matrix/hud_golden.json` | bar fill + percent text per percent, shared by Python and Rust | 1 |
| `tests/test_hud_contract.py` | validates the samples and goldens against the schema; checks the patch's embedded golden copy | 1, 8 |
| `src/privacy_hud/render.py` | `hud_core(percent)`; `hud_line` built on it | 2 |
| `src/privacy_hud/hud_snapshot.py` | owner of contract A: `HudPublisher` (writer), `read_snapshot` (reader), `read_daemon_marker` | 3 |
| `tests/test_hud_snapshot.py` | writer/reader unit tests | 3 |
| `src/privacy_hud/dispatch.py` | three publish call sites + sweep | 4 |
| `tests/test_dispatch_hud.py` | drives `dispatch()` and asserts the file | 4 |
| `hooks/handler.py`, `src/privacy_hud/daemon.py`, `src/privacy_hud/local_ui_server.py`, `mcp/server.py` | `/tmp` removal | 5 |
| `tests/test_no_tmp_fallback.py` | §6 test | 5 |
| `src/privacy_hud/ambient.py` | reads contract A instead of sqlite | 6 |
| `src/privacy_hud/mcp_tools.py`, `mcp/server.py`, `skills/privacy/SKILL.md` | `$privacy hud on/off/status` | 7 |
| `patches/privacy-status-line.patch` | the Codex patch | 8 |
| `scripts/build-patched-codex.sh` | clone → apply → build → tar | 9 |
| `install.sh` | bootstrap + forwarder + manifest + uninstall | 10 |
| `tests/test_install_sh.py` | temp-HOME install/uninstall round trip | 10 |
| `.github/workflows/release-codex.yml`, `.github/workflows/patch-health.yml` | CI | 11 |
| `README.md`, `.claude/CLAUDE.md`, `.claude/docs/architecture.md`, `pyproject.toml` | docs | 12 |

---

### Task 1: Contract A schema and the shared golden file

**Files:**
- Create: `tests/matrix/hud_snapshot.schema.json`
- Create: `tests/matrix/hud_golden.json`
- Create: `tests/test_hud_contract.py`

**Interfaces:**
- Produces: the two JSON files every later task reads. Golden entry shape: `{"percent": int, "core": str}` where `core` is exactly `"<10-cell bar> <pct right-aligned to 2>%"`.

- [ ] **Step 1: Write the schema**

`tests/matrix/hud_snapshot.schema.json`:

```json
{
  "$comment": "Contract A (spec §4.1). Session snapshot the daemon writes to $PLUGIN_DATA/hud/<session_id>.json. No string fields, by design (I1).",
  "type": "object",
  "additionalProperties": false,
  "required": ["v", "percent", "blocked", "unverified", "hidden", "updated_at"],
  "properties": {
    "v": {"type": "integer", "const": 1},
    "percent": {"type": "integer", "minimum": 0, "maximum": 100},
    "blocked": {"type": "integer", "minimum": 0},
    "unverified": {"type": "boolean"},
    "hidden": {"type": "boolean"},
    "updated_at": {"type": "number", "minimum": 0}
  }
}
```

- [ ] **Step 2: Write the golden file**

Generate it from the existing renderer so the values are Python's by construction, then commit the file (never regenerate silently later — a diff here is a copy change that must be reviewed):

```bash
cd "$(git rev-parse --show-toplevel)"
PYTHONPATH=src python3 - <<'PY'
import json
from privacy_hud.render import _bar
cases = sorted({0, 1, 4, 5, 6, 10, 14, 15, 16, 25, 28, 33, 34, 35, 45, 50, 55, 63, 65, 66, 67, 75, 85, 94, 95, 96, 99, 100})
out = [{"percent": p, "core": f"{_bar(p, 10)} {p:>2}%"} for p in cases]
with open("tests/matrix/hud_golden.json", "w") as fh:
    json.dump(out, fh, ensure_ascii=False, indent=2); fh.write("\n")
PY
head -20 tests/matrix/hud_golden.json
```

Expected: 28 entries; `25` → `"██░░░░░░░░ 25%"` (2 cells, half-to-even), `35` → `"████░░░░░░ 35%"` (4 cells), `5` → `"░░░░░░░░░░  5%"`.

- [ ] **Step 3: Write the contract test**

`tests/test_hud_contract.py`:

```python
# tests/test_hud_contract.py
"""Contract A (spec §4.1) and the shared rendering golden, pinned.

Two files under tests/matrix/ are read by code in two languages. This test is
what makes a change to either of them a deliberate act: the schema is checked
with a stdlib-only validator (the plugin has no dependencies and jsonschema is
not going to become one), and the golden is checked for the two properties the
Rust side depends on -- ten cells, and Python's round-half-to-even fill.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

MATRIX = Path(__file__).parent / "matrix"
SCHEMA = json.loads((MATRIX / "hud_snapshot.schema.json").read_text())
GOLDEN = json.loads((MATRIX / "hud_golden.json").read_text())

VALID = {"v": 1, "percent": 28, "blocked": 2, "unverified": False,
         "hidden": False, "updated_at": 1757900000.0}


def validate(doc: dict, schema: dict = SCHEMA) -> list[str]:
    """Minimal validator for exactly the subset of JSON Schema the contract
    uses: object, additionalProperties=false, required, integer/number/boolean,
    const, minimum, maximum. Returns a list of problems; empty means valid."""
    problems = []
    if not isinstance(doc, dict):
        return ["not an object"]
    props = schema["properties"]
    for key in schema["required"]:
        if key not in doc:
            problems.append(f"missing {key}")
    for key in doc:
        if key not in props:
            problems.append(f"unexpected {key}")
    for key, rule in props.items():
        if key not in doc:
            continue
        val = doc[key]
        t = rule["type"]
        if t == "integer" and not (isinstance(val, int) and not isinstance(val, bool)):
            problems.append(f"{key} not integer")
        elif t == "number" and not (isinstance(val, (int, float)) and not isinstance(val, bool)):
            problems.append(f"{key} not number")
        elif t == "boolean" and not isinstance(val, bool):
            problems.append(f"{key} not boolean")
        if "const" in rule and val != rule["const"]:
            problems.append(f"{key} != {rule['const']}")
        if "minimum" in rule and isinstance(val, (int, float)) and val < rule["minimum"]:
            problems.append(f"{key} below minimum")
        if "maximum" in rule and isinstance(val, (int, float)) and val > rule["maximum"]:
            problems.append(f"{key} above maximum")
    return problems


def test_schema_accepts_the_canonical_sample():
    assert validate(VALID) == []


@pytest.mark.parametrize("mutation", [
    {"v": 2},
    {"percent": 101},
    {"percent": -1},
    {"percent": 28.5},
    {"blocked": -1},
    {"unverified": "no"},
    {"hidden": 0},
    {"updated_at": "now"},
    {"note": "hello"},          # any string field is a contract violation (I1)
])
def test_schema_rejects_each_violation(mutation):
    doc = {**VALID, **mutation}
    assert validate(doc) != []


def test_schema_has_no_string_typed_field():
    types = {k: v["type"] for k, v in SCHEMA["properties"].items()}
    assert "string" not in types.values()
    assert SCHEMA["additionalProperties"] is False


def test_golden_covers_every_rounding_tie():
    # Python's round() is half-to-even; every x5 percent is a tie and the Rust
    # port must reproduce all ten of them.
    percents = {g["percent"] for g in GOLDEN}
    assert {5, 15, 25, 35, 45, 55, 65, 75, 85, 95} <= percents
    assert {0, 100} <= percents


def test_golden_core_shape():
    for g in GOLDEN:
        bar, pct = g["core"].rsplit(" ", 1)
        assert len(bar) == 10 and set(bar) <= {"█", "░"}
        assert pct == f"{g['percent']:>2}%"
        assert bar.count("█") == round(g["percent"] / 10)
```

- [ ] **Step 4: Run the test**

Run: `python3 -m pytest tests/test_hud_contract.py -v`
Expected: all PASS (the test pins files that already exist; there is no implementation to fail against yet — this task's value is the pin).

- [ ] **Step 5: Commit**

```bash
git add tests/matrix/hud_snapshot.schema.json tests/matrix/hud_golden.json tests/test_hud_contract.py
git commit -m "test: pin contract A and the shared HUD rendering golden

The snapshot the daemon will write for the status line is read by Python
and by a Rust patch. Both read these two files, so a change to either is
a change to a cross-language contract and must fail a test first."
```

---

### Task 2: `render.hud_core` and `hud_line` rebuilt on it

**Files:**
- Modify: `src/privacy_hud/render.py:141-243`
- Test: `tests/test_render.py`

**Interfaces:**
- Produces: `hud_core(percent: int) -> str` returning exactly `f"{_bar(pct, 10)} {pct:>2}%"`. Later tasks (Rust `render_core`) reproduce this string.
- `hud_line` signature and every existing output unchanged.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_render.py`:

```python
import json
from pathlib import Path

from privacy_hud.render import hud_core

GOLDEN = json.loads((Path(__file__).parent / "matrix" / "hud_golden.json").read_text())


def test_hud_core_matches_golden_for_every_case():
    for g in GOLDEN:
        assert hud_core(g["percent"]) == g["core"], g


def test_hud_core_is_the_segment_hud_line_embeds():
    for pct in (0, 28, 63, 100):
        assert hud_core(pct) in hud_line(pct, 80)
        assert hud_core(pct) in hud_line(pct, 45)      # mid rung too


def test_hud_core_rejects_out_of_band_percent():
    with pytest.raises(Exception):
        hud_core(101)
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_render.py -k hud_core -v`
Expected: FAIL with `ImportError: cannot import name 'hud_core'`

- [ ] **Step 3: Implement**

In `src/privacy_hud/render.py`, directly above `def hud_line(`:

```python
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
```

Then in `hud_line`, replace the two 10-cell call sites:

```python
    def full():
        return f"PRIVACY  {prefix}Disclosure {hud_core(pct)}{full_tail}"

    def mid():
        return f"PRIVACY {prefix}{hud_core(pct)}{tail}"
```

(`compact()` keeps its own 5-cell `_bar(pct, 5)`; it is not part of the shared core.)

- [ ] **Step 4: Run the whole render suite**

Run: `python3 -m pytest tests/test_render.py tests/test_ambient.py -v`
Expected: all PASS, including every pre-existing `hud_line` golden.

- [ ] **Step 5: Commit**

```bash
git add src/privacy_hud/render.py tests/test_render.py
git commit -m "refactor(render): lift the bar+percent segment into hud_core

The Codex status-line patch renders the same segment in Rust. Naming it
once in Python and pinning it against the golden is what lets the two
be tested for equality instead of being eyeballed."
```

---

### Task 3: `hud_snapshot.py` — contract A's writer and reader

**Files:**
- Create: `src/privacy_hud/hud_snapshot.py`
- Create: `tests/test_hud_snapshot.py`

**Interfaces:**
- Produces:
  - `SNAPSHOT_VERSION = 1`, `STALE_AFTER = 30.0`, `SWEEP_AFTER = 4 * 3600.0`
  - `hud_dir(data_dir: Path) -> Path` = `data_dir / "hud"`
  - `snapshot_path(data_dir, session_id) -> Path` = `hud_dir / f"{session_id}.json"`; raises `ValueError` if `session_id` contains `/` or is empty
  - `class HudPublisher(data_dir: Path)` with `publish(session_id, *, percent: int, blocked: int, unverified: bool) -> None`, `set_hidden(session_id, hidden: bool) -> None`, `retire(session_id) -> None`, `sweep(max_age_s: float = SWEEP_AFTER, *, now: float | None = None) -> int`, `mark_daemon(*, unattributed_gaps: bool) -> None`
  - `@dataclass(frozen=True) Snapshot(percent: int, blocked: int, unverified: bool, hidden: bool, updated_at: float)`
  - `read_snapshot(data_dir, session_id, *, now: float | None = None) -> Snapshot | None` — `None` on missing/stale/malformed/wrong-version/out-of-range. **Not** `None` on `hidden`: the reader returns the snapshot and the *caller* decides; `ambient.py` and the Rust side both treat `hidden` as "draw nothing".
  - `read_daemon_marker(data_dir, *, now=None) -> bool | None` — reads `hud/_daemon.json` (`{"v":1,"unattributed_gaps":bool,"updated_at":float}`), `None` if missing/stale/malformed.

- [ ] **Step 1: Write the failing tests**

`tests/test_hud_snapshot.py`:

```python
# tests/test_hud_snapshot.py
"""Contract A's one writer and its Python reader (spec §4.1, §5.1).

The writer is tested for the properties readers rely on: atomicity (no reader
ever sees a partial file), schema conformance (validated with the same
stdlib validator the contract test uses), preservation of `hidden` across
`publish`, 0600/0700 modes, and a sweep that removes only what is old. The
reader is tested for the one rule that matters -- every failure is `None`.
"""
from __future__ import annotations

import json
import os
import stat
import threading
import time

import pytest

from privacy_hud import hud_snapshot as hs
from test_hud_contract import validate  # same directory; pytest adds it to sys.path

SID = "0199abcd-1111-2222-3333-444455556666"


@pytest.fixture
def data_dir(tmp_path):
    return tmp_path


def _read(data_dir, sid=SID):
    return json.loads(hs.snapshot_path(data_dir, sid).read_text())


def test_publish_writes_a_schema_valid_snapshot(data_dir):
    hs.HudPublisher(data_dir).publish(SID, percent=28, blocked=2, unverified=False)
    doc = _read(data_dir)
    assert validate(doc) == []
    assert doc["percent"] == 28 and doc["blocked"] == 2
    assert doc["hidden"] is False
    assert abs(doc["updated_at"] - time.time()) < 5


def test_publish_creates_hud_dir_0700_and_file_0600(data_dir):
    hs.HudPublisher(data_dir).publish(SID, percent=0, blocked=0, unverified=True)
    assert stat.S_IMODE(hs.hud_dir(data_dir).stat().st_mode) == 0o700
    assert stat.S_IMODE(hs.snapshot_path(data_dir, SID).stat().st_mode) == 0o600


def test_publish_preserves_hidden(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=10, blocked=0, unverified=False)
    pub.set_hidden(SID, True)
    pub.publish(SID, percent=20, blocked=1, unverified=False)
    doc = _read(data_dir)
    assert doc["hidden"] is True and doc["percent"] == 20


def test_set_hidden_on_missing_snapshot_creates_a_zero_one(data_dir):
    hs.HudPublisher(data_dir).set_hidden(SID, True)
    doc = _read(data_dir)
    assert validate(doc) == [] and doc["hidden"] is True and doc["percent"] == 0


def test_publish_is_atomic_under_a_concurrent_reader(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=0, blocked=0, unverified=False)
    stop = threading.Event()
    bad = []

    def reader():
        while not stop.is_set():
            try:
                doc = json.loads(hs.snapshot_path(data_dir, SID).read_text())
            except (ValueError, OSError) as exc:
                bad.append(repr(exc))
                continue
            if validate(doc):
                bad.append(doc)

    t = threading.Thread(target=reader)
    t.start()
    for i in range(500):
        pub.publish(SID, percent=i % 101, blocked=i, unverified=bool(i % 2))
    stop.set()
    t.join()
    assert bad == []
    assert not list(hs.hud_dir(data_dir).glob("*.tmp"))


def test_retire_removes_the_file_and_tolerates_absence(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=1, blocked=0, unverified=False)
    pub.retire(SID)
    assert not hs.snapshot_path(data_dir, SID).exists()
    pub.retire(SID)  # no raise


def test_sweep_removes_only_old_files(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish("old", percent=1, blocked=0, unverified=False)
    pub.publish("new", percent=1, blocked=0, unverified=False)
    old = hs.snapshot_path(data_dir, "old")
    past = time.time() - 5 * 3600
    os.utime(old, (past, past))
    removed = pub.sweep(now=time.time())
    assert removed == 1
    assert not old.exists() and hs.snapshot_path(data_dir, "new").exists()


@pytest.mark.parametrize("sid", ["", "../x", "a/b"])
def test_session_id_cannot_escape_hud_dir(data_dir, sid):
    with pytest.raises(ValueError):
        hs.snapshot_path(data_dir, sid)


def test_read_roundtrip(data_dir):
    hs.HudPublisher(data_dir).publish(SID, percent=63, blocked=4, unverified=True)
    snap = hs.read_snapshot(data_dir, SID)
    assert snap == hs.Snapshot(percent=63, blocked=4, unverified=True,
                               hidden=False, updated_at=snap.updated_at)


def test_read_returns_hidden_and_lets_caller_decide(data_dir):
    pub = hs.HudPublisher(data_dir)
    pub.publish(SID, percent=63, blocked=0, unverified=False)
    pub.set_hidden(SID, True)
    assert hs.read_snapshot(data_dir, SID).hidden is True


@pytest.mark.parametrize("text", [
    "", "{", "[]", '{"v": 2, "percent": 1, "blocked": 0, "unverified": false, "hidden": false, "updated_at": 1}',
    '{"v": 1, "percent": 101, "blocked": 0, "unverified": false, "hidden": false, "updated_at": 1}',
    '{"v": 1, "percent": 1, "blocked": 0, "unverified": false, "hidden": false}',
])
def test_read_returns_none_on_malformed(data_dir, text):
    hs.hud_dir(data_dir).mkdir()
    hs.snapshot_path(data_dir, SID).write_text(text)
    assert hs.read_snapshot(data_dir, SID, now=2.0) is None


def test_read_returns_none_when_stale(data_dir):
    hs.HudPublisher(data_dir).publish(SID, percent=5, blocked=0, unverified=False)
    assert hs.read_snapshot(data_dir, SID, now=time.time() + 29) is not None
    assert hs.read_snapshot(data_dir, SID, now=time.time() + 31) is None


def test_read_returns_none_when_missing(data_dir):
    assert hs.read_snapshot(data_dir, SID) is None


def test_daemon_marker_roundtrip_and_staleness(data_dir):
    pub = hs.HudPublisher(data_dir)
    assert hs.read_daemon_marker(data_dir) is None
    pub.mark_daemon(unattributed_gaps=True)
    assert hs.read_daemon_marker(data_dir) is True
    assert hs.read_daemon_marker(data_dir, now=time.time() + 31) is None


def test_snapshot_never_contains_a_string(data_dir):
    hs.HudPublisher(data_dir).publish(SID, percent=1, blocked=1, unverified=False)
    assert not any(isinstance(v, str) for v in _read(data_dir).values())
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_hud_snapshot.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'privacy_hud.hud_snapshot'`

- [ ] **Step 3: Implement**

`src/privacy_hud/hud_snapshot.py`:

```python
# src/privacy_hud/hud_snapshot.py
"""Contract A (spec §4.1): the HUD snapshot file, its one writer and its
Python reader.

`$PLUGIN_DATA/hud/<session_id>.json` carries six fields and no strings:

    {"v": 1, "percent": 28, "blocked": 2, "unverified": false,
     "hidden": false, "updated_at": 1757900000.0}

Two readers exist: `ambient.py` (this package) and the Codex status-line patch
(`privacy_status.rs`). Both apply the same rules, which live here as
constants so the Rust port can cite one source: a file older than
`STALE_AFTER` seconds is treated as absent, any schema version other than
`SNAPSHOT_VERSION` is treated as absent, and every malformed byte is treated
as absent. "Absent" renders nothing. A frozen daemon must never leave a
frozen number on screen, and a number that cannot be vouched for is never
drawn.

**Why a file, not the socket.** The Codex TUI repaints its status line often.
Asking the daemon over its unix socket on each repaint would put the HUD back
on the hook hot path that `ambient.py` deliberately stays off. A sub-kilobyte
file read is microseconds and needs no daemon to be answering.

**Why atomic.** The writer writes `<sid>.json.tmp` and `os.replace`s it. A
reader therefore sees either the old snapshot or the new one, never a
truncated one — `test_publish_is_atomic_under_a_concurrent_reader` hammers
this.

**I1.** There is nowhere to put content: the schema in
`tests/matrix/hud_snapshot.schema.json` has no string-typed field and
`additionalProperties: false`. `session_id` is the file *name*, which the
ledger already uses as a row key; it is a UUID, not content.

`_daemon.json` is a second, tiny file in the same directory with one bit the
per-session files cannot carry: whether the ledger holds hook events it
watched go by without recording (`Ledger.unattributed_gaps()`). `ambient.py`
used to open sqlite for that one question; now the daemon answers it here at
startup and readers stay sqlite-free.

Stdlib only.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

SNAPSHOT_VERSION = 1
#: A snapshot older than this many seconds is treated as absent.
STALE_AFTER = 30.0
#: `sweep()` removes snapshots older than this; matches the daemon's own
#: four-hour bound on a leaked session reference (daemon.py, "Lifetime policy").
SWEEP_AFTER = 4 * 3600.0
_DAEMON_MARKER = "_daemon.json"


def hud_dir(data_dir) -> Path:
    return Path(data_dir) / "hud"


def snapshot_path(data_dir, session_id: str) -> Path:
    """Where `session_id`'s snapshot lives. Refuses anything that could name
    a file outside `hud/`: the id is used as a file name, and a hook payload
    is untrusted input."""
    if not session_id or "/" in session_id or session_id.startswith(".") \
            or os.sep in session_id:
        raise ValueError("session_id is not a safe file name")
    return hud_dir(data_dir) / f"{session_id}.json"


@dataclass(frozen=True)
class Snapshot:
    percent: int
    blocked: int
    unverified: bool
    hidden: bool
    updated_at: float


class HudPublisher:
    """The only writer of contract A. One instance per daemon."""

    def __init__(self, data_dir) -> None:
        self.data_dir = Path(data_dir)

    # -- writing -----------------------------------------------------------

    def _write(self, path: Path, doc: dict) -> None:
        d = hud_dir(self.data_dir)
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(doc, fh, separators=(",", ":"))
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, path)

    def _current_hidden(self, session_id: str) -> bool:
        snap = read_snapshot(self.data_dir, session_id, ignore_staleness=True)
        return bool(snap.hidden) if snap else False

    def publish(self, session_id: str, *, percent: int, blocked: int,
                unverified: bool) -> None:
        percent = int(percent)
        if not 0 <= percent <= 100:
            raise ValueError("percent outside 0..100")
        doc = {"v": SNAPSHOT_VERSION, "percent": percent,
               "blocked": max(0, int(blocked)), "unverified": bool(unverified),
               "hidden": self._current_hidden(session_id),
               "updated_at": time.time()}
        self._write(snapshot_path(self.data_dir, session_id), doc)

    def set_hidden(self, session_id: str, hidden: bool) -> None:
        """Contract B. Flips `hidden`, refreshes `updated_at`, changes nothing
        else. On a session with no snapshot yet, writes a zero one so the
        preference is not lost."""
        snap = read_snapshot(self.data_dir, session_id, ignore_staleness=True)
        doc = {"v": SNAPSHOT_VERSION,
               "percent": snap.percent if snap else 0,
               "blocked": snap.blocked if snap else 0,
               "unverified": snap.unverified if snap else False,
               "hidden": bool(hidden), "updated_at": time.time()}
        self._write(snapshot_path(self.data_dir, session_id), doc)

    def retire(self, session_id: str) -> None:
        try:
            snapshot_path(self.data_dir, session_id).unlink()
        except (FileNotFoundError, ValueError):
            pass

    def sweep(self, max_age_s: float = SWEEP_AFTER, *,
              now: float | None = None) -> int:
        """Delete snapshots (and stray `.tmp` files) older than `max_age_s`.
        Returns how many were removed. Never raises."""
        now = time.time() if now is None else now
        removed = 0
        d = hud_dir(self.data_dir)
        if not d.is_dir():
            return 0
        for p in d.iterdir():
            if p.name == _DAEMON_MARKER:
                continue
            try:
                if p.name.endswith(".tmp") or now - p.stat().st_mtime > max_age_s:
                    p.unlink()
                    removed += 1
            except OSError:
                continue
        return removed

    def mark_daemon(self, *, unattributed_gaps: bool) -> None:
        self._write(hud_dir(self.data_dir) / _DAEMON_MARKER,
                    {"v": SNAPSHOT_VERSION,
                     "unattributed_gaps": bool(unattributed_gaps),
                     "updated_at": time.time()})


# -- reading -----------------------------------------------------------------

def _load(path: Path) -> dict | None:
    try:
        with open(path, "rb") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("v") != SNAPSHOT_VERSION:
        return None
    return doc


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def read_snapshot(data_dir, session_id: str, *, now: float | None = None,
                  ignore_staleness: bool = False) -> Snapshot | None:
    """Contract A's reader. `None` for every failure: missing, unreadable,
    malformed, wrong version, out-of-range, or stale (unless
    `ignore_staleness`, which only the writer uses to carry `hidden` across
    a restart). `hidden` is returned, not folded into `None`, so a caller
    can distinguish "nothing to show" from "asked not to show"."""
    try:
        path = snapshot_path(data_dir, session_id)
    except ValueError:
        return None
    doc = _load(path)
    if doc is None:
        return None
    try:
        percent, blocked = doc["percent"], doc["blocked"]
        unverified, hidden, updated_at = doc["unverified"], doc["hidden"], doc["updated_at"]
    except KeyError:
        return None
    if not (_is_int(percent) and 0 <= percent <= 100 and _is_int(blocked)
            and blocked >= 0 and isinstance(unverified, bool)
            and isinstance(hidden, bool) and _is_num(updated_at)):
        return None
    now = time.time() if now is None else now
    if not ignore_staleness and now - float(updated_at) > STALE_AFTER:
        return None
    return Snapshot(percent=percent, blocked=blocked, unverified=unverified,
                    hidden=hidden, updated_at=float(updated_at))


def read_daemon_marker(data_dir, *, now: float | None = None) -> bool | None:
    doc = _load(hud_dir(data_dir) / _DAEMON_MARKER)
    if doc is None:
        return None
    gaps, updated_at = doc.get("unattributed_gaps"), doc.get("updated_at")
    if not (isinstance(gaps, bool) and _is_num(updated_at)):
        return None
    now = time.time() if now is None else now
    if now - float(updated_at) > STALE_AFTER:
        return None
    return gaps
```

- [ ] **Step 4: Run the tests**

Run: `python3 -m pytest tests/test_hud_snapshot.py tests/test_hud_contract.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/privacy_hud/hud_snapshot.py tests/test_hud_snapshot.py
git commit -m "feat(hud): add the snapshot file the status line will read

One writer (the daemon, via HudPublisher) and one Python reader, both
implementing contract A. Atomic writes, no string fields, 30-second
staleness, and a sweep bounded like the daemon's own session lifetime."
```

---

### Task 4: Publish from `dispatch.py`

**Files:**
- Modify: `src/privacy_hud/dispatch.py` — `State` (line 130), `new_state` (176), `_handle_session_start` (603), `_handle_session_end` (619), the tail of `dispatch()` (746)
- Create: `tests/test_dispatch_hud.py`

**Interfaces:**
- Consumes: `HudPublisher` from Task 3.
- Produces: `State.hud: HudPublisher`. After `SessionStart` a zero snapshot exists; after any recorded observation the snapshot carries `summary.percent`, `summary.prevented`, `not coverage.verified`; after `SessionEnd` the file is gone. `new_state` calls `sweep()` and `mark_daemon(unattributed_gaps=...)`.

- [ ] **Step 1: Write the failing tests**

`tests/test_dispatch_hud.py`:

```python
# tests/test_dispatch_hud.py
"""The three places dispatch.py publishes contract A (spec §5.1).

Drives `dispatch()` with real hook payloads against a real State in a temp
PLUGIN_DATA and reads the snapshot back through `read_snapshot`, so what is
asserted is the end-to-end fact the status line depends on: a hook event
lands, the file changes. The last test pins I6 -- a publisher that raises
must not fail the hook.
"""
from __future__ import annotations

import pytest

from privacy_hud import dispatch, hud_snapshot as hs

SID = "0199abcd-1111-2222-3333-444455556666"


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    st = dispatch.new_state(tmp_path)
    yield st
    st.ledger.conn.close()


def _start(state, sid=SID):
    return dispatch.dispatch(state, {"hook_event_name": "SessionStart",
                                     "session_id": sid, "cwd": "/w", "model": "m"})


def _prompt(state, text, sid=SID):
    return dispatch.dispatch(state, {"hook_event_name": "UserPromptSubmit",
                                     "session_id": sid, "cwd": "/w",
                                     "prompt": text})


def test_session_start_publishes_a_zero_snapshot(state, tmp_path):
    _start(state)
    snap = hs.read_snapshot(tmp_path, SID)
    assert snap is not None and snap.percent == 0 and snap.blocked == 0


def test_an_observation_republishes_the_ledger_numbers(state, tmp_path):
    _start(state)
    _prompt(state, "my key is AKIAIOSFODNN7EXAMPLE and mail me at a@b.co")
    snap = hs.read_snapshot(tmp_path, SID)
    summary = state.ledger.summary(SID)
    coverage = state.ledger.coverage(SID)
    assert snap.percent == summary.percent
    assert snap.blocked == summary.prevented
    assert snap.unverified == (not coverage.verified)


def test_session_end_retires_the_snapshot(state, tmp_path):
    _start(state)
    dispatch.dispatch(state, {"hook_event_name": "SessionEnd", "session_id": SID})
    assert not hs.snapshot_path(tmp_path, SID).exists()


def test_new_state_marks_the_daemon_and_sweeps(tmp_path, monkeypatch):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    hs.hud_dir(tmp_path).mkdir()
    (hs.hud_dir(tmp_path) / "stray.json.tmp").write_text("{")
    st = dispatch.new_state(tmp_path)
    try:
        assert hs.read_daemon_marker(tmp_path) in (True, False)
        assert not (hs.hud_dir(tmp_path) / "stray.json.tmp").exists()
    finally:
        st.ledger.conn.close()


def test_a_broken_publisher_never_fails_the_hook(state, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(state.hud, "publish", boom)
    monkeypatch.setattr(state.hud, "retire", boom)
    assert _start(state) == dispatch._allow()
    out = _prompt(state, "hello")
    assert isinstance(out, dict)
    end = dispatch.dispatch(state, {"hook_event_name": "SessionEnd", "session_id": SID})
    assert "systemMessage" in end
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_dispatch_hud.py -v`
Expected: FAIL — `AttributeError: 'State' object has no attribute 'hud'` and `read_snapshot` returning `None`.

- [ ] **Step 3: Implement**

In `src/privacy_hud/dispatch.py`:

1. Import: `from .hud_snapshot import HudPublisher`
2. Add a field to `State` (dataclass at line 130), next to `data_dir`: `hud: HudPublisher`
3. In `new_state`, after `_record_unobserved_hooks(ledger, data_dir)`:

```python
    hud = HudPublisher(data_dir)
    try:
        hud.sweep()
        hud.mark_daemon(unattributed_gaps=bool(ledger.unattributed_gaps()))
    except Exception:
        pass  # I6: housekeeping for a display surface never blocks the daemon
```

   and pass `hud=hud` into the `State(...)` constructor.
4. Add one private helper above `_handle_session_start`:

```python
def _publish_hud(state: State, session_id: str) -> None:
    """Contract A, after a ledger change. Reads summary and coverage under
    the caller's lock and hands the numbers to the publisher. I6: any
    failure here is swallowed; a hook must never fail because a display
    file could not be written. I3: `percent` is the ledger's, verbatim."""
    try:
        summary = state.ledger.summary(session_id)
        coverage = state.ledger.coverage(session_id)
        state.hud.publish(session_id, percent=int(summary.percent),
                          blocked=int(summary.prevented),
                          unverified=not coverage.verified)
    except Exception:
        pass
```

5. In `_handle_session_start`, inside the `with state.lock:` block after `state.started_at[session_id] = time.time()`: `_publish_hud(state, session_id)`
6. In `_handle_session_end`, inside the `with state.lock:` block after `state.engines.pop(session_id, None)`:

```python
        try:
            state.hud.retire(session_id)
        except Exception:
            pass
```

7. At the tail of `dispatch()`, inside the second `with state.lock:` block after `decision = engine.observe(obs, scan=scan)`: `_publish_hud(state, session_id)`

- [ ] **Step 4: Run the tests**

Run: `python3 -m pytest tests/test_dispatch_hud.py tests/test_daemon.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/privacy_hud/dispatch.py tests/test_dispatch_hud.py
git commit -m "feat(daemon): publish the HUD snapshot on every ledger change

SessionStart writes zeros, each recorded observation rewrites the
session's numbers, SessionEnd removes the file. All three sites swallow
their own failures: the file is a display surface and I6 says a hook
never fails for one."
```

---

### Task 5: Remove the `/tmp` fallback

**Files:**
- Modify: `hooks/handler.py:271`, `src/privacy_hud/daemon.py:1266`, `src/privacy_hud/local_ui_server.py:83-87`, `mcp/server.py:69-75`
- Create: `tests/test_no_tmp_fallback.py`

**Interfaces:**
- Produces: `local_ui_server.resolve_data_dir() -> Path | None` (public, replaces the `/tmp` default; `_ledger_path()` becomes `-> Path | None`). `ambient.py` (Task 6) and `mcp/server.py` call it.
- `daemon.main()` returns `EXIT_FAILURE` (1) with one stderr line when `PLUGIN_DATA` is unset.
- `handler.main()` returns `{}` when `PLUGIN_DATA` is unset.

- [ ] **Step 1: Write the failing tests**

`tests/test_no_tmp_fallback.py`:

```python
# tests/test_no_tmp_fallback.py
"""Spec §6: without a Codex-assigned data directory, nothing is written
anywhere. The old default of `/tmp` put a ledger in a shared directory the
moment anyone ran a component by hand; the 2026-09-03 stray ledger.db beside
this repo is that failure. Each entry point is exercised with PLUGIN_DATA
unset and with the runtime resolver returning nothing, and the assertion is
on the filesystem, not on return values.
"""
from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

from privacy_hud import daemon, local_ui_server, runtime

HANDLER = Path(__file__).parents[1] / "hooks" / "handler.py"


def _snapshot(paths):
    return {p: set(os.listdir(p)) for p in paths if os.path.isdir(p)}


@pytest.fixture
def unset(monkeypatch, tmp_path):
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    monkeypatch.chdir(tmp_path)
    # No Codex install to resolve against either.
    monkeypatch.setattr(runtime, "resolve_data_dir",
                        lambda explicit=None: (None, ["no codex"], []))
    before = _snapshot(["/tmp", str(tmp_path)])
    yield tmp_path
    after = _snapshot(["/tmp", str(tmp_path)])
    new = {k: after[k] - before.get(k, set()) for k in after}
    assert not any(v for v in new.values()), new


def test_daemon_refuses_to_start(unset, capsys):
    assert daemon.main() == daemon.EXIT_FAILURE
    assert "PLUGIN_DATA" in capsys.readouterr().err


def test_handler_is_a_no_op(unset, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("handler", HANDLER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        {"hook_event_name": "UserPromptSubmit", "session_id": "x", "prompt": "hi"})))
    assert mod.main() == {}


def test_ledger_path_is_none(unset):
    assert local_ui_server.resolve_data_dir() is None
    assert local_ui_server._ledger_path() is None


def test_resolver_is_used_when_env_is_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    monkeypatch.setattr(runtime, "resolve_data_dir",
                        lambda explicit=None: (tmp_path, [], [tmp_path]))
    assert local_ui_server.resolve_data_dir() == tmp_path


def test_env_wins_when_set(monkeypatch, tmp_path):
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    assert local_ui_server.resolve_data_dir() == tmp_path
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_no_tmp_fallback.py -v`
Expected: FAIL — daemon returns something other than 1 / writes to `/tmp`; `resolve_data_dir` does not exist.

- [ ] **Step 3: Implement**

`src/privacy_hud/local_ui_server.py` — replace `_ledger_path`:

```python
def resolve_data_dir() -> Path | None:
    """The plugin-data directory, or `None`. `$PLUGIN_DATA` if set; otherwise
    the single directory Codex assigns this plugin, via `runtime`'s resolver;
    otherwise nothing. There is no `/tmp` default any more (spec §6): a
    glance-only surface run by hand must not create a ledger in a shared
    directory, and "nothing to read" is a state every caller here already
    renders as silence."""
    env = os.environ.get("PLUGIN_DATA")
    if env:
        return Path(env).expanduser()
    from . import runtime  # deferred: runtime imports doctor, which imports this module's siblings
    chosen, _notes, _candidates = runtime.resolve_data_dir()
    return chosen


def _ledger_path() -> Path | None:
    data_dir = resolve_data_dir()
    return None if data_dir is None else data_dir / "ledger.db"
```

Then find every caller of `_ledger_path()` in that file (`grep -n "_ledger_path()" src/privacy_hud/local_ui_server.py`) and guard each with `if path is None: <print one stderr line and return/exit 1>`.

`src/privacy_hud/daemon.py` `main()` — replace the first line:

```python
    raw = os.environ.get("PLUGIN_DATA")
    if not raw:
        print("privacy-hud daemon: PLUGIN_DATA is not set; refusing to start "
              "(Codex sets it for hooks; export it to run by hand)", file=sys.stderr)
        return EXIT_FAILURE
    data_dir = Path(raw)
```

`hooks/handler.py` `main()` — replace `data_dir = os.environ.get("PLUGIN_DATA", "/tmp")`:

```python
    data_dir = os.environ.get("PLUGIN_DATA")
    if not data_dir:
        return {}  # never set by Codex for a real hook; by hand, do nothing
```

and update the comment block at line ~173 that says "`PLUGIN_DATA` defaults to /tmp everywhere in this plugin" to say the default was removed and the fstat check stays as defence in depth.

`mcp/server.py` — replace `_ledger_path`:

```python
def _ledger_path() -> Path:
    """`$PLUGIN_DATA/ledger.db`, resolved the same way every other reader
    does (`local_ui_server.resolve_data_dir`). No `/tmp` default (spec §6):
    a server with nowhere to read from exits with a message rather than
    inventing an empty ledger in a shared directory."""
    from privacy_hud.local_ui_server import resolve_data_dir
    data_dir = resolve_data_dir()
    if data_dir is None:
        raise SystemExit("privacy-hud mcp: PLUGIN_DATA is not set and no Codex "
                         "plugin-data directory was found")
    return data_dir / "ledger.db"
```

- [ ] **Step 4: Run the tests**

Run: `python3 -m pytest tests/test_no_tmp_fallback.py tests/test_handler.py tests/test_daemon.py tests/test_ambient.py tests/test_mcp.py -v`
Expected: all PASS. If an existing test relied on the `/tmp` default, it now sets `PLUGIN_DATA` via `monkeypatch.setenv` in its fixture — fix the fixture, not the behaviour.

- [ ] **Step 5: Commit**

```bash
git add hooks/handler.py src/privacy_hud/daemon.py src/privacy_hud/local_ui_server.py mcp/server.py tests/test_no_tmp_fallback.py
git commit -m "fix: never fall back to /tmp when PLUGIN_DATA is unset

A component run by hand without the variable used to create a ledger in
a shared directory. Now the daemon refuses to start, the hook does
nothing, and every reader resolves the Codex-assigned directory or
reports that there is none."
```

---

### Task 6: `ambient.py` reads contract A

**Files:**
- Modify: `src/privacy_hud/ambient.py` — `_line_for` (line ~290-340), `_session_exists`, `_resolve_session_id`, imports, module docstring paragraph "Why polling the DB"
- Modify: `tests/test_ambient.py`

**Interfaces:**
- Consumes: `read_snapshot`, `read_daemon_marker` (Task 3); `local_ui_server.resolve_data_dir` (Task 5).
- Produces: unchanged CLI. `_line_for(session_id, width, *, explicit=False) -> str | None` now built from a `Snapshot`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_ambient.py` (keep the existing tests; where one builds a `Ledger` to feed `_line_for`, it now also writes a snapshot — the daemon is what turns ledger rows into snapshots, and these tests have no daemon):

```python
from privacy_hud import hud_snapshot as hs


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
```

(`import json` at the top of the test file if not already present.)

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_ambient.py -v`
Expected: the new tests FAIL (`_line_for` still opens the ledger; `test_ambient_never_opens_sqlite` raises).

- [ ] **Step 3: Implement**

In `src/privacy_hud/ambient.py`:

1. Imports: remove `from .ledger import Ledger` and `from .local_ui_server import _ledger_path`; add `from .hud_snapshot import read_daemon_marker, read_snapshot` and `from .local_ui_server import resolve_data_dir`. Keep `mcp_tools` and `Ledger` **only** inside `_resolve_session_id` (that function asks the daemon which session is live and still needs the ledger for `resolve_audit_session`; import `Ledger` locally there).
2. Delete `_session_exists` (an explicit `--session-id` with no snapshot now simply renders nothing — the same outcome, without sqlite).
3. Replace `_line_for` body:

```python
    data_dir = resolve_data_dir()
    if data_dir is None:
        return None
    if not session_id:
        # No session resolved. A daemon that recorded hook events it could
        # not attribute says so in `_daemon.json`; that is the one case a
        # session-less pane must not stay silent about (see ledger.py's
        # docstring for the incident). Anything else is "Disabled".
        if read_daemon_marker(data_dir) is True:
            return hud_line(0, width, 0, unverified=True)
        return None
    snap = read_snapshot(data_dir, session_id)
    if snap is None or snap.hidden:
        return None
    # I3: `percent` is the ledger's number, carried verbatim by the daemon.
    return hud_line(snap.percent, width, snap.blocked, unverified=snap.unverified)
```

   `explicit` stays in the signature (callers pass it) but is no longer consulted; note that in the docstring.
4. Rewrite the module docstring paragraph "**Why polling the DB rather than asking the daemon.**" to "**Why reading a file rather than asking the daemon or the DB.**" — the daemon writes `hud/<session_id>.json` (contract A, `hud_snapshot.py`) on every ledger change; this pane reads it. Same load argument as before, now with no sqlite at all in the redraw loop, and the same rules as the Codex status-line patch, which reads the same file.
5. Update the `[project.scripts]` comment for `privacy-hud-ambient` in `pyproject.toml`: it polls `$PLUGIN_DATA/hud/<session>.json`, and it is the fallback when no patched Codex build matches the installed version.

- [ ] **Step 4: Run the tests**

Run: `python3 -m pytest tests/test_ambient.py tests/test_no_tmp_fallback.py -v`
Expected: all PASS. Existing tests that constructed a `Ledger` and expected a line must now also `publish` a snapshot; adjust those fixtures.

- [ ] **Step 5: Commit**

```bash
git add src/privacy_hud/ambient.py tests/test_ambient.py pyproject.toml
git commit -m "refactor(ambient): read the HUD snapshot instead of sqlite

The pane and the Codex status-line patch now read one file with one set
of rules. The redraw loop no longer opens the ledger at all."
```

---

### Task 7: `$privacy hud on|off|status`

**Files:**
- Modify: `src/privacy_hud/mcp_tools.py` (append), `mcp/server.py` (register one tool), `skills/privacy/SKILL.md` (one subsection)
- Test: `tests/test_mcp.py`

**Interfaces:**
- Consumes: `HudPublisher.set_hidden`, `read_snapshot` (Task 3).
- Produces: `mcp_tools.hud_set_hidden(data_dir, session_id: str, hidden: bool) -> dict` and `mcp_tools.hud_status(data_dir, session_id: str) -> dict`, both returning `{"session_id": str, "present": bool, "hidden": bool | None}`. MCP tool name `privacy.hud_toggle(session_id: str, hidden: bool)`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_mcp.py`:

```python
from privacy_hud import hud_snapshot as hs
from privacy_hud.mcp_tools import hud_set_hidden, hud_status


def test_hud_status_absent_then_present(tmp_path):
    assert hud_status(tmp_path, "s1") == {"session_id": "s1", "present": False, "hidden": None}
    hs.HudPublisher(tmp_path).publish("s1", percent=3, blocked=0, unverified=False)
    assert hud_status(tmp_path, "s1") == {"session_id": "s1", "present": True, "hidden": False}


def test_hud_set_hidden_round_trip(tmp_path):
    hs.HudPublisher(tmp_path).publish("s1", percent=3, blocked=0, unverified=False)
    assert hud_set_hidden(tmp_path, "s1", True)["hidden"] is True
    assert hs.read_snapshot(tmp_path, "s1").hidden is True
    assert hud_set_hidden(tmp_path, "s1", False)["hidden"] is False
    assert hs.read_snapshot(tmp_path, "s1").percent == 3   # numbers untouched


def test_hud_toggle_output_carries_no_content(tmp_path):
    out = hud_set_hidden(tmp_path, "s1", True)
    assert set(out) == {"session_id", "present", "hidden"}
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_mcp.py -k hud -v`
Expected: FAIL with `ImportError: cannot import name 'hud_set_hidden'`

- [ ] **Step 3: Implement**

Append to `src/privacy_hud/mcp_tools.py`:

```python
# -- Level 1 toggle (spec §5.4) ---------------------------------------------

def hud_status(data_dir, session_id: str) -> dict:
    """Whether a snapshot exists for `session_id` and whether it is hidden.
    Reads contract A only; never opens the ledger."""
    from .hud_snapshot import read_snapshot
    snap = read_snapshot(data_dir, session_id, ignore_staleness=True)
    return {"session_id": session_id, "present": snap is not None,
            "hidden": None if snap is None else snap.hidden}


def hud_set_hidden(data_dir, session_id: str, hidden: bool) -> dict:
    """Contract B. `$privacy hud off` / `on`. Flips the snapshot's `hidden`
    flag and nothing else; `/statusline` in Codex is the other, independent
    switch (whether the item is configured at all). Does not touch
    config.toml."""
    from .hud_snapshot import HudPublisher
    HudPublisher(data_dir).set_hidden(session_id, bool(hidden))
    return hud_status(data_dir, session_id)
```

In `mcp/server.py`, after the `privacy.start_clean_session` tool:

```python
    @app.tool(name="privacy.hud_toggle")
    def hud_toggle(session_id: str, hidden: bool) -> dict:
        """Hide or show this session's line in the Codex status bar."""
        return mcp_tools.hud_set_hidden(_ledger_path().parent, session_id, hidden)
```

In `skills/privacy/SKILL.md`, add a subsection under `## Steps` (match the existing style of Python snippets run against `PLUGIN_DATA`):

```markdown
### `$privacy hud on|off|status`

Hides or shows this session's `Privacy …` item in the Codex status line
without leaving the session. It does not change `/statusline`; that decides
whether the item is configured, this decides whether it shows right now.

    PYTHONPATH=$PLUGIN_ROOT/src python3 -c "
    import os, sys
    from privacy_hud import mcp_tools
    d = os.environ['PLUGIN_DATA']; sid = '$SESSION_ID'
    arg = sys.argv[1]
    out = (mcp_tools.hud_status(d, sid) if arg == 'status'
           else mcp_tools.hud_set_hidden(d, sid, arg == 'off'))
    print('hidden' if out['hidden'] else 'shown' if out['present'] else 'no snapshot yet')
    " on|off|status
```

- [ ] **Step 4: Run the tests**

Run: `python3 -m pytest tests/test_mcp.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/privacy_hud/mcp_tools.py mcp/server.py skills/privacy/SKILL.md tests/test_mcp.py
git commit -m "feat(\$privacy): hud on|off|status toggles the status-line item

Flips the snapshot's hidden flag through contract B. Codex's own
/statusline remains the switch for whether the item is configured."
```

---

### Task 8: The Codex patch — `StatusLineItem::Privacy`

**Files:**
- Create: `patches/privacy-status-line.patch` (generated from a working tree, committed as a file)
- Create: `patches/README.md`
- Create in the Codex tree (inside the patch): `codex-rs/tui/src/privacy_status.rs`, `codex-rs/tui/src/privacy_status_golden.json`
- Modify in the Codex tree (inside the patch): `codex-rs/tui/src/bottom_pane/status_line_setup.rs`, `codex-rs/tui/src/bottom_pane/status_surface_preview.rs`, `codex-rs/tui/src/chatwidget/status_surfaces.rs`, `codex-rs/tui/src/chatwidget.rs`, `codex-rs/tui/src/lib.rs` (one `mod privacy_status;` line)
- Modify: `tests/test_hud_contract.py` (one test: the golden embedded in the patch equals `tests/matrix/hud_golden.json`)

**Interfaces:**
- Consumes: `tests/matrix/hud_golden.json` (Task 1).
- Produces: the patch. In Rust: `privacy_status::{PrivacyReading, PrivacyStatusSource, parse_snapshot, render_core, render_privacy, data_dir}`; `StatusLineItem::Privacy` serialized as `privacy`.

Work in a scratch clone; the plugin repo only receives the `.patch` file.

- [ ] **Step 1: Clone Codex at the pinned tag**

```bash
export CODEX_SRC=/tmp/codex-src-0.154.0
git clone --depth 1 --branch rust-v0.154.0 https://github.com/openai/codex "$CODEX_SRC"
cd "$CODEX_SRC/codex-rs"
rustup show active-toolchain     # installs 1.95.0 from rust-toolchain.toml on first use
cargo check -p codex-tui 2>&1 | tail -3   # warm the cache; several minutes the first time
```

- [ ] **Step 2: Write the Rust unit tests first (they fail to compile until step 4)**

Create `codex-rs/tui/src/privacy_status.rs` with only the test module and the golden include:

```rust
//! `privacy` status-line item: reads the Codex Privacy HUD plugin's snapshot
//! file (contract A) and renders `Privacy ███░░░░░░░ 28%`.
//!
//! No subprocess, no network, no config key beyond the item id. Every
//! failure — missing file, stale file, malformed JSON, wrong schema version,
//! `hidden`, out-of-range percent — renders nothing. The bar rounding is
//! Python's `round()` (half to even), pinned by `privacy_status_golden.json`,
//! which is a byte copy of the plugin's `tests/matrix/hud_golden.json`.

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: &str = include_str!("privacy_status_golden.json");

    fn reading(percent: u8) -> PrivacyReading {
        PrivacyReading { percent, blocked: 0, unverified: false }
    }

    #[test]
    fn render_core_matches_every_golden_case() {
        let cases: Vec<serde_json::Value> = serde_json::from_str(GOLDEN).unwrap();
        assert!(cases.len() >= 20);
        for c in cases {
            let pct = c["percent"].as_u64().unwrap() as u8;
            assert_eq!(render_core(&reading(pct)), c["core"].as_str().unwrap(), "percent {pct}");
        }
    }

    #[test]
    fn render_privacy_adds_markers_after_the_core() {
        let r = PrivacyReading { percent: 28, blocked: 2, unverified: true };
        assert_eq!(render_privacy(&r), "Privacy ███░░░░░░░ 28% ⚠2 ⚠unverified");
        assert_eq!(render_privacy(&reading(28)), "Privacy ███░░░░░░░ 28%");
    }

    fn snap(v: u64, percent: i64, hidden: bool, updated_at: f64) -> String {
        format!(r#"{{"v":{v},"percent":{percent},"blocked":1,"unverified":false,"hidden":{hidden},"updated_at":{updated_at}}}"#)
    }

    #[test]
    fn parse_accepts_a_fresh_valid_snapshot() {
        let r = parse_snapshot(&snap(1, 28, false, 1000.0), 1010.0).unwrap();
        assert_eq!(r, PrivacyReading { percent: 28, blocked: 1, unverified: false });
    }

    #[test]
    fn parse_rejects_every_failure_as_none() {
        assert!(parse_snapshot("", 0.0).is_none());
        assert!(parse_snapshot("{", 0.0).is_none());
        assert!(parse_snapshot(&snap(2, 28, false, 1000.0), 1010.0).is_none());   // version
        assert!(parse_snapshot(&snap(1, 101, false, 1000.0), 1010.0).is_none());  // range
        assert!(parse_snapshot(&snap(1, -1, false, 1000.0), 1010.0).is_none());   // range
        assert!(parse_snapshot(&snap(1, 28, true, 1000.0), 1010.0).is_none());    // hidden
        assert!(parse_snapshot(&snap(1, 28, false, 1000.0), 1031.0).is_none());   // stale (>30s)
        assert!(parse_snapshot(&snap(1, 28, false, 1000.0), 1029.0).is_some());
    }

    #[test]
    fn source_returns_none_without_a_thread_id_or_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut src = PrivacyStatusSource::with_data_dir(dir.path().to_path_buf());
        assert!(src.current(None).is_none());
        assert!(src.current(Some("nope")).is_none());
    }

    #[test]
    fn source_reads_file_and_throttles() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("hud")).unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
        std::fs::write(dir.path().join("hud/sid.json"), snap(1, 63, false, now)).unwrap();
        let mut src = PrivacyStatusSource::with_data_dir(dir.path().to_path_buf());
        assert_eq!(src.current(Some("sid")).unwrap().percent, 63);
        std::fs::write(dir.path().join("hud/sid.json"), snap(1, 64, false, now)).unwrap();
        assert_eq!(src.current(Some("sid")).unwrap().percent, 63, "cached within READ_INTERVAL");
    }
}
```

Copy the golden: `cp <plugin-repo>/tests/matrix/hud_golden.json codex-rs/tui/src/privacy_status_golden.json`.

Add `mod privacy_status;` to `codex-rs/tui/src/lib.rs` next to the other `mod` lines. Check `tempfile` is already a dev-dependency of `codex-tui` (`grep tempfile codex-rs/tui/Cargo.toml`); if not, add `tempfile = { workspace = true }` under `[dev-dependencies]` — the workspace already has it.

- [ ] **Step 3: Run to verify the tests fail to compile**

Run: `cargo test -p codex-tui privacy_status 2>&1 | tail -5`
Expected: compile errors: `cannot find type PrivacyReading`, etc.

- [ ] **Step 4: Implement the module (above the test module)**

```rust
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const SNAPSHOT_VERSION: u64 = 1;
/// Mirrors `hud_snapshot.STALE_AFTER` in the plugin.
pub(crate) const STALE_AFTER_SECS: f64 = 30.0;
/// One file read per second at most; the status line repaints far more often.
pub(crate) const READ_INTERVAL: Duration = Duration::from_secs(1);
/// `<CODEX_HOME>/plugins/data/<this dir>` is where Codex gives the plugin its `PLUGIN_DATA`.
const PLUGIN_DATA_DIRNAME: &str = "codex-privacy-hud-codex-privacy-hud";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrivacyReading {
    pub percent: u8,
    pub blocked: u32,
    pub unverified: bool,
}

/// `$PRIVACY_HUD_DATA` (tests, scratch setups) else Codex's plugin-data dir for this plugin.
pub(crate) fn data_dir() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("PRIVACY_HUD_DATA") {
        return Some(PathBuf::from(p));
    }
    let home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".codex")))?;
    Some(home.join("plugins").join("data").join(PLUGIN_DATA_DIRNAME))
}

/// Contract A → reading. `None` for every failure, including `hidden`.
pub(crate) fn parse_snapshot(text: &str, now_unix: f64) -> Option<PrivacyReading> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    if v.get("v")?.as_u64()? != SNAPSHOT_VERSION {
        return None;
    }
    if v.get("hidden")?.as_bool()? {
        return None;
    }
    let updated_at = v.get("updated_at")?.as_f64()?;
    if now_unix - updated_at > STALE_AFTER_SECS {
        return None;
    }
    let percent = v.get("percent")?.as_u64()?;
    if percent > 100 {
        return None;
    }
    let blocked = v.get("blocked")?.as_u64()?;
    let unverified = v.get("unverified")?.as_bool()?;
    Some(PrivacyReading {
        percent: percent as u8,
        blocked: blocked.min(u32::MAX as u64) as u32,
        unverified,
    })
}

/// `<10-cell bar> <pct right-aligned to 2>%` — byte-identical to the plugin's `render.hud_core`.
pub(crate) fn render_core(r: &PrivacyReading) -> String {
    // Python's round() is half-to-even; 25 → 2 cells, 35 → 4 cells.
    let filled = ((f64::from(r.percent) / 10.0).round_ties_even() as usize).clamp(0, 10);
    let bar: String = "█".repeat(filled) + &"░".repeat(10 - filled);
    format!("{bar} {:>2}%", r.percent)
}

pub(crate) fn render_privacy(r: &PrivacyReading) -> String {
    let mut s = format!("Privacy {}", render_core(r));
    if r.blocked > 0 {
        s.push_str(&format!(" ⚠{}", r.blocked));
    }
    if r.unverified {
        s.push_str(" ⚠unverified");
    }
    s
}

pub(crate) struct PrivacyStatusSource {
    dir: Option<PathBuf>,
    last_read: Option<Instant>,
    cached: Option<PrivacyReading>,
}

impl PrivacyStatusSource {
    pub(crate) fn new() -> Self {
        Self::with_data_dir_opt(data_dir())
    }

    pub(crate) fn with_data_dir(dir: PathBuf) -> Self {
        Self::with_data_dir_opt(Some(dir))
    }

    fn with_data_dir_opt(dir: Option<PathBuf>) -> Self {
        Self { dir, last_read: None, cached: None }
    }

    /// The reading to show now. At most one file read per `READ_INTERVAL`.
    pub(crate) fn current(&mut self, thread_id: Option<&str>) -> Option<PrivacyReading> {
        let thread_id = thread_id?;
        if thread_id.is_empty() || thread_id.contains('/') || thread_id.starts_with('.') {
            return None;
        }
        let now = Instant::now();
        if let Some(last) = self.last_read {
            if now.duration_since(last) < READ_INTERVAL {
                return self.cached;
            }
        }
        self.last_read = Some(now);
        let path = self.dir.as_ref()?.join("hud").join(format!("{thread_id}.json"));
        let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs_f64();
        self.cached = std::fs::read_to_string(path).ok().and_then(|t| parse_snapshot(&t, now_unix));
        self.cached
    }
}
```

- [ ] **Step 5: Run the module tests**

Run: `cargo test -p codex-tui privacy_status 2>&1 | tail -8`
Expected: `test result: ok. 6 passed`.

- [ ] **Step 6: Wire the four upstream touch points**

`codex-rs/tui/src/bottom_pane/status_line_setup.rs`:
- In `enum StatusLineItem`, after the `TaskProgress` variant (last one), add:
  ```rust
      /// Disclosure reading from the Codex Privacy HUD plugin (omitted when it is not running).
      Privacy,
  ```
- In `fn description`, add: `StatusLineItem::Privacy => "Privacy disclosure of this session (omitted when the Privacy HUD plugin is not running)",`
- In `fn preview_item`, add: `StatusLineItem::Privacy => StatusSurfacePreviewItem::Privacy,`
- Update the module doc comment list "# Available Status Line Items" (line ~10) with one bullet for `privacy`.

`codex-rs/tui/src/bottom_pane/status_surface_preview.rs`:
- Add `Privacy,` to `enum StatusSurfacePreviewItem`.
- In `fn placeholder`, add: `StatusSurfacePreviewItem::Privacy => "Privacy ███░░░░░░░ 28%",`
- If the file has any other exhaustive `match` on the enum (grep `StatusSurfacePreviewItem::TaskProgress`), add the `Privacy` arm alongside each.

`codex-rs/tui/src/chatwidget/status_surfaces.rs`:
- In `status_line_value`, after the `SessionId` arm:
  ```rust
              StatusLineItem::Privacy => {
                  let thread_id = self.thread_id.map(|id| id.to_string());
                  self.privacy_status
                      .current(thread_id.as_deref())
                      .map(|r| crate::privacy_status::render_privacy(&r))
              }
  ```
- Next to `refresh_status_line_if_workspace_headline_due`, add:
  ```rust
      pub(super) fn refresh_status_line_if_privacy_due(&mut self) {
          if self
              .status_line_items_with_invalids()
              .0
              .contains(&StatusLineItem::Privacy)
          {
              self.refresh_status_line();
              self.frame_requester
                  .schedule_frame_in(crate::privacy_status::READ_INTERVAL);
          }
      }
  ```

`codex-rs/tui/src/chatwidget.rs`:
- Add the field to the widget struct (near `status_line_workspace_headline`): `privacy_status: crate::privacy_status::PrivacyStatusSource,`
- Initialise it wherever the struct is constructed (grep `status_line_workspace_headline: None` — every constructor site): `privacy_status: crate::privacy_status::PrivacyStatusSource::new(),`
- At line ~1193, directly after `self.refresh_status_line_if_workspace_headline_due();` add `self.refresh_status_line_if_privacy_due();`

Also grep the whole tree for any other exhaustive match on `StatusLineItem` (`grep -rn "StatusLineItem::TaskProgress" codex-rs --include='*.rs'`) and add a `Privacy` arm to each; the compiler will name any you miss.

- [ ] **Step 7: Build and test the TUI crate**

```bash
cargo test -p codex-tui 2>&1 | tail -5
cargo clippy -p codex-tui -- -D warnings 2>&1 | tail -5
```

Expected: all tests pass, clippy clean. If a snapshot test enumerates picker items (`status_line_setup` tests using `insta`), accept the new snapshot with `cargo insta accept` only after reading the diff and confirming the only change is the added `privacy` row.

- [ ] **Step 8: Export the patch and pin its size**

```bash
cd "$CODEX_SRC"
git add -A codex-rs
git diff --cached --stat
git diff --cached > "<plugin-repo>/patches/privacy-status-line.patch"
wc -l "<plugin-repo>/patches/privacy-status-line.patch"
```

Expected: ≤ 300 lines excluding `privacy_status_golden.json`. Above that, stop and simplify.

- [ ] **Step 9: Pin the embedded golden and write `patches/README.md`**

Append to `tests/test_hud_contract.py`:

```python
def test_patch_embeds_the_same_golden_file():
    patch = (Path(__file__).parents[1] / "patches" / "privacy-status-line.patch").read_text()
    expected = (MATRIX / "hud_golden.json").read_text().splitlines()
    # Every line of the golden must appear as an added line in the patch.
    added = {line[1:] for line in patch.splitlines() if line.startswith("+")}
    missing = [l for l in expected if l and l not in added]
    assert missing == [], missing
```

`patches/README.md`:

```markdown
# Codex patch

`privacy-status-line.patch` adds one status-line item, `privacy`, to Codex's
TUI. It is applied to the upstream tag named in `scripts/build-patched-codex.sh`
and nothing else is changed. See `docs/superpowers/specs/2026-09-15-patched-codex-status-line-design.md` §5.3.

Regenerate against a new tag:

    git clone --depth 1 --branch rust-v<ver> https://github.com/openai/codex /tmp/codex-src
    cd /tmp/codex-src && git apply --3way ../codex-privacy-hud/patches/privacy-status-line.patch
    # resolve, cargo test -p codex-tui, then:
    git add -A && git diff --cached > ../codex-privacy-hud/patches/privacy-status-line.patch

`privacy_status_golden.json` inside the patch must stay a byte copy of
`tests/matrix/hud_golden.json`; `tests/test_hud_contract.py` checks.
```

- [ ] **Step 10: Verify the patch applies to a fresh clone and commit**

```bash
rm -rf /tmp/codex-verify && git clone -q --depth 1 --branch rust-v0.154.0 https://github.com/openai/codex /tmp/codex-verify
git -C /tmp/codex-verify apply --check "<plugin-repo>/patches/privacy-status-line.patch" && echo APPLIES
cd <plugin-repo> && python3 -m pytest tests/test_hud_contract.py -v
git add patches/ tests/test_hud_contract.py
git commit -m "feat(codex): patch adding a 'privacy' status-line item

Reads the plugin's snapshot file, renders the shared bar segment with
Python's rounding, and is omitted whenever the file is missing, stale,
hidden or malformed. Five files, no subprocess, no new config key."
```

---

### Task 9: `scripts/build-patched-codex.sh` and a laptop build

**Files:**
- Create: `scripts/build-patched-codex.sh`
- Test: `tests/test_build_script.py` (shell-level: `--help`, argument validation, and a dry run that stops before cargo)

**Interfaces:**
- Produces: `scripts/build-patched-codex.sh <codex-version> [--target <triple>] [--out <dir>] [--dry-run]` → `<out>/codex-privacy-<ver>-<triple>.tar.gz` + `.sha256`. Tarball contains one file, `codex`.

- [ ] **Step 1: Write the failing test**

`tests/test_build_script.py`:

```python
# tests/test_build_script.py
"""The build script's contract, minus cargo. `--dry-run` runs every step up
to the compile and prints the plan, so argument handling and file naming are
testable in CI without a Rust toolchain or a 20-minute build."""
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "build-patched-codex.sh"


def run(*args):
    return subprocess.run(["sh", str(SCRIPT), *args], capture_output=True, text=True)


def test_requires_a_version():
    r = run()
    assert r.returncode == 2 and "usage" in r.stderr.lower()


def test_rejects_a_non_version():
    r = run("latest")
    assert r.returncode == 2


def test_dry_run_names_tag_target_and_artifact(tmp_path):
    r = run("0.154.0", "--dry-run", "--out", str(tmp_path), "--target", "aarch64-apple-darwin")
    assert r.returncode == 0, r.stderr
    assert "rust-v0.154.0" in r.stdout
    assert "codex-privacy-0.154.0-aarch64-apple-darwin.tar.gz" in r.stdout
    assert "patches/privacy-status-line.patch" in r.stdout
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_build_script.py -v`
Expected: FAIL — script not found.

- [ ] **Step 3: Write the script**

`scripts/build-patched-codex.sh`:

```sh
#!/bin/sh
# Build a Codex binary with patches/privacy-status-line.patch applied.
# Same script on a laptop and in CI. Output: <out>/codex-privacy-<ver>-<triple>.tar.gz + .sha256
set -eu

usage() { echo "usage: $0 <codex-version> [--target <triple>] [--out <dir>] [--dry-run] [--src <dir>]" >&2; exit 2; }

[ $# -ge 1 ] || usage
VER="$1"; shift
echo "$VER" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || usage

TARGET="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
OUT="dist"; DRY=0; SRC=""
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --src) SRC="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    *) usage ;;
  esac
done
[ -n "$TARGET" ] || { echo "cannot determine target; pass --target" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PATCH="$HERE/patches/privacy-status-line.patch"
TAG="rust-v$VER"
ARTIFACT="codex-privacy-$VER-$TARGET.tar.gz"
[ -n "$SRC" ] || SRC="${TMPDIR:-/tmp}/codex-src-$VER"

echo "tag:      $TAG"
echo "patch:    patches/privacy-status-line.patch"
echo "target:   $TARGET"
echo "artifact: $OUT/$ARTIFACT"
[ "$DRY" -eq 1 ] && exit 0

[ -f "$PATCH" ] || { echo "missing $PATCH" >&2; exit 1; }
if [ ! -d "$SRC/.git" ]; then
  git clone --depth 1 --branch "$TAG" https://github.com/openai/codex "$SRC"
fi
cd "$SRC"
git checkout -q -- . && git clean -qfd codex-rs
git apply --check "$PATCH"
git apply "$PATCH"
cd codex-rs
cargo build --release -p codex-cli --target "$TARGET"
BIN="target/$TARGET/release/codex"
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 1; }
"$BIN" --version | grep -q "$VER" || { echo "built binary reports the wrong version" >&2; exit 1; }

mkdir -p "$HERE/$OUT"
tar -C "$(dirname "$BIN")" -czf "$HERE/$OUT/$ARTIFACT" codex
( cd "$HERE/$OUT" && shasum -a 256 "$ARTIFACT" > "$ARTIFACT.sha256" )
echo "built $OUT/$ARTIFACT"
```

`chmod +x scripts/build-patched-codex.sh`.

- [ ] **Step 4: Run the tests, then a real build**

Run: `python3 -m pytest tests/test_build_script.py -v` → PASS.

Then, on the laptop (this is the long step; 10–20 minutes on Apple Silicon):

```bash
scripts/build-patched-codex.sh 0.154.0 --out dist
ls -la dist/
tar -xzf dist/codex-privacy-0.154.0-aarch64-apple-darwin.tar.gz -C /tmp && /tmp/codex --version
```

Expected: `codex-cli 0.154.0`. `dist/` is git-ignored (add `dist/` to `.gitignore`).

- [ ] **Step 5: Manual integration check (document the result in the commit body)**

With the plugin installed and the daemon able to start (`privacy-hud-doctor` all OK):

```bash
PRIVACY_HUD_DATA=~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud /tmp/codex
```

Inside Codex: `/statusline` → the list contains `privacy` → enable it. Type a prompt containing a fake email. Within one second the status line shows `Privacy … %`. Note the session id shown by `/statusline`'s `session-id` item and compare it with `ls ~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud/hud/` — **they must be the same string** (spec §4.1's assumption). If they differ, stop: the daemon must additionally learn Codex's thread id, and that is a spec change to raise before continuing.

Then `$privacy hud off` → item disappears; `$privacy hud on` → returns.

- [ ] **Step 6: Commit**

```bash
git add scripts/build-patched-codex.sh tests/test_build_script.py .gitignore
git commit -m "build: script that clones, patches and packages Codex

One script for laptops and CI. Verified on 0.154.0 / aarch64-apple-darwin:
/statusline lists privacy, the item follows the snapshot within a second,
hook session_id and TUI thread id are the same string."
```

---

### Task 10: `install.sh` — bootstrap, forwarder, manifest, uninstall

**Files:**
- Create: `install.sh`
- Create: `tests/test_install_sh.py`

**Interfaces:**
- Produces: `install.sh [--yes] [--no-model] [--release-base-url URL] [--uninstall [--purge]]`. Environment for tests: `HOME`, `PATH`, `PRIVACY_HUD_FAKE=1` skips pip/model/plugin steps (2–5) so the forwarder/manifest/uninstall logic is testable without network. Manifest per spec §4.3 at `$HOME/.local/share/codex-privacy-hud/manifest.json`.

- [ ] **Step 1: Write the failing tests**

`tests/test_install_sh.py`:

```python
# tests/test_install_sh.py
"""install.sh and --uninstall in a throwaway HOME (spec §5.6).

A fake `codex` on PATH reports a version; a fake release directory served
over file:// carries a tarball for that version. PRIVACY_HUD_FAKE=1 skips the
venv, model, plugin and setup steps -- they need the network and a real
Codex -- so what is tested here is the part that touches the user's
filesystem: the forwarder, the manifest, config.toml, PATH, and that
uninstall restores the tree exactly.
"""
import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

INSTALL = Path(__file__).parents[1] / "install.sh"
VER = "0.154.0"
TRIPLE = "aarch64-apple-darwin"


def _tree(root: Path):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "home"; home.mkdir()
    bin_ = tmp_path / "officialbin"; bin_.mkdir()
    fake = bin_ / "codex"
    fake.write_text(f'#!/bin/sh\n[ "$1" = --version ] && echo "codex-cli {VER}" && exit 0\necho official "$@"\n')
    fake.chmod(0o755)
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text('model = "gpt-5.4"\n')
    (home / ".zshrc").write_text("# user rc\n")
    # a "release" the installer can download
    rel = tmp_path / "release"; rel.mkdir()
    patched = tmp_path / "codex-patched"
    patched.write_text('#!/bin/sh\necho patched "$@"\n'); patched.chmod(0o755)
    tgz = rel / f"codex-privacy-{VER}-{TRIPLE}.tar.gz"
    with tarfile.open(tgz, "w:gz") as t:
        t.add(patched, arcname="codex")
    (rel / f"{tgz.name}.sha256").write_text(f"{hashlib.sha256(tgz.read_bytes()).hexdigest()}  {tgz.name}\n")
    env = {"HOME": str(home), "PATH": f"{bin_}:/usr/bin:/bin", "SHELL": "/bin/zsh",
           "PRIVACY_HUD_FAKE": "1", "PRIVACY_HUD_TARGET": TRIPLE}
    return home, env, rel


def run(env, *args):
    return subprocess.run(["sh", str(INSTALL), *args], capture_output=True, text=True, env=env)


def test_install_then_uninstall_restores_the_tree(home):
    home, env, rel = home
    before = _tree(home)
    r = run(env, "--yes", "--release-base-url", rel.as_uri())
    assert r.returncode == 0, r.stderr
    fwd = home / ".local/bin/codex"
    assert fwd.exists() and "codex-privacy-hud forwarder" in fwd.read_text()
    assert (home / f".local/share/codex-privacy-hud/{VER}/codex").exists()
    m = json.loads((home / ".local/share/codex-privacy-hud/manifest.json").read_text())
    assert m["codex_version"] == VER and str(fwd) in m["created"]
    assert "privacy" in (home / ".codex/config.toml").read_text()
    assert "# codex-privacy-hud" in (home / ".zshrc").read_text()

    r = run(env, "--uninstall")
    assert r.returncode == 0, r.stderr
    assert _tree(home) == before
    assert (home / ".codex/config.toml").read_text() == 'model = "gpt-5.4"\n'
    assert (home / ".zshrc").read_text() == "# user rc\n"


def test_existing_tui_table_gets_only_the_key(home):
    home, env, rel = home
    cfg = home / ".codex/config.toml"
    cfg.write_text('[tui]\ntheme = "dark"\n')
    run(env, "--yes", "--release-base-url", rel.as_uri())
    assert cfg.read_text().count("[tui]") == 1 and "privacy" in cfg.read_text()
    run(env, "--uninstall")
    assert cfg.read_text() == '[tui]\ntheme = "dark"\n'


def test_forwarder_runs_patched_when_versions_match(home):
    home, env, rel = home
    run(env, "--yes", "--release-base-url", rel.as_uri())
    out = subprocess.run([str(home / ".local/bin/codex"), "hello"], capture_output=True, text=True, env=env)
    assert out.stdout.strip() == "patched hello"


def test_forwarder_falls_through_when_no_build_matches(home):
    home, env, rel = home
    run(env, "--yes", "--release-base-url", rel.as_uri())
    # simulate `brew upgrade codex`: the official binary now reports a newer version
    official = Path(env["PATH"].split(":")[0]) / "codex"
    official.write_text('#!/bin/sh\n[ "$1" = --version ] && echo "codex-cli 0.155.0" && exit 0\necho official "$@"\n')
    out = subprocess.run([str(home / ".local/bin/codex"), "hello"], capture_output=True, text=True, env=env)
    assert out.stdout.strip() == "official hello"


def test_uninstall_refuses_a_forwarder_it_did_not_write(home):
    home, env, rel = home
    run(env, "--yes", "--release-base-url", rel.as_uri())
    (home / ".local/bin/codex").write_text("#!/bin/sh\necho mine\n")
    r = run(env, "--uninstall")
    assert r.returncode != 0 and "not ours" in r.stderr
    assert (home / ".local/bin/codex").read_text() == "#!/bin/sh\necho mine\n"


def test_checksum_mismatch_aborts_before_installing(home):
    home, env, rel = home
    (rel / f"codex-privacy-{VER}-{TRIPLE}.tar.gz.sha256").write_text("0" * 64 + "  x\n")
    r = run(env, "--yes", "--release-base-url", rel.as_uri())
    assert r.returncode != 0 and "checksum" in r.stderr.lower()
    assert not (home / ".local/bin/codex").exists()


def test_missing_release_continues_without_forwarder(home):
    home, env, rel = home
    for p in rel.iterdir():
        p.unlink()
    r = run(env, "--yes", "--release-base-url", rel.as_uri())
    assert r.returncode == 0, r.stderr
    assert "no patched build" in r.stdout.lower()
    assert not (home / ".local/bin/codex").exists()
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_install_sh.py -v`
Expected: FAIL — `install.sh` missing.

- [ ] **Step 3: Write `install.sh`**

```sh
#!/bin/sh
# Codex Privacy HUD — one-command install / uninstall for macOS.
# Spec: docs/superpowers/specs/2026-09-15-patched-codex-status-line-design.md §5.6
set -eu

REPO="inin-zou/codex-privacy-hud"
BASE_URL="${PRIVACY_HUD_RELEASE_BASE_URL:-https://github.com/$REPO/releases/download}"
SHARE="$HOME/.local/share/codex-privacy-hud"
BIN="$HOME/.local/bin"
FWD="$BIN/codex"
MANIFEST="$SHARE/manifest.json"
MARK="# codex-privacy-hud"
YES=0; NO_MODEL=0; UNINSTALL=0; PURGE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1 ;;
    --no-model) NO_MODEL=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    --release-base-url) BASE_URL="$2"; shift ;;
    *) echo "usage: install.sh [--yes] [--no-model] [--release-base-url URL] | --uninstall [--purge]" >&2; exit 2 ;;
  esac
  shift
done

log() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

target() {
  [ -n "${PRIVACY_HUD_TARGET:-}" ] && { echo "$PRIVACY_HUD_TARGET"; return; }
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) echo aarch64-apple-darwin ;;
    Darwin-x86_64) echo x86_64-apple-darwin ;;
    *) die "unsupported platform $(uname -s)-$(uname -m); macOS only" ;;
  esac
}

official_codex() {
  # `command -v -a` is not POSIX (and /bin/sh on macOS rejects it); walk PATH.
  saved_ifs="$IFS"; IFS=:
  for d in $PATH; do
    [ -n "$d" ] && [ -x "$d/codex" ] && [ "$d/codex" != "$FWD" ] && { IFS="$saved_ifs"; echo "$d/codex"; return 0; }
  done
  IFS="$saved_ifs"; return 1
}

rc_file() {
  case "${SHELL:-}" in */zsh) echo "$HOME/.zshrc" ;; */bash) echo "$HOME/.bash_profile" ;; *) echo "$HOME/.profile" ;; esac
}

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" -eq 1 ]; then
  [ -f "$MANIFEST" ] || die "nothing to uninstall: $MANIFEST not found"
  if [ -f "$FWD" ]; then
    head -2 "$FWD" | grep -q "codex-privacy-hud forwarder" || die "$FWD is not ours; not removing it"
    rm -f "$FWD"; log "removed $FWD"
  fi
  # config.toml: remove "privacy" from status_line; drop the key if we created it
  CFG="$HOME/.codex/config.toml"
  if [ -f "$CFG" ] && grep -q '"privacy"' "$CFG"; then
    if grep -q '"config.toml": "status_line:created-table"' "$MANIFEST"; then
      sed -i '' -e '/^\[tui\]$/d' -e '/^status_line = .*"privacy".*$/d' "$CFG"
    elif grep -q '"config.toml": "status_line:created-key"' "$MANIFEST"; then
      sed -i '' -e '/^status_line = .*"privacy".*$/d' "$CFG"
    else
      sed -i '' -e 's/, *"privacy"//; s/"privacy", *//' "$CFG"
    fi
    log "removed privacy from status_line"
  fi
  RC="$(rc_file)"
  if [ -f "$RC" ] && grep -q "$MARK" "$RC"; then
    sed -i '' "/$MARK/d" "$RC"; log "removed PATH line from $RC"
  fi
  if [ "$PURGE" -eq 1 ]; then
    PD="$(sed -n 's/.*"plugin_data": *"\([^"]*\)".*/\1/p' "$MANIFEST")"
    MS="$(sed -n 's/.*"model_snapshot": *"\([^"]*\)".*/\1/p' "$MANIFEST")"
    [ -n "$PD" ] && [ -d "$PD" ] && rm -rf "$PD" && log "purged $PD"
    [ -n "$MS" ] && [ -d "$MS" ] && rm -rf "$MS" && log "purged $MS"
  fi
  rm -rf "$SHARE"; log "removed $SHARE"
  rmdir "$BIN" 2>/dev/null || true
  rmdir "$HOME/.local" 2>/dev/null || true
  log "codex now resolves to: $(official_codex || echo '(none found)')"
  log "the plugin itself is separate: codex plugin remove codex-privacy-hud"
  exit 0
fi

# ------------------------------------------------------------------ install
OFFICIAL="$(official_codex)" || die "codex not found on PATH; install Codex CLI first"
VER="$("$OFFICIAL" --version | awk '{print $2}')"
echo "$VER" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "cannot parse codex version from: $("$OFFICIAL" --version)"
TRIPLE="$(target)"
log "codex $VER at $OFFICIAL ($TRIPLE)"

CREATED=""; EDITED=""
add_created() { CREATED="$CREATED\"$1\","; }
add_edited() { EDITED="$EDITED\"$1\": \"$2\","; }

mkdir -p "$SHARE"
if [ "${PRIVACY_HUD_FAKE:-0}" != "1" ]; then
  command -v python3 >/dev/null || die "python3 >= 3.11 required: brew install python@3.12"
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || die "python3 >= 3.11 required: brew install python@3.12"
  log "step 2/9: creating venv and installing the plugin package (a few minutes)"
  python3 -m venv "$SHARE/venv"
  "$SHARE/venv/bin/pip" -q install --upgrade pip
  "$SHARE/venv/bin/pip" -q install "privacy-hud[detectors] @ git+https://github.com/$REPO"
  add_created "$SHARE/venv/"
  if [ "$NO_MODEL" -eq 0 ]; then
    if [ "$YES" -eq 0 ]; then
      printf 'step 3/9: download openai/privacy-filter weights (~2.8 GB, from Hugging Face, once; everything after is offline)? [y/N] '
      read -r ans; case "$ans" in y|Y) ;; *) NO_MODEL=1 ;; esac
    fi
  fi
  if [ "$NO_MODEL" -eq 0 ]; then
    "$SHARE/venv/bin/python" - <<'PY'
from huggingface_hub import snapshot_download
snapshot_download('openai/privacy-filter', allow_patterns=[
    'config.json', 'model.safetensors', 'tokenizer.json',
    'tokenizer_config.json', 'viterbi_calibration.json'])
PY
  else
    log "skipping model weights: tier 3 (names, addresses) will be unavailable"
  fi
  log "step 4/9: installing the Codex plugin"
  codex plugin marketplace add "$REPO" >/dev/null 2>&1 || true
  codex plugin add "codex-privacy-hud@codex-privacy-hud" >/dev/null 2>&1 || true
  log "step 5/9: recording the interpreter"
  "$SHARE/venv/bin/privacy-hud-setup" $( [ "$NO_MODEL" -eq 1 ] && echo --allow-degraded )
fi

log "step 6/9: fetching patched Codex $VER"
ART="codex-privacy-$VER-$TRIPLE.tar.gz"
TMP="$(mktemp -d)"
if curl -fsSL "$BASE_URL/codex-$VER-hud/$ART" -o "$TMP/$ART" 2>/dev/null || curl -fsSL "$BASE_URL/$ART" -o "$TMP/$ART" 2>/dev/null; then
  curl -fsSL "$BASE_URL/codex-$VER-hud/$ART.sha256" -o "$TMP/$ART.sha256" 2>/dev/null || curl -fsSL "$BASE_URL/$ART.sha256" -o "$TMP/$ART.sha256"
  EXPECT="$(awk '{print $1}' "$TMP/$ART.sha256")"
  ACTUAL="$(shasum -a 256 "$TMP/$ART" | awk '{print $1}')"
  [ "$EXPECT" = "$ACTUAL" ] || die "checksum mismatch for $ART; not installing"
  mkdir -p "$SHARE/$VER"
  tar -xzf "$TMP/$ART" -C "$SHARE/$VER"
  chmod +x "$SHARE/$VER/codex"
  xattr -d com.apple.quarantine "$SHARE/$VER/codex" 2>/dev/null || true
  add_created "$SHARE/$VER/"
  mkdir -p "$BIN"
  cat > "$FWD" <<'FWD'
#!/bin/sh
# codex-privacy-hud forwarder — remove with: install.sh --uninstall
self="$HOME/.local/bin/codex"
official=""
saved_ifs="$IFS"; IFS=:
for d in $PATH; do
  [ -n "$d" ] && [ -x "$d/codex" ] && [ "$d/codex" != "$self" ] && { official="$d/codex"; break; }
done
IFS="$saved_ifs"
[ -x "$official" ] || { echo "codex-privacy-hud: official codex not found" >&2; exit 127; }
ver="$("$official" --version | awk '{print $2}')"
patched="$HOME/.local/share/codex-privacy-hud/$ver/codex"
[ -x "$patched" ] && exec "$patched" "$@"
exec "$official" "$@"
FWD
  chmod +x "$FWD"; add_created "$FWD"
  log "step 7/9: forwarder at $FWD"
  case ":$PATH:" in *":$BIN:"*) ;; *)
    RC="$(rc_file)"; printf 'export PATH="$HOME/.local/bin:$PATH" %s\n' "$MARK" >> "$RC"
    add_edited "$RC" "path-line"; log "added $BIN to PATH in $RC (open a new shell)" ;;
  esac
  log "step 8/9: enabling the privacy status item"
  CFG="$HOME/.codex/config.toml"; touch "$CFG"
  if grep -q '^status_line *=' "$CFG"; then
    grep -q '"privacy"' "$CFG" || { sed -i '' 's/^\(status_line *= *\[\)/\1"privacy", /' "$CFG"; add_edited "config.toml" "status_line:privacy"; }
  elif grep -q '^\[tui\]$' "$CFG"; then
    # the table exists without the key: add only the key, right under the header
    sed -i '' '/^\[tui\]$/a\
status_line = ["model-with-reasoning", "current-dir", "privacy"]
' "$CFG"
    add_edited "config.toml" "status_line:created-key"
  else
    printf '[tui]\nstatus_line = ["model-with-reasoning", "current-dir", "privacy"]\n' >> "$CFG"
    add_edited "config.toml" "status_line:created-table"
  fi
else
  log "no patched build published for codex $VER yet; skipping the status line."
  log "the fallback pane still works: privacy-hud-ambient --watch"
fi
rm -rf "$TMP"

if [ "${PRIVACY_HUD_FAKE:-0}" != "1" ]; then
  log "step 9/9: doctor"
  "$SHARE/venv/bin/privacy-hud-doctor" || true
fi

PD="$HOME/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud"
MS="${HF_HUB_CACHE:-${HF_HOME:-$HOME/.cache/huggingface}/hub}/models--openai--privacy-filter"
cat > "$MANIFEST" <<EOF
{"v": 1, "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "codex_version": "$VER",
 "created": [${CREATED%,}],
 "edited": {${EDITED%,}},
 "plugin_data": "$PD", "model_snapshot": "$MS"}
EOF
log "done. run: codex   (then /statusline to toggle the privacy item)"
```

`chmod +x install.sh`. On Linux CI `sed -i ''` is BSD syntax; the tests run on macOS locally, and CI for this test file should use a `macos-*` runner (Task 11 adds it). Keep the script macOS-only as the spec says.

- [ ] **Step 4: Run the tests**

Run: `python3 -m pytest tests/test_install_sh.py -v`
Expected: all PASS. Then a real run on the laptop against the tarball from Task 9 uploaded to a GitHub pre-release tag `codex-0.154.0-hud.1`:

```bash
curl -fsSL https://raw.githubusercontent.com/inin-zou/codex-privacy-hud/main/install.sh | sh -s -- --yes
codex            # /statusline → privacy
sh install.sh --uninstall
command -v codex # official path again
```

- [ ] **Step 5: Commit**

```bash
git add install.sh tests/test_install_sh.py
git commit -m "feat: one-command install and uninstall for macOS

Bootstraps the venv, model, plugin and setup, fetches the patched Codex
matching the installed version, and takes over the codex name with a
forwarder that falls through to the official binary. Uninstall reverses
exactly what the manifest lists."
```

---

### Task 11: CI — release builds and patch health

**Files:**
- Create: `.github/workflows/release-codex.yml`
- Create: `.github/workflows/patch-health.yml`
- Modify: `.github/workflows/ci.yml` (add a `macos-14` leg that runs `tests/test_install_sh.py` and `tests/test_build_script.py`)

**Interfaces:**
- Consumes: `scripts/build-patched-codex.sh` (Task 9).
- Produces: on tag `codex-<ver>-hud.<n>`, a GitHub Release with `codex-privacy-<ver>-aarch64-apple-darwin.tar.gz`, `…-x86_64-apple-darwin.tar.gz` and their `.sha256`. Install URL shape used by `install.sh`: `$BASE_URL/codex-<ver>-hud/<artifact>` — so the release **tag** must be `codex-<ver>-hud` when `n` is 1; use `codex-<ver>-hud` as the tag and bump with `-hud.2` only for rebuilds, in which case `install.sh`'s first URL misses and the second (`$BASE_URL/<artifact>`, the "latest" alias) is what serves it. Set `BASE_URL` default accordingly: `https://github.com/inin-zou/codex-privacy-hud/releases/download`, and additionally publish every artifact to a rolling `latest` release.

- [ ] **Step 1: Write `release-codex.yml`**

```yaml
name: Release patched Codex

on:
  push:
    tags: ["codex-*-hud*"]

permissions:
  contents: write

jobs:
  build:
    name: build (${{ matrix.target }})
    strategy:
      fail-fast: false
      matrix:
        include:
          - { os: macos-14, target: aarch64-apple-darwin }
          - { os: macos-15-intel, target: x86_64-apple-darwin }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - name: Derive Codex version from tag
        id: ver
        run: echo "ver=$(echo '${{ github.ref_name }}' | sed -E 's/^codex-([0-9.]+)-hud.*/\1/')" >> "$GITHUB_OUTPUT"
      - uses: dtolnay/rust-toolchain@stable
        with: { toolchain: 1.95.0, targets: "${{ matrix.target }}" }
      - uses: Swatinem/rust-cache@v2
        with: { workspaces: "${{ runner.temp }}/codex-src/codex-rs" }
      - name: Build
        run: scripts/build-patched-codex.sh "${{ steps.ver.outputs.ver }}" --target "${{ matrix.target }}" --out dist --src "${{ runner.temp }}/codex-src"
      - uses: softprops/action-gh-release@v2
        with:
          files: dist/*
          prerelease: false
      - name: Also publish under the rolling 'latest' release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: latest
          name: latest
          files: dist/*
```

- [ ] **Step 2: Write `patch-health.yml`**

```yaml
name: Patch health

on:
  schedule: [{ cron: "17 6 * * *" }]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  apply-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Latest upstream tag
        id: up
        run: echo "tag=$(git ls-remote --tags --refs https://github.com/openai/codex 'rust-v*' | awk -F/ '{print $NF}' | sort -V | tail -1)" >> "$GITHUB_OUTPUT"
      - run: git clone --depth 1 --branch "${{ steps.up.outputs.tag }}" https://github.com/openai/codex /tmp/codex
      - name: Does the patch still apply?
        run: git -C /tmp/codex apply --check "$GITHUB_WORKSPACE/patches/privacy-status-line.patch"
```

- [ ] **Step 3: Extend `ci.yml`**

Add a job:

```yaml
  shell-scripts:
    name: shell scripts (macos)
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e ".[test]"
      - run: python3 -m pytest tests/test_install_sh.py tests/test_build_script.py -v
```

- [ ] **Step 4: Validate the YAML and commit**

Run: `python3 -c "import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]; print('ok')" .github/workflows/*.yml` (install `pyyaml` in the venv if missing, or use `ruby -ryaml -e 'ARGV.each{|f| YAML.load_file(f)}; puts "ok"'` which macOS ships).
Expected: `ok`.

```bash
git add .github/workflows/release-codex.yml .github/workflows/patch-health.yml .github/workflows/ci.yml
git commit -m "ci: release patched Codex builds for macOS, and check the patch daily

Tag codex-<ver>-hud to publish arm64 and x86_64 tarballs with checksums;
a daily job applies the patch to the newest upstream tag so a break is
known the day it happens."
```

Then push a tag for the first release: `git tag codex-0.154.0-hud && git push origin codex-0.154.0-hud`, and watch the two matrix jobs.

---

### Task 12: Documentation

**Files:**
- Modify: `README.md` (§"What it does" Level 1 paragraph, §"Using it in Codex", "Known limits" #5, add "Install" and "Uninstall")
- Modify: `.claude/CLAUDE.md` §5
- Modify: `.claude/docs/architecture.md` §9
- Modify: `pyproject.toml` script comments (if not done in Task 6)

- [ ] **Step 1: README**

Replace the Level 1 paragraph under "What it does" with:

```markdown
**Level 1 — Ambient.** One item in Codex's own status line, under the composer:

```text
gpt-5.4 · ~/proj · Privacy ███░░░░░░░ 28% ⚠2
```

Stock Codex has no plugin-owned status item, so this needs a Codex build
with a small patch (`patches/privacy-status-line.patch`, one added item,
nothing else). `install.sh` fetches that build for your exact Codex version
and places it beside your official binary — it never modifies the official
one — and `codex` then resolves to the patched build only while the versions
match. Toggle the item with `/statusline` inside Codex, or hide it for now
with `$privacy hud off`. Without a matching build, the fallback is a
companion pane: `privacy-hud-ambient --watch` in a second terminal.
```

Add, before "Prerequisites":

```markdown
### Install (macOS, one command)

```bash
curl -fsSL https://raw.githubusercontent.com/inin-zou/codex-privacy-hud/main/install.sh | sh
```

It creates a private virtualenv, asks before downloading the ~2.8 GB
detection model (the only network access the plugin ever causes; the
runtime itself is offline), installs the plugin into Codex, records the
interpreter, fetches the patched Codex build matching `codex --version`,
and runs `privacy-hud-doctor`. `--yes` skips the question, `--no-model`
skips the weights (names and addresses then go undetected; doctor says so).

### Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/inin-zou/codex-privacy-hud/main/install.sh | sh -s -- --uninstall
```

Removes exactly what the installer created (listed in
`~/.local/share/codex-privacy-hud/manifest.json`) and restores `codex` to
the official binary. Your disclosure ledger and the model weights stay
unless you add `--purge`. The plugin itself is removed separately with
`codex plugin remove codex-privacy-hud`.
```

Rewrite known-limits #5 to state: the status item lives in a *separately
built* Codex; what the patch is (five files, one item, no subprocess); that
the official binary is untouched; that a Codex upgrade without a matching
release silently returns you to stock Codex plus the fallback pane; and that
the build is reproducible from `scripts/build-patched-codex.sh`.

Keep the manual prerequisite/setup steps as an "Installing by hand" subsection for people who want to see each step.

- [ ] **Step 2: CLAUDE.md §5 and architecture.md §9**

In `.claude/CLAUDE.md` §5, replace the sentence forbidding claims that the plugin injects a native Codex footer with: "The plugin never modifies the user's official Codex binary. The status-line item exists only in the separately built binary from `patches/privacy-status-line.patch`; never describe it as a feature of stock Codex, and never describe the forwarder as anything other than a script that chooses between two binaries." Keep the rest of §5.

In `.claude/docs/architecture.md` §9, append a paragraph summarising spec §3 (six units, three contracts) and link the spec.

- [ ] **Step 3: Run everything and commit**

Run: `python3 -m pytest -q`
Expected: all PASS.

```bash
git add README.md .claude/CLAUDE.md .claude/docs/architecture.md pyproject.toml
git commit -m "docs: install, uninstall, and what the patched Codex build is

The README now leads with the one-command install, states the one
network access it makes and when, and says exactly what the patched
binary changes and does not change."
```

---

## Self-review

**Spec coverage.** §4.1 contract A → Tasks 1, 3, 4. §4.2 contract B → Tasks 3, 7. §4.3 contract C → Task 10. §5.1 → Tasks 3, 4. §5.2/§5.3 → Task 8. §5.4 → Task 7. §5.5 → Task 6. §5.6 build/CI/install/uninstall → Tasks 9, 10, 11. §6 `/tmp` → Task 5. §7 silence rule → tested in Tasks 3, 6, 8. §8 test table → every row has a task (integration row is Task 9 step 5). §9 docs → Task 12. §4.1's `_daemon.json` addition (needed so `ambient.py` can drop sqlite while keeping the unattributed-gaps line) is a small extension of the spec, recorded in Task 3's docstring; the spec file should gain one line for it in Task 12.

**Placeholders.** None. Every step has its code or its command.

**Type consistency.** `HudPublisher.publish(session_id, *, percent, blocked, unverified)` is used identically in Tasks 3, 4, 6, 7. `read_snapshot(data_dir, session_id, *, now=None, ignore_staleness=False)` in Tasks 3, 6, 7. `resolve_data_dir()` from `local_ui_server` in Tasks 5, 6. Rust `PrivacyStatusSource::current(Option<&str>)`, `render_privacy(&PrivacyReading)`, `READ_INTERVAL` in Task 8 only. `hud_core(percent)` in Tasks 2, 8 (as the Rust `render_core` twin).
