# Native privacy status line via a patched Codex binary — design

**Status:** Draft v1 · **Date:** 2026-09-15 · **Companion to:** `.claude/docs/design.md` §4, `.claude/docs/architecture.md` §9, README "Known limits" #5

Privacy HUD 0.9.4 retains snapshot version 2. New sessions observed from a genuine SessionStart use version-2 accounting; existing sessions and late attachments retain legacy accounting. Snapshot-v2 readers accept version 1 as explicitly legacy and version 2 with nullable accounting fields. Older snapshot-v1-only readers reject version 2 and show no Privacy item. Matching Codex version numbers do not establish snapshot compatibility.

The snapshot-v2 patched Codex builds for 0.154.0, 0.155.0, and 0.155.1 were re-released on 2026-09-22. An earlier installation of one of those versions may still contain the older reader. Updating the plugin does not replace that binary. No additional patched-Codex release is required solely for Privacy HUD 0.9.4.

The native Privacy item displays accounting snapshots; it does not verify runtime alignment. Before repair, an old daemon may continue refreshing a legacy reading. Use the bundled doctor command to check alignment. The bundled ambient launcher reports runtime failure instead of displaying a percentage.

Privacy HUD loads Python code from the selected plugin bundle. The recorded Python environment supplies dependencies. Run $privacy repair to obtain the exact recovery command for another terminal. Explicit installation may download dependencies and model weights; runtime checks and offline repair do not.

The active ledger is $PLUGIN_DATA/ledger/active.db after repair. $PLUGIN_DATA/ledger.db is a directory that fences the historical pathname. Do not replace it with a file or symlink. Repair preserves the accounting generation and recorded values; it does not activate version-2 accounting. The selected daemon activates accounting only when it receives a genuine SessionStart for an absent session.

Generation 5402 requires the activated-accounting implementation introduced in Privacy HUD 0.9.0. A live client must also match the selected runtime build and activation epoch. Unsupported or altered schemas are preserved and refused. No downgrade migration is provided.

Runtime mismatches produce an unverified warning on ingress and a denial for outbound calls the hook cannot verify. These are plugin decisions, not confirmation of host enforcement. Monitoring gaps and lost in-memory detection state cannot be reconstructed. Open version-2 sessions whose accounting keys were lost remain unavailable for the rest of those sessions.

## 1. Goal

Move the Level 1 ambient HUD from a second terminal pane into the Codex TUI
itself: one `privacy` item in Codex's own status line, under the composer,
rendering `Privacy legacy 28% · 2 prevented rows` beside other items, toggled from
inside a running session, installed and uninstalled by one command each, for
macOS users.

Stock Codex cannot do this. Its status line is a fixed list of built-in
item identifiers compiled into the binary (`codex-rs/tui/src/bottom_pane/
status_line_setup.rs`, enum `StatusLineItem`); there is no runtime registry
and no command-backed item ([openai/codex#17827], open since 2026-04-14 with
no PR). So the binary that runs must carry a patch. Everything below is
shaped by two consequences of that fact:

- The patch must be tiny and idiomatic, because it is rebased on every
  upstream release (roughly weekly).
- The user's official `codex` is never modified. We install a full,
  separately built Codex beside it and take over the `codex` *name* with a
  forwarding script that falls back to the official binary whenever we have
  no build matching its version.

Verified inputs: Codex CLI 0.153.0 on this machine, upstream latest
`rust-v0.154.0` (2026-09-09), toolchain pinned to Rust 1.95.0 by
`rust-toolchain.toml`. The prior-art patch (`anhannin/codex-hud`, February
2026) no longer applies: 6 of its 7 hunks fail against 0.154.0 and one file it
touches no longer exists. We write our own.

## 2. Non-goals

- Running arbitrary user commands from the status line (anhannin's
  `status_line_command`). Our item reads a file; no subprocess, no timeout,
  no shell.
- Windows or Linux packaging. The build script is portable; only macOS
  (arm64, x86_64) gets CI releases and an installer.
- Replacing `$privacy` (Level 2/3). Unchanged.
- Any change to what is *detected* or *counted*. This is a display layer.

## 3. Architecture

Six units, three contracts. Units know only the contracts drawn between them.

```
┌──────────────────────────────────────────────────────────────────┐
│  Codex TUI (patched binary)                                      │
│    StatusLineItem::Privacy ──reads──▶ PrivacyStatusSource         │
│                                          │ contract A: hud/<sid>.json
├──────────────────────────────────────────┼───────────────────────┤
│  privacy_hud (Python plugin)              │                       │
│    HudPublisher ◀── dispatch ◀── Engine/Ledger (existing, unchanged)
│         ▲                                                        │
│         │ contract B: HudPublisher.set_hidden(sid, bool)          │
│    mcp_tools: `$privacy hud on|off|status`                        │
│    ambient.py (fallback pane; reads contract A only)              │
├──────────────────────────────────────────────────────────────────┤
│  distribution (shell)                                            │
│    scripts/build-patched-codex.sh → release tarball               │
│    install.sh / --uninstall ──writes──▶ contract C: manifest.json │
└──────────────────────────────────────────────────────────────────┘
```

Dependency direction: Rust → A. Python → A, B. ambient.py → A.
Distribution → C. Rust and Python share no code; distribution and runtime
share no code. If upstream ships #17827, units 2 and 3 are replaced and
nothing else changes.

## 4. Contracts

### 4.1 Contract A — HUD snapshot file

Path: `$PLUGIN_DATA/hud/<session_id>.json`. Writer: the daemon, only.
Readers: the patched TUI, `ambient.py`. Readers never write.

```json
{"v": 2, "accounting_version": 1, "percent": 28,
 "confirmed_points": null, "denials_issued": null,
 "legacy_prevented_rows": 2, "unresolved_actions": null,
 "unverified": false, "hidden": false, "updated_at": 1757900000.0}
```

Exactly these ten fields are allowed. Counts are integers in `0..2^53-1`; booleans are not numbers. Percentages are null or integers in `0..100`; points are null or finite nonnegative numbers; timestamps are finite nonnegative numbers. `hidden` and `unverified` are booleans.

- Accounting 0: all five numeric reading fields null, `unverified=true`.
- Accounting 1: numeric `percent` and `legacy_prevented_rows`; points, denials, and unresolved actions null. The percent retains the legacy permitted-crossing arithmetic; rows are not calls.
- Reserved accounting 2: nonnegative points, denial and unresolved counts, null legacy count. A numeric percentage requires zero unresolved actions and `unverified=false`; a null percentage remains valid. Phase 1 does not publish accounting 2.

Updated readers also accept the exact six-field v1 document and normalize `blocked` to `legacy_prevented_rows`. The v2 schema describes the writer format; cross-field rules are enforced by both readers. The daemon marker retains its separate version 1.

Rules:

- **No string fields, ever.** I1 is enforced by the schema, the same way the
  ledger has no `content` column.
- **Atomic writes**: write `<sid>.json.tmp` then `os.replace`. A reader
  never sees a partial file.
- **Written on every change**: after each observation is recorded for the
  session, on `SessionStart` (the actual summary), and when `hidden` flips on a valid snapshot. The *numbers*
  change only on those events — never on a timer.
- **Heartbeat every 10 s** (`HudPublisher.heartbeat`, amended 2026-09-15):
  the daemon's serve loop re-stamps `updated_at` on the snapshots of every
  session it believes is live (`dispatch.State.live`, same staleness cutoff
  the lifetime policy uses) and on `_daemon.json`, preserving every reading field. A legacy v1 snapshot is normalized and rewritten as v2.
  This is not a second writer of the numbers; it is the writer saying "still
  here". Without it the staleness rule below meant "nothing has happened
  lately" rather than "the daemon is gone": a session whose user paused for
  31 s lost its status item, and `_daemon.json` — written once at startup —
  went stale half a minute in, so `ambient.py` stopped rendering the
  unattributed-gaps line for the rest of the daemon's life. 10 s leaves room
  for two missed beats inside the 30 s window, so a daemon busy with a
  tier-3 scan does not make the item blink.
- **Stale after 30 s**: a reader that finds `updated_at` older than 30 s
  treats the file as absent. Age exactly 30 s is fresh. Staleness does not establish why refresh stopped or whether ledger recording continued.
- **Deleted on `SessionEnd`**, and the whole `hud/` directory is swept of
  files older than 4 h at daemon start (matches the daemon's own leaked-
  session bound).
- File mode 0600; directory 0700.
- `session_id` is the id Codex passes to hooks. The TUI reads its own thread
  id for the lookup. The plan verifies on 0.154.0 that these are the same
  string (Task 9, step 5); the design assumes they are.
- One extra file, `hud/_daemon.json` — `{"v": 1, "unattributed_gaps": bool,
  "updated_at": float}` — written by the daemon at start. It carries the one
  bit no per-session file can: whether the ledger holds hook events it
  watched go by without recording. `ambient.py` used to open sqlite for that
  single question; with this file it opens sqlite for nothing.

### 4.2 Contract B — hide/show

`HudPublisher.set_hidden(session_id: str, hidden: bool) -> None`. Rewrites
a valid session snapshot as v2 with `hidden` changed and `updated_at` refreshed, preserving every reading field. Missing or malformed snapshots are a no-op. The `$privacy hud` skill calls the Python helper; it is not an exposed MCP tool.

### 4.3 Contract C — install manifest

Path: `~/.local/share/codex-privacy-hud/manifest.json`. Writer: `install.sh`.
Reader: `install.sh --uninstall`. Lists **only what the installer created or
edited**:

```json
{"v": 1, "installed_at": "...", "codex_version": "0.154.0",
 "created": ["~/.local/bin/codex", "~/.local/share/codex-privacy-hud/0.154.0/",
             "~/.local/share/codex-privacy-hud/venv/"],
 "edited": {"~/.zshrc": "path-line", "~/.codex/config.toml": "status_line:privacy"},
 "plugin_data": "~/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud",
 "model_snapshot": "~/.cache/huggingface/hub/models--openai--privacy-filter"}
```

Uninstall never infers; it only reverses what is listed.

## 5. Units

### 5.1 `HudPublisher` (`src/privacy_hud/hud_snapshot.py`)

- `publish(session_id, *, summary, unverified)` — writes contract A,
  preserving the current `hidden`.
- `set_hidden(session_id, hidden)` — contract B.
- `retire(session_id)` — deletes the file.
- `sweep(max_age_s=4*3600)` — startup housekeeping.
- `heartbeat(session_ids)` — re-stamps `updated_at` on each listed session's
  snapshot and on `_daemon.json`, changing nothing else (§4.1's heartbeat
  rule). Called from `daemon.Daemon`'s serve loop, not from a hook path.

Depends on `PLUGIN_DATA` only. Never opens the ledger; the caller passes
the typed summary and coverage it already has. Call sites in `dispatch.py`: after
`state.ledger.record(...)` for the session, in the `SessionStart` branch, and
in the `SessionEnd` branch. Three lines. Any exception inside the publisher
is caught there and logged; publishing must never fail a hook (I6).

### 5.2 `PrivacyStatusSource` (new, Rust, `codex-rs/tui/src/privacy_status.rs`)

```rust
pub(crate) enum PrivacyReading {
    Unrecorded,
    Legacy { percent: u8, prevented_rows: u64, unverified: bool },
    Evidence {
        percent: Option<u8>, confirmed_points: f64,
        denials_issued: u64, unresolved_actions: u64, unverified: bool,
    },
}
pub(crate) struct PrivacyStatusSource { last_read: Option<Instant>, cached: Option<PrivacyReading> }
impl PrivacyStatusSource {
    pub(crate) fn current(&mut self, thread_id: Option<&str>) -> Option<PrivacyReading>;
}
```

- Throttled to one file read per second; returns the cache between reads.
- Data dir: `$PRIVACY_HUD_DATA` if set (tests), else
  `$CODEX_HOME/plugins/data/codex-privacy-hud-codex-privacy-hud` with
  `CODEX_HOME` defaulting to `~/.codex`. The plugin id is a constant in the
  patch; it is our plugin.
- Returns `None` for: no thread id, missing file, unreadable file, JSON parse
  error, unsupported version, `hidden == true`, age greater than 30 s, wrong fields/types/ranges, or an invalid accounting-field combination. Versions 1 and 2 are supported; no partial readings.
- Never logs file contents. There are none to log, by contract A.

### 5.3 `StatusLineItem::Privacy` (patch to Codex)

Four touch points, chosen because each is a one-line addition next to an
existing sibling, which is what keeps the rebase cheap:

1. `tui/src/bottom_pane/status_line_setup.rs`: add `Privacy` to
   `StatusLineItem` (strum serializes it as `privacy`); add its
   `description()` — "Privacy HUD accounting for this session; legacy scores are labelled, and unavailable readings have no percentage"; add its `preview_item()`.
2. `tui/src/bottom_pane/status_surface_preview.rs`: add
   `StatusSurfacePreviewItem::Privacy` with placeholder
   `Privacy legacy 28%`.
3. `tui/src/chatwidget/status_surfaces.rs`: in the item → `Option<String>`
   match, `StatusLineItem::Privacy => self.privacy_status.current(thread_id)
   .map(render_privacy)`. Items here are plain strings; the current privacy line is bar-free. Colour follows Codex's existing
   `status_line_use_colors` treatment of items; per-band colour is a
   follow-up, not part of this change, because the composition API is
   string-typed.
4. `tui/src/chatwidget.rs`: one field `privacy_status: PrivacyStatusSource`,
   and a `refresh_status_line_if_privacy_due()` modelled on the existing
   `refresh_status_line_if_workspace_headline_due()`, called from the same
   place, so the item updates within a second of the file changing without a
   new timer.

`render_privacy(reading) -> String` prefixes `Privacy ` to the accounting-aware core. Legacy readings show `legacy {P}%` and an optional singular/plural prevented-row count; zero omits the count. Incomplete legacy coverage appends `⚠unverified`. Unrecorded readings show `Privacy —% · No session on record` without an extra warning suffix. Reserved accounting-2 examples are `Privacy —% · 3 unresolved · 2 denials issued` and `Privacy 28% · 2 denials issued`; Phase 1 does not publish them.

Python `hud_line(reading, width)` uses the complete candidates in `design.md` §4, rendering nothing if none fits. Rust returns the full line and Codex owns final layout. Python `hud_core(percent)` and Rust's test-only `render_bar_core(percent)` retain the numeric rounding fixture; neither supplies the current HUD text. `hud_reading_golden.json` and its byte-identical embedded Rust copy pin snapshot-to-text behavior.

`/statusline` needs no change: the picker enumerates `StatusLineItem` and
persists selections through `status_line_items_edit`. `privacy` appears in
the list, is checked or unchecked there, and the choice survives restarts.

### 5.4 `$privacy hud on|off|status` (extend `mcp_tools.py`)

The `$privacy hud` skill invokes Python helpers for contract B; no HUD toggle is exposed to the model as an MCP tool. `status` reports `shown`, `hidden`, `stale`, or `absent`. Stale means a valid snapshot has not been refreshed for more than 30 seconds; it does not establish why or whether ledger recording continued. Missing or malformed snapshots are absent. Only shown and hidden have `present=true`. `/statusline` controls configuration; `$privacy hud` changes current visibility without editing `config.toml`.

### 5.5 `ambient.py` (existing, data source only)

`_line_for()` reads contract A and passes the complete reading to `hud_line(reading, width)`. Without a resolved session, a daemon marker reporting gaps uses `unattributed_gap_line(width)` and no invented zero. `_SessionPin` and `--watch` remain. The pane is the fallback when no snapshot-compatible patched build matches the installed Codex version.

### 5.6 Distribution (`scripts/`, `install.sh`)

**`scripts/build-patched-codex.sh <codex-version>`** — one script for laptop
and CI: clone `openai/codex` at `rust-v<ver>` (shallow), `git apply --check`
then `git apply patches/privacy-status-line.patch`, `cargo build --release
-p codex-cli`, tar the binary as
`codex-privacy-<ver>-<target>.tar.gz`, write `.sha256`. rustup installs
1.95.0 from `rust-toolchain.toml` automatically.

**CI** (`.github/workflows/release-codex.yml`): on tag
`codex-<ver>-hud.<n>`, matrix `macos-14` (aarch64-apple-darwin) and
`macos-15-intel` (x86_64-apple-darwin; `macos-13` was retired on 2025-12-04), run the script, upload both tarballs and
checksums to a GitHub Release. `Swatinem/rust-cache` for dependencies.
Also a daily `git apply --check` job against the latest upstream tag so a
broken patch is known the day it breaks.

**`install.sh`** — first-run bootstrap, one command:

```
curl -fsSL https://raw.githubusercontent.com/inin-zou/codex-privacy-hud/main/install.sh | bash
```

| step | action | consent |
|---|---|---|
| 1 | require `python3 ≥ 3.11` and `codex`; print the `brew install` line and exit otherwise | – |
| 2 | create `~/.local/share/codex-privacy-hud/venv`; `pip install "codex-privacy-hud[detectors] @ git+https://github.com/inin-zou/codex-privacy-hud"` | – |
| 3 | download `openai/privacy-filter` weights, the five files README lists, with progress | **asks**; `--yes` skips the question, `--no-model` skips the download |
| 4 | `codex plugin marketplace add inin-zou/codex-privacy-hud`; `codex plugin add codex-privacy-hud@codex-privacy-hud` | – |
| 5 | `venv/bin/privacy-hud-setup` (records the interpreter) | – |
| 6 | read `codex --version`; download matching `codex-privacy-<ver>-<target>.tar.gz` + `.sha256`; verify; extract to `~/.local/share/codex-privacy-hud/<ver>/codex`; `chmod +x`; `xattr -d com.apple.quarantine` if present | – |
| 7 | write forwarding script `~/.local/bin/codex`; add `~/.local/bin` to PATH in the user's shell rc with a `# codex-privacy-hud` marker if not already on PATH | – |
| 8 | add `privacy` to `[tui].status_line` in `~/.codex/config.toml` if absent, creating the key with Codex's defaults plus `privacy` if unset | – |
| 9 | `venv/bin/privacy-hud-doctor`; print its table | – |
| 10 | write contract C | – |

Installation downloads packages and the patched Codex build; model weights are downloaded only through the explicit model-download step. Runtime, setup probes and doctor checks enforce offline mode regardless of inherited environment values and never download missing weights.

No matching release for the user's Codex version: step 6 prints which
versions exist and continues; the forwarding script then falls through to
the official binary and the user has the fallback pane.

**Forwarding script** `~/.local/bin/codex`:

```sh
#!/bin/sh
# codex-privacy-hud forwarder — remove with: install.sh --uninstall
self="$HOME/.local/bin/codex"
official=""
saved_ifs="$IFS"; IFS=:
for d in $PATH; do                            # every codex on PATH, in order
  [ -n "$d" ] && [ -x "$d/codex" ] && [ "$d/codex" != "$self" ] && { official="$d/codex"; break; }
done
IFS="$saved_ifs"
[ -x "$official" ] || { echo "codex-privacy-hud: official codex not found" >&2; exit 127; }
ver="$("$official" --version | awk '{print $2}')"
patched="$HOME/.local/share/codex-privacy-hud/$ver/codex"
[ -x "$patched" ] && exec "$patched" "$@"
exec "$official" "$@"
```

Version mismatch after `brew upgrade codex` → official binary runs
unchanged, the status item disappears, nothing breaks.

**`install.sh --uninstall [--purge]`** — reads contract C and reverses it:

1. Remove `~/.local/bin/codex` after checking its first comment line is our
   marker; refuse and explain if it is not.
2. Remove `~/.local/share/codex-privacy-hud/` (all builds, venv, manifest).
3. Remove `privacy` from `[tui].status_line`; if the installer created the
   key, remove the key.
4. Remove the marked PATH line if present.
5. Print `command -v codex` so the user sees it resolve to the official
   binary again.
6. Print, but do not run, `codex plugin remove codex-privacy-hud` — the
   plugin is a separate install and the user may want to keep the audit.
7. `--purge` additionally deletes `plugin_data` (the ledger) and
   `model_snapshot`. Without it, both stay: the ledger is the user's
   record; the weights take a long time to fetch again.

Missing entries are skipped with a note, never an abort. Order of plugin
removal and binary removal does not matter: the patched build shows nothing
without a daemon, and the plugin under stock Codex is today's behaviour.

## 6. Removing the `/tmp` fallback

Three sites default `PLUGIN_DATA` to `/tmp` when unset:
`hooks/handler.py:271`, `src/privacy_hud/daemon.py:1266`,
`src/privacy_hud/local_ui_server.py:86`. A hand-run without the variable
creates a ledger in a shared directory. The 2026-09-03 `ledger.db` and
`daemon.sock` in the parent folder of this repo are that failure with the
variable pointed at `.`.

Change: no fallback to `/tmp` anywhere.

- `handler.py`: unset → return `{}` (fail open, write nothing). Codex always
  sets it for hooks.
- `daemon.py` `main`: unset → one line on stderr, exit 2. Never start.
- `local_ui_server._ledger_path()`: unset → ask `runtime`'s existing resolver
  (Codex-assigned directory first); exactly one candidate → use it; else
  `None`, which `ambient.py` renders as silence and the UI server reports and
  exits.
- `mcp/server.py` follows whichever of the above matches its role (the plan
  checks it).

Test: with `PLUGIN_DATA` unset and no Codex state, exercising all three
paths leaves no new file under `/tmp` or the working directory.

## 7. Error handling, in one rule

**Failure is silence; a number that cannot be vouched for is never drawn.**
Missing daemon, missing file, stale file, bad JSON, wrong schema version,
version-mismatched binary: the item is omitted. `⚠unverified` keeps its one
meaning — coverage has a hole — and is never reused for "I am not sure which
session this is" (ambient.py's docstring already argues this; the Rust side
inherits it).

## 8. Testing

| layer | test |
|---|---|
| contract A | JSON Schema in `tests/matrix/hud_snapshot.schema.json`; Python writer and Rust reader each validated against it and against golden samples |
| rendering | `hud_golden.json` pins the retained numeric primitive; `hud_reading_golden.json` pins accounting-aware text in Python and the executed Rust module. Width characterization is rebaselined to the new complete candidates. |
| `HudPublisher` | atomic write (no `.tmp` visible to a concurrent reader), `hidden` preserved across `publish`, `retire`, `sweep` |
| `PrivacyStatusSource` | missing / stale / malformed / hidden / unsupported version → `None`; v1 is legacy, v2 is discriminated; age exactly 30 s is fresh; throttle returns cache within 1 s |
| `$privacy hud` | on/off/status through skill-invoked Python helpers; missing/malformed hide is a no-op |
| `ambient.py` | legacy, unrecorded, gaps, hidden, malformed, stale, and complete width candidates |
| distribution | `install.sh` then `--uninstall` in a temporary `HOME` with a fake `codex`; assert filesystem before == after; assert manifest lists every created path |
| patch health | CI `git apply --check` against latest upstream tag, daily |
| `/tmp` | §6 test |
| integration (manual, documented) | real Codex 0.154.0, plugin installed, `/statusline` shows `privacy`, item appears within 1 s of a hook event, `$privacy hud off` hides it |

## 9. Documentation changes

- README: new "Install" section (one command), "Uninstall" section,
  known-limits #5 rewritten from "cannot appear in the TUI" to "appears in
  the TUI via a separately built binary; here is exactly what that binary is
  and is not", fallback-pane paragraph, and the network-access split (§5.6).
- `.claude/CLAUDE.md` §5 updated: the claim "we do not patch the Codex
  binary" becomes "we never modify the user's official binary; we ship a
  separately built one and say so".
- `architecture.md` §9 gains this design's summary and a pointer here.

## 10. Sequencing

1. Contract A + `HudPublisher` + dispatch call sites + `/tmp` removal (Python
   only; testable without Rust).
2. `ambient.py` on contract A. At this point the fallback pane works end to
   end on the new data source.
3. Rust patch on `rust-v0.154.0`; local build via the build script; manual
   integration check.
4. `$privacy hud` toggle.
5. `install.sh` + `--uninstall` + forwarding script, tested in a temp HOME.
6. CI release workflow.
7. Docs.

Steps 1–5 are the hackathon-critical path; a laptop-built tarball uploaded
by hand to a Release stands in for step 6 until it exists.

[openai/codex#17827]: https://github.com/openai/codex/issues/17827
