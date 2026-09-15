# Native privacy status line via a patched Codex binary — design

**Status:** Draft v1 · **Date:** 2026-09-15 · **Companion to:** `.claude/docs/design.md` §4, `.claude/docs/architecture.md` §9, README "Known limits" #5

## 1. Goal

Move the Level 1 ambient HUD from a second terminal pane into the Codex TUI
itself: one `privacy` item in Codex's own status line, under the composer,
rendering `Privacy ███░░░░░░░ 28%` beside `Context 18% used`, toggled from
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
{"v": 1, "percent": 28, "blocked": 2, "unverified": false,
 "hidden": false, "updated_at": 1757900000.0}
```

| field | type | meaning |
|---|---|---|
| `v` | int | schema version; readers treat any value ≠ 1 as "no file" |
| `percent` | int 0–100 | `Ledger.summary()["percent"]`, verbatim (I3) |
| `blocked` | int ≥ 0 | prevented-event count, as `hud_line(blocked=…)` takes today |
| `unverified` | bool | `Ledger.coverage()` says the record has a known hole (design.md §4 "Engine degraded") |
| `hidden` | bool | set by contract B; readers render nothing while true |
| `updated_at` | float | Unix seconds, daemon clock |

Rules:

- **No string fields, ever.** I1 is enforced by the schema, the same way the
  ledger has no `content` column.
- **Atomic writes**: write `<sid>.json.tmp` then `os.replace`. A reader
  never sees a partial file.
- **Written on every change**: after each observation is recorded for the
  session, on `SessionStart` (zeros), and when `hidden` flips. Not on a timer.
- **Stale after 30 s**: a reader that finds `updated_at` older than 30 s
  treats the file as absent. A crashed daemon must not leave a frozen number
  on screen.
- **Deleted on `SessionEnd`**, and the whole `hud/` directory is swept of
  files older than 4 h at daemon start (matches the daemon's own leaked-
  session bound).
- File mode 0600; directory 0700.
- `session_id` is the id Codex passes to hooks. The TUI reads its own thread
  id for the lookup. The plan's first task verifies on 0.154.0 that these are
  the same string; the design assumes they are.

### 4.2 Contract B — hide/show

`HudPublisher.set_hidden(session_id: str, hidden: bool) -> None`. Rewrites
the session's snapshot with `hidden` flipped and `updated_at` refreshed;
nothing else changes. Sole caller: the MCP tool behind `$privacy hud`.

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

### 5.1 `HudPublisher` (new, `src/privacy_hud/hud_publisher.py`)

- `publish(session_id, *, percent, blocked, unverified)` — writes contract A,
  preserving the current `hidden`.
- `set_hidden(session_id, hidden)` — contract B.
- `retire(session_id)` — deletes the file.
- `sweep(max_age_s=4*3600)` — startup housekeeping.

Depends on `PLUGIN_DATA` only. Never opens the ledger; the caller passes
numbers it already has. Call sites in `dispatch.py`: after
`state.ledger.record(...)` for the session, in the `SessionStart` branch, and
in the `SessionEnd` branch. Three lines. Any exception inside the publisher
is caught there and logged; publishing must never fail a hook (I6).

### 5.2 `PrivacyStatusSource` (new, Rust, `codex-rs/tui/src/privacy_status.rs`)

```rust
pub(crate) struct PrivacyReading { percent: u8, blocked: u32, unverified: bool }
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
  error, `v != 1`, `hidden == true`, `updated_at` older than 30 s, `percent`
  outside 0–100. One exit for every failure; no partial readings.
- Never logs file contents. There are none to log, by contract A.

### 5.3 `StatusLineItem::Privacy` (patch to Codex)

Four touch points, chosen because each is a one-line addition next to an
existing sibling, which is what keeps the rebase cheap:

1. `tui/src/bottom_pane/status_line_setup.rs`: add `Privacy` to
   `StatusLineItem` (strum serializes it as `privacy`); add its
   `description()` — "Privacy disclosure of this session (omitted when the
   Privacy HUD plugin is not running)"; add its `preview_item()`.
2. `tui/src/bottom_pane/status_surface_preview.rs`: add
   `StatusSurfacePreviewItem::Privacy` with placeholder
   `Privacy ███░░░░░░░ 28%`.
3. `tui/src/chatwidget/status_surfaces.rs`: in the item → `Option<String>`
   match, `StatusLineItem::Privacy => self.privacy_status.current(thread_id)
   .map(|r| render_privacy(&r))`. Items here are plain strings
   (`Context 28% used` is the sibling), so the bar is Unicode text, exactly
   as `render.hud_line()` draws it today. Colour follows Codex's existing
   `status_line_use_colors` treatment of items; per-band colour is a
   follow-up, not part of this change, because the composition API is
   string-typed.
4. `tui/src/chatwidget.rs`: one field `privacy_status: PrivacyStatusSource`,
   and a `refresh_status_line_if_privacy_due()` modelled on the existing
   `refresh_status_line_if_workspace_headline_due()`, called from the same
   place, so the item updates within a second of the file changing without a
   new timer.

`render_privacy(reading) -> String` is a pure function in
`privacy_status.rs`: `Privacy ` followed by the **core segment**
`{bar} {pct}%`, plus ` ⚠{blocked}` when `blocked > 0`, plus ` ⚠unverified`
when unverified. Bar: 10 cells, `█` filled, `░` empty, band thresholds
0–33 / 34–66 / 67–100 per design.md §3. Width degradation is left to Codex's
status line, which already truncates items to the available width.

The core segment is the part the two languages share. `render.py` gains
`hud_core(percent, blocked, unverified) -> str` producing exactly that
segment, and `hud_line()` is refactored to build its full/mid formats from it
(its wider `PRIVACY  Disclosure … ›` framing and the compact/dot rungs stay
Python-only). The golden file in §8 pins `hud_core`, so a copy change in one
language fails the other's test.

Patch budget: ≤ 300 lines including the new file and its unit tests. If it
grows past that, stop and revisit.

`/statusline` needs no change: the picker enumerates `StatusLineItem` and
persists selections through `status_line_items_edit`. `privacy` appears in
the list, is checked or unchecked there, and the choice survives restarts.

### 5.4 `$privacy hud on|off|status` (extend `mcp_tools.py`)

New MCP tool `privacy_hud_toggle(session_id, hidden: bool)` → contract B.
The skill gains the subcommand. `status` reports whether the snapshot exists
and whether it is hidden. Does not touch `config.toml`; does not know
`/statusline` exists. The two toggles compose: `/statusline` decides whether
the item is configured, `$privacy hud` decides whether it currently shows.

### 5.5 `ambient.py` (existing, data source only)

`_line_for()` reads contract A instead of opening sqlite. `_SessionPin`,
`hud_line`'s width ladder, `--watch`, the silence-on-failure rules all stay.
README demotes it from "the Level 1 surface" to "the fallback when no
patched build matches your Codex version".

### 5.6 Distribution (`scripts/`, `install.sh`)

**`scripts/build-patched-codex.sh <codex-version>`** — one script for laptop
and CI: clone `openai/codex` at `rust-v<ver>` (shallow), `git apply --check`
then `git apply patches/privacy-status-line.patch`, `cargo build --release
-p codex-cli`, tar the binary as
`codex-privacy-<ver>-<target>.tar.gz`, write `.sha256`. rustup installs
1.95.0 from `rust-toolchain.toml` automatically.

**CI** (`.github/workflows/release-codex.yml`): on tag
`codex-<ver>-hud.<n>`, matrix `macos-14` (aarch64-apple-darwin) and
`macos-13` (x86_64-apple-darwin), run the script, upload both tarballs and
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

Step 3 is the only network access the *plugin* ever causes, and it happens
here, once, with consent, before any session exists. The runtime keeps
`HF_HUB_OFFLINE=1` and its no-outbound-calls guarantee (I2). README states
this split explicitly.

No matching release for the user's Codex version: step 6 prints which
versions exist and continues; the forwarding script then falls through to
the official binary and the user has the fallback pane.

**Forwarding script** `~/.local/bin/codex`:

```sh
#!/bin/sh
# codex-privacy-hud forwarder — remove with: install.sh --uninstall
self="$HOME/.local/bin/codex"
official=""
for c in $(command -v -a codex); do            # every codex on PATH, in order
  [ "$c" = "$self" ] && continue               # skip this forwarder
  official="$c"; break
done
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
| rendering | `tests/matrix/hud_golden.json` pins the core segment; `render.hud_core` (Python) and `render_privacy` (Rust, after stripping the `Privacy ` prefix) must both reproduce it for every case; `hud_line`'s existing goldens are unchanged |
| `HudPublisher` | atomic write (no `.tmp` visible to a concurrent reader), `hidden` preserved across `publish`, `retire`, `sweep` |
| `PrivacyStatusSource` | missing / stale / malformed / hidden / `v=2` → `None`; throttle returns cache within 1 s |
| `$privacy hud` | on/off/status round-trip through the MCP tool |
| `ambient.py` | existing goldens pass with the new data source |
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
