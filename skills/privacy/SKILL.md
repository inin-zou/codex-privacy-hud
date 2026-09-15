---
name: privacy
description: Open the Privacy HUD session audit — what sensitive data reached the model, subagents, or external tools this session, what was prevented, and what you can do about it.
---

## What this does

Prints the Level 2 session audit (design.md §5) as an ASCII table using
real data from the running session's ledger, and starts the local audit
UI so the same data is also browsable — the ASCII table is the one that
always works; the browser UI is an enhancement, never a dependency
(design.md P6).

Both surfaces are built from the exact same functions:
`privacy_hud.mcp_tools.get_session_summary` / `list_exposures` for the
data, and `privacy_hud.render.audit` for the ASCII table's wording — do
not hand-write a summary of the numbers instead of running the commands
below; the whole point of routing through these functions is that the
`exposed`/`prevented`/`local_access` distinction (design.md P2) and the
copy rules (design.md §9) are enforced in one place, not re-derived by
whichever agent happens to invoke this skill.

## Steps

**1. Resolve the ledger and the session.**

The ledger lives at `$PLUGIN_DATA/ledger.db` (same path the daemon writes
to). Run this as written, substituting the id the user typed after
`$privacy` (design.md §2's `$privacy <id>` deep link) for the empty string
argument — leave it empty if they did not give one:

```bash
python3 - "" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(os.environ.get("PLUGIN_ROOT", "."), "src"))

from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud import mcp_tools

data_dir = os.environ["PLUGIN_DATA"]
explicit = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
ledger = Ledger(os.path.join(data_dir, "ledger.db"), load_matrix())

resolved = mcp_tools.resolve_audit_session(
    ledger, data_dir, explicit=explicit or None)
print(f"session_id: {resolved.session_id or ''}")
print(f"basis: {resolved.basis}")
print(f"also_active: {','.join(resolved.also_active)}")
if resolved.note:
    print(f"note: {resolved.note}")
PY
```

`session_id` is what the rest of the steps use, and `basis` /
`also_active` travel with it into step 2 — the audit table's own header
line is written from them (`render._subtitle`), so an id passed on its
own makes the table go back to claiming "Current session" for a session
nothing established was current. Resolve once, here, and carry all three;
do not re-run this script per step.

**If a `note:` line is printed, print it to the user verbatim, above the
audit table.** It is there because the resolution was not certain, and the
copy is already written to design.md §9's rules — see
`mcp_tools.ResolvedSession.note`.

Do not replace this with `SELECT session_id FROM sessions ORDER BY
started_at DESC LIMIT 1`, which is what this skill used to do. That is the
most recently *started* session, so a user with two Codex windows open who
runs `$privacy` in the first one is shown the second one's audit, silently
— confirmed against a real ledger, where the most recently started and the
most recently active session were two different sessions. Nor is
`MAX(events.ts)` the fix: a session that has disclosed nothing has no
event rows at all, so ordering by event time skips the cleanest possible
session and serves an older one's numbers in its place. The daemon is the
only process that knows which session is live, because it sees every hook
including the ones that record nothing, and asking it works because
**running `$privacy` itself fires hooks** — this skill runs bash, which is
a `PreToolUse` in the session you are in, so that session is the most
recently active one by construction rather than by guess.

`basis` says how the id was reached — `explicit`, `active` (the daemon
named it), `started_at` (fallback, daemon unreachable or no live session),
`none` (the ledger holds no session yet). Never describe a `started_at`
resolution as "your current session"; the `note:` line already says what
it is, and so does the table's own header once `basis` reaches step 2.

If `session_id` comes back empty (`basis: none`), stop here: print the
`note:` line and nothing else. There is no session to audit, and steps 2
and 3 would render an empty table for an id that does not exist, which
reads exactly like a clean session.

**2. Print the ASCII audit.**

Run this with `SESSION_ID`, `BASIS` and `ALSO_ACTIVE` set to the three
values step 1 printed. It imports `privacy_hud` from the plugin's own
source tree — adjust `sys.path` if `$PLUGIN_ROOT` is not already
importable in your shell:

```bash
python3 - "$SESSION_ID" "$BASIS" "$ALSO_ACTIVE" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(os.environ.get("PLUGIN_ROOT", "."), "src"))

from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud import mcp_tools, render

argv = sys.argv[1:] + ["", ""]
session_id = argv[0]
# No basis carried over -> the weakest claim the id can support, never the
# strongest. An unlabelled session id read out of a ledger IS the most
# recently started one; assuming "current" here is the overclaim this
# argument exists to prevent.
basis = argv[1].strip() or "started_at"
resolved = mcp_tools.ResolvedSession(
    session_id, basis,
    tuple(s for s in argv[2].split(",") if s))

data_dir = os.environ["PLUGIN_DATA"]
ledger = Ledger(os.path.join(data_dir, "ledger.db"), load_matrix())

summary = mcp_tools.get_session_summary(ledger, session_id)
rows = mcp_tools.list_exposures(ledger, session_id, "Exposed")
coverage = mcp_tools.get_session_coverage(ledger, session_id)
print(render.audit(summary, rows, "Exposed",
                   coverage=coverage, resolved=resolved))
PY
```

Two keyword arguments, two different questions, and neither substitutes
for the other.

`coverage` says whether the ledger's account of this session is complete.
Without it `render.audit` cannot tell "0% because nothing was disclosed"
from "0% because nothing was recorded", and the second is exactly what a
session whose daemon was down looks like (README known limit 1) — the same
condition that makes step 1 fall back to `basis: started_at`.
`render.audit` adds one banner line when the record is incomplete and
leaves the table untouched otherwise.

`resolved` says *whose* session those numbers are. It sets the header's
second line: `Current session` only when the daemon named a single live
session, `Session <id>` for `$privacy <id>`, `Most recently active
session` when two windows were active in the same moment, `Most recently
started session` for the no-daemon fallback. Passing it is what stops the
table asserting "Current session" over a row nothing established was
current — the same claim the `note:` line above it is busy retracting.

Swap the tab argument (`"Exposed"` / `"Prevented"` / `"All events"`) to
show a different one — `render.audit` and `mcp_tools.list_exposures` both
already take `tab` as a plain argument, so there is no reason to
re-implement tab switching here.

If the user asked for one specific flow (`$privacy <id>`, design.md §2's
L3 deep link), show that instead:

```bash
python3 - "$SESSION_ID" "$EVENT_ID" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(os.environ.get("PLUGIN_ROOT", "."), "src"))

from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud import mcp_tools, render

session_id, event_id = sys.argv[1], int(sys.argv[2])
data_dir = os.environ["PLUGIN_DATA"]
ledger = Ledger(os.path.join(data_dir, "ledger.db"), load_matrix())

row = mcp_tools.get_exposure_detail(ledger, session_id, event_id)
print(render.detail(row))
PY
```

`event_id` is the `id` field on any row `list_exposures` returns — the
same one the audit table above and the web UI's rows both key off of.

**3. Start the local audit UI and print its URL.**

```bash
python3 -m privacy_hud.local_ui_server "$SESSION_ID" &
```

This binds to `127.0.0.1` on an OS-assigned port and prints exactly one
line — the URL to open, e.g. `http://127.0.0.1:54219/?session_id=...` —
so the demo works with no browser (the ASCII table from step 2 already
covers that) and, when a browser is available, the same ledger is also
browsable with the three tabs, row selection, and the L3 detail view
(`ui/index.html`, `ui/app.js`). Print that URL to the user verbatim; do
not describe it as anything more than a local page on their own machine.

Do not start a second copy if one is already running for this session —
if a prior `$privacy` invocation in this same conversation already
printed a URL and that process is still alive, reuse it instead of
binding a new port.

### `$privacy hud on|off|status`

Hides or shows this session's `Privacy …` item in the Codex status line
without leaving the session. It does not change `/statusline`; that decides
whether the item is configured, this decides whether it shows right now.

Replace `on` with `off` to hide the item or `status` to check the current
state. It prints one word: `shown`, `hidden`, `stale` (a snapshot exists but
nothing has refreshed it for 30 s — the daemon is gone or wedged, so the
session is not being recorded either), or `absent` (no snapshot at all).
Report `stale` as what it is; it is not the same as "off".

```bash
python3 - "$SESSION_ID" on <<'PY'
import os, sys
sys.path.insert(0, os.path.join(os.environ.get("PLUGIN_ROOT", "."), "src"))

from privacy_hud import mcp_tools

session_id, arg = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "status")
data_dir = os.environ["PLUGIN_DATA"]

out = (mcp_tools.hud_status(data_dir, session_id) if arg == "status"
       else mcp_tools.hud_set_hidden(data_dir, session_id, arg == "off"))
# shown | hidden | stale (the daemon that writes it is gone) | absent
print(out["state"])
PY
```

### `$privacy setup`

For an install that came from `codex plugin add` alone: the first turn of
such a session shows `Privacy HUD is installed but not set up`, and
`$privacy` above finds no daemon. This runs the installer Codex copied in
beside this skill. It creates the daemon's Python environment, downloads
the detection model (~2.8 GB, once), fetches the patched Codex build for
the installed Codex version, and adds the `privacy` item to
`[tui].status_line`. It is safe to run over an existing install.

The script writes under `~/.local/share/codex-privacy-hud/` and
`~/.codex/`, appends one `PATH` line to the shell rc file, and needs the
network for its downloads, so it cannot run inside the workspace sandbox:
request escalated permissions for exactly this command, with that sentence
as the justification. Run it as written; if the user said to skip the
model, replace `--yes` with `--no-model` and nothing else.

```bash
ROOT="${PLUGIN_ROOT:-$(ls -d "${CODEX_HOME:-$HOME/.codex}"/plugins/cache/codex-privacy-hud/codex-privacy-hud/*/ | tail -1)}"
sh "$ROOT/install.sh" --yes
```

(`PLUGIN_ROOT` is set for hooks; in a skill's shell it may not be, so the
fallback locates the installed copy under Codex's plugin cache and takes
the newest version.) It takes several minutes; the model download
dominates. Keep waiting on
the same process instead of starting a second one. It ends in one of two
ways, and the user needs to hear which:

- `done. restart codex …`: tell the user to restart Codex. This session is
  still the official binary; the patched build, the status-line item and
  the `PATH` change apply to the next one.
- `no patched build published for codex <ver> yet`: everything else
  installed. Say that the status-line item needs a build for their Codex
  version, and that the fallback pane (`privacy-hud-ambient --watch`)
  works meanwhile. A restart is still needed for the daemon's hooks.

If it fails before either line, print its last lines verbatim and stop; do
not retry with different flags, and do not edit `~/.codex/config.toml` or
the rc file by hand.

## What NOT to do

- Do not fetch the installer from the network for `$privacy setup`. The
  copy at `$PLUGIN_ROOT/install.sh` is the one Codex installed with the
  plugin and the one the user can read; a `curl | sh` from inside a
  session is exactly the kind of call this plugin exists to flag.

- Do not call the audit "your session" when step 1 printed a `note:` line.
  The note exists because the resolution could not be certain — two Codex
  windows both active in the same moment, or no daemon to ask — and
  dropping it turns "here is a session's audit" into a claim about *this*
  session that nothing supports. Print the note, then the table.
- Do not summarize the numbers from memory or from an earlier tool call
  instead of running step 2 again — the ledger is append-only and grows
  as the session continues; a stale summary is a wrong one.
- Do not print a URL you have not actually started a server for. If step
  3 fails for any reason, say so and fall back to the ASCII table alone
  rather than printing a URL that will not load.
- Do not paraphrase `render.audit()`'s or `render.detail()`'s output —
  print it verbatim, irreversibility notice included. Every word in it
  was chosen to satisfy design.md §9's copy rules (no "undo", no "your
  data is protected", no severity adjectives); a paraphrase can silently
  reintroduce exactly the claims those rules forbid.
- Do not claim protection this tool cannot back up. A
  `[ Protect future occurrences ]` / `[ Block this source ]` action
  writes a real, durable rule to the session's policy table, and
  `Engine.observe()` now consults that table before its own defaults on
  every subsequent egress observation — a `block_source` rule denies a
  later call from that source, a `mask` rule forces a rewrite for that
  data type. It is correct to tell the user the rule is now enforced,
  not merely recorded. This still does not apply retroactively: data
  already disclosed before the rule was written stays disclosed (design.md
  P4) — the rule only changes what happens on the *next* call, not what
  already happened.
