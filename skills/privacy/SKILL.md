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
to). If the user gave an explicit id after `$privacy` (design.md §2's
`$privacy <id>` deep link), use that. Otherwise resolve the most recently
started session — in the common case there is exactly one, the session
you are running in right now:

```bash
python3 - <<'PY'
import os, sqlite3
data_dir = os.environ.get("PLUGIN_DATA", "/tmp")
conn = sqlite3.connect(os.path.join(data_dir, "ledger.db"))
row = conn.execute(
    "SELECT session_id FROM sessions ORDER BY started_at DESC LIMIT 1"
).fetchone()
print(row[0] if row else "")
PY
```

**2. Print the ASCII audit.**

Run this with `SESSION_ID` set to whatever step 1 resolved (or the id the
user gave). It imports `privacy_hud` from the plugin's own source tree —
adjust `sys.path` if `$PLUGIN_ROOT` is not already importable in your
shell:

```bash
python3 - "$SESSION_ID" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(os.environ.get("PLUGIN_ROOT", "."), "src"))

from privacy_hud.ledger import Ledger
from privacy_hud.matrix.loader import load_matrix
from privacy_hud import mcp_tools, render

session_id = sys.argv[1]
data_dir = os.environ.get("PLUGIN_DATA", "/tmp")
ledger = Ledger(os.path.join(data_dir, "ledger.db"), load_matrix())

summary = mcp_tools.get_session_summary(ledger, session_id)
rows = mcp_tools.list_exposures(ledger, session_id, "Exposed")
print(render.audit(summary, rows, "Exposed"))
PY
```

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
data_dir = os.environ.get("PLUGIN_DATA", "/tmp")
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

## What NOT to do

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
