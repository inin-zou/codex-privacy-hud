---
name: privacy
description: Open the Privacy HUD session audit — inspect confirmed disclosure evidence, issued interventions, unresolved actions, and separately labelled legacy accounting for the selected session.
---

## What this does

Prints the Level 2 session audit (design.md §5) as an ASCII table using
real data from the selected session's ledger, and starts the local audit
UI so the same data is also browsable — the ASCII table is the one that
always works; the browser UI is an enhancement, never a dependency
(design.md P6).

This skill reads the ledger through the plugin bundle's own launcher; it does not call the MCP server, and it never opens the ledger file itself. The MCP worker-thread failure in 0.7.4 and earlier does not affect this audit path.

Both surfaces are built from the exact same functions:
`privacy_hud.mcp_tools.get_session_summary` / `list_exposures` for the
data, and `privacy_hud.render.audit` for the ASCII table's wording,
reached through `runtime_commands` — do not hand-write a summary of the
numbers instead of running the commands below; the whole point of routing through these functions is that the
`exposed`/`prevented`/`local_access` distinction (design.md P2) and the
copy rules (design.md §9) are enforced in one place, not re-derived by
whichever agent happens to invoke this skill.

## The one command everything runs through

Privacy HUD loads its Python code from the plugin bundle Codex installed,
and every command below goes through that bundle's bootstrap. Do not
import `privacy_hud` yourself, do not open the ledger, and do not pick a
bundle by listing Codex's plugin cache and taking the newest directory:
the bundle is **this skill file's own installation** — the directory two
levels above `skills/privacy/SKILL.md` — and nothing else.

`PLUGIN_ROOT` is that directory and Codex sets it. If it is not set in
the shell you get, take it from the absolute path of this file, two
directories up. Never from `cwd`, and never by sorting cache directories.

```bash
BUNDLE="${PLUGIN_ROOT:?the installed plugin bundle: two directories above this skill file}"
HUD=(python3 "$BUNDLE/scripts/runtime.py" --plugin-data "${PLUGIN_DATA:?}")
```

Run `"${HUD[@]}" <subcommand>` for everything that follows. If a command
fails, print what it printed and stop; do not fall back to opening the
ledger by hand. The ledger's location is not a fixed pathname any more —
after a runtime repair `$PLUGIN_DATA/ledger.db` is a *directory* that
exists to stop exactly that — and the bootstrap is what resolves it.

## Steps

**0. `$privacy repair`.**

Handle this branch before anything below.

A host plugin update may leave the receipt selecting a deleted bundle.
The hook's runtime-selection warning or denial may already contain the
external-terminal repair command. Reproduce that command verbatim when
present. Repair is not automatic. Do not run installation or stop
processes merely because the user requested this command-printing branch.
After a successful repair, the user must restart the Codex app, CLI, or
IDE integration that loaded the plugin, as the repair output instructs.

Explicit repair and the shared stop-only operation can recognize MCP and
daemon ledger holders naming any canonical N.N.N sibling path under the
same existing canonical plugin parent, whether the version directory is
present or absent. Each N is an ASCII nonnegative integer without leading
zeros except zero itself. An absent version directory need never have
existed or been installed; no record of prior selection is required.
Existing version directories must contain a canonical scripts/runtime.py
file; incomplete existing bundles and aliases remain refused. Recognition
still requires the same UID, exact supported launch form, recorded
interpreter and resolved plugin-data directory. Process identity and ledger
ownership are rechecked before signalling. This follows the same-user
trust model and does not authenticate the Python code a process loaded.
Unverified holders cause refusal; there is no SIGKILL escalation.

`$privacy repair` prints the recovery command for another terminal.
Invoke the bundled launcher with `repair --print-command` and reproduce
its output verbatim. This branch does not start installation, stop
processes, or request an enforcement bypass. If hook execution prevents
the launcher from running, construct the same shell-quoted command from
this skill's exact bundle location and the resolved plugin-data
directory. Do not select another cached version.

```bash
BUNDLE="${PLUGIN_ROOT:?}"
python3 "$BUNDLE/scripts/runtime.py" --plugin-data "${PLUGIN_DATA:?}" \
  repair --print-command
```

**1. Print the audit.**

One command resolves the session, reads the ledger read-only, and renders the Level 2 table (design.md §5). After handling the documented command branches, a positional ID supplied to `$privacy` is a session ID. Set `SESSION_ID` to that session ID; omit it when no session ID was supplied. It is not an event or flow deep link.

```bash
BUNDLE="${PLUGIN_ROOT:?}"
python3 "$BUNDLE/scripts/runtime.py" --plugin-data "${PLUGIN_DATA:?}" \
  audit ${SESSION_ID:+"$SESSION_ID"}
```

An argument after $privacy is a session ID. It is not a flow or event ID.

It prints, in order:

- a runtime banner, **only** when the daemon does not match this plugin.
  Print it verbatim above the table. It says monitoring is unverified and
  policy changes are unavailable; it does **not** say the records below
  are wrong.
- the ASCII table, which is `render.audit()`'s output. Print it verbatim,
  irreversibility notice included.
- one JSON line: `session_id`, `basis`, `also_active`, `runtime_mismatch`.
  That is the resolution, made **once**. Carry `session_id` into every
  later step rather than resolving again — two separately timed
  resolutions can name two different sessions, which is how one machine
  ended up showing two at once.

`basis` says how the id was reached — `explicit`, `active` (the daemon
named it), `started_at` (fallback, daemon unreachable or no live
session), `none` (the ledger holds no session yet). Never describe a
`started_at` resolution as "your current session"; the table's own header
already says what it is.

If `session_id` is empty (`basis: none`), stop: there is no session to
audit, and the steps below would render an empty table for an id that
does not exist, which reads exactly like a clean session.

The summary distinguishes new accounting, legacy accounting, and an
unrecorded session. New accounting shows confirmed points, distinct
disclosures and recipients, issued interventions, and unresolved actions.
Its percentage is unavailable when the required evidence is incomplete.
Zero confirmed points with unresolved actions does not mean no disclosure
occurred. Legacy accounting retains its explicit legacy labels. An
unrecorded session has no numeric score or counts. Print the renderer's
accounting note and unavailable reasons; never substitute zero.

Coverage separately reports recorded observation gaps. It does not establish that every event was seen, that a crossing occurred, or that the host applied an intervention.

When guard-target metadata is present, preserve the renderer's wording:
it identifies the path representation evaluated by Privacy HUD, not a
filesystem object. A "Same evaluated target as event #N" link refers to an
earlier event in the selected session. It does not resolve the accounting
file subject or confirm host enforcement. Do not infer filenames, file
contents, or execution identity from it. Null or absent metadata is not
evidence of a different target. The IDs are not source-rule selectors.

Swap the tab with `--tab Exposed` / `--tab Prevented` / `--tab "All events"`
to show a different one.

**2. Show one event's detail.**

Use this step only when the request identifies a particular event in the selected session. `SESSION_ID` is the session selected in step 1; `EVENT_ID` is that event's numeric `id`, not the positional argument after `$privacy`. The detail command requires both identifiers. Do not infer an event ID from a denial message: those messages contain no event deep link. If no event ID is available, show the session audit and its browser URL; the browser opens detail when a row is selected.

```bash
BUNDLE="${PLUGIN_ROOT:?}"
python3 "$BUNDLE/scripts/runtime.py" --plugin-data "${PLUGIN_DATA:?}" \
  detail "${SESSION_ID:?}" "${EVENT_ID:?}"
```

If the user asks for an event from the selected session, use that row's id
as EVENT_ID in the detail command. $privacy <id> alone selects a session;
it does not select an event.

**3. Start the local audit UI and print its URL.**

Hand it the session step 1 resolved, so the pane and the table are about
the same session.

```bash
BUNDLE="${PLUGIN_ROOT:?}"
python3 "$BUNDLE/scripts/runtime.py" --plugin-data "${PLUGIN_DATA:?}" \
  ui ${SESSION_ID:+"$SESSION_ID"} &
```

This binds to `127.0.0.1` on an OS-assigned port and prints exactly one
line — the URL to open, e.g. `http://127.0.0.1:54219/?session_id=...` —
so the demo works with no browser (the ASCII table from step 1 already
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
state. It prints one word: `shown`, `hidden`, `stale`, or `absent` (no
snapshot at all). stale means a valid snapshot has not been refreshed for more than 30 seconds. The HUD cannot establish why it stopped updating or whether ledger recording continued.
Report `stale` as what it is; it is not the same as "off".

```bash
BUNDLE="${PLUGIN_ROOT:?}"
python3 "$BUNDLE/scripts/runtime.py" --plugin-data "${PLUGIN_DATA:?}" \
  hud "${SESSION_ID:?}" status
```

It prints one JSON object; `state` is the word to report.


### `$privacy read on|off|status`

Turns the known-sensitive-path read guard on or off. When enabled, Privacy HUD issues denials for recognized matching reads. The default is off. These hooks do not confirm whether the host enforced a denial.

Replace `on` with `off` to turn it off or `status` to check the current
state. It prints one word: `on` or `off`. This setting lives in
`$PLUGIN_DATA/settings.json`, not `config.toml`, and a change here is
picked up by the running daemon immediately — no restart needed.

If a second line follows that word, the file could not be written: the
word is what the setting still says, not what the user asked for. Report
both, and do not describe the guard as having changed.

```bash
BUNDLE="${PLUGIN_ROOT:?}"
python3 "$BUNDLE/scripts/runtime.py" --plugin-data "${PLUGIN_DATA:?}" \
  read status
```

It prints one JSON object: `deny_read` is the setting, and an `error`
field means the write failed and `deny_read` is what the setting still
says, not what the user asked for.


### `$privacy setup`

For an install that came from `codex plugin add` alone: the first turn of
such a session shows `Privacy HUD is installed but not set up`, and
`$privacy` above finds no daemon. This runs the installer Codex copied in
beside this skill — the one in **this bundle**, resolved the same way
every other command here is, never a cached version chosen by sorting.

The script writes under `~/.local/share/codex-privacy-hud/` and
`~/.codex/`, appends one `PATH` line to the shell rc file, and needs the
network for its downloads, so it cannot run inside the workspace sandbox:
request escalated permissions for exactly this command, with that sentence
as the justification. Print the command for the user to run in another
terminal rather than assuming it can run here; if the user said to skip
the model, replace `--yes` with `--no-model` and nothing else.

```bash
BUNDLE="${PLUGIN_ROOT:?}"
printf 'sh %s --yes\n' "$BUNDLE/install.sh"
```

It takes several minutes; the model download dominates. Keep waiting on
the same process instead of starting a second one.

`$privacy setup` installs and configures the whole plugin. It is not
`$privacy repair`, which only prints the command that repairs the runtime
and never installs or replaces a patched Codex binary. Do not describe
either as doing the other's job.

Privacy HUD 0.9.4 writes snapshot version 2. The native Privacy item requires
a patched Codex build containing the snapshot-v2 reader. Matching Codex
versions and successful plugin installation do not establish that
compatibility. Until the installed build is verified, run the bundled
ambient launcher in a separate terminal pane.

```bash
BUNDLE="${PLUGIN_ROOT:?}"
python3 "$BUNDLE/scripts/runtime.py" --plugin-data "${PLUGIN_DATA:?}" \
  ambient --watch
```

- `done. restart codex …`: tell the user to restart Codex to load the
  installed plugin and PATH changes. Do not promise a native Privacy item
  unless the installed patched build is verified to contain the
  snapshot-v2 reader. Until then, use the bundled ambient launcher in a
  separate terminal pane with the command above.
- `no patched build published for codex <ver> yet`: report that no patched
  build was installed for that version. This warning can precede the
  final `done` line; that line does not cancel it. Use the fallback pane.
  A restart is still needed for the daemon's hooks.

If the installer exits unsuccessfully, print its last lines verbatim and
stop; do not retry with different flags, and do not edit
`~/.codex/config.toml` or the rc file by hand.

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
- Do not claim protection this tool cannot back up. The terminal detail view does not save policy rules. The local audit browser has buttons that POST to /api/policy; the MCP privacy.update_policy tool is a separate policy-writing surface. Report a rule as saved only after that surface returns success, and include its returned conditions. Host application of a later denial or rewritten input is not confirmed.
  A saved `mask` rule is in the session's policy table, and
  `Engine.observe()` consults that table before its own defaults on every
  subsequent egress observation. Say the rule is **saved**, and that
  Privacy HUD can return rewritten input for a later outbound call **when
  that data type is detected on it**. Do not say it is
  enforced, and do not say later calls will be masked: the rule fires only
  on a finding some tier actually produced. For every type other than
  `path` and `credential`, matching requires an accepted deep-scan result.
  A scan gap means an applicable deep scan supplied no accepted result
  (`docs/known-limits.md` #21); on that call this rule has no matching
  deep-scan finding. Egress uses a requested timeout based on the
  remaining budget and an inclusive completion cutoff; neither guarantees
  elapsed time. See `engine.TIER3_EGRESS_BUDGET`. At most one egress scan
  worker is admitted at a time. Admission is nonblocking; the worker retains
  its slot until it exits, including after caller abandonment. The
  tool's own reply carries the conditions; pass them on rather than
  summarizing them away.
- A row whose `source` names a real origin — a file the value was read
  from, or the command whose output carried it — gets a second button in
  the local audit browser, one of two labels (#40):
  `Save block rule for values read from <path>`, which saves a `block_path`
  rule, or ``Save block rule for values from `<command>` output``, a
  `block_command` rule.
  Both save an origin rule for this session. Report it as saved and pass
  on the origin conditions: The value must be detected on ingress and
  again on egress. When either detection depends on the deep scan, a scan
  gap can prevent this rule from matching (known limit 21). Detection is
  heuristic and can miss values, and hosted tools never reach this plugin
  at all. A row with no origin — `source` is a bare tool
  label like `Bash` — offers neither, because no rule could name it, and
  `apply_policy` refuses the withdrawn `block_source` type outright (#38).
- State the limit whenever you describe a source rule: **it matches the
  whole value, normalised** (known limit 10). A model that summarizes,
  rewrites, or quotes part of what it read defeats it. Matching the whole normalised value is necessary but does not establish
  that a saved rule will match a later call; pass on the origin conditions
  above. Matching keys on an HMAC of `value.strip().lower()`, so values
  differing only in case or surrounding whitespace match too — wider than a
  byte comparison, not narrower, and never describe it as one. Two more
  facts, if the user asks: a source rule is scoped to the
  session (`Ledger.add_policy` writes `session:<id>`) and ends with it, and
  nothing removes one before then — there is no removal path, and an
  "allow once" token does not override one (known limit 13). No surface
  mints that token today — not `$privacy`, not the audit UI, not an MCP
  tool — so this is not a workaround the user has and is missing.
- Data already disclosed before the rule was saved stays disclosed
  (design.md P4). Whether a saved rule changes a later outbound call
  depends on the matching findings and the conditions above.
