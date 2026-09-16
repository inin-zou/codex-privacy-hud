# Stop a read of a known-sensitive path before it reaches the model

**Status:** Design · **Date:** 2026-09-16 · **Issue:** [#36](https://github.com/inin-zou/codex-privacy-hud/issues/36) · **Builds on:** [#40](https://github.com/inin-zou/codex-privacy-hud/issues/40) / [#41](https://github.com/inin-zou/codex-privacy-hud/pull/41)

## The problem

Every rule this plugin enforces applies on **egress** — data leaving for an MCP tool or the network. Most `exposed` events happen on **ingress**: the model reads a file and the bytes are in context before any rule is consulted. #36's table found one path that is genuinely interceptable: a tool call that reads a *known* sensitive path fires `PreToolUse` before it runs, and that hook can deny.

#40 built the piece this needs: `origin.extract_origin` already reads a file path out of a Bash read command or a file tool's own argument, and it has been hardened twice against putting an argument where a path belongs.

## What this is not

- **Not general read protection.** It stops the reads it can recognise. `python -c "open('.env')"` is not one of them, and that is the same root cause as known limit 6.
- **Not on by default.** It records and mentions itself until the user turns it on.
- **Not a detector change.** Tier 0 keeps flagging exactly what it flags today, including `.env.example`.

## Decisions taken, and why

**Default is warn; blocking is opt-in.** The first time a user meets this feature it should not be by having their agent's work refused. design.md P1: a tool that interrupts constantly gets disabled within a day, and `cat .env` to read config is an ordinary development move. Same default as the prompt guard in #37, so the two features behave alike.

**The toggle lives in `$PLUGIN_DATA/settings.json`, not in Codex's `config.toml`.** Three reasons, in order. Python's standard library reads TOML (3.11's `tomllib`) but cannot write it, so a toggle in `config.toml` means either a new dependency (I2 forbids it) or `sed` against the user's own Codex config. The setting is the plugin's policy, not a Codex setting — `[tui].status_line` holds a Codex identifier the plugin adds to; `deny_read` is a concept Codex knows nothing about. And `install.sh --purge` already removes `PLUGIN_DATA`, so uninstall leaves nothing behind.

It is a **separate file** from `runtime.json`: that one is machine configuration written by `privacy-hud-setup` and rewritten on reinstall, and a user's protection setting must not be lost when the interpreter is re-recorded.

The cost is that the file is invisible. `$privacy read status` and a `privacy-hud-doctor` line are the compensation, and they are part of this work rather than a follow-up.

**The decision happens in the engine, not in `dispatch`.** `dispatch` currently returns `None` for a local `PreToolUse`, so nothing reaches the engine. Keeping the check there would be a smaller diff and would split "who decides allow/deny" across two modules — the same shape of drift that let #38 ship. The engine stays the only place a call is denied.

**Enforcement reuses `detect/paths.py`'s patterns, narrowed.** Those regexes already define "a known-sensitive path" for tier 0, and a second list would drift from the first. Blocking narrows them by one rule: a template file (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`) is not blocked.

**Why blocking is narrower than detection, in one line:** a false positive costs 2.0 budget points and a row nobody minds, versus a command that does not run and a user who turns the whole protection off to get their work done. The fix belongs on the blocking side; narrowing the *detector* would mean a `.env.example` that really does hold a key stops being noticed at all, and noticing is cheap.

## How it works

```
PreToolUse  Bash {"command": "cat .env"}
  dispatch: extract_origin -> Origin(".env", PATH)
            -> Observation(direction="local", origin=...)   [new: no longer an early return]
  engine:   settings.deny_read and is_sensitive_path(".env")
            -> deny, ledger row kind="prevented", budget 0 (I4)
            -> the command never runs

PreToolUse  Bash {"command": "cat .env.example"}   -> allowed (template)
PreToolUse  Bash {"command": "env"}                -> COMMAND origin, early return as today
PreToolUse  Bash {"command": "python -c ..."}      -> no origin, early return as today
```

### Module boundaries

| Unit | Owns | Must not |
|---|---|---|
| `detect/paths.py` | The patterns, and `is_sensitive_path()` over one path | Know about settings, rules, or hooks |
| `settings.py` (new) | Reading and writing `settings.json`, with an mtime cache | Know what any setting means |
| `dispatch` | Building a local-read `Observation` when the origin is a path | Decide whether to deny |
| `Engine` | The deny, the prevented row, and the once-per-session notice | Parse paths or read files |
| `mcp_tools` / skill / `doctor` | Showing and flipping the toggle | Duplicate the predicate |

### Taxonomy and Ruling 1

`tables.toml` gains `"PreToolUse/local" = "local_access"`. A denied read classifies through the existing `"PreToolUse/blocked" = "prevented"`.

**Ruling 1 is amended**, for the first time: "a `local` destination always classifies as `local_access`" becomes "…unless the call was denied, which classifies as `prevented`". Without the exception a blocked read and an ordinary read are the same row, and the audit cannot show that anything was stopped.

### The setting, read at decision time

`settings.json` is read through an mtime-checked cache, not once at `SessionStart`. A user who turns blocking on inside a running session must see it apply to that session — a setting that needs a restart reads as a broken setting.

Absent or unreadable file means `deny_read: false`: this feature never fails closed on its own configuration.

## Copy

Warn mode, **once per session** rather than once per path — the message exists to make the feature discoverable, not to narrate every read:

```
PRIVACY HUD: this session read .env — a path it can stop before it
reaches the model. Turn that on with `$privacy read on`.
```

Blocking:

```
PRIVACY HUD blocked a read

  Bash  would read  .env

  Reads of known-sensitive paths are blocked. This one did not run,
  so nothing from it reached the model.

  Run `$privacy read off` to allow them again.
```

"did not run, so nothing from it reached the model" is one of the few unqualified claims this project can make — the call is stopped before execution, not recorded after it. The operator surface mirrors the existing `$privacy hud on|off|status`: `$privacy read on|off|status`.

## Error handling

- **No origin, or a COMMAND origin** — `dispatch` early-returns exactly as it does today. An unrecognised read is allowed, and known limit 6 already says why.
- **An unreadable or malformed `settings.json`** — treated as `deny_read: false`, and `privacy-hud-doctor` reports it. A protection that cannot read its own setting must not start blocking reads on a guess.
- **No daemon** — unchanged: the hook client fails open on ingress (I6). A local read is never denied by our own failure.
- Catch only the exception a call actually raises (`OSError`, `json.JSONDecodeError`), never a bare `Exception`.

## Testing

TDD throughout.

1. **`is_sensitive_path`**: `.env`, `.env.local`, `id_rsa`, `deploy/key.pem`, `~/.aws/credentials` block; `.env.example`, `.env.sample`, `.env.template`, `src/main.py` do not. **Plus a guard that tier 0's detection of `.env.example` is unchanged** — it pins "blocking is narrower than detection" as deliberate rather than a gap someone should close.
2. **`settings.py`**: default when absent; round-trip; a change made mid-session is visible without a restart; a corrupt file reads as off.
3. **Engine**: on + sensitive → deny, one prevented row, budget unchanged (I4); off → allow; non-sensitive → allow; no origin → allow; `PostToolUse` local rows unaffected.
4. **`dispatch`**: a PATH origin builds an Observation; COMMAND and `None` still early-return and raise no `UnknownKey`.
5. **End to end**: `cat .env` through the real hook path — allowed with one notice by default, silent on the second read, denied once the toggle is on.

`tests/matrix/` and the contract goldens move with the new taxonomy entry.

## Known limits to add

1. **Only recognised reads are stopped.** `cat .env` is; `python -c "open('.env')"` is not — the same root cause as limit 6, and the two should point at each other.
2. **Template files are never blocked**, even one that really holds a key. Detection still flags them.
3. **Nothing is blocked until you turn it on.** The default records and mentions; it does not stop anything.

## Build order

| Step | Change | Verified by |
|---|---|---|
| 1 | `detect/paths.py::is_sensitive_path` + template exclusion | Unit tests |
| 2 | `settings.py`, `$privacy read on\|off\|status`, doctor line | Toggle persists and is visible mid-session |
| 3 | `dispatch` builds the local-read Observation; taxonomy entry; Ruling 1 amended | No early return, no `UnknownKey` |
| 4 | Engine deny + once-per-session notice | Engine tests |
| 5 | Copy, the three limits, version 0.6.0 | CI |
