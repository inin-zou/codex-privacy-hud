# Origin tracking, so a source rule can name a source
> Historical implementation snapshot. The policy labels, confirmations,
> enforcement wording and response examples below predate #49 item 2.
> They are retained as history, not current implementation instructions.
> Current behavior reports a saved rule with conditional enforcement;
> `mcp_tools.rule_enforcement_note` supplies its conditions.

**Status:** Design · **Date:** 2026-09-16 · **Issue:** [#40](https://github.com/inin-zou/codex-privacy-hud/issues/40) · **Follows:** [#38](https://github.com/inin-zou/codex-privacy-hud/issues/38) / [#39](https://github.com/inin-zou/codex-privacy-hud/pull/39) · **Shares work with:** [#36](https://github.com/inin-zou/codex-privacy-hud/issues/36)

## The problem

`Block this source` compared a rule's selector with an observation's `source`, and `dispatch._build_observation` only ever writes fixed labels there: `"tool input"` on every outbound call, the tool name or `"user prompt"` on the way in. A rule written from a tool-output row matched nothing; one written from an outbound row denied every outbound call in the session. #39 withdrew the action rather than repair it in place, because no selector a user could pick meant "this source".

The ledger has never recorded where data came from. This spec adds that, and lets a rule name it.

## What this is not

- **Not `deny_read`** (#36). That prevents a read; this contains data already read. Both need the same path extraction, which is why `origin.py` below is built here and used there. The two rules make different promises and must keep different names and different copy.
- **Not a persisted taint store.** See "Lifetime" below: the salt that makes hashes comparable lives only in memory, so persisting the map would buy nothing.
- **Not protection against a model that rewrites what it read.** See "Known limits".

## How it works

A value read from `.env` and later sent outbound is the same value, so under one session's salt it has the same `value_hash`. The engine already computes that hash for every finding. Remembering which origin a hash first arrived from is what lets a later outbound call be recognised as carrying data from that file.

```
cat .env              PostToolUse   finding sk-proj-…  ->  hash 7f3a9c…
                                    origin  (".env", PATH)
                                    remembered: 7f3a9c… -> .env

curl -d key=sk-proj-… PreToolUse    finding sk-proj-…  ->  hash 7f3a9c…
                                    origin of that hash: .env
                                    rule block_path ".env" in force  ->  deny
```

### Decisions taken, and why

**Enforcement is per value, not per session.** A rule denies an outbound call that carries a value tainted from that origin; it does not deny every outbound call after the origin was read. Two reasons. Enforcement and accounting are then the same event: a deny always produces a finding, which is what the session-wide variant #38's kill switch lacked — that denied calls with no findings and left the audit unable to say why. This is not the same as saying the ledger always ends up with a row that explains a given deny: `Ledger.record` dedupes on `(session_id, value_hash, destination)` and only increments `count` on a repeat key, so a deny whose value already has a row from an earlier, differently-classified call (e.g. an earlier `local_access` read of the same value) leaves that row's `kind` unchanged — the deny happened, but the ledger shows no new row saying so (known limit 17). And design.md P1: a privacy tool that interrupts constantly gets disabled within a day.

The cost is stated in the copy rather than hidden: only byte-identical values match.

**Origin has two kinds, and no third.** A path (`.env`) when one can be extracted; otherwise the command's program and subcommand (`env`, `git log`), arguments always discarded. When neither can be extracted, there is no origin: `source` keeps the tool name and the row is not blockable. "No origin" is `None`, not an `OriginKind.TOOL` member — a missing origin and an origin that happens to be a tool name are different facts.

**Arguments are never recorded.** Command lines routinely carry secrets (`curl -u admin:hunter2`, `psql postgres://u:pw@h`, `export TOKEN=ghp_…`) and `events.source` is persisted, rendered in the audit, and served to the browser UI. Storing a command verbatim would make the ledger a command history with credentials in it, against I1. Storing a *masked* command is worse than it sounds: it would downgrade the ledger's promise from "we never store content" to "we store content we believe we masked", and detection is heuristic (known limit 7). The program name carries no arguments and is safe.

**Two precise rule types, not the old name.** `block_path` and `block_command`, rather than reviving `block_source` — which named something else, is refused by `apply_policy` (#39), and would need a prefix convention inside `selector` to tell a file called `env` from the `env` command. `policy` is already keyed by `rule_type`, so two types need no parsing at all.

## Module boundaries

Each unit below owns one thing and is testable without the others.

| Unit | Owns | Must not |
|---|---|---|
| `src/privacy_hud/origin.py` (new) | Reading an origin out of a tool call | Touch the ledger, the engine, policy, or any I/O. Pure and stdlib-only, like `budget.py`. |
| `dispatch._build_observation` | Payload → `Observation`, now carrying the origin | Decide anything about policy |
| `Engine` | The taint map, and the allow/deny ruling | Parse commands or paths |
| `Ledger` | Persisting `source_kind`, the schema migration | Know what an origin means |
| `mcp_tools.apply_policy` | Which rule types exist and are accepted | Know how origins are extracted |
| `render` / `ui/app.js` | Which action a row offers, and its copy | Re-derive blockability from the string |

### `origin.py`

```python
class OriginKind(Enum):
    PATH = "path"        # a value read from this file
    COMMAND = "command"  # a value in this command's output

@dataclass(frozen=True)
class Origin:
    value: str
    kind: OriginKind

def extract_origin(tool_name: str, tool_input: dict) -> Origin | None: ...
```

Frozen for `DetectorProfile`'s reason: an `Origin` is stored as a value in a map and read later; a mutable one could stop being what was recorded. A dataclass and an `Enum`, matching `Finding`/`Cost` — not pydantic, which `tests/test_network_isolation.py`'s import allowlist forbids and which would validate input this module produces itself.

Extraction order:

1. A file tool's own argument (`file_path`, `path`) → `PATH`.
2. A Bash command whose program is a read verb (`cat`, `head`, `tail`, `less`, `grep`, …) with a file argument → `PATH`.
3. Otherwise the Bash program name plus a subcommand where the program takes one (`git log`, `gh pr`) → `COMMAND`.
4. Otherwise `None`.

`.env.example` and `.env.sample` are not `.env`. A command that writes rather than reads (`cp .env.example .env`) yields no path — its output is not the file's contents.

### Engine

```python
self._origins: dict[bytes, Origin] = {}
```

On the `Engine` instance, which `dispatch` already creates per session around that session's salt (`dispatch.py:391`). Same lifetime as the salt, deliberately: when the salt is gone the hashes are incomparable, so a surviving map would be worthless.

Ingress observations record `value_hash → origin` for each finding, when the observation carries an origin. Egress observations look each finding's hash up and deny when that origin is under a `block_path`/`block_command` rule, writing a prevented row (budget 0, per I4).

## Data model

`events` gains one nullable column:

```sql
source_kind TEXT    -- 'path' | 'command' | NULL when source is a bare tool name
```

`SCHEMA` is applied with `CREATE TABLE IF NOT EXISTS`, which does not add columns to a database that already exists, so **this needs the ledger's first migration**: read `PRAGMA table_info(events)`, `ALTER TABLE events ADD COLUMN source_kind TEXT` when absent. Additive and idempotent; existing rows keep `NULL` and stay un-blockable, which is correct — nothing knows where they came from.

`ExposureRow` and `_EXPOSURE_JSON_FIELDS` gain `source_kind`, since the browser UI cannot otherwise tell `.env` (blockable) from `Bash` (not). A value the code does not recognise is treated as not blockable, so an older or newer ledger degrades to "no button" rather than to a wrong one.

## Error handling

The rule throughout: this plugin never breaks a Codex session, and it never guesses.

- **`extract_origin` does not raise.** `shlex.split` raises `ValueError` on unbalanced quotes; that one exception is caught where it is raised and the function returns `None` — the same narrow handling `detect/shell.py::_tokens` already uses. No blanket `except Exception`: a `TypeError` from a payload shape we misread is a bug that should surface in tests, not be swallowed into "no origin".
- **Malformed `tool_input`.** `dispatch` already coerces a non-dict `tool_input` to `{}`. Missing or non-string fields yield `None`, never a partial `Origin`.
- **Migration failure** (a read-only or corrupt ledger) raises out of `Ledger.__init__`. The daemon then fails to start, the hook client gets no answer, and I6 takes over: ingress fails open with "unverified", egress fails closed. A daemon running against a schema it could not migrate would write rows that silently lose their origin, which is worse. `privacy-hud-doctor` should name this state.
- **No taint entry for a finding** — a daemon replaced mid-session, or a value the detectors missed on the way in — is an *absence of evidence*, not an engine failure, so the call is allowed. Denying on absence would block every outbound call after a daemon restart, which is #38's kill switch again by another route. I6's fail-closed rule covers engine failure and timeouts, and is unchanged. This is a known limit, below.
- **A policy rule whose origin never appears** simply never matches. It is refused at write time only when its `rule_type` is unknown (`apply_policy`'s existing `ValueError`).

## Testing

TDD throughout: each behaviour below gets a failing test first, and the failure is read before the code is written.

1. **`origin.py`, table-driven.** Positive: `cat .env`, `head -n5 config/.env`, a `Read` tool's `file_path`, `env`, `git log --oneline`. Negative: `.env.example`/`.env.sample` are not `.env`; `cp .env.example .env` yields no path; an `ls -la` *output* mentioning `.env` is not a read; unbalanced quotes yield `None`.
   **One property test guards I1**: for a corpus of commands carrying secrets in arguments, the extracted origin must contain no fragment of any argument. That test is the gatekeeper for "program name only" — it fails first if anyone later widens extraction to arguments.
2. **Engine.** Taint recorded on ingress; a later egress carrying that value denied under a rule; other values in the same session unaffected; a deny writes a prevented row contributing 0; ingress never denied (Ruling 3); rules scoped to the session.
3. **End to end**, extending `tests/test_block_source_e2e.py` (renamed): hook payloads through `dispatch()`, the audit read over the UI server's API, the rule written the way the browser writes it, the later call's reply asserted on.
4. **Migration.** Build a database with the pre-migration schema, open it with `Ledger`, assert the column is added, old rows read back `NULL`, and new inserts work.

`_EXPOSURE_JSON_FIELDS` and `render.detail()` goldens move with the wire format; they are pinned contracts and are meant to fail here.

## Copy

Action labels name the origin instead of saying "this source":

```
[ Block values read from .env ]
[ Block values from `git log` output ]
```

Confirmation states the limit rather than leaving it to be discovered:

```
Rule added: block values read from .env.
Applies to later outbound calls. Only exact values match — if the model
summarizes or rewrites the content, it still leaves.
```

Deny message:

```
PRIVACY HUD blocked a tool call

  mcp__slack__post_message  would send  credential
  read from .env.

  Run $privacy to review or adjust policy.
```

## Known limits to add

1. **Only byte-identical values match.** A model that summarizes, rewrites, or quotes part of what it read defeats this — and that is a likely path, not an exotic one. This limit goes first, because the action's name invites the opposite assumption.
2. **Origin extraction is best-effort.** `cat .env` is recognised; `python -c "open('.env')"` is not. A row with no origin offers no action.
3. **The taint map dies with the daemon.** A daemon replaced mid-session loses it, and source rules stop matching with no error. The ledger marks that session `⚠unverified` (limit 2 already detects a replaced daemon), but that marker means "this session's record has a hole", not "your rules stopped applying" — two different facts, stated separately.

## Build order

| Step | Change | Verified by |
|---|---|---|
| 1 | `origin.py` + tests, wired to nothing | Unit tests |
| 2 | `source_kind` column + migration | Migration test |
| 3 | `dispatch` fills the origin at PostToolUse | Audit row shows `.env` |
| 4 | Engine taint map, enforcement, two rule types | Engine tests |
| 5 | `apply_policy`, UI, `render`, copy | End to end |
| 6 | known-limits, both READMEs, version 0.5.0 | CI |

Steps 1–4 make the feature real; step 5 makes it reachable; step 6 keeps the claims honest. The zh-CN README line is written by Codex, per house practice.
