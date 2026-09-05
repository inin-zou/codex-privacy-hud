# Design decisions — Codex Privacy HUD MVP build

Rescued from `.superpowers/sdd/2026-09-03-implementation/` (gitignored scratch: task
briefs, per-task reports, review diffs, and a `progress.md` controller ledger). The
scratch is one `rm -rf` from gone and most of it deserves to be — but the rulings taken
during the build do not, because they explain code that looks arbitrary without them.

**Why this document exists.** Twice in the days after this build, work stalled on
rediscovering *why* code was the way it was: a regex gate that silently prevented the
model detector from ever running on addresses, and a lock-scope cost estimate that had
quietly gone ~50-100x stale. Both had reasons once. The reasons did not travel with the
code. Everything below is a reason, attached to the thing it explains.

**Why grouped this way, not chronologically.** The build order was driven by task
dependencies and agent scheduling, which is exactly the ordering a future maintainer does
not care about. A reader arrives holding a *file* — `engine.py`, `shell.py`,
`daemon.py` — and one question: "why is this branch here?" So the sections below are
subsystems and invariants, and each entry names the module or function that embodies it.
The one deliberately chronological section is the last: rulings that no longer hold.

**Scope.** Decisions only. Task status, test counts, merge order, review verdicts, and
who did what when are all dropped — that is git's job. The `review-*.diff` files are
duplicated git history and were not read into this document at all.

**Verification.** Every "lives in" pointer below was checked against the working tree on
2026-09-05, not copied from the scratch. Where the code no longer matches the ruling, the
ruling is in [Superseded](#superseded-rulings--do-not-treat-these-as-current) instead.
Two entries are marked *unverified* where the claim is not checkable from the code alone.

---

## 1. Scoring and the budget

**Credential severity is 50.0, not 40.0 — the original number rendered a leaked API key
as green.**
`PRD.md` asserted that one leaked credential should push the HUD into the red band and
computed `40 × 1.0 / 120 = 33%` — but 0–33 is the *green* band in the same document's own
table. So an API key entering model context would have rendered green and labeled safe:
the worst possible false negative for this product. Raised to 50.0, which puts model
context at 42% (amber) and an external host at 83% (red). Chosen over lowering the cap
(the cap is an open calibration question and lowering it inflates every other score) and
over relabelling the bands (the renderer and demo both depend on 0–33 = green). Being one
band too hot on credentials is recoverable; a key reading green is not.
*Lives in:* `src/privacy_hud/matrix/tables.toml` `[severity] credential = 50.0`.

**Never wrap a `Matrix.*` lookup in a bare `except KeyError` / `except Exception` that
continues.**
`UnknownKey` subclasses `KeyError`, so a blanket handler swallows it and silently scores
an unmapped data type as zero — the exact failure the fail-loud matrix layer exists to
prevent. Rather than change the exception hierarchy mid-build, this became a standing
constraint on every consumer. It is why the engine's *only* `except` catches `UnknownKey`
by name, attempts one named recovery, and re-raises.
*Lives in:* `matrix/loader.py` (`UnknownKey`), `engine.py::_normalize_destination`.

**The budget cap is data, not a constant the UI may hardcode.**
`budget_cap` is stored per session and `tables.toml`'s value is expected to be retuned.
The renderer therefore never reads the live matrix default to fill in "of 120" for a past
session — a session's stored cap can legitimately diverge from the current table, and
rendering the current one would fabricate a number for older sessions.
*Lives in:* `render.py::detail` (appends `of {cap}` only if the row carries one);
`sessions.budget_cap` in `ledger.py`.

---

## 2. Classification taxonomy (I3 — detection is not disclosure)

**A `local` destination classifies as `local_access` regardless of what direction the
caller passed.**
The single most load-bearing ruling in the codebase. The B0 boundary multiplier is 0.0,
so the *budget* is correct either way — but I3 is about the **kind**, not the score. A
caller passing `direction="ingress"` on a local file read must still produce
`local_access`, never `exposed`, or the audit reports reading a local file as a
disclosure: precisely the conflation the product exists to reject.
*Lives in:* `engine.py::Engine.observe` — `if dest_kind == "local": classify_direction =
"local"`, evaluated before the deny/rewrite branches and ignoring `obs.direction`.

**The ledger stores the bare destination *kind*, never `subagent:<id>` / `mcp:<server>`
detail.**
Not a style choice — forced by `Ledger.record()` calling `boundary_for()` on exactly the
string it is handed, and there is no second column for the detail (the schema comment
suggests one; the DDL never had it). Consequence a UI maintainer will hit: the audit
cannot distinguish "sent to subagent A" from "sent to subagent B", only "sent to a
subagent". Fixing that is a schema change, not a rendering change.
*Lives in:* `engine.py::_normalize_destination` (maps `subagent:*` → `subagent`, `mcp:*` →
`mcp_tool`, `net:*` → `external_net`, re-raises `UnknownKey` otherwise); `events.destination`
in `ledger.py`.

**`policy_defaults` (mask/block) binds egress only. Ingress is never rewritten.**
An ingress observation's bytes are already in model context; rewriting them would be
theatre, and I5 forbids implying recall. So a credential arriving via `PostToolUse` is
recorded as `exposed` and allowed — never `rewrite`.
*Lives in:* `engine.py::Engine.observe`, inside `if is_egress and ...`.

**A `PreToolUse` Bash command resolving to `local` skips the engine entirely rather than
catching `UnknownKey`.**
`tables.toml` has `PostToolUse/local` but deliberately no `PreToolUse/local` taxonomy
entry and no `local` in `policy_defaults`: nothing crosses a boundary, so there is nothing
to score. The alternative — building the Observation anyway and swallowing the resulting
`UnknownKey` — would violate the fail-loud rule above. So dispatch fails toward
*not calling the engine*, which sits alongside how `SessionStart`/`SessionEnd` are already
outside the Observation mapping.
**Accepted gap, stated so nobody mistakes it for completeness:** `PostToolUse`'s ingress
scan still catches a credential that appears in command *output*, but one that appears
only in argv and never prints (illustratively, `mysql -p$SECRET`) is missed. A
`PreToolUse/local` taxonomy entry was recommended as follow-up, not as a blocker.
*Lives in:* `dispatch.py::_build_observation` (`if destination == "local"`) and that
module's docstring.

---

## 3. Detection heuristics — the chosen failure direction

**The governing rule for this whole subsystem: a wrongly-`external` verdict is a visible
annoyance; a wrongly-`local` verdict is undetectable.** A finding in the unsafe direction
entered the fix loop regardless of how mildly the reviewer framed its severity; a finding
in the safe direction was allowed to stand. Several concrete decisions below only make
sense against that asymmetry.

**Hostname matching anchors on a known-TLD allowlist, not "looks dotted".**
The original regex `^(?:[\w-]+\.)+[a-z]{2,}$` matched `support.log` and `bar.txt` as
hostnames, because `.log` and `.txt` look like TLDs. `cat support.log` would have been
classified as external egress and **blocked** — and `support.log` is the file in the demo's
first step, so this would have broken the demo at step 1 while looking like correct
enforcement.
*Lives in:* `detect/shell.py` — `KNOWN_TLDS`, `BARE_HOST`.

**Tokenizer failure returns `external_net`, not `local`.**
`extract_destinations` originally fell through to `"local"` when `shlex.split` raised on
unbalanced quotes — the fail-*open* direction, contradicting the fail-closed rule the same
module specifies. Now an untokenizable command is treated as egress.
*Lives in:* `detect/shell.py::extract_destinations`.

**IP literals: loopback is local; everything else — RFC1918 included, link-local
especially — is external.**
Decided via `ipaddress`'s own `.is_loopback` rather than a hand-maintained prefix list, so
it cannot drift from the stdlib's definition. Loopback provably never leaves the machine's
network stack. Link-local was deliberately *not* carved out as a class, and
`169.254.169.254` (cloud metadata, a known exfil target) deliberately *not* special-cased:
`.is_loopback` is already False for the whole range, so it falls through to external with
no extra code. Private ≠ local — the module is about trust-boundary crossing, and a
private-network host is a different trust domain. Before this, bare IP literals were not
recognized as hosts at all, so `exfil --to 10.0.0.9:9999 secrets.env` classified as
`local`: a silent leak with a green HUD.
The hostname `localhost` (not the IP) resolves to `local` by falling through every
pattern; there is a test pinning that as intentional rather than accidental.
*Lives in:* `detect/shell.py` (`ipaddress.ip_address`, `.is_loopback`).

**The generic entropy backstop requires quotes and a length floor of 20; the
keyword-gated path keeps 16.**
Without quotes the surface includes `PATH=...` env lines, import paths and config values
with no delimiting signal — a far larger false-positive space. The extra 4 characters (vs.
the keyword path) compensate for having no keyword to narrow the search. The entropy
threshold itself (3.5) was not touched.
*Lives in:* `detect/secrets.py` — `GENERIC_QUOTED`.

**Hex strings at digest lengths {32, 40, 64, 128} are excluded — but only from
`GENERIC_QUOTED`, and base64 is *not* excluded.**
The false-positive rate was measured, not guessed: 2 of 5 probes, a quoted 40-char git SHA
and a quoted base64 blob. The two cases are asymmetric. A hex string at a digest length in
a coding session is a git SHA essentially by construction, and a coding agent touches SHAs
constantly — under the unmodified rule each one on an egress path is a blocked call or,
worse, gets pseudonymized, which rewrites the SHA and corrupts a legitimate git operation.
That is the tool breaking the user's work while claiming to protect them. Base64 genuinely
can be an encoded key, appears less often in this workload, and missing one is a silent
leak — the failure direction we accept. Exact lengths were chosen over a blanket
"any pure hex" rule, which would have blinded the backstop to hex-alphabet API tokens
generally (a much wider false-negative surface than the narrow gap of, say, a 56-char
sha224).
**`ASSIGNMENT` is deliberately not exempted: keyword beats shape**, so
`api_key = "<40 hex chars>"` still flags.
*Lives in:* `detect/secrets.py` — `HEX_DIGEST_LENGTHS`, `_is_hex_digest`, guarded by
`if pat is GENERIC_QUOTED`.

**Known evasion, documented as a limit rather than chased.**
`/dev/tcp`, `$IFS`-splitting, `bash -c`, `&&` chaining and `;`-chained `scp` are all
caught. `python -c "import socket; ..."` **evades** — no scheme, no allowlisted binary.
This is why `README`/`PRD` must keep saying enforcement is incomplete (CLAUDE.md §5); it
is a stated limit, not an open bug.

**Deliberately not fixed: `NET_BINARIES` matches any token, not just `argv[0]`.**
So `echo curl` over-blocks as external. Real, and left alone — the failure is in the safe
direction, and restricting to `argv[0]` plus post-separator tokens is real complexity for
a safe-direction miss. Noted for whoever next touches binary-detection precision.

---

## 4. Masking and minimization (I1 — no raw sensitive data persisted)

**Credentials get no masked exemplar at all** — even a two-character prefix narrows the
keyspace. `mask()` returns `None` for `data_type == "credential"`.

**Values of length ≤ 4 all mask to a fixed four-dot width, because a variable-width mask
is a length oracle.**
Graded minor by review and fixed anyway: `mask.py` is the only module between raw values
and disk, the masked exemplar's entire purpose is to be safe to persist, and leaking the
exact length of a short value (a PIN, an account suffix) contradicts what the README tells
users. The test asserts the *property* — `mask(x, "1") == mask(x, "1234")` — not a literal
string, so it survives changing the mask glyph.
*Lives in:* `mask.py::mask`.

**Minimization operates on the same string the findings were computed against — the
offsets are passed through, never re-derived.**
This was a real, reproduced leak, and it is the subtlest bug in the project's history.
For an MCP `PreToolUse` egress call, findings are computed against
`json.dumps(tool_input)` — a **blob**-relative coordinate space. The original code then
tried to apply those offsets to individual dict field *values*, which are different
strings with different offsets. A credential and an email shipped **fully unredacted**
while the engine reported `action="rewrite"` as if minimization had succeeded. The pinned
test missed it because its hand-constructed findings happened to be field-relative — an
artifact of the test, not of production behavior.
The fix is architectural: minimize the *same* serialized blob, then `json.loads` the
result back into a dict — one coordinate space, no distribution step. And rather than
factor `json.dumps` into a shared helper both sides call, `Engine.observe` passes
`text=obs.text` (the exact string it scanned) straight through. A shared helper only
guarantees agreement if every future caller remembers to use it; passing the actual string
requires no such discipline.
*Lives in:* `minimize.py::minimize_tool_input` (keyword-only `text=`) and
`engine.py::Engine.observe` (the single production call site, passing `text=obs.text`).

**A "silently drop the finding that fails validation" guard was the wrong fix, and is
worth remembering as a pattern.**
It was introduced to make a stub-detector test fixture stop crashing — a test-only problem
patched in production code — and it *hid* the offset-domain bug above by dropping every
finding that could not be field-attributed. Given three separate offset bugs already found
in this project, "drop and continue" on a validation failure is exactly how a genuine
finding passes through unredacted with no signal to the user or the audit. Fail closed on
the whole call instead, and fix the fixture.

**The offset invariant `text[f.start:f.end] == f.value` should have been a global
constraint from the start.** Three separate modules shipped offset bugs from the same
plan's reference code (`detect/paths.py`, `detect/model.py`, and `minimize.py`). A shared
cross-detector property test remains an open follow-up.

**Pseudonyms are JSON-safe by construction, and this was verified rather than assumed** —
built only from a code-controlled `data_type` string and a lowercase hex digest, joined
with `_` / `@` / `.`, none of which require escaping.
*Lives in:* `mask.py::pseudonym`.

---

## 5. Enforcement and the failure direction (I6)

**The daemon's reply *is* the hook-output JSON Codex expects. There is no envelope.**
`architecture.md` §2 sketched `{"v":1,"decision":"deny",...}` — nothing parses that shape.
The hook client writes the daemon's reply straight to stdout, so a daemon sending the
envelope would produce an unknown blob and the deny would silently not take effect.
`dispatch._deny()` was written to byte-match the client's own `_deny()` helper for exactly
this reason. Verified end to end against a real Codex session, where the deny actually
blocked a real tool call.
*Lives in:* `dispatch.py::_deny` ↔ `hooks/handler.py::_deny`.

**`{}` means allow — so `except Exception: reply = {}` was failing *open* on egress.**
The daemon's per-request exception boundary collapsed any internal failure to `{}`, which
is `_allow()`'s exact shape. The client cannot distinguish "the daemon deliberately
allowed this" from "the daemon crashed": its own fail-open/fail-closed logic only fires on
the *client's* exception (refused connection, timeout, malformed JSON), never on a cleanly
received reply's content. So a bug anywhere inside `Engine.observe` while scanning a
`PreToolUse` egress call silently allowed the call through — violating I6 for exactly the
crash scenario I6 exists to cover.
The fix gates on the cheap, exception-proof `payload.get("hook_event_name") ==
"PreToolUse"` (the only event that can be egress) and returns a deny built from a plain
dict literal — deliberately *not* re-running the classification logic that just raised,
which would risk a second exception inside a last-resort handler. Non-`PreToolUse` events
keep the original fail-open behavior.
*Lives in:* `daemon.py::_deny_for_internal_failure` and `_Handler.handle`.

**User-written policy rules outrank the built-in matrix defaults, and are consulted before
them: `block_source` (deny) > `mask` (rewrite) > `Matrix.default_action()`.**
Two of the three L3 actions — "Block this source" and "Protect future occurrences" — wrote
durable, correctly-scoped rows to the `policy` table that **nothing ever read**. They were
cosmetic buttons for most of the build. Closing this was ruled load-bearing rather than
deferrable: shipping two dead buttons in the L3 UI costs more than one extra policy read
per egress observation. Egress-only, for the same reason ingress is never rewritten. It is
also **not retroactive** — data disclosed before a rule was written stays disclosed
(design.md P4), and the docstrings say so.
*Lives in:* `engine.py::_policy_selectors`, consulted in `Engine.observe` ahead of
`Matrix.default_action()`; written by `mcp_tools.py::apply_policy`; pinned by
`tests/test_engine.py::test_a_blocked_source_denies_a_later_egress`.
**Two known narrowings:** `selector` matching is exact-string, not glob, though the schema
comment allows for a path glob; and `allow_dest` is untouched because nothing mints it yet.

**Deliberately deferred: the hook client's own egress heuristic is weaker than the server's
detector, and that is accepted.**
`hooks/handler.py::_looks_like_egress` recognizes only a `://` substring or an
`mcp`-prefixed tool name — much less than `detect/shell.py` (NET_BINARIES, bare IPs with
no scheme) after two hardening rounds. Duplicating the real detection into the client
either breaks the stdlib-only constraint or creates a second copy that will drift. Recorded
as a known limit rather than silently dropped.

---

## 6. Platform reality beats platform documentation

The generalized lesson from this section: **the Codex docs were wrong about our two most
load-bearing integration points, and only a smoke test against the real CLI found it.**
Where they conflict, trust observed behavior and record the divergence.

**`"async": true` hooks are silently skipped ("async hooks are not supported yet"), so
`PostToolUse` is synchronous.**
`PostToolUse` is the primary ingress chokepoint — it is how tool results, i.e. file
contents, are observed entering model context. Silently skipped means the ledger records
nothing for the largest source of disclosure in a session while the HUD sits at 0% and
looks like it is working: the product would have been hollow and convincing at the same
time. `PreCompact`'s marker-row mechanism was equally dead.
Resolution: drop `async`, and bound the synchronous work instead of deferring it (see §7).
*Lives in:* `hooks/hooks.json` — zero `async` keys; the eight entries are plain
`{type, command, timeout}`.

**The plugin manifest lives at `.claude-plugin/`, not the documented `.codex-plugin/`.**
`codex plugin marketplace add` fails outright against the documented path. Real plugins on
the test machine use `.claude-plugin/plugin.json` plus `.claude-plugin/marketplace.json`.
Shipped what actually loads, single location, no second manifest.
*Lives in:* `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`
(`.codex-plugin/` is absent from disk and from git).

**Platform drift is ongoing: `SessionEnd`'s hook timeout is silently clamped 10s → 3s on
newer Codex builds** — and the same clamp hits the official first-party plugin on the same
machine, so it is a platform change, not something about us. 3s still covers `SessionEnd`'s
work. *(Observed on Codex 0.153.0 during the build; not re-verified since — treat the
version boundary as approximate.)*

---

## 7. Cost bounds and concurrency

**`MAX_TIER3_CHARS = 8192`: above it, the model tier is skipped **entirely**, not
truncated.**
`architecture.md` describes truncate-and-run; skip-entirely was chosen deliberately. It
resolves both clauses of the bound with one threshold and one code path, and is strictly
more conservative on latency (zero tier-3 cost above the bound instead of a fixed ~40ms).
Measured in **characters, not encoded bytes**: encoding a string just to decide whether to
bound it costs an O(n) pass over exactly the large input the bound exists to avoid, and
UTF-8 byte count ≥ char count, so the character bound is never looser.
*Lives in:* `engine.py` — `MAX_TIER3_CHARS`, checked in `Engine._scan`.

**`Decision.degraded` covers both "skipped for size" and "model unavailable", on
purpose** — one flag, one UI banner ("Deep scan unavailable — fast-path results only"),
one fewer state for the renderer to invent. The banner was designed for detector failure
and now also covers large payloads.
*Lives in:* `engine.py::Decision.degraded`; `render.py::audit`.

**The daemon-wide lock exists because of one shared `sqlite3.Connection`, and that scope
is not negotiable — but its *hold time* is.**
A per-session lock would correctly serialize two calls for the same session and still let
two *different* sessions' worker threads hit the one shared connection concurrently, which
`sqlite3` documents as unsafe. So the necessary scope is set by the shared connection, not
by session identity. What changed later is how much code the lock covers — see
[Superseded](#superseded-rulings--do-not-treat-these-as-current).
*Lives in:* `dispatch.py::State.lock`; the full argument is in `daemon.py`'s `Daemon`
docstring, "Lock scope"/"Hold time" — read that before touching either lock.

**`check_same_thread=False` is set at the daemon call site, not in `Ledger.__init__`.**
Under a threading socket server every ledger touch from a worker thread raised
`sqlite3.ProgrammingError`, was swallowed by the outer handler, and came back to the client
as a silent empty reply — indistinguishable from "nothing to report". The reopen happens in
`dispatch.new_state()` because `Ledger`'s single-threaded-by-default contract is correct for
every other caller, and external serialization (the lock above) is what sqlite then
requires.
*Lives in:* `dispatch.py::_allow_cross_thread_access`. The UI server does the same thing for
its own reason and needs no lock, being single-threaded by design
(`local_ui_server.py`).

---

## 8. UI honesty (I5, and CLAUDE.md §5 applied to rendered copy)

The through-line: **where the data cannot support what the design mockup shows, render the
smaller true thing and document the gap — never fabricate the difference.** Each of these
is a place where a maintainer might otherwise "fix" the renderer by inventing data.

- **No fake transcript path.** The receipt states the true generic fact (Codex persists the
  transcript, outside this ledger) rather than printing a plausible `~/.codex/sessions/...`
  path it cannot know.
- **No invented row aggregation.** design.md's "×12" grouping is an explicit *open* design
  question; no shipped code aggregates, so the UI does not either — an independent
  aggregation would disagree with every other view.
- **No invented qualifiers.** design.md's example table says "Customer email"; `data_type`
  only ever holds `email`. Rows render the plain category.
- **The compressed-bar formula is inferred from a single data point** (`min(round(pct/10),
  cells)`, derived from one 28% example) and is flagged as inferred in `_bar`'s docstring
  rather than presented as certain.
- **`degraded` is not persisted to the ledger**, so a UI reading history after the fact has
  no honest signal — the banner is omitted rather than defaulting to "not degraded".
- **Tab counts for non-"All events" tabs are a documented best-effort estimate** that
  undercounts when `local_access`/`retention` events exist. It errs toward *understating*
  exposure, which is the wrong direction for a privacy tool to err in reverse.

**`$privacy` prints a URL that actually works, because a printed URL to a nonexistent
server is exactly the overclaim CLAUDE.md §5 forbids.** A ~250-line stdlib-only HTTP server
was built to fulfil a design commitment that was otherwise unmet, rather than leaving the
gap and printing the URL anyway.
*Lives in:* `local_ui_server.py`; `skills/privacy/SKILL.md`.

**`allow_once` has no UI button, and that is a consequence of I1, not an omission.** The
ledger deliberately never stores `tool_input` (it could carry a raw value), so a
historical, ledger-backed page has nothing to mint a consent token against. The tool is
implemented and exposed over MCP for a live caller that still holds the real `tool_input`
in memory.
*Lives in:* `mcp_tools.py::allow_once`; `render.py::detail` renders only the two
source-scoped actions for the same reason.

**`get_exposure_detail` is keyed on `events.id`, scoped by `session_id`.** A composite
`(data_type, source, destination)` key was rejected because it is **not unique** — the
dedupe key is `(session_id, value_hash, destination)`, so two distinct values of the same
type from the same source to the same destination already produce two rows sharing that
composite. Session-scoping means an id belonging to another session resolves as not-found
rather than as a cross-session read.
*Lives in:* `mcp_tools.py::get_exposure_detail`.

**The ambient HUD is a separate polling process, and we deliberately do not patch Codex.**
Stock Codex's `tui.status_line` accepts built-in status-item identifiers only — there is no
plugin-owned renderer, so nothing this package produces can appear under the input area
without patching and recompiling Codex's own source. Forked-binary HUDs go stale on every
upstream release. It polls the ledger (WAL mode, safe concurrent read) rather than asking
the daemon, because the daemon's socket is the hook hot path. It checks the DB file exists
before opening, because `sqlite3.connect()` *creates* missing files and a glance-only
surface must not leave an empty `ledger.db` wherever `PLUGIN_DATA` points.
*Lives in:* `ambient.py` — its module docstring carries this in full.

---

## Superseded rulings — do not treat these as current

Listed because the reasoning is still instructive and because a reader who finds the old
ruling elsewhere needs to know it was overturned.

| Ruling as taken | Status today |
|---|---|
| Tier 3 is gated behind a cheap `_looks_pii_shaped` regex (email/phone/SSN shapes) so it does not run on obviously clean text. | **Reversed.** The gate could only ever admit the categories that needed tier 3 *least* — it permanently excluded address, person, date and account number, which tiers 0-2 cannot shape-match at all. `Engine._scan` now always deep-scans when the boundary/destination guards allow; the cost bound is `MAX_TIER3_CHARS` alone. The reasoning is preserved in `_scan`'s inline comment. |
| A detector is "tier 3" if it has an `available` attribute. | **Reversed.** That conflated *cost* with *runtime availability*: a cheap detector tracking availability was silently reclassified as expensive (stopped running on local reads and B3/B4, skipped past the size cap), and an expensive one without the flag ran unconditionally, uncapped. Tiering now reads `DetectorProfile.cost`; availability is read separately via `is_available` and decides only whether *this instance* can run. See `detect/base.py`'s module docstring. |
| Hold the single daemon-wide lock across the whole of `observe()`, including tier-3 inference — justified by "~5ms ledger write + ~6ms tiers 0-2, negligible next to the 150ms target". | **Reversed, and this is the stale-estimate case that motivated this document.** That estimate predates tier 3 running unconditionally and is ~50-100x off: one warm ingress request measures ~540ms, essentially all model inference. Holding the lock across it put a sub-millisecond egress `PreToolUse` behind the queue — measured ~3060ms under six concurrent ingress scans, past the client's timeout, so I6 made it **deny** a benign call. `Engine` now splits `scan()` (no ledger) from `observe(obs, scan=...)` (every sqlite touch), `dispatch()` runs the scan between two short lock holds, and a separate `engine._TIER3_LOCK` serializes inference. Full measurements in `daemon.py`'s `Daemon` docstring. Note what it does *not* buy: ingress throughput is unchanged, bounded by inference. |
| Hook client socket timeout 0.12s. | **Superseded** — now 2.0s, recalibrated against a measured ~280ms real round trip once tier 3 ran unconditionally, with headroom under the clamped 3s `SessionEnd` timeout. `hooks/handler.py::TIMEOUT` carries the reasoning. |
| The daemon does not auto-spawn; a manual `python -m privacy_hud.daemon &` is a documented startup step. (Itself a reversal of an earlier "MUST FIX before demo" ruling, overturned by an explicit user scope decision — the finding was correct, the response changed.) | **Superseded — auto-spawn now exists.** `hooks/handler.py::_spawn_daemon` starts it lazily when `connect()` fails, behind a cooldown latch and an opt-out env var. Two details a maintainer will wonder about: the spawn lives in the hook client specifically because hooks are Codex's children, so `PLUGIN_DATA` is already correct in the environment (which makes "daemon listening on a socket no hook will use" impossible rather than merely detectable); and the interpreter is read from a setup receipt rather than the shebang's `PATH`, because Codex's minimal `PATH` resolves to a system Python with no `transformers`, producing a daemon whose tier 3 is silently dead while it reports itself healthy. Note the earlier ruling proposed `os.posix_spawn` to preserve the stdlib-only rule; the shipped code uses a lazily imported `subprocess.Popen` inside `_spawn_daemon`, leaving the hot path's four imports untouched. |
| Policy rules written by `apply_policy` / `update_policy` are cosmetic and "not currently consulted". | **False since the policy-enforcement fix** — see §5. Some source docstrings carried the stale claim for a while; that drift was itself a review finding. |
| The 13-task plan shipped no ambient HUD. | **Superseded** — `ambient.py` exists (see §8). Docs that describe the Level 1 HUD as unbuilt are stale; docs that describe it as a *native Codex status item* are wrong in the other direction and violate CLAUDE.md §5. |

---

## Known-inert code, so nobody assumes it works

Not decisions, but each is a place where reading the code alone suggests a capability that
does not exist — the same failure mode this document exists to prevent.

- **The `flows` table has no writer.** Multi-hop chains are dead schema;
  `render.detail()` falls back to a single `source → destination` line.
- **`.claude-plugin/plugin.json` declares no `mcp` key**, so the MCP server is built but
  not registered by the manifest. The skill invokes it directly.
- **I7 (the tool survives its own audit) — verified 2026-09-05, by hand.** It was
  UNVERIFIED at build time: every `codex exec` attempt 404'd against an external backend
  outage, so the run was blocked rather than failed. Re-run once the outage passed, against
  Codex CLI 0.153.0 with a **warm** daemon: a session that read `src/privacy_hud/budget.py`
  and answered a question about it recorded zero events, budget 0.0/120.0.

  Two cautions for whoever re-runs it. There is **no automated test** — it needs a live
  Codex session, which CI has neither the binary nor the network for, so `CLAUDE.md` §3 no
  longer claims one exists. And a **cold** daemon invalidates the run: the first attempt
  here produced a session that was never recorded at all (README known limit 1), which in
  the ledger is indistinguishable from a clean one. Confirm the session row exists and its
  `started_at` is your run before reading anything into zero exposures.
