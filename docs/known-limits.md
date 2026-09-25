# Known limits

Stated up front, because a privacy tool that overclaims is worse than none:

**Linux install/repair holder visibility.** The storage transition checks observable same-uid processes through `/proc`. It skips a process when listing its fd directory returns `EACCES`, and skips a descriptor when both stat and readlink return `EACCES`. These are inspection blind spots, not evidence that the process is unrelated to the ledger. An inaccessible process may still hold a ledger or sidecar; a successful scan does not prove that all ledger users have stopped. Close other ledger users before install or repair. A readable filesystem link whose inode cannot be checked still causes refusal, as do other inspection errors except vanished processes or descriptors. Linux remains supported within this visibility limit.

A denial or rewritten input returned by Privacy HUD is not confirmation that the host applied it. Current hooks do not establish that a denied call did not run or that rewritten input reached its intended recipient.

The historical headings retain their link anchors. References to blocking below describe plugin decisions or legacy classifications, not confirmed host enforcement.

## 1. The start of a session is unmonitored.

The daemon starts itself now (`architecture.md`'s lazy auto-spawn, built), but it loads ~2.8 GB of model weights before it binds its socket — about seven seconds. The hook that starts it does not wait, and the hooks that fire during the load get the same answer as a missing daemon: fail open on ingress with an "unverified" note, fail closed on egress. **Whatever is disclosed in those first seconds is not in the ledger, and no later reading can say what it was.** The ledger does now know that *something* is missing — see limit 2 — but knowing a gap exists is not knowing what fell into it, and nothing recovers the difference. Measured: a `codex exec` one-shot that finished in 8.2 s from a cold start recorded *nothing at all* — the daemon it started was still loading when the session ended, so for short non-interactive runs this is not "the first few seconds" but the whole session. An interactive session is a different story, since typing the first prompt already outlasts the load. Starting a daemon by hand before the session (step 2) is the only way to close that window. It reopens whenever the daemon exits and a later hook has to start a new one — which now happens five minutes after your last session ends, rather than in the middle of a session that merely went quiet for half an hour.

A running older daemon continues to use its own snapshot writer until it exits. Updated readers accept v1 snapshots as legacy. Once the 0.7.8 daemon writes v2, older patched Codex readers show no Privacy item; install a snapshot-v2-compatible patched build or use the ambient pane. Restarting Codex alone does not necessarily stop a daemon serving other live sessions.

The other half of the trade: auto-start works only if `privacy-hud-setup` has recorded an interpreter that can load the model. It refuses to record one that cannot, and with no recorded interpreter no daemon is started at all — deliberately, since guessing one produces a daemon that detects nothing while looking healthy. `privacy-hud-doctor` is the detector for both states: it round-trips the socket, and it re-imports the recorded interpreter's stack.

## 2. "Unverified" marks the gaps it can see, and there are gaps it cannot.

A recorded legacy session with known coverage gaps appends `⚠unverified` to its labelled reading and carries a `⚠ Session record incomplete` audit banner. An explicitly unrecorded session instead shows `Privacy —% · No session on record`, without numeric quantities or an extra coverage suffix. No resolved session plus a daemon marker reporting gaps produces `Privacy —% · unattributed hook gaps` in the companion pane. Missing, malformed, stale, or hidden snapshots produce no line. Neither a legacy zero nor the absence of a coverage warning proves that nothing was disclosed. Recorded gap evidence includes a missing session record, an unobserved start, daemon replacement, hook calls answered without a daemon, and observed scan gaps (limit 21).

What is **not** detectable, and is not marked: a gap in the middle of a session while one daemon stayed up throughout. A hook Codex never fired, a hook whose 2 s client timeout expired against a busy daemon, a hosted tool that bypassed hooks (limit 3) — each of those leaves no trace anywhere, by construction, and no heuristic here guesses at one. So `⚠unverified` means "the ledger holds evidence of a hole"; its absence means "nothing on record contradicts a complete account", which is a weaker claim than "complete" and must not be read as the stronger one. The marker also does not appear if `PLUGIN_DATA` is unwritable or auto-spawn is off (`PRIVACY_HUD_NO_SPAWN`), because then no latch is written and the dropped hooks leave nothing behind either.

## 3. Hosted tools bypass hooks.

WebSearch and similar do not trigger local function-tool hook paths. This is a practical guardrail, not a complete enforcement boundary.

## 4. No `ask` decision in Codex hooks, and no interactive consent at all.

This historical heading describes tool-call consent. Codex hooks have no ask decision, and no shipped browser button, $privacy branch, or exposed MCP tool issues a consent token for a denied tool call.

UserPromptSubmit credential holds now have a separate resubmission confirmation path, described in limit 22. It neither issues tool-consent tokens nor changes saved tool policies.

## 5. The status-line item lives in a separately built Codex — never in your official one.

`tui.status_line` accepts only built-in identifiers compiled into the binary, and stock Codex has no plugin-owned renderer or runtime registry ([openai/codex#17827](https://github.com/openai/codex/issues/17827), open since 2026-04-14 with no PR). So the `privacy` item exists only in a Codex built from `patches/privacy-status-line.patch` — one added `StatusLineItem::Privacy`, no subprocess, no shell, no timeout: it only ever reads `$PLUGIN_DATA/hud/<session_id>.json` and nothing else. **The plugin never modifies your official Codex binary.** `install.sh` fetches the patched build for your exact `codex --version`, places it beside the official one under `~/.local/share/codex-privacy-hud/<version>/`, and installs a forwarding script as `~/.local/bin/codex` — the forwarder is a script that chooses between two binaries by version match, nothing more; it is never itself the status-line feature, and stock Codex never gains one. Toggle whether the item is configured with `/statusline`; toggle whether it currently shows with `$privacy hud on|off`. **A Codex upgrade with no matching release silently falls back**: the forwarder finds no build for the new version, runs the official binary unchanged, the status item disappears, and you are left with the fallback pane (`privacy-hud-ambient --watch`, [above](../README.md#installing-by-hand)) — nothing breaks. The whole build is reproducible from source: `scripts/build-patched-codex.sh <codex-version>` clones `openai/codex` at that tag, applies the patch, and builds it — the same script CI runs to publish the releases `install.sh` downloads. (Prior art paid a heavier cost for the same feature: both [`anhannin/codex-hud`](https://github.com/anhannin/codex-hud) and [`brandonwie/codex-hud`](https://github.com/brandonwie/codex-hud) also patch Codex's own Rust source, but through a runtime `status_line_command` that shells out to an arbitrary user command — this project's patch reads one file, no subprocess, no shell, precisely to avoid that surface. Notably, `brandonwie/codex-hud`'s *default* mode avoids patching entirely and is exactly the second-pane companion pattern this project's fallback uses.)

## 6. A command that reads a file itself is not inspected.

The engine does not inspect file contents referenced by a command. In 0.9.2, a default-on lexical network guard denies an observed shell command when a recognized network-program token and a known-sensitive-path fragment occur together. It reuses the existing path rules and template suffix exemptions. It does not open files or rewrite uploads.

This covers visible sensitive paths in curl command substitutions, backticks, process substitutions, `@file` arguments, `--data-urlencode name@file`, form uploads, `-T`/`--upload-file`, stdin redirection and pipelines. It also covers visible sensitive paths accompanying the other recognized network programs, including wget, scp and rsync.

The check does not trace payload data flow. A sensitive-path reference in a literal argument, header, URL or unrelated part of the same compound command can also cause denial. Ordinary non-sensitive uploads such as `curl -F file=@report.txt https://example.com` remain eligible for the existing policy checks. A recognized network program remains conservatively classified as external even when an argument names 127.0.0.1; the guard does not establish effective routing or configuration.

Tokenization failure with a recognizable network-program token causes denial, even when no sensitive path can be recovered. A missing sensitive-path match is not itself a parser failure. Variables, aliases, configuration files, generated or encoded paths, symlinks, wrapper scripts and nested shell programs passed as one quoted argument are not resolved. A file such as `secrets.env` remains outside the existing `.env` rule unless another rule matches it; undiscovered secrets inside otherwise ordinary files remain outside this guard.

The network guard is on by default and independent of the optional local read guard. Mask rules and internal consent tokens do not bypass it. A returned denial does not confirm host enforcement.

Legacy accounting records matched rule markers as `prevented` with zero additional charge; repeated markers may merge. Version-2 accounting records a denial observation and one unresolved file-reference subject per matched rule, without a path, suffix, exemplar or identity hash. These subjects do not identify or count files. A parse-failure denial without a recovered path or detector finding has no fabricated finding event; legacy accounting has no row for that case, while version 2 still records the denial observation. Neither accounting mode establishes that the host stopped execution.

## 7. Detection is heuristic.

A determined adversary can encode around regex and NER.

It also over-reports on ordinary development text, in ways that inflate the budget rather than deflate it — and an inflated number is a number people learn to ignore. Measured over 61 synthetic development-session strings containing no personal data (paths, `git` output, SQL, shell pipelines, JSON, log lines, stack traces, source), tier 3 produces at least one finding on 9 of them. Four classes account for nearly all of it, and all four are the model's *confident* output (0.92–1.00), so the confidence floor in `detect/model.py` does not reach them and no floor that would reach them still keeps real disclosures:

- **Your own username, as a `person`.** Every path under `/Users/<you>` or `/home/<you>` scores ~1.00 as a person name. Suppressing entity spans inside filesystem paths would also silence `/Users/<someone-else>/Downloads/patient-intake-2026.csv`, which is a row you want.
- **Log and database timestamps, as a `date`.** `2026-09-05T18:53:02` scores 1.00, and so does a real date of birth in the same shape — the model does not distinguish them, and neither can we without dropping the one that matters. `date` carries the lowest severity in the matrix (2.0), which is the only thing that keeps this cheap.
- **Identifier-shaped and size-shaped numbers**, as `person`, `account`, `address`, or `credential`: container image IDs, UUIDs, digests, `SEQ=00194427`, the byte counts in `ls -l` output. A UUID scores 0.978 as a secret while a genuine database password scores 0.949, so this one is provably not separable by confidence.
- **Capitalized words in structured data**, as a `person`: `"tool_name": "Bash"` scores 1.00.

Read a `person` or `date` row on a `Bash` source with that in mind: the exemplar column is there so you can tell at a glance which findings are yours and which are the machine's.

## 8. Which session is being shown is inferred, not read — and the audit says so when it cannot be sure.

Codex exposes no session id to a skill, so the session to audit is worked out rather than read: the daemon knows which session fired a hook most recently, and running `$privacy` itself fires one (the skill runs bash, which is a `PreToolUse` in the session you typed in), so the asking session is the most recently active one. Two consequences. With **two sessions active in the same few seconds** the signal cannot separate them — the skill's terminal audit names the other active session in a line above the table instead of picking one silently, its header reads `Most recently active session` rather than `Current session`, and `$privacy <session id>` audits a specific one. With **no daemon to ask**, it falls back to the most recently started session in the ledger and labels it as that, in both the note and the table header, rather than as yours; a session with no daemon is also not being recorded (limit 1), so that is the state in which the numbers mean least. The browser and its ASCII view show `Session <full ID>`, not the resolution basis. The skill's URL pins its selected ID; a browser opened without an ID resolves independently.

The ambient line (limit 5) resolves the same way, so the pane beside your window and the audit typed into it name the same session. It does so on a slower clock — once when it starts and roughly every 30 s after, not on every two-second redraw — because that resolution asks the daemon over the socket the hooks use, and because a HUD that changed which session it was reporting on between redraws would be unreadable. Two things follow. A session that starts right after a re-resolution can take up to half a minute to appear in the pane. And the ambient line carries **no marker for session ambiguity at all**: the compact width candidates do not include one, and the `⚠unverified` glyph is not available for it — that marker means the session's *record* has a known hole (limit 2), and one glyph cannot mean two things. If you need certainty about which session a pane is showing, pin it with `privacy-hud-ambient --session-id <id>`, or ask `$privacy`, which has the room to explain itself.

## 9. Nothing recalls disclosed data.

Ever.

## 10. A source rule matches the whole value, normalised — not a summary of it, and not a byte comparison either.

A model that summarizes, rewrites, or quotes part of what it read defeats it, and that is a likely path rather than an exotic one. The value must be detected on ingress and again on egress. When either detection depends on the deep scan, a scan gap can prevent this rule from matching (known limit 21). Detection is heuristic and can miss values, and hosted tools never reach this plugin at all.

This said "byte-identical" until #49 item 7, and that was wrong in the other direction. Matching keys on `mask.value_hash`, which is an HMAC of `value.strip().lower()` (`mask.py:21`) — the same hash the taint map is keyed by (`engine.py:448`). So the set that matches is **wider** than byte-identical: two values differing only in case or surrounding whitespace are one value here. Whether that is the right identity is open (#43, #44); what is not open is describing it as a byte comparison.

Collapsing two sightings into one ledger row needs more than a hash collision — the row's key is `(session_id, value_hash, destination)` — so a `×N` count is N hits on that key, not N distinct values and not N hops.

## 11. Origin extraction is best-effort.

The network guard is separate from origin extraction and does not turn a lexical path reference into an origin or accounting file identity. Its broader co-occurrence rule and limitations are described in limit 6.

`cat .env` is recognised; `python -c "open('.env')"` is not. A path under your own home directory is recorded as `~/…`: the account name is kept out of the ledger, the same way `runtime.display_path` keeps it out of a report and a masked exemplar reads `/Users/•••/app.log`. Another account's home is left as it is — that is a row you want to be able to read. A row with no origin offers no rule, rather than offering one that would not work.

Within the commands it does read, it errs the same way: a candidate that is not shaped like a path (`cat Makefile`, or a file named by an option the extractor does not know) is recorded as the command, not as a file. The cost of guessing wrong runs the other way — `events.source` is persisted, served and rendered, so an option value taken for a filename would put an argument, possibly a credential, into the ledger (I1).

## 12. The taint map dies with the daemon.

A daemon replaced mid-session loses it, and source rules stop matching with no error. The ledger marks such a session `⚠unverified` (limit 2 already detects a replaced daemon), but that marker means "this session's record has a hole", not "your rules stopped applying" — state both, separately.

## 13. No policy rule can be removed within the session that wrote it.

There is no removal path for any of them: nothing deletes a policy row — no `remove_policy`, no `DELETE FROM policy` anywhere in the code. This is **not new with source rules**; it has always been true of `Mask detected <type> in future calls` (a `mask` rule) as well, and was simply never written down. A rule written by mistake is lived with.

For a source rule there is also no way around it in the moment: an "allow once" token does not override one, because an origin deny is decided before the token is consulted and the token path only runs on a call that is otherwise allowed. This is not a workaround you are missing — no surface mints such a token today: not `$privacy`, not the audit UI, not an MCP tool.

What limits every rule is the session. `Ledger.add_policy` scopes it to `session:<id>`, so it applies until that session ends and not after — a new Codex conversation starts with none of them. That is the only escape, and it is the same one the red band already points at for context: what the old session sent stays sent.

## 14. Only a shell command whose read the extractor recognises is stopped.

This limit describes the optional local read guard. Network commands are also subject to the independent default-on guard in limit 6.

**The guard covers one tool: the shell.** A read reaches the guard only as a `Bash` tool call, because that is how Codex reads a file — it has no native file-read tool, so the model shells out to `cat` or `sed -n`. Any other tool is allowed unexamined, including one a plugin adds that takes a file path and reads it. The plugin does not enumerate the tools Codex can send, and a path in an unknown tool's arguments is as likely to be written as read, so blocking on one would risk refusing a write under a message that says "blocked a read".

Within the shell, the guard acts on the path `origin.extract_origin` reads out of the command text — limit 11 holds that mechanism and its "never guess" rule. A command it does not resolve to a path is allowed: no deny, no notice, no ledger row. The engine reads command text, not execution; the separate network guard can deny visible sensitive-path references without resolving the read's origin.

Ordinary shell forms that are not stopped, in three groups:

- **The verb is not one of the read verbs.** `wc -l .env`, `source .env`, `. .env`, `cp .env /tmp/x` and `openssl rsa -in key.pem` all put the file's bytes somewhere; none of them is `cat`. So does `python -c "open('.env')"`.
- **The argument is not shaped like a path.** `strings id_rsa` and `cat id_rsa` record the command, not the file: a bare word with no `/` and no extension is not taken for a filename, for the reason limit 11 gives — an option value mistaken for one would be persisted in `events.source` (I1). `strings ./id_rsa` and `xxd ~/.ssh/id_rsa` are stopped.
- **The flag is not one the extractor knows for that verb.** `head -5 .env` is allowed; `head -n 5 .env` is stopped.

And within the paths it does resolve: the pattern behind `.env` requires a start of string or a separator (whitespace, `/`, `=`, a quote) just before it, so `prod.env` is not matched — the guard covers the paths those patterns name, not every file that looks like an env file.

## 15. A template file is never blocked.

The carve-out applies to path-based denial only. Both the optional local read guard and the default-on network guard reuse `is_sensitive_path`, which exempts paths ending in `.example`, `.sample`, `.template` or `.dist`. Detection still flags matching path text. A literal credential elsewhere in a template-upload command can independently cause denial; the plugin does not inspect the template file's contents.

## 16. Nothing is blocked until you turn it on.

This historical heading concerns the optional shell-read guard. That guard is off by default; $privacy read status reports its setting. Credential prompt holds are separate and do not depend on this setting.

The network guard is on by default and does not depend on that setting. Existing credential-based egress policy and failure handling also operate without enabling the local read guard. These are denial decisions returned by the plugin, not confirmation of host enforcement.

## 17. A blocked read can leave a record that says the opposite, in one sequence.

This limitation remains for legacy-accounted sessions and historical rows. Legacy deduplication can merge a later denial into an earlier row with a different outcome. Those records are preserved without reconstruction or rescoring.

New-accounting sessions append independent observations and finding outcomes. An earlier permission or disclosure does not suppress a later denial, and a later denial does not subtract an earlier charge. The summary counts denials issued by action, including actions with no findings.

A denial issued by Privacy HUD is not confirmation that the host enforced it. Current hooks leave that outcome unresolved.

## 18. A blocked read's row does not name the file.

Network-file denials also keep shell-derived file identities unresolved. Their version-2 file-reference subjects use source `tool input`, an allowlisted path-rule ID and an opaque label, with no filename, suffix, exemplar or identity hash. One subject represents one matched rule within an observation, not one identified file. Network parse failures without a recovered path create no file subject.

Legacy-accounted sessions and historical rows can still merge files matching one detector pattern. Version-2 accounting removes that pattern-based merging, but the audit still cannot identify which file a shell-read denial concerned.

All shell-derived accounting file identities remain unresolved in 0.9.0, including ordinary `cat .env` reads. Command text does not attest the executable, shell expansion, inherited environment, or program configuration. Each separate observation of a guarded shell read receives an unresolved file subject; distinct opaque IDs do not establish distinct files, and another observation of the same path also receives another unresolved subject. The audit uses source `local file` and label `file <opaque-id>`, without the filename or a suffix. The extracted path remains available to the guard and its immediate denial message; that does not establish which files execution actually read.

The HUD counts denials issued by action, not confirmed stopped reads. Two separately denied actions count as two denials issued; current hooks establish no confirmed reads stopped. Supported literal structured path inputs can still supply lexical file identity when the accounting key is available; symlinks and filesystem aliases are not resolved. This is parser support, not an evidenced native Codex file-read hook in this integration, and resolved identity alone does not provide a useful path label. #44 remains open for supported guard-target identity and I1-safe audit display. 0.10.0 is a proposed target for that remaining work, not a release commitment.

## 19. What a subagent inherited is not recorded.

`SubagentStart` is one of the four accounting chokepoints in `architecture.md`, and the observation built for it carries no text: `dispatch.py:527` constructs it with `text=""`, so no detector ever runs on it and no row can result. A subagent is still a `destination` for data sent to it through a tool call, but the question "did the subagent inherit the `.env` the main agent had read?" — named in `PRD.md` as one the product answers — has no answer in the ledger.

This says nothing about what happens *inside* a subagent's own session, which has its own hooks and its own session id.

## 20. A destination is a boundary category, not a recipient.

Legacy accounting groups destinations by boundary category.

New accounting separates boundary category from recipient identity. Supported, unambiguous MCP namespaces identify intended server configurations; multiple tools in one namespace share a recipient. A narrow parser identifies the intended endpoint of supported simple network commands. Ambiguous names, unsupported command forms, dynamic destinations, and unknown recipients remain unresolved.

Intended identity does not prove transmission, backend identity, downstream forwarding, subagent inheritance, or continuity across unobserved configuration changes. Current hooks do not supply the crossing receipts needed to turn those intentions into confirmed disclosures.

## 21. On an outbound call, the deep scan is best-effort.

Until #47 item 1 the deep scan never ran on an outbound call at all, so `email`, `person`, `address`, `phone` and `account` — the five types only it can find — could not appear on any egress row, whatever the tool was sending. It runs there now, under a deadline. Egress uses a requested timeout based on the remaining budget and an inclusive completion cutoff; neither guarantees elapsed time. See `engine.TIER3_EGRESS_BUDGET`. Ingress does not use the egress deadline.

The model is a serial resource: one inference pipeline, one lock, around half a second per scan on the machine it was measured on. The hook client uses one 2.0-second deadline across connection, hello, event transmission and reply, and I6 turns an unchecked outbound call into a **deny**. Historically — before #47 item 1 — an egress decision was regex-only and never waited for the model (it still waited for the ledger lock, as every request does). That history is why a deadline exists: a version that simply queued behind other sessions' scans would have reproduced a failure measured here at the time — a benign `curl https://example.com/health` denied, at 2002 ms, because six unrelated ingress scans were in flight.

The budget, `engine.TIER3_EGRESS_BUDGET`, is 1.0 s: half the client's 2.0 s, the other half left as margin for the parts of the hook round trip nobody has measured. At most one egress scan worker is admitted at a time. Admission is nonblocking; the worker retains its slot until it exits, including after caller abandonment.

Completion at or before the deadline is necessary but not sufficient for accepting the result; see `engine.TIER3_EGRESS_BUDGET`, which states the exact condition. The mechanism does not cancel inference, which Python cannot do, and does not guarantee actual wait duration, caller return time or hook round-trip time. Measured, as a measurement and not a bound: a call under the 1.0 s budget returned at **1.25 s**, having correctly rejected the result. Lock contention on the ledger, sqlite and the socket are outside the deadline, and nobody has measured the end-to-end distribution against the client's 2.0 s, so this is a guard against the failure that was measured, not a proof that the hook always answers in time.

**The fallback is not decision-neutral.** A scan gap can omit findings that would otherwise cause blocking or masking. `detect/model.py`'s label map includes `SECRET`, so the deep scan can produce the `credential` finding that blocks a call, and a `mask` rule can only fire on a finding some tier actually produced. An outbound call with a scan gap is decided on the fast tiers alone — exactly what every outbound call did before #47 item 1, which is why it is an acceptable fallback, and why it is recorded rather than silent.

**What you see.** A scan gap means an applicable deep scan supplied no accepted result. Each observed scan gap is recorded per observation and counted per session, including observations with no event row, so `coverage` for that session stops reading as verified instead of showing a clean account. An accepted empty result is a clean scan, not a scan gap. The banner names one reason at a time and the scan-gap count is the last of them, so a session that *also* started unobserved or survived a daemon restart shows that instead — the account is still marked incomplete, but the line you read will not mention the scans. The no-event-row case is the one a per-event flag could not cover: an outbound call whose fast tiers found nothing and which had a scan gap writes no event row at all, and would otherwise be indistinguishable from a clean scan. The recorded histories (`engine.GAP_*`) are: a payload over `engine.MAX_TIER3_CHARS` (8192 characters), where inference is not attempted; no expensive detector supplying a successful available result, including weights that never loaded and a detector becoming unavailable during inference; a failed admission; and a timeout. `ModelDetector.scan()` catches inference exceptions and marks the detector unavailable instead of returning an empty result that counts as a clean scan. The unavailable history requires that no expensive detector supplies a successful available result. A false wait return yields `GAP_TIMEOUT`; after a true return, a worker error is re-raised, otherwise an unsuccessful outcome supplies its gap reason, or a rejected completion yields `GAP_TIMEOUT`.

One consequence of that worth knowing: in the current single-model configuration, an inference exception caught by `ModelDetector.scan()` marks the detector unavailable for the life of the daemon, so a single transient failure takes the deep scan out until the daemon restarts (five minutes after your last session ends, or sooner if you restart it). In that configuration, every later observation *that the deep scan applies to* has a scan gap, recorded — a local read is not one, since the deep scan is out of scope there — so those sessions are marked rather than silently shallow.

Legacy scan gaps remain session-level records without an event link. New accounting also records the gap on its observation, including observations with no findings; finding-event detail carries that observation's gap reason. A gap does not establish whether a particular value crossed a boundary.

What is still missing is *which* calls: the gap count is per session, and no individual row is marked.

How often this happens has not been measured on real sessions. The `busy` history means nonblocking egress admission fails. A timeout can occur before inference, when the worker cannot start inference within its deadline, including model-lock contention; when the caller’s wait returns `False`, whether work is pending, running or completed; or when the wait returns `True`, but an otherwise successful result has no completion timestamp or completed after the deadline. A timeout does not require contention or slow inference.

Missing or incomplete model weights leave tier 3 unavailable; the plugin does not fetch replacements. A process that already imported the ML stack in online mode also leaves tier 3 unavailable and must be restarted to load it offline.

## 22. Credential prompt holds have a narrow scope.

Prompt holds inspect only text supplied to UserPromptSubmit. Images and attachments are not scanned. Supported well-formed formats mean the first five KEY_PATTERNS in SecretDetector: API keys, AWS access key IDs, GitHub tokens, JWT-shaped strings, and database connection strings with passwords. Matching a format does not establish that a credential is valid. ASSIGNMENT and GENERIC_QUOTED entropy findings, private-key headers, and tier-3 NER findings never trigger this hold.

Confirmation is case-sensitive and matches the complete detected credential, not the surrounding prompt. All credentials not already allowed must have been held, and the next submission must arrive at least 2 seconds after the hold and no later than 300 seconds after it. A new or expired credential holds the whole submission and starts a new window for its not-yet-allowed credentials. An early repeat remains held without resetting that window. No credential is partially authorized while another credential holds the submission.

Confirmation state consists of salted hashes and timing metadata in daemon memory. It is not persisted or recovered from the ledger. Allowed credentials remain allowed for that session while the daemon runs. A replacement daemon holds them again when it can answer. During startup or whenever no usable daemon reply arrives, prompts fail open under I6 with an unverified warning. A client crash can instead produce empty hook output. The current startup loads the model before binding the socket, so the existing cold-start gap remains.

Once the daemon answers, the hold decision runs before deep scanning and does not wait for the model. Held submissions skip deep scanning. Allowed submissions retain normal scanning and its existing ingress fail-open behavior. A new confirmation becomes reusable only after its observation is recorded successfully. Until then, another delivery cannot borrow that authorization and may be held again. If scanning or recording raises, the failed delivery's provisional confirmation and replay verdict are discarded without restoring its consumed hold window or changing another delivery's state. SessionEnd clears provisional confirmations too; a late completion cannot restore them or emit a confirmation notice. This is not a guarantee that socket, scheduling, or ledger work always completes before the client deadline.

The inspected Codex 0.154.0 and 0.155.1 source clears the composer during submission preparation and does not restore it on hook completion. This is source inspection, not a live TUI test. Paste or type the message again to resubmit. Codex may retain local input history even when a submission is held out of model context.

A hold returns only decision and reason. Additional context returned alongside a valid block would still enter model context in both inspected versions. Confirmation messages use systemMessage, which those versions display as hook output without adding it to model context.

Version-2 accounting records an issued denial as prevented with zero points, while host enforcement remains unresolved. Resubmission authorization does not establish model-context admission. Legacy held rows use no deduplication hash so a later permitted crossing can be recorded separately. Other legacy deduplication limitations remain.

## Note on tests

`cargo test -p codex-tui` and the upstream `insta` picker snapshots have not been run anywhere.
