# Codex Privacy HUD — Design Document

**Status:** Draft v0.1 · **Date:** 2026-09-03 · **Companion to:** `PRD.md`, `architecture.md`

**Current contract — #54 Phase 3 (0.7.10).**

The new accounting core is implemented and tested but is not active for production sessions. Production session creation still selects legacy accounting. Prepared-schema migration remains unchanged. No historical rows are backfilled or rescored. #43, #44, and the related #47 accounting limitations remain unresolved in production.

This document covers product and interaction design: what the user sees, what they can do, and the rules governing how we talk about disclosure. Implementation lives in `architecture.md`.

---

## 1. Design principles

**P1 — Ambient by default, deep on demand.**
A privacy tool that interrupts constantly gets disabled within a day. Level 1 is a glance; Levels 2–3 are opt-in. Intervention messages describe a denial issued or rewritten input returned; they do not confirm host application.

**P2 — Honest accounting beats alarming.**
Never show a number that conflates "we detected something" with "something left the machine." A scanner that screams about every email in every file is noise. The product's credibility rests on the `detected` / `exposed` / `prevented` distinction being visible everywhere.

**P3 — Show flows, not findings.** *(Intent. The `flows` table is created and nothing writes it, so what ships renders one row per crossing — `docs/known-limits.md` #20 and issue #47 item 11.)*
`support.log → main agent → GitHub MCP` answers the user's actual question. "Found 12 emails" does not.

**P4 — Never imply recall.**
Disclosed data is gone. Every affordance that looks like undo must be labeled as forward-looking policy. This is a copy rule with teeth — see §9.

**P5 — The tool must survive its own audit.**
Any design that requires shipping user content off-machine is rejected on sight. *(This principle used to open "Running Privacy HUD on Privacy HUD produces zero exposures", which measurement contradicted — 88%, 100% and 100% of budget on three read-only source reviews. The off-machine half is I2 and still holds; the zero-exposure half is now I7's corpus-based form, and `docs/self-audit.md` has the numbers.)*

**P6 — Degrade to text.**
The terminal is the primary habitat. Every view must have a legible ASCII rendering; the web UI is an enhancement, not a dependency.

---

## 2. Information architecture

```text
Level 1  AMBIENT          one line, always visible, zero interaction
   │      "how exposed am I right now?"
   ▼  click / $privacy
Level 2  SESSION AUDIT    summary tiles + tabbed event table
   │      "what crossed, from where, to where?"
   ▼  click a row
Level 3  EXPOSURE DETAIL  one flow, its evidence, its remedies
          "what exactly was this, and what can I do now?"
```

Each level answers exactly one question. A view that answers two questions is a view that will be redesigned.

**Escape hatches:** every level reachable directly — `$privacy` opens L2; `$privacy <id>` deep-links to L3; a block notification deep-links to the L3 for the offending flow.

---

## 3. Visual language

Terminal-native, dark-first. The hand-drawn mockup records design intent; the current copy and display contract below supersede its historical labels.

| Token | Value | Use |
|---|---|---|
| `bg` | `#0a0e14` | canvas |
| `surface` | `#111820` | cards, table rows |
| `border` | `#1e2936` | dividers, card edges |
| `text` | `#c9d4e0` | primary copy |
| `muted` | `#5c6b7f` | labels, column headers, metadata |
| `accent` | `#22d3ee` | interactive, links, section markers, `›` |
| `safe` | `#4ade80` | legacy score band only; never proof of safety |
| `warn` | `#fbbf24` | amber band, masked, irreversibility notice |
| `danger` | `#f87171` | red band, exposed |

**Typography:** monospace throughout (`ui-monospace, SF Mono, Menlo, monospace`). Column alignment is the layout system — no proportional fonts anywhere, including the web UI. Section labels are `UPPERCASE` + `muted` + letterspaced.

**Status chips** identify stored legacy classifications with neutral styling: `LEGACY PERMITTED`, `LEGACY PREVENTED ROW`, `LEGACY LOCAL ACCESS`, `LEGACY DETECTED`, `LEGACY RETENTION`, or `LEGACY UNKNOWN`. They do not establish delivery or host enforcement.

**Bands** remain an existing legacy-score presentation primitive: 0–33 `safe`, 34–66 `warn`, 67–100 `danger`. The current HUD is bar-free. Unavailable quantities have no numeric band or bar.

---

## 4. Level 1 — Ambient HUD

```text
Privacy legacy 28% · 2 prevented rows
```

`hud_line(reading, width)` selects the first complete candidate that fits. It never slices text. Hidden readings render nothing; readers filter absent, malformed, and stale snapshots.

| State | Full-width text |
|---|---|
| Recorded legacy zero | `Privacy legacy 0%` |
| Legacy | `Privacy legacy 28% · 2 prevented rows` |
| Legacy with a coverage gap | `Privacy legacy 28% · 2 prevented rows ⚠unverified` |
| Explicitly unrecorded | `Privacy —% · No session on record` |
| No resolved session, daemon-reported gaps | `Privacy —% · unattributed hook gaps` |

The secondary count is legacy rows, not calls. Use `1 prevented row`; omit zero. Coverage does not establish delivery or host enforcement.

Width candidates, in order:

```text
Legacy:
Privacy legacy {P}% · {N} prevented rows
Privacy legacy {P}%
legacy {P}%
legacy

Legacy with incomplete coverage:
Privacy legacy {P}% · {N} prevented rows ⚠unverified
Privacy legacy {P}% ⚠unverified
legacy {P}% ⚠unverified
⚠ legacy {P}%
⚠ legacy

Unrecorded:
Privacy —% · No session on record
Privacy —% · no record
—% · no record
⚠ —%

Unattributed gaps:
Privacy —% · unattributed hook gaps
Privacy —% ⚠unverified
⚠ —%
```

Apply singular/zero handling before testing widths. If no candidate fits, render nothing. Reserved accounting-2 readings use their full line only and render nothing when it does not fit; Phase 1 does not publish them. The Rust item returns the full line; Codex owns its final layout.

**Which session the line is about** is resolved by the same function `$privacy`
uses (`mcp_tools.resolve_audit_session`), but separately timed resolutions can select different sessions. It is resolved once at
startup and roughly every 30 s after, never per redraw: the resolution asks the
daemon, whose socket is the hook hot path, and a pane that changed which
session it reported on between two-second frames would be unreadable even if
every frame were individually correct. `--session-id` pins it outright.

**L1 says nothing about session ambiguity, and that is deliberate.** When
resolution is uncertain — two windows active in the same moment, or no daemon
to ask — `$privacy` prints a two-sentence note above a full-width table. The compact candidates omit session-identity caveats, and `⚠unverified` is not available to carry one. That glyph means *this session's record has a known hole*, which is a
different question from *whose session this is*, and a marker that meant both
would mean neither — collapsing the three states above back into two. Say
nothing here and let L2 explain.

**Non-goals for L1:** no data types, no last-event ticker, no session-identity caveat. The one secondary count labels legacy prevented rows. Every addition here is a tax paid on every frame of
the user's attention.

---

## 5. Level 2 — Session Audit

```text
Privacy Audit
Session session_123

28%  legacy permitted-crossing score
4    legacy permitted-crossing rows
2    legacy boundary kinds
17   legacy prevented rows

Historical accounting includes permitted crossings and may collapse different outcomes. It does not establish confirmed disclosure.

Legacy permitted crossings 4 · Legacy prevented rows 17 · All legacy events 24
```

This is a compact content example, not a literal rendering of the tile borders.

**Header subtitle.** The browser and its ASCII view show `Session <full ID>`. Before resolution they show `Session ID unknown`; a successful resolution with no session shows `No session on record`. The skill's terminal audit retains the resolution-specific subtitles below.

| Resolution | Subtitle |
|---|---|
| The daemon named one live session | `Current session` |
| The daemon named it, but another window was active in the same moment | `Most recently active session` |
| The user named it (`$privacy <id>`) | `Session <id>` |
| No daemon to ask — the ledger's most recently *started* row | `Most recently started session` |
| The ledger holds no session | `No session on record` |

Only the first line supports the word "current", and it supports it for a specific reason: running `$privacy` fires a hook in the asking session, so "most recently active" *is* "current" by construction. A header asserting certainty above a note retracting it is the same overclaim §9 forbids anywhere else.

**Summary tiles.** Four, fixed. Legacy wire keys are `legacy_percent`, `legacy_permitted_crossing_rows`, `legacy_boundary_kinds`, and `legacy_prevented_rows`; their labels are the four shown above. The legacy summary also returns `legacy_score`, `legacy_cap`, `score_label`, and `accounting_note`. Accounting 0 returns `percent=null` with no numeric score, cap, or counts; the tiles show unavailable values and the unrecorded accounting note.

`legacy_boundary_kinds` is the tile people underestimate — it is meant to be the "how far did this spread" number, and that is what would distinguish this from a scanner. **As built it does not reach that** (`docs/known-limits.md` #20): `dispatch.py` normalises every MCP call to `mcp_tool` before the engine sees it, so the count is over boundary categories — a handful at most — and a second MCP server adds nothing to it. Restoring the recipient detail `architecture.md` specifies (`mcp:<server>`, `net:<host>`, `subagent:<id>`) is what would make this paragraph true.

**Tabs.**
- `Legacy permitted crossings` — API argument `Exposed`; stored legacy permitted classifications, ordered by legacy contribution.
- `Legacy prevented rows` — API argument `Prevented`; stored legacy prevented classifications, most recent first.
- `All legacy events` — API argument `All events`; all stored legacy rows, chronological. Its count comes from the full list, not the sum of the other tabs.

**Table columns.** `SENSITIVE DATA` (type + count) · `SOURCE` · `DESTINATION` · `STATUS`. Legacy deduplication keys on `(session_id, value_hash, destination)`; `×N` is the stored repetition count, not distinct values, calls, or flow hops.

**Row affordances.** Whole row is the click target; hover raises `surface` and shows a left accent rule. Selected row keeps the accent.

**Empty states** (each says what it means, not just "no data"):
- Legacy permitted crossings, empty: `No exposure recorded this session.`
- Legacy prevented rows, empty: `Nothing recorded as blocked or minimized yet.`
- All events, empty: `No privacy events recorded for this session.` — and, on a verified coverage reading, what the check found. The second sentence used to read `The engine is running.`, which answered the right question — an empty audit is otherwise indistinguishable from a broken plugin — with evidence that cannot answer it, since a ledger is history and cannot vouch for a live process (#49 item 3). Liveness belongs to `privacy-hud-doctor`.

**Scan-gap banner.** A scan gap: an applicable deep scan supplied no accepted result. Over the event rows it is given: `⚠ 2 events had scan gaps — fast-path results only.` That line counts supplied rows carrying the flag; what the session actually counts — per observation, including observations with no event row — reaches the session-record banner below as `2 observations had scan gaps — fast-path results only`. Never silently present partial results as complete.

**Session-record banner.** The same rule at session scope, and it takes
precedence in reading order because it is the larger caveat. If the ledger's
account of the session is not verified:

```text
⚠ Session record incomplete — observation began after this session was already under way.
  Figures below are not a full account of this session.
```

The clause after the dash names the recorded evidence — the session was never
recorded at all, observation began mid-session, Privacy HUD restarted during it,
or tool calls went unverified with no daemon listening. Nothing in this copy may
imply the unrecorded events can be listed, retrieved or replayed (§9 / I5):
"unverified" is a statement about the ledger, not a promise.

**The empty states above are replaced, not supplemented, when the record is
incomplete.** All three make positive claims — "No sensitive data has crossed a
trust boundary this session", "…The engine is running." — both removed in #49 item 3 — and an unverified
session supports none of them. The third is the worst of the three to get wrong:
it exists so an empty audit cannot be mistaken for a broken plugin, which is
precisely why printing it *when the plugin was broken for this session* spends
the reader's trust vouching for the one case it cannot vouch for. On that path
the line becomes:

```text
No events recorded for this tab. With this session's record incomplete, that is not evidence that none occurred.
```

---

## 6. Level 3 — Exposure Detail

```text
Customer email ×12
support.log → model context

Legacy intervention   no intervention recorded
Example               jo•••@acme.com

This legacy source-to-destination association does not establish delivery or a multi-hop flow.
Policy rules can be saved in the local audit browser opened by $privacy.

Already disclosed data cannot be recalled from this session.
```

**Fields.** Stored type and repetition count, source/destination association, timestamps when available, `Legacy intervention`, masked exemplar, and `Legacy contribution`. The accounting note accompanies the detail. Terminal text does not save policy.

**The flow line is the hero.** For multi-hop flows it renders the full chain with each hop's boundary — *designed, never built; no multi-hop chain is assembled today, and a `×N` count is N hits on one dedupe key*:

```text
support.log → main agent → GitHub MCP
   B0            B1            B3
```

**Browser actions.** The local browser POSTs rules to `/api/policy`; `privacy.update_policy` is a separate MCP writer. The terminal detail view has no policy buttons.
- `Save mask rule for detected <type>` — the browser POSTs a `mask` rule to `/api/policy`. The rule selects a data type, not a source. The former label `Protect future occurrences` claimed an outcome that saving a rule cannot guarantee. Matching requires detection; types other than `path` and `credential` require an accepted deep-scan result. Host application is not confirmed.
- Where a row names a real origin, `Save block rule for values read from {source}` or `Save block rule for values from {source} output` saves `block_path` or `block_command`. Saving succeeds independently of whether a later observation matches or the host applies a denial.

A source rule matches the whole value, normalised: it compares a later outbound value against the origin-tagged value under a salted HMAC of `value.strip().lower()` (`mask.py`), so if the model summarizes, rewrites, or quotes part of what it read, the copy no longer matches and the rule does not catch it (`docs/known-limits.md` #10). This said "only byte-identical values" until #49 item 7, which contradicted the salted hash described in the same sentence: case and surrounding whitespace do not defeat the rule, so the set that matches is wider than a byte comparison, not narrower. Origin extraction is best-effort too (`docs/known-limits.md` #11) — a row with no recognised origin offers no rule at all, rather than one that would not work.

This replaces the earlier `Block this source` (`block_source`), withdrawn in #38: the ledger then recorded only a fixed label as `source` on the outbound observation (`tool input`, or the tool name / `user prompt` on the way in), never the file or command a value came from, so no selector could name a source. `block_path`/`block_command` match against the ledger's own origin record instead, which is why they work where `block_source` could not.

In the red band the detail view also shows a note, not an action: `Want a clean context? Start a new conversation in Codex. What this session already sent to the model stays sent.` A clean context is a new Codex conversation, which the plugin cannot start; an earlier `Start a clean session` action opened a ledger row under an id Codex never sends and was removed (#23).

Every policy action confirms the saved rule and the conditions returned by `mcp_tools.rule_enforcement_note`. Mask rules may return rewritten input for later matching findings; origin rules require detection on ingress and egress. Detection misses, scan gaps, and hosted tools can prevent matching. Host application of a later denial or rewritten input is not confirmed.

**The irreversibility notice is required, permanent, and `warn`-colored.** It never collapses, never becomes a dismissible toast, never gets an "I understand" button that hides it. It is the single most honest element in the product.

---

## 7. Interruption design

Intervention copy arrives through hook `systemMessage` and describes what the plugin returned.

```text
PRIVACY HUD issued a tool-call denial

  github.create_issue  would send  Customer email ×12
  from support.log to GitHub MCP.

  Host enforcement is not confirmed.
  Run $privacy to review the ledger.
```

**Rules for block copy:** name the tool, name the data type and count, name the source and destination, and give exactly one next step. No severity adjectives ("dangerous", "critical") — the facts are alarming enough and adjectives erode trust when the tool is wrong.

**Warnings that do not block do not interrupt.** They accrue into the ledger and surface at L1/L2. A tool that cries wolf on non-blocking events retrains the user to ignore the blocking ones.

---

## 8. Consent flow

Historical proposal, not shipped behavior. No surface offers the buttons or token-minting steps below; this section does not authorize user-facing instructions to use them.

Codex `PreToolUse` has no `ask` decision, so consent is a three-beat flow rather than a modal (see `architecture.md` §8 for the token mechanics).

```text
1. BLOCK      hook denies · systemMessage explains
2. REVIEW     $privacy → L3 for the blocked flow
3. RESOLVE    user picks one:

   [ Minimize & retry ]   pseudonymize, then allow — recommended, shown first
   [ Allow once ]         one-shot token, 120 s TTL, this exact call only
   [ Keep blocked ]       dismiss; adds nothing to the budget
```

`Minimize & retry` leads because it is the option that preserves both the user's privacy and the agent's task. The UI shows a **before/after preview** of the minimization so the user can see what the tool will receive:

```text
before   "contact jordan@acme.com about ticket 4412"
after    "contact user_7f3a@example.invalid about ticket 4412"
```

Pseudonyms are stable within the session, so the agent's reasoning survives the rewrite — worth stating in the UI, because users assume redaction breaks the task.

`Allow once` requires the user to have seen the L3 detail first. The button is disabled with the hint `Review the exposure first` until the detail view has been opened. Consent without information is not consent.

---

## 9. Copy rules

**Required phrasings**

| Situation | Copy |
|---|---|
| After any exposure | `Already disclosed data cannot be recalled from this session.` |
| Policy rule saved | `Rule saved:` followed by the rule and its conditions from `mcp_tools.rule_enforcement_note`. |
| Hosted-tool gap | `Hosted tools such as web search do not pass through local hooks and are not covered.` |
| Scan gap | `Scan gap — fast-path results only.` |

**Forbidden phrasings**

- ~~"Your data is protected"~~ — unfalsifiable and untrue for anything already exposed.
- ~~"Remove from context"~~ / ~~"Revoke"~~ / ~~"Undo"~~ — implies recall.
- ~~"100% secure"~~, ~~"complete protection"~~ — §9 of the PRD lists real gaps; claiming completeness makes the whole tool a liar.
- ~~"N threats detected"~~ — "threat" is the scanner vocabulary we are explicitly rejecting.

**Vocabulary.** `exposed` not "leaked" · `prevented` not "saved" · `disclosure` not "risk score" · `source`/`destination` not "from"/"to" in table headers. Consistency here is what lets the numbers be trusted.

---

## 10. Session privacy receipt

Returned at `SessionEnd` for the host to display:

```text
PRIVACY RECEIPT · session_123 · 41 min

legacy permitted-crossing score: 28%
legacy permitted-crossing rows: 4
legacy boundary kinds: 2
legacy prevented rows: 17

Historical accounting includes permitted crossings and may collapse different outcomes. It does not establish confirmed disclosure.
Transcript retention is outside this ledger's account.
This ledger stores metadata, not file contents, prompts, or raw values.
```

Duration is omitted when unavailable. Unrecorded receipts show unavailable accounting, omit duration, and do not invent transcript-retention evidence. The receipt does not assert that a rewrite was applied.

---

## 11. Accessibility and constraints

- **Never color-only.** Accounting qualifiers, unavailable values, and status labels remain explicit in monochrome. The current HUD has no bar.
- **No emoji as sole meaning.** `⚠` always accompanies text.
- **Web UI:** semantic table markup, keyboard row navigation (`↑`/`↓`/`Enter`), visible focus rings in `accent`, respects `prefers-reduced-motion` (no bar animation).
- **No horizontal scroll** in the terminal rendering; columns truncate with `…` from the middle of paths (`support/.../app.log`) so both ends stay readable.

---

## 12. Component inventory

| Component | Levels | Notes |
|---|---|---|
| `HudReading` | 1 | accounting-aware text, complete width candidates, no bar |
| `SummaryTile` | 2 | explicit legacy label or neutral unavailable value |
| `TabBar` | 2 | three tabs with counts |
| `FlowTable` | 2 | aggregated rows, sortable, selectable |
| `StatusChip` | 2, 3 | outlined, four variants |
| `FlowLine` | 3 | recorded source/destination association; no reconstructed chain |
| `MaskedExemplar` | 3 | pre-masked at detection, never raw |
| `ActionButton` | browser L3 | saves a policy rule; terminal text has no buttons |
| `IrreversibilityNotice` | 3 | permanent, `warn`, non-dismissible |
| `BlockNotice` | systemMessage | tool + data + flow + one next step |
| `Receipt` | SessionEnd | terminal + Markdown |

---

## 13. Open design questions

1. **Does L1 ship in v1?** The companion renderer needs a terminal pane we do not own. `systemMessage` + `$privacy` may carry the demo alone.
2. **Row aggregation granularity.** Aggregating by `(type, source, destination)` hides per-occurrence timing. Does `All events` need an expandable row, or is the flat timeline enough?
3. **Budget calibration.** 120 points is a guess. A normal 40-minute session should land in the 20–40% range; needs one real-session pass to tune.
4. **Minimization preview length.** Long payloads need a diff view rather than before/after strings.
