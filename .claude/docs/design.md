# Codex Privacy HUD — Design Document

**Status:** Draft v0.1 · **Date:** 2026-09-03 · **Companion to:** `PRD.md`, `architecture.md`

This document covers product and interaction design: what the user sees, what they can do, and the rules governing how we talk about disclosure. Implementation lives in `architecture.md`.

---

## 1. Design principles

**P1 — Ambient by default, deep on demand.**
A privacy tool that interrupts constantly gets disabled within a day. Level 1 is a glance; Levels 2–3 are opt-in. The only unprompted interruption is a *block*, because a block already stopped the agent.

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

Terminal-native, dark-first. The mockup's aesthetic is the spec.

| Token | Value | Use |
|---|---|---|
| `bg` | `#0a0e14` | canvas |
| `surface` | `#111820` | cards, table rows |
| `border` | `#1e2936` | dividers, card edges |
| `text` | `#c9d4e0` | primary copy |
| `muted` | `#5c6b7f` | labels, column headers, metadata |
| `accent` | `#22d3ee` | interactive, links, section markers, `›` |
| `safe` | `#4ade80` | green band, prevented |
| `warn` | `#fbbf24` | amber band, masked, irreversibility notice |
| `danger` | `#f87171` | red band, exposed |

**Typography:** monospace throughout (`ui-monospace, SF Mono, Menlo, monospace`). Column alignment is the layout system — no proportional fonts anywhere, including the web UI. Section labels are `UPPERCASE` + `muted` + letterspaced.

**Status chips** are outlined, not filled: `EXPOSED` (danger), `MASKED` (warn), `PREVENTED` (safe), `LOCAL` (muted). Outlines keep the table scannable when many rows share a status.

**Bands** (§5.3 of the PRD): 0–33 `safe`, 34–66 `warn`, 67–100 `danger`. The bar is 10 cells; a filled cell is `█`, empty is `░`.

---

## 4. Level 1 — Ambient HUD

```text
PRIVACY  Disclosure ███░░░░░░░ 28%  ›
```

**Composition:** label · metric name · 10-cell bar · percentage · affordance chevron. The bar and percentage are colored by band; everything else is `muted`.

**States**

| State | Render |
|---|---|
| Clean session | `PRIVACY  Disclosure ░░░░░░░░░░  0%  ›` |
| Normal | `PRIVACY  Disclosure ███░░░░░░░ 28%  ›` |
| Red band | bar + `%` in `danger`; `PRIVACY` label also `danger` |
| Active block | `PRIVACY  ⚠ 1 blocked · Disclosure ███░░░░░░░ 28%  ›` for 30 s, then decays |
| Engine degraded | `PRIVACY  Disclosure ███░░░░░░░ 28% ⚠unverified ›` |
| Disabled | render nothing (never a "privacy off" banner that itself nags) |

**`⚠unverified` is a third state, not a variant of the other two.** "Disabled"
means there is nothing to report on. "Engine degraded" means there is something
to report on and the report has a hole in it — which makes it the only state
that can distinguish `0%` meaning *nothing sensitive was disclosed* from `0%`
meaning *I have no idea what was disclosed*. For a privacy tool those must
never render identically, and until this state was wired up they did: an I7
self-audit passed on a ledger that had never recorded the session being
audited. The renderer takes it as a flag it cannot infer (`render.hud_line`'s
`unverified=`); the ledger's `coverage` table is what decides it, from recorded
evidence only — never from a heuristic guess that a gap probably happened.

Below 28 columns the word does not fit, so the warning glyph **replaces** the
band dot: `⚠ 28%`, not `⬤ 28% ⚠`. A marker appended after the percentage is the
first thing width-truncation removes, and what it leaves behind is a
clean-looking number — the exact failure the state exists to prevent. The band
colour is the cheaper thing to lose.

**Width degradation** — the companion renderer is terminal-width aware:

```text
≥ 52 cols   PRIVACY  Disclosure ███░░░░░░░ 28%  ›
40–51 cols  PRIVACY ███░░░░░░░ 28% ›
28–39 cols  PRIV ███░░ 28% ›
< 28 cols   ⬤ 28%          (dot colored by band)
```

**Which session the line is about** is resolved by the same function `$privacy`
uses (`mcp_tools.resolve_audit_session`), so the pane beside a window and the
audit typed into it can never name different sessions. It is resolved once at
startup and roughly every 30 s after, never per redraw: the resolution asks the
daemon, whose socket is the hook hot path, and a pane that changed which
session it reported on between two-second frames would be unreadable even if
every frame were individually correct. `--session-id` pins it outright.

**L1 says nothing about session ambiguity, and that is deliberate.** When
resolution is uncertain — two windows active in the same moment, or no daemon
to ask — `$privacy` prints a two-sentence note above a full-width table. This
line has 52 columns at its widest and 5 at its narrowest; there is no honest
way to fit a second caveat into that, and `⚠unverified` is not available to
carry it. That glyph means *this session's record has a known hole*, which is a
different question from *whose session this is*, and a marker that meant both
would mean neither — collapsing the three states above back into two. Say
nothing here and let L2 explain.

**Non-goals for L1:** no counts, no data types, no last-event ticker, no
session-identity caveat. Every addition here is a tax paid on every frame of
the user's attention.

---

## 5. Level 2 — Session Audit

```text
Privacy Audit
Current session · 41 min

┌───────────┐ ┌─────────────────────┐ ┌────────────────┐ ┌───────────┐
│    28%    │ │          4          │ │       2        │ │     17    │
│ of budget │ │ permitted crossings │ │ boundary kinds │ │ prevented │
└───────────┘ └─────────────────────┘ └────────────────┘ └───────────┘

 Exposed 4      Prevented 17      All events 24
 ─────────

SENSITIVE DATA        SOURCE           DESTINATION      STATUS
Customer email ×12    support.log      model context    [EXPOSED]
Full name ×1          user prompt      model context    [EXPOSED]
Repository path ×4    tool input       GitHub MCP       [EXPOSED]
Internal hostname ×3  terminal output  model context    [MASKED]
```

**Header subtitle.** `Current session` in the mockup above, but it is a claim, not a label, and it is written from how the session was actually resolved (`mcp_tools.ResolvedSession.basis` → `render._subtitle`):

| Resolution | Subtitle |
|---|---|
| The daemon named one live session | `Current session` |
| The daemon named it, but another window was active in the same moment | `Most recently active session` |
| The user named it (`$privacy <id>`) | `Session <id>` |
| No daemon to ask — the ledger's most recently *started* row | `Most recently started session` |
| The ledger holds no session | `No session on record` |

Only the first line supports the word "current", and it supports it for a specific reason: running `$privacy` fires a hook in the asking session, so "most recently active" *is* "current" by construction. A header asserting certainty above a note retracting it is the same overclaim §9 forbids anywhere else.

**Summary tiles.** Four, fixed. The field names are `percent`, `exposed_items`, `destinations`, `prevented`; the labels shown are "of budget", "permitted crossings", "boundary kinds", "prevented" (#49 item 9).

`destinations` is the tile people underestimate — it is meant to be the "how far did this spread" number, and that is what would distinguish this from a scanner. **As built it does not reach that** (`docs/known-limits.md` #20): `dispatch.py` normalises every MCP call to `mcp_tool` before the engine sees it, so the count is over boundary categories — a handful at most — and a second MCP server adds nothing to it. Restoring the recipient detail `architecture.md` specifies (`mcp:<server>`, `net:<host>`, `subagent:<id>`) is what would make this paragraph true.

**Tabs.**
- `Exposed` — crossed a boundary. Default tab. Sorted by budget contribution descending, not chronologically: the worst thing should be the first row.
- `Prevented` — blocked, redacted, or minimized. Sorted most-recent-first. This tab is the product's proof of work.
- `All events` — full timeline including `local_access` and `retention`, chronological. The forensic view.

**Table columns.** `SENSITIVE DATA` (type + count) · `SOURCE` · `DESTINATION` · `STATUS`. Rows aggregate by `(data_type, source, destination)` — one row per *flow*, not per occurrence, which is why counts are `×12`.

**Row affordances.** Whole row is the click target; hover raises `surface` and shows a left accent rule. Selected row keeps the accent.

**Empty states** (each says what it means, not just "no data"):
- Exposed, empty: `No sensitive data has crossed a trust boundary this session.`
- Prevented, empty: `Nothing has been blocked or minimized yet.`
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

First seen   12:41:08
Protection   none
Example      jo•••@acme.com

[ Mask detected email in future calls ]

Already disclosed data cannot be recalled from this session.
```

**Fields.** Title (`type ×count`) · flow line · `First seen` · `Last seen` (when > first) · `Protection` (`none` / `masked` / `minimized`) · `Example` (masked exemplar) · `Budget contribution` (`+9 pts of 120`).

**The flow line is the hero.** For multi-hop flows it renders the full chain with each hop's boundary — *designed, never built; no multi-hop chain is assembled today, and a `×N` count is N hits on one dedupe key*:

```text
support.log → main agent → GitHub MCP
   B0            B1            B3
```

**Actions.** One always, a second where the row allows it:
- `Mask detected <type> in future calls` — writes a policy rule to mask this data type going forward. *(Two corrections to what this line used to say. It said "from this source": the rule carries the data type only, and the engine matches type without source — issue #47 item 10. And the label used to be `Protect future occurrences`, which named an outcome the rule cannot guarantee; the rule fires when a later call produces a matching finding, and for every type other than `path` and `credential` matching requires an accepted deep-scan result — #49 item 2.)*
- On a row whose source names a real origin — a file path or a command, not a bare tool label — `Block values read from {source}` (path) or `` Block values from `{source}` output `` (command). It writes a `block_path` or `block_command` rule keyed to the `Origin` that finding's value was first seen with (#40).

A source rule matches the whole value, normalised: it compares a later outbound value against the origin-tagged value under a salted HMAC of `value.strip().lower()` (`mask.py`), so if the model summarizes, rewrites, or quotes part of what it read, the copy no longer matches and the rule does not catch it (`docs/known-limits.md` #10). This said "only byte-identical values" until #49 item 7, which contradicted the salted hash described in the same sentence: case and surrounding whitespace do not defeat the rule, so the set that matches is wider than a byte comparison, not narrower. Origin extraction is best-effort too (`docs/known-limits.md` #11) — a row with no recognised origin offers no rule at all, rather than one that would not work.

This replaces the earlier `Block this source` (`block_source`), withdrawn in #38: the ledger then recorded only a fixed label as `source` on the outbound observation (`tool input`, or the tool name / `user prompt` on the way in), never the file or command a value came from, so no selector could name a source. `block_path`/`block_command` match against the ledger's own origin record instead, which is why they work where `block_source` could not.

In the red band the detail view also shows a note, not an action: `Want a clean context? Start a new conversation in Codex. What this session already sent to the model stays sent.` A clean context is a new Codex conversation, which the plugin cannot start; an earlier `Start a clean session` action opened a ledger row under an id Codex never sends and was removed (#23).

Every policy action confirms the saved rule and its conditions. For a mask rule selecting email: `Rule saved: mask email, for this session. On later outbound calls this plugin checks, a detected email is masked unless the call is blocked outright. What the call is then allowed to do is decided by the rest of the policy, not by this rule. Matching email requires an accepted deep-scan result. A scan gap means an applicable deep scan supplied no accepted result (known limit 21); on that call this rule has no matching deep-scan finding. Detection can also miss values, and hosted tools never reach this plugin at all.` The confirmation uses `mcp_tools.rule_enforcement_note`: cheap data types receive the cheap-detection clause; origin rules receive the ingress-and-egress clause.

**The irreversibility notice is required, permanent, and `warn`-colored.** It never collapses, never becomes a dismissible toast, never gets an "I understand" button that hides it. It is the single most honest element in the product.

---

## 7. Interruption design

Only one thing interrupts: a **block**. It arrives via hook `systemMessage`, which is native and always available.

```text
⚠ PRIVACY HUD blocked a tool call

  github.create_issue  would send  Customer email ×12
  from support.log to GitHub MCP.

  Run $privacy to review, minimize, or allow once.
```

**Rules for block copy:** name the tool, name the data type and count, name the source and destination, and give exactly one next step. No severity adjectives ("dangerous", "critical") — the facts are alarming enough and adjectives erode trust when the tool is wrong.

**Warnings that do not block do not interrupt.** They accrue into the ledger and surface at L1/L2. A tool that cries wolf on non-blocking events retrains the user to ignore the blocking ones.

---

## 8. Consent flow

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

Emitted at `SessionEnd`, rendered in-terminal and saved as Markdown:

```text
PRIVACY RECEIPT · session_123 · 41 min

Disclosure       28% of budget
Exposed          4 crossings across 2 boundary kinds
Prevented        17 events
Retained         transcript written to ~/.codex/sessions/...

  Customer email ×12    support.log     → model context
  Full name ×1          user prompt     → model context
  Repository path ×4    tool input      → GitHub MCP
  Internal hostname ×3  terminal output → model context  (masked)

No file contents, prompts, or raw values were stored.
```

The last line is the receipt's real payload. It is the sentence that makes the tool trustworthy, and it is verifiable by inspecting the ledger.

---

## 11. Accessibility and constraints

- **Never color-only.** Band is conveyed by bar fill and percentage; status by chip text. A monochrome terminal loses nothing but hue.
- **No emoji as sole meaning.** `⚠` always accompanies text.
- **Web UI:** semantic table markup, keyboard row navigation (`↑`/`↓`/`Enter`), visible focus rings in `accent`, respects `prefers-reduced-motion` (no bar animation).
- **No horizontal scroll** in the terminal rendering; columns truncate with `…` from the middle of paths (`support/.../app.log`) so both ends stay readable.

---

## 12. Component inventory

| Component | Levels | Notes |
|---|---|---|
| `DisclosureBar` | 1, 2 | 10-cell, banded, width-degrading |
| `SummaryTile` | 2 | value + label, banded value |
| `TabBar` | 2 | three tabs with counts |
| `FlowTable` | 2 | aggregated rows, sortable, selectable |
| `StatusChip` | 2, 3 | outlined, four variants |
| `FlowLine` | 3 | multi-hop chain with boundary labels |
| `MaskedExemplar` | 3 | pre-masked at detection, never raw |
| `ActionButton` | 3 | bracketed terminal style, max three |
| `IrreversibilityNotice` | 3 | permanent, `warn`, non-dismissible |
| `BlockNotice` | systemMessage | tool + data + flow + one next step |
| `Receipt` | SessionEnd | terminal + Markdown |

---

## 13. Open design questions

1. **Does L1 ship in v1?** The companion renderer needs a terminal pane we do not own. `systemMessage` + `$privacy` may carry the demo alone.
2. **Row aggregation granularity.** Aggregating by `(type, source, destination)` hides per-occurrence timing. Does `All events` need an expandable row, or is the flat timeline enough?
3. **Budget calibration.** 120 points is a guess. A normal 40-minute session should land in the 20–40% range; needs one real-session pass to tune.
4. **Minimization preview length.** Long payloads need a diff view rather than before/after strings.
