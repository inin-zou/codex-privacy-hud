# Codex Privacy HUD — Design Document

**Status:** Draft v0.1 · **Date:** 2026-09-03 · **Companion to:** `PRD.md`, `architecture.md`

This document covers product and interaction design: what the user sees, what they can do, and the rules governing how we talk about disclosure. Implementation lives in `architecture.md`.

---

## 1. Design principles

**P1 — Ambient by default, deep on demand.**
A privacy tool that interrupts constantly gets disabled within a day. Level 1 is a glance; Levels 2–3 are opt-in. The only unprompted interruption is a *block*, because a block already stopped the agent.

**P2 — Honest accounting beats alarming.**
Never show a number that conflates "we detected something" with "something left the machine." A scanner that screams about every email in every file is noise. The product's credibility rests on the `detected` / `exposed` / `prevented` distinction being visible everywhere.

**P3 — Show flows, not findings.**
`support.log → main agent → GitHub MCP` answers the user's actual question. "Found 12 emails" does not.

**P4 — Never imply recall.**
Disclosed data is gone. Every affordance that looks like undo must be labeled as forward-looking policy. This is a copy rule with teeth — see §9.

**P5 — The tool must survive its own audit.**
Running Privacy HUD on Privacy HUD produces zero exposures. Any design that requires shipping user content off-machine is rejected on sight.

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

**Width degradation** — the companion renderer is terminal-width aware:

```text
≥ 52 cols   PRIVACY  Disclosure ███░░░░░░░ 28%  ›
40–51 cols  PRIVACY ███░░░░░░░ 28% ›
28–39 cols  PRIV ███░░ 28% ›
< 28 cols   ⬤ 28%          (dot colored by band)
```

**Non-goals for L1:** no counts, no data types, no last-event ticker. Every addition here is a tax paid on every frame of the user's attention.

---

## 5. Level 2 — Session Audit

```text
Privacy Audit
Current session · 41 min

┌──────────┐ ┌───────────────┐ ┌──────────────┐ ┌─────────────┐
│   28%    │ │      4        │ │      2       │ │     17      │
│disclosure│ │ exposed items │ │ destinations │ │  prevented  │
└──────────┘ └───────────────┘ └──────────────┘ └─────────────┘

 Exposed 4      Prevented 17      All events 24
 ─────────

SENSITIVE DATA        SOURCE           DESTINATION      STATUS
Customer email ×12    support.log      model context    [EXPOSED]
Full name ×1          user prompt      model context    [EXPOSED]
Repository path ×4    tool input       GitHub MCP       [EXPOSED]
Internal hostname ×3  terminal output  model context    [MASKED]
```

**Summary tiles.** Four, fixed: disclosure %, exposed items, destinations, prevented. `destinations` is the tile people underestimate — it is the "how far did this spread" number, and it is what distinguishes this from a scanner.

**Tabs.**
- `Exposed` — crossed a boundary. Default tab. Sorted by budget contribution descending, not chronologically: the worst thing should be the first row.
- `Prevented` — blocked, redacted, or minimized. Sorted most-recent-first. This tab is the product's proof of work.
- `All events` — full timeline including `local_access` and `retention`, chronological. The forensic view.

**Table columns.** `SENSITIVE DATA` (type + count) · `SOURCE` · `DESTINATION` · `STATUS`. Rows aggregate by `(data_type, source, destination)` — one row per *flow*, not per occurrence, which is why counts are `×12`.

**Row affordances.** Whole row is the click target; hover raises `surface` and shows a left accent rule. Selected row keeps the accent.

**Empty states** (each says what it means, not just "no data"):
- Exposed, empty: `No sensitive data has crossed a trust boundary this session.`
- Prevented, empty: `Nothing has been blocked or minimized yet.`
- All events, empty: `No privacy events recorded. The engine is running.` — the second sentence matters; an empty audit is otherwise indistinguishable from a broken plugin.

**Degraded state banner.** If the deep scanner timed out at any point: `⚠ Deep scan unavailable for 2 events — fast-path results only.` Never silently present partial results as complete.

---

## 6. Level 3 — Exposure Detail

```text
Customer email ×12
support.log → model context

First seen   12:41:08
Protection   none
Example      jo•••@acme.com

[ Protect future occurrences ]
[ Block this source ]

Already disclosed data cannot be recalled from this session.
```

**Fields.** Title (`type ×count`) · flow line · `First seen` · `Last seen` (when > first) · `Protection` (`none` / `masked` / `minimized`) · `Example` (masked exemplar) · `Budget contribution` (`+9 pts of 120`).

**The flow line is the hero.** For multi-hop flows it renders the full chain with each hop's boundary:

```text
support.log → main agent → GitHub MCP
   B0            B1            B3
```

**Actions.** Maximum three, always forward-looking:
- `Protect future occurrences` — writes a policy rule to mask this data type from this source going forward.
- `Block this source` — writes a deny rule for the source path.
- `Start a clean session` — only offered when disclosure is in the red band.

Every action shows a confirmation of what rule it wrote, in plain terms: `Rule added: mask email from support.log. Applies from the next tool call.`

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
| Policy action taken | `Applies from the next tool call.` |
| Hosted-tool gap | `Hosted tools such as web search do not pass through local hooks and are not covered.` |
| Deep scan skipped | `Fast-path results only.` |

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
Exposed          4 flows across 2 destinations
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
