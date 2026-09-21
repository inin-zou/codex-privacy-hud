# frontend — Privacy HUD web UI (prototype, mock data)

A React front-end for the Level 2 / Level 3 surfaces of Privacy HUD, plus the
consent prompt of the live block flow. Styled after openai.com: white ground,
near-black ink, hairline borders, pill buttons; green only for *allowed*, red
only for *blocked*.

**Status: UI prototype on mock data.** Nothing in this folder reads the ledger
or talks to the daemon yet. `ui/index.html` + `ui/app.js` remain the UI the
`$privacy` skill actually serves. This folder is a proposal for what that UI
could grow into, with the data model kept close to the existing endpoints so
wiring it is a swap of one module, not a rewrite.

## Run

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, localhost only
npm run build      # type-check + bundle into frontend/dist/ (relative paths)
```

To point the dev server's `/api/*` calls at a running `local_ui_server.py`,
pass the URL the `$privacy` skill prints:

```bash
VITE_API_TARGET=http://127.0.0.1:51234 npm run dev
```

(The proxy exists so the wiring step has somewhere to land; no screen calls
`/api` today.)

## What is in the prototype

| Route (hash-routed) | Screen                                                                 |
| ------------------- | ---------------------------------------------------------------------- |
| `#/`                | Landing page explaining the model: data → policy gate → agents and apps |
| `#/app`             | Overview: counts, recent flows, open alerts, one agent suggestion        |
| `#/app/data`        | Data vault: fields with provenance (websites, Codex / Claude Code sessions, browser) |
| `#/app/apps`        | Destinations by category, declared scopes coloured by the effective policy, "Explain" drawer |
| `#/app/rules`       | Plain-language rule composer (keyword parser), rule list, suggestions    |
| `#/app/activity`    | Flow log: agent, session, destination, fields, decision, rule; raw request on expand |
| `#/app/alerts`      | Critical / warning / info alerts with a resolve action                  |

"Simulate agent request" in the top bar cycles through `SCENARIOS` in
`src/data/mock.ts`. Each one runs through `src/store/engine.ts`: secrets are
always blocked, unverified destinations are blocked, a destination asking
beyond its declared scopes is flagged, otherwise the most specific rule wins
(app › agent › category › everything) and the stricter effect wins a tie.
Outcomes surface as a consent modal, a red takeover for a blocked secret, or a
toast, and every outcome lands in the activity log.

## Mapping onto the existing backend

| Prototype concept                    | Existing counterpart                                        |
| ------------------------------------ | ----------------------------------------------------------- |
| Activity row (`ShareEvent`)          | ledger event row from `GET /api/exposures?tab=…`             |
| Overview counts                      | `GET /api/summary`                                           |
| Activity row expanded                | `GET /api/detail?id=…`                                       |
| Rule with effect `deny` / `ask`      | `POST /api/policy` (`rule_type`, `selector`)                 |
| Consent modal (Allow once / Deny)    | the live `PreToolUse` block flow, **not** the audit server (see `local_ui_server.py` docstring: the ledger never stores `tool_input`, so "Allow once" cannot be minted from historical rows) |
| Alerts, data vault, app catalogue    | no counterpart yet; mock only                                |

Wording to keep when wiring: the ledger records *flows*, not findings, and
disclosed data cannot be recalled. The prototype's copy avoids "undo",
"revoke" and "remove from context" for that reason; keep it that way.

## Layout

- `src/data/types.ts`, `src/data/mock.ts` — data model and all mock data. `BRAND` is the product name shown everywhere.
- `src/store/engine.ts` — decision engine, keyword rule parser, per-app explanation text.
- `src/store/store.tsx` — React reducer: apps, rules, events, alerts, pending prompt, takeover, toasts.
- `src/components/` — shell, overlays (consent modal, takeover, drawer, toasts), icons, primitives.
- `src/pages/` — one file per route.
- `src/styles/global.css` — design tokens and all styles, no CSS framework.
