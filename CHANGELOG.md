# Changelog

## 0.8.2

- Stop a verified legacy Privacy HUD daemon during explicit runtime repair, and complete the storage transition in the same invocation.
- Share that process classifier with `repair --stop-runtime` and the uninstall stop.
- Refuse unverified or uninspectable ledger holders, and a verified process that does not stop, each with its own message; send SIGTERM once and never escalate.
- Wait for a recent daemon heartbeat to expire before the storage transition, rechecking holders and the socket; delete neither.
- Name the check that refused runtime repair in one allowlisted diagnostic line.
- Keep version-2 accounting inactive, the prepared schema at generation 5401 and snapshot version 2.

Refs #70, #71.

## 0.8.1

- Implement the version-2 accounting core, inactive for production sessions.
- Keep production session creation on legacy accounting and the prepared schema at generation 5401.
- Refuse version-2 sessions explicitly on the legacy renderers, publisher and browser surfaces.
- Rehearse the inactive core on private copies of a ledger, under real writer leases.
- Retain #66's runtime selection, writer ownership and fenced ledger layout.
- Retain snapshot version 2; backfill and rescore nothing.

Refs #54.

## 0.8.0

- Load first-party Python code from the selected plugin bundle.
- Require matching daemon identity before sending hook events or policy mutations.
- Add explicit offline runtime repair and a separate dependency-installation path.
- Preserve ledger values during a crash-recoverable transition to a fenced active store.
- Make the compatible daemon the ledger writer and open consumer connections read-only.
- Report runtime failures in doctor, hooks, MCP, audit, the local browser, and the bundled ambient launcher.
- Retain snapshot version 2 and the existing native-reader contract.
- Preserve Phase 2 migration timing and legacy production accounting.
- Provide no downgrade migration or reconstruction of monitoring gaps.

Refs #66.
