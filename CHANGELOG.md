# Changelog

## 0.9.4

- Recognize MCP and daemon ledger holders naming any canonical N.N.N sibling path under the same existing canonical plugin parent during explicit runtime repair and the shared stop-only operation, whether the version directory is present or absent. Each N is an ASCII nonnegative integer without leading zeros except zero itself. Absent version directories need never have existed or been installed; no record of prior selection is required.
- Retain same-user, exact-launch, recorded-interpreter, resolved-plugin-data, identity-revalidation and quiescence checks. Existing version directories must contain a canonical scripts/runtime.py file; incomplete existing bundles and aliases remain refused. Recognition follows the same-user trust model and does not authenticate the Python code a process loaded.
- Keep runtime repair explicit and unchecked egress fail-closed. Show the external-terminal repair command when hooks detect a runtime selection mismatch, including at SessionStart.
- Clarify doctor's explicit-repair requirement and add recovery guidance to ambient runtime failures. Preserve ledger history, runtime formats, accounting generations and snapshot version 2.

Refs #74.

## Unreleased

- Reconcile the flow requirements with the shipped event-based audit. Withdraw aggregated causal multi-hop chains from the current requirements and document the limits of same-subject associations. No flow writer, cross-observation history view, schema change or accounting change is introduced.

Refs #47.

## 0.9.3

- Recognize verified MCP ledger holders from existing canonical sibling versions of the same cached plugin during explicit runtime repair and the shared stop-only operation.
- Retain the same-user, exact-launch, recorded-interpreter and resolved-plugin-data checks; refuse missing or aliased sibling bundles and unverified holders.
- Preserve existing daemon and legacy launch rules, MCP interruption announcements, identity revalidation and quiescence checks.
- Read doctor's guard setting from the plugin-data root for both historical and fenced ledger layouts.

Refs #74.

## 0.9.2

- Add a default-on lexical denial for recognized shell network commands containing known-sensitive-path references, including curl substitutions and upload forms, pipelines, wget, scp and rsync.
- Keep this guard independent of the optional local read setting; mask rules and internal consent tokens cannot bypass it.
- Reuse the existing sensitive-path rules and template suffix exemptions. Ordinary non-sensitive uploads remain eligible for existing policy checks.
- Deny recognizable network commands when tokenization fails. Document conservative co-occurrence false positives and unresolved expansion, configuration and wrapper-script cases.
- Keep shell-derived file identities unresolved. Record zero-charge prevented rule evidence without persisted paths, filenames, suffixes or file identity hashes; issued denials do not establish host enforcement.
- No file contents are opened and no upload rewrite or helper executable is added. Preserve schema generations, protocol versions, snapshot version 2 and historical accounting.

Refs #47.

## 0.9.1

- Request UserPromptSubmit holds for supported credential formats before deep scanning.
- Allow confirmation by resubmitting the same case-sensitive credential after 2 seconds and within 5 minutes; keep authorization in session-scoped daemon memory only.
- Exclude entropy findings, private-key headers, and tier-3 NER findings from prompt holds. Images and attachments are not scanned.
- Record prompt denials as zero-cost prevention with issued-denial evidence, without claiming host enforcement or model-context admission.
- Keep ingress fail-open behavior, including the existing daemon cold-start window.
- Preserve Phase 4 accounting activation, legacy sessions, schema generation 5402, runtime protocol 2, and snapshot version 2.

Refs #37.

## 0.9.0

- Activate evidence-based accounting only for new sessions observed from a genuine SessionStart. Existing sessions and late attachments retain legacy accounting.
- Record delivered observations, finding outcomes, intended recipient identities, and first charged disclosures separately. Preserve historical rows and scores without backfill or rescoring.
- Distinguish issued denials and rewrites from confirmed host enforcement. Current hooks do not confirm crossing or enforcement; unresolved evidence withholds the percentage.
- Integrate version-2 accounting with the HUD, ambient pane, audit, event detail, session receipt, local browser, and MCP presentation.
- Discard session accounting keys at end and make open-session accounting unavailable after key loss. Identity-hash erasure retains opaque IDs and accounting joins.
- Activate generation 5402 under the selected daemon's writer lease. Preserve receipt v2, socket protocol 2, the activation epoch contract, read-only readers, daemon policy RPC, and the fenced ledger layout.
- Support generation-preserving repair of activated ledgers while retaining verified daemon stop and quiescence checks.
- Narrow known limit 17: #43 is addressed for new version-2 sessions only; legacy sessions and historical rows retain their limitations. Narrow known limit 18 to record pattern-merging and action-counting improvements, while #44 remains open for supported guard-target identity and I1-safe audit display. All shell-derived accounting file identities remain unresolved, including ordinary `cat .env` reads; opaque subject IDs do not identify distinct files. 0.10.0 is a proposed target for the remaining #44 work, not a release commitment.
- Retain snapshot version 2 and compatibility with the published snapshot-v2 patched Codex builds. No downgrade migration is provided.

Generation 5402 requires the activated-accounting implementation introduced in Privacy HUD 0.9.0. A live client must also match the selected runtime build and activation epoch.

Refs #54, #43, #44, #47.

## 0.8.3

- Stop this installation's verified bundle-launched MCP server during explicit runtime repair and the shared stop-only operation.
- Announce the MCP interruption and require a host restart after successful repair; refuse any replacement ledger holder found by the quiescence checks.
- Give unverified-holder refusals a process-inspection step and the exact repair command.
- Check the plugin-data root in doctor for both historical and fenced ledger layouts.
- Keep version-2 accounting inactive, the prepared schema at generation 5401 and snapshot version 2.

Refs #74.

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
