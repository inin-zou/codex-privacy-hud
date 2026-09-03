# src/privacy_hud/engine.py
"""Orchestrates detection, ledger writes, and the allow/deny/rewrite decision.

This is the piece where the matrix (Task 1), budget (Task 2), mask (Task 3),
detectors (Tasks 5-7) and ledger (Task 4) meet. Four controller rulings bind
this module beyond the original brief (task-8-brief.md does not exist; this
was extracted from .claude/docs/plans/2026-09-03-implementation.md — see
task-8-report.md for the full account):

  Ruling 1 — a `local` destination always classifies as `local_access`,
             never `exposed`, regardless of the caller-supplied `direction`.
  Ruling 2 — destinations are normalized to the bare kinds
             `[destination_boundary]` in tables.toml understands
             (local/model_context/subagent/mcp_tool/external_net) before any
             Matrix call. `Ledger.record()` itself calls
             `Matrix.boundary_for(destination)`, so the *same* normalized
             value is what gets persisted in the ledger's `destination`
             column — see `_normalize_destination` below for the chosen
             convention.
  Ruling 3 — `Matrix.default_action()` (the mask/block policy_defaults
             table) is consulted only when `direction == "egress"`. Applying
             it to an ingress observation would claim we can still decide
             the fate of bytes that have already entered context.
  Ruling 4 — tier 3 (the model/NER detector) is bounded: it runs on the
             observation text only when under `MAX_TIER3_CHARS`; above that,
             it is skipped entirely (not truncated-and-run) and the
             `Decision` is marked `degraded` so the renderer can show
             design.md §5's "fast-path results only" banner.

Global constraints this module must not violate:
  I2 — never wrap a `Matrix.*` lookup in a bare `except KeyError`/`Exception`
       that continues. `UnknownKey` is caught in exactly one place
       (`_normalize_destination`), and only to attempt one specific, known
       recovery before re-raising.
  I3 — detection is not disclosure: `kind` distinguishes exposed / prevented
       / local_access, and only `exposed` moves the budget (enforced again,
       independently, inside `Ledger.record`).
  I4 — prevented observations contribute exactly 0.0 (guaranteed by the
       ledger; this module never re-derives a budget number itself).
  No raw value is ever persisted, logged, or printed here — every value that
  reaches the ledger has already passed through `value_hash()` and `mask()`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .mask import mask, value_hash
from .matrix.loader import UnknownKey
from .minimize import consume_token, minimize_tool_input

# --- Ruling 4: bound the synchronous deep scan --------------------------
#
# PostToolUse is now synchronous (Codex 0.145.0 silently skips `async: true`
# hooks) and carries the largest payloads in the system (tool results, i.e.
# file contents). architecture.md §10 works out a concrete number for this
# same problem at the daemon layer: 8 KB keeps tier 3's cost close to the
# ~40 ms figure the latency budget already assumes, comfortably under the
# 150 ms p99 target and the hook's own 5 s timeout. We reuse that number
# here rather than inventing a second one, so Task 10's daemon-level bound
# and this engine-level bound agree.
#
# Measured in `str` length (characters), not encoded bytes: encoding a
# payload just to decide whether to bound it would itself cost O(n) on the
# exact large inputs this bound exists to protect against, and for typical
# text, char count is a close-enough, slightly conservative proxy (UTF-8
# byte count >= char count, so this bound is never looser than the 8 KB
# byte figure it is modeled on).
MAX_TIER3_CHARS = 8192

# Cheap, deterministic heuristic for "this text looks like it might carry
# PII that only a deep scan (tier 3) could type" — used to decide whether a
# clean-looking, low-boundary observation is worth a deep scan at all, so a
# StubModelDetector/ModelDetector isn't invoked on every allow-shaped event.
_PII_SHAPE = re.compile(
    r"[\w.+-]+@[\w-]+\.\w{2,}"            # email-shaped
    r"|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"   # phone-shaped
    r"|\b\d{3}-\d{2}-\d{4}\b",             # SSN-shaped
    re.IGNORECASE,
)


def _looks_pii_shaped(text: str) -> bool:
    return bool(_PII_SHAPE.search(text))


def _is_tier3_detector(detector) -> bool:
    """Tier 3 (the model/NER detector) is the only detector kind that
    tracks weight availability. `ModelDetector` and `StubModelDetector`
    both set `self.available`; the cheap tiers (`PathDetector`,
    `SecretDetector`) do not."""
    return hasattr(detector, "available")


# Detailed destination literals architecture.md's schema comments suggest
# (`subagent:<id>`, `mcp:<server>`, `net:<host>`) map to the bare kinds
# `[destination_boundary]` in tables.toml actually indexes by.
_DETAIL_PREFIX_TO_KIND = {
    "subagent": "subagent",
    "mcp": "mcp_tool",
    "net": "external_net",
}


@dataclass(frozen=True)
class Observation:
    session_id: str
    turn_id: str | None
    hook_event: str
    direction: str
    source: str
    destination: str
    text: str
    tool_name: str | None
    # Task 12: the actual tool_input dict (or bare command string) from the
    # PreToolUse payload, when known. Needed to mint/consume single-use
    # consent tokens (hashed via canonical_json) and to call
    # minimize_tool_input with something structurally real to rewrite.
    # Optional/defaulted for backward compatibility with callers (and
    # existing tests) built before Task 12 that only ever passed `text`.
    tool_input: dict | str | None = None


@dataclass
class Decision:
    action: str
    reason: str | None = None
    system_message: str | None = None
    budget_percent: int = 0
    # Populated only for action="rewrite" (see minimize_tool_input). An
    # unpopulated (None) updated_input on a rewrite decision must NEVER be
    # forwarded to Codex as if it were safe to send unchanged — Task 12
    # guarantees every "rewrite" Decision this engine returns carries a
    # real, non-None value here; a caller that ever sees rewrite+None has
    # found a bug, not a no-op.
    updated_input: str | dict | None = None
    # Ruling 4: True when tier 3 was skipped for size rather than run.
    # Renderer shows design.md §5's "Deep scan unavailable — fast-path
    # results only" banner when this is set.
    degraded: bool = False


BLOCK_TEMPLATE = (
    "PRIVACY HUD blocked a tool call\n\n"
    "  {tool}  would send  {label}\n"
    "  from {source} to {destination}.\n\n"
    "  Run $privacy to review, minimize, or allow once."
)

REWRITE_TEMPLATE = (
    "PRIVACY HUD masked a tool call\n\n"
    "  {tool}  would send  {label}\n"
    "  from {source} to {destination}.\n\n"
    "  Sensitive values were replaced with stable pseudonyms before send. "
    "Run $privacy to review or adjust policy."
)


class Engine:
    def __init__(self, *, ledger, matrix, salt: bytes, detectors: list):
        self.ledger = ledger
        self.matrix = matrix
        self.salt = salt
        self.detectors = detectors

    # -- Ruling 2: destination normalization --------------------------
    def _normalize_destination(self, destination: str) -> str:
        """Return the bare kind `Matrix.boundary_for` and `Ledger.record`
        both index by.

        Chosen convention: try the value as-is first (a caller that already
        passes a bare kind — `local`, `model_context`, `subagent`,
        `mcp_tool`, `external_net` — pays no normalization cost). If the
        matrix does not recognize it, and it looks like one of
        architecture.md's detailed literals (`<kind>:<detail>`), fold it
        down to the bare kind. Anything still unrecognized re-raises
        `UnknownKey` rather than silently defaulting — an unmapped
        destination must fail loud, not score as nothing.

        Note for Tasks 11/13: the detailed half (`<id>`/`<server>`/`<host>`)
        is NOT separately preserved anywhere today. `Ledger.record()` calls
        `Matrix.boundary_for(destination)` on exactly the string it is
        given, so whatever we pass as `destination` is both the value used
        for the boundary/policy lookups *and* the value persisted in the
        ledger's `destination` column — there is no second column for the
        detail. If per-instance detail (which subagent, which MCP server)
        is needed for the audit UI, that requires a schema change to
        `events` (e.g. a `destination_detail` column), which is out of
        scope for this task.
        """
        try:
            self.matrix.boundary_for(destination)
            return destination
        except UnknownKey:
            prefix, sep, _detail = destination.partition(":")
            if sep and prefix in _DETAIL_PREFIX_TO_KIND:
                return _DETAIL_PREFIX_TO_KIND[prefix]
            raise

    def _scan(self, obs: Observation, dest_kind: str, boundary: str) -> tuple[list, bool]:
        """Run tiers 0-2 unconditionally, then tier 3 only when it is
        gated on and the payload is small enough (Ruling 4). Returns
        (findings, degraded)."""
        nonmodel = [d for d in self.detectors if not _is_tier3_detector(d)]
        tier3 = [d for d in self.detectors if _is_tier3_detector(d)]

        findings = []
        for d in nonmodel:
            findings.extend(d.scan(obs.text, {"source": obs.source}))

        degraded = False
        # Never run the deep scan on a purely local read (Ruling 1's
        # domain): B0 never crosses a boundary worth a model call, and
        # architecture.md's "Never on local" is explicit about this.
        # B3/B4 (mcp_tool/external_net) is reached only via PreToolUse
        # egress in this taxonomy, where tiers 0-2's credential regex and
        # the shell parser already fully determine the block/mask decision
        # — a redundant deep scan there only adds synchronous latency risk
        # (the exact thing Ruling 4 exists to bound) for no new signal.
        if tier3 and dest_kind != "local" and boundary not in ("B3", "B4"):
            should_deep_scan = bool(findings) or _looks_pii_shaped(obs.text)
            if should_deep_scan:
                if len(obs.text) > MAX_TIER3_CHARS:
                    degraded = True
                else:
                    ran_any = False
                    for d in tier3:
                        if not getattr(d, "available", True):
                            continue
                        findings.extend(d.scan(obs.text, {"source": obs.source}))
                        ran_any = True
                    if not ran_any:
                        degraded = True
        return findings, degraded

    def observe(self, obs: Observation) -> Decision:
        dest_kind = self._normalize_destination(obs.destination)
        # I2: UnknownKey propagates; never caught-and-defaulted.
        boundary = self.matrix.boundary_for(dest_kind)

        findings, degraded = self._scan(obs, dest_kind, boundary)

        is_egress = obs.direction == "egress"
        has_credential = any(f.data_type == "credential" for f in findings)

        action = "allow"
        if is_egress and has_credential:
            # Ruling 3: default_action is an egress-only policy. An ingress
            # observation never reaches this branch, no matter what it
            # contains — the bytes are already in context.
            policy_action = self.matrix.default_action(dest_kind)
            if policy_action == "block":
                # Task 12: before finalizing a deny, honor a single-use
                # consent token minted for exactly this call's arguments
                # (mint_token/consume_token, architecture.md §8). A token
                # never authorizes a different tool_input than it was
                # minted for — consume_token re-hashes obs.tool_input and
                # only matches an identical canonical JSON, so a retried
                # call with different arguments still gets denied here.
                ti = obs.tool_input if obs.tool_input is not None else obs.text
                token_mode = consume_token(self.ledger, obs.session_id,
                                            obs.tool_name or "", ti)
                if token_mode == "allow_once":
                    action = "allow"
                elif token_mode == "minimize":
                    action = "rewrite"
                else:
                    action = "deny"
            elif policy_action == "mask":
                action = "rewrite"

        if dest_kind == "local":
            # Ruling 1: local always classifies as local_access, overriding
            # whatever `direction` the caller supplied, and taking priority
            # over any blocking decision above (which never arises for a
            # local read in practice, since B0 is never egress-blocking).
            classify_direction = "local"
        elif action == "deny":
            classify_direction = "blocked"
        elif action == "rewrite":
            classify_direction = "rewritten"
        else:
            classify_direction = obs.direction

        kind = self.matrix.classify(obs.hook_event, classify_direction)
        protection = {"deny": "blocked", "rewrite": "masked"}.get(action)

        for f in findings:
            self.ledger.record(
                obs.session_id, turn_id=obs.turn_id, kind=kind,
                data_type=f.data_type, source=obs.source,
                destination=dest_kind,
                value_hash=value_hash(self.salt, f.value),
                masked_example=mask(f.data_type, f.value),
                tool_name=obs.tool_name,
                protection=protection)

        pct = self.ledger.summary(obs.session_id)["percent"]

        if action in ("deny", "rewrite"):
            label = ", ".join(sorted({f.data_type for f in findings})) or "sensitive data"
            template = BLOCK_TEMPLATE if action == "deny" else REWRITE_TEMPLATE
            msg = template.format(tool=obs.tool_name or "tool", label=label,
                                   source=obs.source, destination=dest_kind)
            updated_input = None
            if action == "rewrite":
                # Task 12: every "rewrite" Decision returned by this engine
                # must carry a real, non-None updated_input — see the
                # caveat on Decision.updated_input above. Reached from two
                # places: the policy_defaults "mask" branch above, and the
                # "minimize" token-consumption branch above; both leave
                # `findings` non-empty (has_credential was required to
                # reach either), so there is always something to rewrite.
                ti = obs.tool_input if obs.tool_input is not None else obs.text
                updated_input = minimize_tool_input(self.salt, obs.tool_name or "",
                                                     ti, findings)
            return Decision(action, reason=msg, system_message=msg,
                             budget_percent=pct, updated_input=updated_input,
                             degraded=degraded)

        return Decision("allow", budget_percent=pct, degraded=degraded)
