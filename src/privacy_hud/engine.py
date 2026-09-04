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

Two phases, and why they are separately callable
------------------------------------------------
`observe()` is the single decision entry point and its whole body must run
under the daemon's lock (`dispatch.State.lock`) — it reads and writes one
shared `sqlite3.Connection`. But only *part* of the work it does needs that
lock, and the expensive part does not:

  `scan()`   — destination normalization, boundary lookup, tiers 0-3
               detection. Reads `self.matrix` (a frozen dataclass over an
               immutable dict) and `self.detectors` (stateless regex tiers
               plus one shared HF inference pipeline). **Touches no ledger,
               no sqlite, no per-session daemon state.** This is also where
               ~all the latency lives: tier 3 inference measures ~430-540ms
               on the development machine, versus single-digit milliseconds
               for everything else in this module.
  `observe()` — the allow/deny/rewrite ruling: the `policy`-table reads,
               `consume_token`, the `Ledger.record` loop, and
               `Ledger.summary`. Every sqlite touch in this module is here.

So a concurrent caller (the daemon) can run `scan()` unlocked and then hand
the resulting `ScanResult` to `observe(obs, scan=...)` under the lock, so
that a slow scan no longer stalls every other session's ledger work — while
still serializing every ledger access. `observe(obs)` with no `scan=`
computes it inline, exactly as before, for the single-threaded callers
(tests, the MCP/UI side) that have no lock to release. See
`dispatch.dispatch()` for the daemon's use and `daemon.Daemon`'s docstring
for the lock-scope reasoning this enables.

Note what the split does NOT claim: scans do not run in parallel with each
other. Tier 3 is serialized by `_TIER3_LOCK` below, because concurrent use
of the shared pipeline is both unsafe and slower — see that lock's comment.
The gain is that inference stops blocking *ledger* work and the synchronous
egress decision path, not that inference gets faster.

The phase order matters and is load-bearing: detection happens *before* any
ledger read, so there is no read-then-scan-then-write window in which a
consulted policy row or a dedupe probe could go stale. Everything the
ruling reads from sqlite is read after the scan, under the lock, in one
critical section — see `observe`'s own docstring.

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

import threading
from dataclasses import dataclass

from .detect.base import Finding
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

# --- Tier 3 is a serial resource, and that is a measurement, not a guess ---
#
# `scan()` is called without the daemon's lock (see the module docstring),
# so two worker threads can reach the tier-3 detectors at the same time.
# They must not. The shared `ModelDetector._pipe` is one `transformers`
# pipeline, and calling it concurrently from Python threads is not safe:
# running the existing 20-thread daemon concurrency test with tier 3
# genuinely loaded and unserialized aborts the interpreter outright
# (`Fatal Python error: Segmentation fault`, inside
# `transformers/pipelines/token_classification.py:preprocess`). A crashed
# daemon is the worst possible outcome for I6 — every in-flight call falls
# back to the client's own timeout path.
#
# And there is nothing to win by allowing it anyway. Measured on this
# machine (12 cores, torch 2.14, one warm pipeline, ~430ms per scan), six
# concurrent scans of the SAME pipeline take 3.5-3.6s wall — 8.3x a single
# scan, i.e. ~140% of what simply serializing them would cost. Repeating
# the sweep with `torch.set_num_threads()` at 2, 4 and 8 moves that number
# by less than 3%: inference already saturates the machine on its own, so
# overlapping it only adds contention. Tier 3 is a genuinely serial
# resource here, and this lock says so explicitly rather than leaving the
# OS scheduler to discover it.
#
# Module-level, not per-`Engine`: there is one `Engine` per session but the
# detector list behind them is one shared object per daemon (see
# `dispatch.new_state`), so a per-instance lock would guard nothing. This
# is deliberately NOT the daemon's `State.lock` — that one exists to
# serialize sqlite, and conflating "sqlite must not interleave" with
# "inference must not interleave" is exactly the merge that produced the
# bottleneck this split exists to remove. Ledger work proceeds freely
# while a scan holds this.
#
# Keep it a LEAF lock: nothing may be acquired while it is held. That is
# what makes the two locks deadlock-free without needing an ordering rule
# — `_scan` takes it, calls the detectors, and releases it, never touching
# `State.lock` in between, so no thread can ever hold one while waiting for
# the other in the opposite direction.
_TIER3_LOCK = threading.Lock()


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


@dataclass(frozen=True)
class ScanResult:
    """Everything `Engine.observe` needs that can be derived without the
    ledger — the output of `Engine.scan`.

    Frozen, with `findings` as a tuple rather than a list, on purpose: a
    `ScanResult` is the one value in this system that is produced outside
    the daemon's lock and consumed inside it. Making it immutable means the
    handoff cannot be the place a shared mutable list gets appended to from
    two threads, and a reader of `observe()` can trust that nothing between
    the two phases rewrote the findings.
    """

    dest_kind: str
    boundary: str
    findings: tuple[Finding, ...]
    # Ruling 4: tier 3 was skipped (too large, or no weights) rather than run.
    degraded: bool


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

# Task 8 policy-fix: a *user-written* `block_source` rule (Ledger's `policy`
# table, minted by mcp_tools.apply_policy's "Block this source" L3 action)
# is a different reason for a deny than the built-in credential/default_action
# path above, and copy must let the user tell them apart (see engine.py's
# module docstring / task instructions) — hence a distinct template rather
# than reusing BLOCK_TEMPLATE verbatim.
POLICY_BLOCK_TEMPLATE = (
    "PRIVACY HUD blocked a tool call\n\n"
    "  {tool}  would send data from {source}\n"
    "  to {destination} — a source-level block rule is in effect.\n\n"
    "  Run $privacy to review or adjust policy."
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

    # -- Task 8 policy-fix: consult the user-written `policy` table --------
    def _policy_selectors(self, session_id: str, rule_type: str) -> set[str]:
        """Return the `selector`s of every `rule_type` row in the `policy`
        table that applies to this session: rows scoped `"global"` plus
        rows scoped `f"session:{session_id}"` (ledger.py SCHEMA's
        `policy.scope` comment: `global|session:<id>`).

        `mcp_tools.apply_policy` (the only writer today) always inserts
        `scope=f"session:{session_id}"` — no caller currently mints a
        `"global"` row — but the schema documents `global` as a first-class
        scope, so a rule of that scope (however it eventually gets
        written) must be honoured identically to a session-scoped one
        rather than silently ignored because this query only checked one
        of the two.

        A plain `WHERE ... IN (?, ?)` equality query: a non-matching row
        just doesn't come back, which is a normal empty result, not an
        error to catch. No `except` around this query — a malformed
        `policy` row must fail loud like anything else in this module
        (I2's sibling constraint for the policy table)."""
        rows = self.ledger.conn.execute(
            "SELECT selector FROM policy WHERE rule_type=? AND scope IN (?, ?)",
            (rule_type, "global", f"session:{session_id}"),
        ).fetchall()
        return {r["selector"] for r in rows}

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
            # Always deep-scan (no cheap-shape pre-filter): tier 3's whole
            # purpose is catching categories tiers 0-2 cannot shape-match at
            # all (address, person, date, account number) — gating its
            # invocation on "does this already look PII-shaped by regex"
            # would only ever admit the categories that needed it least
            # (email/phone/SSN, which tiers 0-2 already have some coverage
            # for) and permanently exclude the rest. The two guards already
            # in this `if` (boundary, dest_kind) plus MAX_TIER3_CHARS below
            # are the intended cost bound, not a shape heuristic on top.
            if len(obs.text) > MAX_TIER3_CHARS:
                degraded = True
            else:
                ran_any = False
                # `_TIER3_LOCK`, not the daemon lock: the shared inference
                # pipeline is not safe to call concurrently (and is slower
                # when you try) — see that lock's own comment. Held only
                # around the model call, so ledger work in other threads is
                # never blocked by it.
                with _TIER3_LOCK:
                    for d in tier3:
                        if not getattr(d, "available", True):
                            continue
                        findings.extend(d.scan(obs.text, {"source": obs.source}))
                        ran_any = True
                if not ran_any:
                    degraded = True
        return findings, degraded

    def scan(self, obs: Observation) -> ScanResult:
        """Phase 1: classify the destination and run detection. No ledger.

        Safe to call WITHOUT the daemon's lock, and the whole point of
        being a separate method — this is where tier 3's ~430-540ms of
        model inference is paid, and holding a daemon-wide lock across it
        made every concurrent hook call in every session queue behind one
        model forward pass, including the sub-millisecond egress decisions
        I6 makes fail closed (see daemon.Daemon's docstring for the
        measured consequence).

        What this reads is safe to read from several threads at once:
        `self.matrix` is a frozen dataclass over a dict nothing ever
        mutates after `load_matrix()`, and the tier 0-2 detectors are pure
        functions over compiled regexes. Tier 3 is the exception and is
        handled explicitly — the shared `transformers` pipeline is NOT safe
        to call concurrently, so `_scan` serializes it on `_TIER3_LOCK`, a
        lock private to this module and unrelated to the daemon's. What
        this method deliberately does not read is anything session-scoped
        or persistent: no `self.ledger`, so no sqlite call can happen here,
        which is the property that makes running it outside the daemon's
        lock correct rather than merely faster.

        I2 still holds: an unmapped destination raises `UnknownKey` out of
        here rather than defaulting. That exception now escapes on the
        unlocked path, which is fine — `daemon._Handler.handle()` wraps the
        entire `dispatch()` call, not just its locked sections, so a raise
        here still lands on the fail-closed-on-egress path.
        """
        dest_kind = self._normalize_destination(obs.destination)
        # I2: UnknownKey propagates; never caught-and-defaulted.
        boundary = self.matrix.boundary_for(dest_kind)

        findings, degraded = self._scan(obs, dest_kind, boundary)
        return ScanResult(dest_kind=dest_kind, boundary=boundary,
                           findings=tuple(findings), degraded=degraded)

    def observe(self, obs: Observation, *, scan: ScanResult | None = None) -> Decision:
        """Phase 2: rule on `obs` and record it. Caller must hold the lock.

        Every sqlite touch in this module happens in this method's body —
        `_policy_selectors`, `consume_token`, `Ledger.record`,
        `Ledger.summary` — so a concurrent caller must serialize the whole
        of it (`dispatch.State.lock`). It is deliberately cheap: single-digit
        milliseconds of sqlite, no inference.

        Pass `scan=` the `ScanResult` from a prior `self.scan(obs)` call to
        keep that inference outside the lock. Omit it and this scans inline,
        which is the correct behavior for every single-threaded caller and
        keeps `observe(obs)` a complete, unchanged entry point.

        Why re-using a scan computed earlier is safe — what can change in
        between, and why none of it breaks:

          * The scan reads no ledger state, so nothing it produced can go
            stale. Findings are `(data_type, value, start, end)` tuples over
            `obs.text`, which is immutable and private to this request.
          * Policy is consulted *here*, after the scan, so a `policy` row
            written while the scan was running is honoured on this very
            observation rather than missed — strictly fresher than the old
            single-critical-section ordering, never staler.
          * Dedupe (`UNIQUE(session_id, value_hash, destination)`) is
            unaffected: `Ledger.record`'s SELECT-then-INSERT-or-bump runs
            entirely inside this method, hence entirely inside one lock
            hold. Two concurrent observations of the same value to the same
            destination still serialize here, so exactly one inserts and the
            other increments `count` for a 0.0 delta, as before.
          * I4 (monotonic budget) is unaffected for the same reason: the
            `budget_score=budget_score+?` read-modify-write is inside
            `Ledger.record`, inside this lock hold. No increment can be lost
            and no path decrements.
          * The scan's salt-independence is what makes the *engine object*
            interchangeable across the gap: `value_hash`/`mask`/`pseudonym`
            are applied here, from `self.salt`, never during the scan. So a
            caller that re-resolves the session's Engine between the two
            phases (which `dispatch` does, so a `SessionEnd` landing
            mid-scan is handled by the documented "new salt after
            SessionEnd" rule) gets exactly the salt it would have gotten had
            the two phases run back to back.
        """
        if scan is None:
            scan = self.scan(obs)
        dest_kind = scan.dest_kind
        findings = scan.findings
        degraded = scan.degraded

        is_egress = obs.direction == "egress"
        has_credential = any(f.data_type == "credential" for f in findings)

        action = "allow"
        policy_source_block = False

        # Task 8 policy-fix: a user-written policy rule outranks the
        # built-in default. Egress-only (Ruling 3's own logic extends
        # unchanged to user-written policy — an ingress observation's
        # bytes are already in context, so no policy check applies to it
        # either). Checked in this precedence order:
        #   1. block_source — denies regardless of what findings turned up
        #      (a source-level block covers the whole call, not just
        #      credential-shaped content).
        #   2. mask — rewrites only when there is something matching to
        #      mask.
        # Only when neither matches does this fall through, unchanged, to
        # the existing Matrix.default_action() logic below.
        if is_egress:
            if obs.source in self._policy_selectors(obs.session_id, "block_source"):
                action = "deny"
                policy_source_block = True
            elif findings:
                mask_selectors = self._policy_selectors(obs.session_id, "mask")
                if mask_selectors & {f.data_type for f in findings}:
                    action = "rewrite"

        if action == "allow" and is_egress and has_credential:
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
            if action == "deny":
                template = POLICY_BLOCK_TEMPLATE if policy_source_block else BLOCK_TEMPLATE
            else:
                template = REWRITE_TEMPLATE
            msg = template.format(tool=obs.tool_name or "tool", label=label,
                                   source=obs.source, destination=dest_kind)
            updated_input = None
            if action == "rewrite":
                # Task 12: every "rewrite" Decision returned by this engine
                # must carry a real, non-None updated_input — see the
                # caveat on Decision.updated_input above. Reached from
                # three places: the policy-table "mask" branch above, the
                # policy_defaults "mask" branch below it, and the
                # "minimize" token-consumption branch further below; all
                # three leave `findings` non-empty (either a policy mask
                # rule matched an existing finding's data_type, or
                # has_credential was required to reach the other two), so
                # there is always something to rewrite.
                ti = obs.tool_input if obs.tool_input is not None else obs.text
                # fix-round-1: pass obs.text straight through as the exact
                # blob findings were scanned against, rather than letting
                # minimize_tool_input re-derive json.dumps(tool_input)
                # itself and hope it byte-matches. See minimize.py's
                # minimize_tool_input docstring for the full rationale.
                updated_input = minimize_tool_input(self.salt, obs.tool_name or "",
                                                     ti, findings, text=obs.text)
            return Decision(action, reason=msg, system_message=msg,
                             budget_percent=pct, updated_input=updated_input,
                             degraded=degraded)

        return Decision("allow", budget_percent=pct, degraded=degraded)
