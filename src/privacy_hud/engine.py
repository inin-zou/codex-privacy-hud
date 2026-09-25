# src/privacy_hud/engine.py
"""Orchestrates detection, ledger writes, and the allow/deny/rewrite decision.

This is the piece where the matrix (Task 1), budget (Task 2), mask (Task 3),
detectors (Tasks 5-7) and ledger (Task 4) meet. Four controller rulings bind
this module beyond the original brief (task-8-brief.md does not exist; this
was extracted from .claude/docs/plans/2026-09-03-implementation.md — see
task-8-report.md for the full account):

  Ruling 1 — a `local` destination always classifies as `local_access`,
             never `exposed`, regardless of the caller-supplied `direction`
             -- with one exception (#36): a local read the engine DENIES
             classifies as `prevented`, through the existing
             `"PreToolUse/blocked"` taxonomy entry, not `local_access`.
             Without that exception a blocked read and an ordinary one
             would write the same ledger row, and the audit could never
             show that anything was stopped.
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
  Ruling 4 — tier 3 (the model/NER detector) is gated two ways. By size:
             it runs on the observation text only when under
             `MAX_TIER3_CHARS`; above that it is skipped entirely (not
             truncated-and-run). And, on egress only, by a deadline and by
             admission, because I6 turns a missed client deadline into a
             deny of a call that should have been allowed. Egress uses a
             requested timeout based on the remaining budget and an
             inclusive completion cutoff; neither guarantees elapsed time.
             See `engine.TIER3_EGRESS_BUDGET`. At most one egress scan
             worker is admitted at a time. Admission is nonblocking; the
             worker retains its slot until it exits, including after
             caller abandonment. When an applicable deep scan supplied no
             accepted result, the scan carries a `GAP_*` reason and the
             `Decision` is `degraded`. Each observed scan gap is recorded
             per observation and counted per session, including
             observations with no event row (`Ledger.record_scan_gap`).

Which detectors those gates apply to is a declaration, not a deduction:
each detector states its own `DetectorProfile(tier=..., cost=...)` and
`_scan` groups by the declared `Cost`. This module used to infer "is this
the expensive tier?" from `hasattr(detector, "available")`, which silently
misfiled any cheap detector that tracked availability and let any expensive
one that did not escape the gate entirely. `detect/base.py`'s module
docstring has the full account; the rule here is that `engine.py` never
inspects a detector's shape to decide how to schedule it.

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

import posixpath
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import get_args

from .detect.base import Cost, Finding, is_available, profile_of
from .accounting import (
    EventRecord,
    Evidence,
    ObservationRecord,
    RecipientInput,
    SafeSuffix,
    SubjectInput,
    ValueFinding,
    coalesce_value_findings,
)
from .accounting import Decision as AccountingDecision
from . import codex
from .detect.paths import PATTERNS, is_sensitive_path
from .detect.secrets import CredentialMatch, SecretDetector
from .detect.shell import network_file_rules
from .hook_evidence import HookEvidence, classify_evidence
from .identity import file_identity, safe_masked_example
from .mask import mask, value_hash
from .matrix.loader import HARD_BLOCKED_DATA_TYPES, UnknownKey
from .minimize import consume_token, minimize_tool_input
from .origin import Origin, OriginKind, origin_phrase
from .prompt_hold import PromptGate

# --- Ruling 4: cap the deep scan's input size ---------------------------
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


# --- The egress half of Ruling 4: a deadline, not just a size cap ---------
#
# #47 item 1 put tier 3 back on B3/B4, where architecture.md §4 always said
# it belonged. That reopens a queue `daemon.Daemon`'s docstring measured and
# closed, and the measurement is why egress gets a budget rather than a
# plain `with _TIER3_LOCK`:
#
#   * tier 3 is a serial resource (see the block above), ~430-540ms warm on
#     one development machine — a typical figure, NOT a proven maximum;
#   * `hooks/handler.py` gives the daemon 2.0s per socket operation;
#   * I6 makes an egress that misses that deadline **deny**.
#
# So an egress `PreToolUse` that queues behind a few in-flight ingress scans
# does not merely answer late — it answers never, and Codex is told to block
# a call the daemon would have allowed. That was demonstrated end to end
# before the scan/observe split: a benign `curl .../health`, real answer
# allow, took 2002ms behind six ingress scans and was denied.
#
# --- The contract ------------------------------------------------------
#
# `TIER3_EGRESS_BUDGET` sets an egress deadline using `time.monotonic()`
# before task creation, admission and thread creation. The caller requests
# `task.done.wait(max(0.0, deadline - time.monotonic()))`. Deep-scan
# findings are used if and only if that wait returns `True`,
# `task.error is None`, `task.outcome is None`, `task.finished_at is not
# None`, and `task.finished_at <= deadline`; an accepted result may contain
# zero findings. Completion before the caller starts waiting is allowed,
# including a timely completion observed after the deadline. A false wait
# return yields `GAP_TIMEOUT`; after a true return, a worker error is
# re-raised, otherwise an unsuccessful outcome supplies its gap reason, or a
# rejected completion yields `GAP_TIMEOUT`. This mechanism neither cancels
# inference nor guarantees actual wait duration, caller return time or hook
# round-trip time. Ingress does not use this deadline.
#
# MEASURED, as a measurement and not a bound: with a detector holding the
# interpreter, a call under this 1.0s budget returned at 1.25s, having
# correctly rejected the result. Half of the client's 2.0s is the split
# defensible without measuring the rest of the hook round trip (`State.lock`,
# sqlite, the socket), which nobody has; `tests/test_daemon.py`'s lock-scope
# tests are where a change to this number shows up as a number.
TIER3_EGRESS_BUDGET = 1.0

#: The boundaries an outbound call crosses, and the only ones whose decision
#: a timeout can turn into a deny.
EGRESS_BOUNDARIES = ("B3", "B4")

#: Admission control for the egress deep scan. At most one egress scan
#: worker is admitted at a time. Admission is nonblocking; the worker retains
#: its slot until it exits, including after caller abandonment.
#:
#: Without this, a burst of outbound calls whose callers abandoned their
#: results would each leave a worker queued for the model, and later egress
#: scans would queue behind work whose results nobody will use. With it, a
#: worker that never exits retains the admission slot. Later egress scans
#: that reach admission fail it and return `GAP_BUSY`; applicable oversized
#: payloads return `GAP_OVERSIZE` before admission.
_TIER3_EGRESS_SLOT = threading.BoundedSemaphore(1)

#: Scan-gap reasons. A scan gap: an applicable deep scan supplied no accepted
#: result. Each reason names a specific, recorded history — the same
#: discipline `ledger.COVERAGE_*` holds itself to. `None` means no scan gap,
#: not necessarily "the scan ran": an out-of-scope scan has no gap either.
#: An accepted empty result is a clean scan, not a scan gap.
#:
#: oversize    — applicable payload exceeds `MAX_TIER3_CHARS`; inference is
#:               not attempted.
#: unavailable — no expensive detector supplies a successful available
#:               result, including missing weights and a detector becoming
#:               unavailable during inference.
#: busy        — nonblocking egress admission fails.
#: timeout     — egress only, three histories: the worker cannot start
#:               inference within its deadline (including model-lock
#:               contention); the caller's wait returns False, whether the
#:               work is pending, running or completed; or the wait returns
#:               True but an otherwise successful result has no completion
#:               timestamp or completed after the deadline.
GAP_OVERSIZE = "oversize"
GAP_UNAVAILABLE = "unavailable"
GAP_BUSY = "busy"
GAP_TIMEOUT = "timeout"


class _DeepScanTask:
    """One egress deep scan's handoff between its worker and its caller.

    The worker records its outcome here; whether the caller accepts it is
    decided by the contract above `TIER3_EGRESS_BUDGET`, not by the worker.
    Completion before the caller starts waiting is allowed.
    """

    __slots__ = ("done", "findings", "outcome", "error", "finished_at")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.findings: list[Finding] = []
        #: The worker's outcome: None for a successful scan, a `GAP_*` reason
        #: otherwise. Initialised to `GAP_TIMEOUT` for a worker that returns
        #: before starting inference.
        self.outcome: str | None = GAP_TIMEOUT
        #: What `scan()` raised. A false wait return yields `GAP_TIMEOUT`;
        #: after a true return, a worker error is re-raised on the CALLER's
        #: thread so it reaches the daemon's exception boundary and I6 denies.
        self.error: BaseException | None = None
        #: When the scan finished, by the same clock as the deadline. `done`
        #: being set says the worker completed; it does not say the result
        #: is accepted. Completion at or before the deadline is necessary but
        #: not sufficient for accepting the result; see
        #: `engine.TIER3_EGRESS_BUDGET`.
        self.finished_at: float | None = None


def _in_time(finished_at: float | None, deadline: float) -> bool:
    """The completion-cutoff part of the acceptance condition.

    Inclusive: a completion exactly at the deadline passes (`<=`).
    Completion at or before the deadline is necessary but not sufficient for
    accepting the result; see `engine.TIER3_EGRESS_BUDGET`.
    """
    return finished_at is not None and finished_at <= deadline


def _run_expensive(text, ctx, expensive, into: list) -> str | None:
    """Every available expensive detector, appending to `into`.

    Returns `GAP_UNAVAILABLE` when no expensive detector supplies a
    successful available result, `None` when at least one does. An accepted
    empty result is a clean scan, not a scan gap. Assumes `_TIER3_LOCK` is
    held.
    """
    ran_any = False
    for d in expensive:
        # Availability, unlike cost, is per-instance runtime state — the
        # weights loaded on this machine or they did not. It is read through
        # `is_available` (default True: a detector that declares nothing has
        # no reason to be considered broken) and it decides only whether
        # *this instance* can run, never which tier it belongs to. That
        # conflation is the bug the DetectorProfile refactor removed.
        if not is_available(d):
            continue
        found = d.scan(text, ctx)
        # Read availability AGAIN, because a detector is allowed to discover
        # mid-scan that it cannot do its job and say so by going
        # unavailable — `ModelDetector.scan` does exactly that when the
        # inference pipeline raises. Without this re-read the empty list it
        # returns is indistinguishable from a clean scan, `ran_any` goes
        # True, and a session whose every deep scan crashed reports as
        # fully verified with nothing found.
        if not is_available(d):
            continue
        into.extend(found)
        ran_any = True
    return None if ran_any else GAP_UNAVAILABLE


def _deep_scan_blocking(text, ctx, expensive, findings) -> str | None:
    """The ingress path: blocks until the model finishes.

    Ingress does not use the egress deadline.

    `_TIER3_LOCK`, not the daemon lock: the shared inference pipeline is not
    safe to call concurrently (and is slower when you try) — see that lock's
    own comment. Held only around the model call, so ledger work in other
    threads is never blocked by it.
    """
    with _TIER3_LOCK:
        return _run_expensive(text, ctx, expensive, findings)


def _deep_scan_worker(text, ctx, expensive, task: _DeepScanTask,
                      deadline: float) -> None:
    """Run one egress deep scan, then release the admission slot.

    Runs on its own thread. At most one egress scan worker is admitted at a
    time. Admission is nonblocking; the worker retains its slot until it
    exits, including after caller abandonment. Nothing here touches the
    ledger, the policy tables or the caller's findings list: the worker owns
    nothing but `task`, so a result the caller does not accept is dropped
    without consequence. Completion at or before the deadline is necessary
    but not sufficient for accepting the result; see
    `engine.TIER3_EGRESS_BUDGET`.
    """
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        if not _TIER3_LOCK.acquire(timeout=remaining):
            return
        try:
            # The deadline passed while queueing for the model. A result
            # completed from here would fail the completion cutoff, so
            # starting inference would only hold the model and the admission
            # slot against the next egress call. The outcome stays
            # `GAP_TIMEOUT`.
            if time.monotonic() >= deadline:
                return
            found: list[Finding] = []
            outcome = _run_expensive(text, ctx, expensive, found)
            task.findings = found
            task.outcome = outcome
            task.finished_at = time.monotonic()
        finally:
            _TIER3_LOCK.release()
    except BaseException as exc:                           # noqa: BLE001
        # Caught, not propagated: an exception escaping this function would
        # reach `threading.excepthook`, which prints it — and a detector's
        # exception text can quote the payload it was scanning, which is an
        # I1 problem, not just noise. After a true wait return, the caller
        # re-raises it instead; a false wait return yields `GAP_TIMEOUT`.
        task.error = exc
    finally:
        task.done.set()
        _TIER3_EGRESS_SLOT.release()


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
    #: Where this observation's data came from (`origin.extract_origin`),
    #: when it can be named. `None` means the source is a bare label -- a
    #: tool name or `user prompt` -- and no rule can target the row.
    origin: Origin | None = None
    #: #54 Phase 4: the daemon-normalized evidence for a version-2 session's
    #: delivery, or None for legacy accounting. V2 uses `accounting.turn_id`;
    #: the legacy `turn_id` above is unchanged.
    accounting: HookEvidence | None = None
    #: The transient literal path the read guard evaluated, before display
    #: collapse, and the payload's working directory. Inputs to a file
    #: identity only; never persisted, displayed or kept in origin state.
    evaluated_path: str | None = None
    cwd: str = ""


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
    # Ruling 4: a scan gap — an applicable deep scan supplied no accepted
    # result (see the `GAP_*` reasons for the histories that covers).
    degraded: bool
    # Which `GAP_*` reason it was; None means no scan gap, not necessarily
    # that the scan ran. The bool above is `degraded_reason is not None` and is kept because every
    # reader that only asks "is this partial?" should not have to know the
    # taxonomy. `Ledger.record_scan_gap` is the reader that does.
    degraded_reason: str | None = None
    # None: no network-file denial. Empty tuple: parse failure without a
    # recovered sensitive path. Otherwise: indexes into PATTERNS only.
    # Never carries a path, command, filename, suffix or file identity.
    network_file_rules: tuple[int, ...] | None = None


@dataclass
class Decision:
    action: str
    reason: str | None = None
    system_message: str | None = None
    # Display only: the session's legacy percentage, or None when the ledger
    # has no record of the session. Never read by a decision.
    budget_percent: int | None = None
    # Populated only for action="rewrite" (see minimize_tool_input). An
    # unpopulated (None) updated_input on a rewrite decision must NEVER be
    # forwarded to Codex as if it were safe to send unchanged — Task 12
    # guarantees every "rewrite" Decision this engine returns carries a
    # real, non-None value here; a caller that ever sees rewrite+None has
    # found a bug, not a no-op.
    updated_input: str | dict | None = None
    # Ruling 4: True when this observation had a scan gap: an applicable
    # deep scan supplied no accepted result. The histories are the `GAP_*`
    # reasons above. An accepted empty result is a clean scan, not a scan
    # gap. NOT set when the deep scan was out of scope (a local destination,
    # or no configured expensive detector): claiming a gap there would tell
    # the user the tool is impaired when it is behaving as specified. A
    # B3/B4 egress was on that out-of-scope list until #47 item 1 and is not
    # any more. A scan gap can omit findings that would otherwise cause
    # blocking or masking. Renderer shows design.md §5's "Scan gap —
    # fast-path results only." banner when this is set.
    degraded: bool = False


# The intervention templates say what Privacy HUD returned, never that the
# host applied it: no current hook reports whether a denial or rewritten
# input was applied (#54's evidence baseline). "Run $privacy to review the
# ledger" traces to the skill's audit heredoc.
BLOCK_TEMPLATE = (
    "PRIVACY HUD issued a tool-call denial\n\n"
    "  {tool}  would send  {label}\n"
    "  from {source} to {destination}.\n\n"
    "  Host enforcement is not confirmed.\n"
    "  Run $privacy to review the ledger."
)

REWRITE_TEMPLATE = (
    "PRIVACY HUD returned rewritten input\n\n"
    "  {tool}  would send  {label}\n"
    "  from {source} to {destination}.\n\n"
    "  Privacy HUD returned rewritten input. Application by the host is not "
    "confirmed.\n"
    "  Run $privacy to review the ledger."
)

# A deny that a user's own origin rule caused reads differently from the
# built-in credential default, and the copy must let them tell the two
# apart: this one names the file or command the value came from, which is
# the fact the user acted on when they wrote the rule. `{origin_phrase}`
# rather than a hardcoded "read from", because a command origin is not a
# file -- `origin.origin_phrase` owns the wording for both kinds, and the
# button the user pressed took its label from the same place.
#
# It ends in "Run $privacy to review the ledger", which the audit performs,
# and never "or adjust policy": an origin deny is decided above, before the
# consent-token branch, which only runs when the action is still "allow";
# and no code path removes a policy row. `Ledger.add_policy` scopes the rule
# to `session:<id>`, so it does not outlive the session.
#
# It says "a source rule saved for this session", not "a source rule you
# wrote". `privacy.update_policy` is an exposed MCP tool, which means the
# model can write one of these rules -- and known limit 13 says nothing can
# remove it. Attributing to the user a rule they may not have written is
# §5's own defect (copy naming an actor that is no longer traceable to a
# user surface).
#
# It also does not say "allow once does not override it" -- the clause used
# to, and the fact is still true (the consent-token branch only runs when
# the action is still "allow", so it is never reached here), but no surface
# mints an allow-once token, so naming it told the user they had a button
# that does not exist. Stating what cannot be overridden is only useful
# copy when overriding it is a real option; here it is not one at all, so
# the clause is gone rather than reworded.
ORIGIN_BLOCK_TEMPLATE = (
    "PRIVACY HUD issued a tool-call denial\n\n"
    "  {tool}  would send  {label}\n"
    "  {origin_phrase}.\n\n"
    "  A source rule saved for this session caused Privacy HUD to issue this "
    "denial.\n"
    "  Host enforcement is not confirmed. The rule is scoped to this session.\n"
    "  Run $privacy to review the ledger."
)

# It used to say the read "did not run, so nothing from it reached the
# model". That is what the denial asks for, not what the hooks can report:
# no current hook confirms the host applied it. `$privacy read off` traces
# to the skill's `read_guard_set()` heredoc.
READ_BLOCK_TEMPLATE = (
    "PRIVACY HUD issued a read denial\n\n"
    "  {tool}  would read  {path}\n\n"
    "  Privacy HUD issued a denial for this read. Host enforcement is not "
    "confirmed.\n\n"
    "  Run `$privacy read off` to turn off this read guard."
)

NETWORK_FILE_BLOCK_TEMPLATE = (
    "PRIVACY HUD issued a network-call denial.\n"
    "The command references a known-sensitive path or could not be parsed "
    "reliably. File contents were not inspected.\n"
    "Host enforcement is not confirmed.\n"
    "Run $privacy to review the ledger."
)

# Shown once per session, not once per path: this is how the feature is
# discovered, and a line on every read would be noise.
#: Present tense, because this is emitted from `PreToolUse` and the read has
#: not happened: the file may not exist, another approval layer may still
#: refuse, the command may fail. It said "this session read {path}" until
#: #49 item 4 — the same tense error as writing an `exposed` row before the
#: host returns its decision, and cheaper to fix here than there.
READ_NOTICE_TEMPLATE = (
    "PRIVACY HUD: this call requests a read of {path}, which matches a "
    "known-sensitive-path rule.\n"
    "Run `$privacy read on` to enable denial requests for recognized matching "
    "reads. Host enforcement is not confirmed."
)


class _PermissiveSettings:
    """The "off" default for `Engine(settings=...)`: every existing caller
    and test that builds an `Engine` without a settings object keeps
    behaving exactly as before this task -- I6, applied to our own default
    rather than just to Settings' file-read failure mode."""

    deny_read = False


class Engine:
    def __init__(self, *, ledger, matrix, salt: bytes, detectors: list,
                 settings=None, accounting_key: bytes | None = None,
                 prompt_clock: Callable[[], float] = time.monotonic):
        self.ledger = ledger
        #: #54 Phase 4: this session's version-2 accounting key, installed
        #: by the daemon only after the session's activation committed, or
        #: None. Separate from `salt`, the enforcement salt: a replacement
        #: enforcement engine never recreates accounting identity.
        self.accounting_key = accounting_key
        #: Set by `clear_session_identity`; the engine then takes no further
        #: identity-bearing observation work.
        self._identity_cleared = False
        self.matrix = matrix
        self.salt = salt
        self.detectors = detectors
        # #36: an object exposing `.deny_read`, not the concrete `Settings`
        # class -- this is what lets a test pass a tiny double instead of a
        # real file on disk. `None` means "no settings object was given",
        # and defaults to the permissive answer (I6): a guard that was never
        # configured must not start blocking on a guess.
        self.settings = settings if settings is not None else _PermissiveSettings()
        # Fail at wiring time, not at the first scan of the first session.
        # `profile_of` raises `UndeclaredDetector` for a detector that has
        # not declared its tier and cost, and this loop is what makes that
        # raise land on the line that assembled the stack (dispatch's
        # `new_state`, a test fixture) rather than several hook calls later
        # inside `_scan`. There is no default to fall back to: see
        # `UndeclaredDetector`'s docstring for why every candidate default
        # is a silent misclassification.
        for d in detectors:
            profile_of(d)
        #: value_hash -> where that value entered this session from (#40).
        #: Lives on the Engine because `dispatch` builds one Engine per
        #: session around that session's salt: once the salt is gone the
        #: hashes are incomparable, so a map that outlived it would be
        #: worthless. A daemon replaced mid-session therefore starts empty,
        #: which allows rather than denies (I6, and known limit 3).
        self._origins: dict[bytes, Origin] = {}
        #: #36: the read-guard discoverability notice fires once per
        #: session, not once per path -- same per-session lifetime as
        #: `_origins` above, and for the same reason: it lives on the
        #: Engine because `dispatch` builds one Engine per session.
        self._read_notice_shown = False
        #: #37: this session's credential-prompt confirmation state, in
        #: memory only and keyed with this engine's enforcement salt. Same
        #: per-session lifetime as `_origins`: a replacement engine starts
        #: empty and holds again, which fails safe.
        self.prompt_gate = PromptGate(salt=salt, clock=prompt_clock)

    def clear_session_identity(self) -> None:
        """Discard this engine's session identity (#54 Phase 4): the
        accounting-key reference, the salt reference and every origin
        association keyed by it. The engine is unusable for identity-bearing
        observation work afterwards; `scan` stays usable because it never
        touched identity. Idempotent. This drops references; it does not
        promise that Python memory is wiped."""
        self.accounting_key = None
        self.salt = b""
        self._origins.clear()
        self.prompt_gate.clear()
        self._identity_cleared = True

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
        """The `selector`s of every user-written `rule_type` rule in force for
        this session — `Ledger.policy_selectors`, which owns the `policy`
        table and the scope rule (session rules plus `global` ones).

        Kept as a method here, rather than inlining the ledger call at its two
        use sites in `observe`, because the engine's contract is that policy is
        consulted *after* the scan and before the matrix defaults; this name is
        where that ordering is documented and what `test_engine.py`'s
        "`scan()` never touches the ledger" guards point at."""
        return self.ledger.policy_selectors(session_id, rule_type)

    # -- Task 4 (#40): the taint map, and the deny --------------------------
    _ORIGIN_RULE_TYPES = {OriginKind.PATH: "block_path",
                          OriginKind.COMMAND: "block_command"}

    def _remember_origins(self, obs: Observation, findings: Sequence[Finding]) -> None:
        """Record where each finding's value entered this session from.

        Two things must hold, and #36 made the second one load-bearing.

        The observation must name an origin — on most events `source` is a
        fixed label (`tool input`), which is a place-shaped word for
        something that is not a place.

        And the call must already have run. A `PreToolUse` has not: since
        #36 a local read reaches here with a PATH origin, but its findings
        are matches against the *text of a command that has not executed*,
        so the only value they carry is the low-entropy tier-0 pattern
        literal the text matched (`.pem`, `.env`) — never a byte of the
        file. Mapping that literal to the path in the command would make
        every later call mentioning any `.pem` look like it carries data
        from that one file, and a `block_path` rule on it would deny calls
        that never touched it while naming it as the source. The map
        answers "where did this value enter the session"; a call that has
        not run is not an answer to that.
        """
        if obs.origin is None or obs.hook_event == "PreToolUse":
            return
        # The enforcement representation only (#54 Phase 4): the transient
        # evaluated path is an accounting input and never outlives the
        # observation that carried it.
        origin = Origin(value=obs.origin.value, kind=obs.origin.kind)
        for f in findings:
            self._origins.setdefault(value_hash(self.salt, f.value), origin)

    def _blocked_origin(self, session_id: str, findings: Sequence[Finding]) -> Origin | None:
        """The origin of the first finding whose source the user has blocked.

        A finding with no entry is *not* evidence of anything: it may have
        entered before this Engine existed, or through a read the detectors
        did not flag. It allows (I6 covers engine failure, not absent
        evidence).
        """
        for f in findings:
            origin = self._origins.get(value_hash(self.salt, f.value))
            if origin is None:
                continue
            rule_type = self._ORIGIN_RULE_TYPES[origin.kind]
            if origin.value in self._policy_selectors(session_id, rule_type):
                return origin
        return None

    def _scan(self, obs: Observation, dest_kind: str,
              boundary: str) -> tuple[list, str | None]:
        """Run every cheap detector unconditionally, then the expensive ones
        only when they are gated on and the payload is small enough
        (Ruling 4). Returns (findings, gap) — `gap` is a `GAP_*` reason
        when an applicable deep scan supplied no accepted result, and None
        when there is no scan gap (including an out-of-scope scan).

        The split is read off each detector's own `DetectorProfile.cost`, not
        guessed from its shape. This used to ask
        `hasattr(detector, "available")` and call a yes "tier 3", which
        silently reclassified any cheap detector that tracked availability
        (an optional ruleset, a config file) as expensive — it stopped
        running on local reads (and, at the time, on B3/B4) and was skipped
        past the size cap, with nothing raised — and left any expensive
        detector without an `available` flag running unconditionally on
        every observation with no cap at all. See `detect/base.py`'s module
        docstring.

        Re-read from `self.detectors` on every call rather than partitioned
        once in `__init__`: `dispatch`/`daemon` build one shared detector
        list on a mutable `State` and several tests reassign it, so a cached
        partition could describe a stack the engine is no longer using.
        Reading two attributes per detector per scan is free next to the
        regex pass it precedes.
        """
        cheap: list = []
        expensive: list = []
        for d in self.detectors:
            (cheap if profile_of(d).cost is Cost.CHEAP else expensive).append(d)

        findings = []
        for d in cheap:
            # Availability is deliberately NOT consulted here. A cheap
            # detector that cannot do its job is expected to say so from
            # inside `scan()` by returning no findings (as
            # `ModelDetector.scan` does), because there is no degradation
            # story to tell about it: `Decision.degraded` drives design.md
            # §5's "Scan gap — fast-path results only." banner, which is a
            # claim about the model tier specifically. Skipping cheap detectors here
            # would either fly that banner dishonestly or drop findings with
            # no signal at all.
            findings.extend(d.scan(obs.text, {"source": obs.source}))

        gap: str | None = None
        # Never run the deep scan on a purely local read (Ruling 1's
        # domain): B0 never crosses a boundary worth a model call, and
        # architecture.md's "Never on local" is explicit about this.
        #
        # B3/B4 (mcp_tool/external_net) used to be excluded here too, on the
        # argument that "tiers 0-2 already fully determine the block/mask
        # decision". That argument is false twice over. It is false about the
        # mask, obviously. It is also false about the *block*, less
        # obviously: `detect/model.py`'s LABEL_MAP maps `SECRET` to
        # `credential`, and `observe`'s hard-block test reads findings from
        # every tier, so tier 3 can produce the finding that denies a call.
        # (An earlier version of this comment repeated "only a credential
        # blocks" as if that settled it. It does not — the deep tier is one
        # of the things that can find a credential.) `email`, `person`,
        # `address`, `phone` and `account` are tier-3-only, so the exclusion
        # meant no outbound call could produce a finding of any of them: the
        # session's whole outbound record was paths and credentials, a `mask`
        # rule on `email` had nothing to intersect and could never fire, and
        # architecture.md §4's "Tier 3 runs ... when the payload crosses
        # B3/B4" was the opposite of what ran (#47 item 1).
        if expensive and dest_kind != "local":
            # Always deep-scan (no cheap-shape pre-filter): tier 3's whole
            # purpose is catching categories tiers 0-2 cannot shape-match at
            # all (address, person, date, account number) — gating its
            # invocation on "does this already look PII-shaped by regex"
            # would only ever admit the categories that needed it least
            # (email/phone/SSN, which tiers 0-2 already have some coverage
            # for) and permanently exclude the rest. The guard already in
            # this `if` (dest_kind) and MAX_TIER3_CHARS below are the cost
            # gates — not a shape heuristic on top. Egress additionally uses
            # a requested timeout based on the remaining budget and an
            # inclusive completion cutoff; neither guarantees elapsed time.
            # See `engine.TIER3_EGRESS_BUDGET`.
            ctx = {"source": obs.source}
            if len(obs.text) > MAX_TIER3_CHARS:
                gap = GAP_OVERSIZE
            elif boundary in EGRESS_BOUNDARIES:
                gap = self._deep_scan_on_a_deadline(obs.text, ctx, expensive,
                                                    findings)
            else:
                gap = _deep_scan_blocking(obs.text, ctx, expensive, findings)
        return findings, gap

    def _deep_scan_on_a_deadline(self, text, ctx, expensive, findings):
        """The egress path: a deadline, and admission one worker at a time.

        Returns a `GAP_*` reason, or None when the result is accepted and
        its findings are in `findings`. Which of those it is follows the
        contract above `TIER3_EGRESS_BUDGET` exactly; this method is its
        implementation, not a second statement of it.

        Three properties, each the fix for a specific way the first version
        of this was wrong (#47 item 1, rejected in review):

        **The deadline applies to the result, not only to the lock.** The
        first version took `_TIER3_LOCK` with a timeout and then ran the
        scan with no deadline at all, and inference is the slow part.
        `deadline` is absolute; the worker re-checks it after it gets the
        lock, so a worker whose deadline passed while queueing never starts
        inference; and `_in_time` applies the completion cutoff before any
        finding is used. Completion at or before the deadline is necessary
        but not sufficient for accepting the result; see
        `engine.TIER3_EGRESS_BUDGET`.

        **Admission.** At most one egress scan worker is admitted at a time.
        Admission is nonblocking; the worker retains its slot until it
        exits, including after caller abandonment. A failed admission is
        `GAP_BUSY`.

        **Result isolation.** The worker writes only to its own
        `_DeepScanTask`, and this method reads the task's findings only when
        the result is accepted. Once this method returns, a result the
        worker records later is never merged into a ledger row or a block
        ruling.
        """
        deadline = time.monotonic() + TIER3_EGRESS_BUDGET
        # Built before the slot is taken, so that nothing between the
        # acquire and the `try` below can raise: an allocation failure there
        # would leave the admission slot acquired with nobody to release it.
        # Later egress scans that reach admission would return `GAP_BUSY`;
        # applicable oversized payloads return `GAP_OVERSIZE` before admission.
        task = _DeepScanTask()
        if not _TIER3_EGRESS_SLOT.acquire(blocking=False):
            return GAP_BUSY
        try:
            threading.Thread(
                target=_deep_scan_worker,
                args=(text, ctx, expensive, task, deadline),
                name="privacy-hud-tier3-egress", daemon=True).start()
        except BaseException:
            # The worker owns the slot's release, so a worker that never
            # started has to give it back here or egress degrades forever.
            _TIER3_EGRESS_SLOT.release()
            raise

        if not task.done.wait(max(0.0, deadline - time.monotonic())):
            return GAP_TIMEOUT
        if task.error is not None:
            # On this thread, so it leaves `Engine.scan` the way it would
            # have before the scan moved to a worker: out through
            # `dispatch()` to the daemon's exception boundary, where I6
            # denies an outbound call whose engine failed. After a true wait
            # return, a worker error is re-raised rather than converted into
            # an ordinary gap.
            raise task.error
        if task.outcome is None and _in_time(task.finished_at, deadline):
            findings.extend(task.findings)
            return None
        return task.outcome if task.outcome is not None else GAP_TIMEOUT

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

        file_rules = None
        if (obs.hook_event == "PreToolUse"
                and obs.direction == "egress"
                and obs.tool_name == codex.SHELL_TOOL
                and dest_kind == "external_net"):
            file_rules = network_file_rules(obs.text)

        findings, gap = self._scan(obs, dest_kind, boundary)
        return ScanResult(
            dest_kind=dest_kind, boundary=boundary,
            findings=tuple(findings), degraded=gap is not None,
            degraded_reason=gap, network_file_rules=file_rules)

    # -- #37: credential prompt holds ------------------------------------
    def scan_prompt_credentials(self, obs: Observation
                                ) -> tuple[CredentialMatch, ...]:
        """The hold-eligible tier-1 credential matches in a user prompt.

        Only `SecretDetector`'s well-formed formats can hold a prompt: never
        its entropy backstop or a bare key header, and never a tier-3
        finding, whatever data type it reports. Regex-only, so it does not
        wait for the model. Like `scan`, it reads no ledger and no session
        state, so it is safe outside `State.lock`."""
        if obs.hook_event != "UserPromptSubmit":
            return ()
        matches: list[CredentialMatch] = []
        for d in self.detectors:
            if isinstance(d, SecretDetector):
                matches.extend(
                    m for m in d.scan_labeled(obs.text, {"source": obs.source})
                    if m.hold_eligible)
        return tuple(matches)

    def record_prompt_hold(self, obs: Observation,
                           matches: Sequence[CredentialMatch],
                           reason: str) -> Decision:
        """Record a held prompt as a prevention and return the hold.
        Caller holds the lock.

        Only the eligible credential findings are recorded: the held
        submission is not deep-scanned, which is out of scope rather than a
        scan gap. Version 2 records an issued denial (`DENY_ISSUED`), never
        confirmed enforcement or crossing. Legacy writes one `prevented` row
        per distinct credential with no dedupe hash, so it cannot absorb a
        later permitted crossing of the same value, and no masked example."""
        if self._identity_cleared:
            raise RuntimeError("this engine's session identity was cleared")
        dest_kind = self._normalize_destination(obs.destination)
        boundary = self.matrix.boundary_for(dest_kind)
        findings = tuple(m.finding for m in matches)
        scan = ScanResult(dest_kind=dest_kind, boundary=boundary,
                          findings=findings, degraded=False)
        if obs.accounting is not None:
            return self._observe_v2(
                obs, scan, action="deny", blocked_origin=None,
                read_block=None, notice=None, prompt_reason=reason)

        kind = self.matrix.classify(obs.hook_event, "blocked")
        seen: set[str] = set()
        for f in findings:
            if f.value in seen:
                continue
            seen.add(f.value)
            self.ledger.record(
                obs.session_id, turn_id=obs.turn_id, kind=kind,
                data_type=f.data_type, source=obs.source,
                destination=dest_kind, value_hash=None,
                masked_example=None, tool_name=None, protection="blocked",
                source_kind=None)
        summary = self.ledger.summary(obs.session_id)
        pct = getattr(summary, "legacy_percent", None)
        return self._decision(obs, findings, action="deny",
                              blocked_origin=None, read_block=None,
                              notice=None, pct=pct, degraded=False,
                              dest_kind=dest_kind, prompt_reason=reason)

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
            mid-scan gets the temporary post-end engine, whose findings are
            recorded with a NULL hash and no charge) gets exactly the
            result it would have gotten had the two phases run back to
            back.
        """
        if self._identity_cleared:
            # A cleared engine must not hash, remember or record anything
            # for its session again (#54 Phase 4). `dispatch` re-resolves
            # the session's engine under the lock, so it never gets here.
            raise RuntimeError("this engine's session identity was cleared")
        if scan is None:
            scan = self.scan(obs)
        dest_kind = scan.dest_kind
        findings = scan.findings
        degraded = scan.degraded

        # Write the gap down before the ruling, not after, and unconditionally.
        # Each observed scan gap is recorded per observation and counted per
        # session, including observations with no event row. That last case
        # is the reason this is recorded at all: a call whose cheap tiers
        # found nothing and which had a scan gap leaves no event row, and
        # would otherwise look exactly like a clean scan.
        # `Ledger.record_scan_gap` has the argument; the consequence is that
        # `coverage().verified` goes false, so the audit's banner and its
        # empty-state line both stop claiming a complete account (#47 item 6).
        # A version-2 observation carries its gap inside its one atomic
        # write instead (#54 Phase 4).
        if scan.degraded_reason is not None and obs.accounting is None:
            self.ledger.record_scan_gap(obs.session_id,
                                        boundary=scan.boundary,
                                        reason=scan.degraded_reason)

        is_egress = obs.direction == "egress"
        # The gate on the whole `policy_defaults` consultation below, and so
        # the only thing that decides whether a call can be hard-blocked at
        # all. `HARD_BLOCKED_DATA_TYPES` rather than a literal `"credential"`:
        # `mcp_tools.apply_policy` has to refuse exactly the `mask` rules that
        # would downgrade this deny, and a second literal there would be free
        # to drift away from this one. See that constant's comment.
        hard_blocked = any(f.data_type in HARD_BLOCKED_DATA_TYPES
                           for f in findings)

        network_block = scan.network_file_rules is not None
        action = "deny" if network_block else "allow"
        blocked_origin = None
        read_block: str | None = None
        notice: str | None = None

        # #36: the read guard -- the one interception point that acts BEFORE
        # the bytes exist, rather than recording them after. Ahead of the
        # egress-only policy block below on purpose: this is a local read
        # (`Ruling 3` never applies to it), and it must be decided before
        # anything downstream assumes `action` is still "allow".
        if obs.hook_event == "PreToolUse" and obs.direction == "local":
            path = obs.origin.value if obs.origin else ""
            if is_sensitive_path(path):
                if self.settings.deny_read:
                    action = "deny"
                    read_block = path
                elif not self._read_notice_shown:
                    self._read_notice_shown = True
                    notice = READ_NOTICE_TEMPLATE.format(path=path)

        # #40: remember where each of this observation's findings came from
        # (a no-op unless obs.origin is set and the call has already run —
        # PostToolUse ingress only; see `_remember_origins`), then
        # check whether an egress carries a value from a blocked origin
        # before any other policy. Per-value, not per-session: a deny here
        # always produces a finding (I3/I4's "prevented" classification), and
        # a finding with no taint entry allows rather than denies (I6). That
        # is not a promise that the ledger always gains a row explaining the
        # deny -- `Ledger.record`'s dedupe on (session_id, value_hash,
        # destination) only increments `count` on a repeat key, so a deny
        # whose value already has a row under a different `kind` (e.g. an
        # earlier, unguarded `local_access` read) leaves that row as it was.
        # See known-limits.md #17.
        self._remember_origins(obs, findings)

        # Task 8 policy-fix: a user-written `mask` rule outranks the
        # built-in default. Egress-only (Ruling 3's own logic extends
        # unchanged to user-written policy — by the time an ingress
        # observation reaches this accounting phase its bytes are treated as
        # already in context, so no policy check applies to it either; a
        # user prompt's credential hold is decided earlier, in dispatch's
        # preflight, #37). It rewrites only when there is something matching to
        # mask; otherwise this falls through, unchanged, to the
        # Matrix.default_action() logic below.
        #
        # `and not hard_blocked` is the whole of C1's fix, and it is load
        # bearing. This branch sets `action = "rewrite"`, and the hard block
        # below only runs while `action` is still `"allow"` — so without the
        # guard a mask rule REPLACES the plugin's one unconditional deny with
        # an executed, masked call, for the rest of the session, with no
        # removal path (known limit 13), while the ledger still records
        # `prevented` and the audit still reports that protection held.
        #
        # The guard is *here*, in the branch, and not only at the rule's mint
        # site, because the intersection below is over every finding on the
        # observation rather than over the finding that triggers the block.
        # A mask rule on any data type that merely CO-OCCURS with a
        # hard-blocked one — a path on the same command line — fired and
        # skipped the block for the whole call. Those selectors are
        # innocuous and `apply_policy` accepts them (one click of the audit
        # UI's "Mask detected <type> in future calls" on a path exposure writes one),
        # so no refusal keyed on the selector can reach that case. An earlier
        # fix wave asserted it could, on the false premise that `mask` +
        # `credential` was the only loosening combination; the comment that
        # said so is what let the defect survive the wave that looked for it.
        #
        # What the guard costs: with a hard-blocked finding present the
        # observation falls through to `Matrix.default_action(dest_kind)`
        # instead of rewriting here — `block` for `mcp_tool`/`external_net`
        # (the deny, which is the point) and `mask` for
        # `model_context`/`subagent`, which yields the same `"rewrite"` the
        # mask branch would have produced. So the user's rule is never
        # weaker than the default it yields to, and an observation carrying
        # no hard-blocked finding is decided exactly as before
        # (`test_a_mask_rule_still_rewrites_when_no_hard_blocked_type_is
        # _present`).
        #
        # `mcp_tools.apply_policy` still refuses a `mask` rule whose selector
        # is a hard-blocked type. That refusal is no longer what makes this
        # ordering safe — this branch is — and its remaining job is stated
        # there: such a rule is now silently inert, and writing an
        # unremovable rule that decides nothing while reporting success is
        # #38's defect.
        #
        # Every other rule a caller can write only tightens — `block_path`
        # and `block_command` are decided in the `if` above this `elif`, so a
        # mask rule can never undo a source rule either.
        #
        # `block_source` rows are deliberately not read (#38). That rule
        # compared its selector with `obs.source`, which dispatch only ever
        # fills with fixed labels ("tool input" on every egress call), so it
        # matched nothing or denied every outbound call. `apply_policy` no
        # longer writes one; a row an older ledger still holds decides nothing.
        if is_egress and not network_block:
            blocked_origin = self._blocked_origin(obs.session_id, findings)
            if blocked_origin is not None:
                action = "deny"
            elif findings and not hard_blocked:
                mask_selectors = self._policy_selectors(obs.session_id, "mask")
                if mask_selectors & {f.data_type for f in findings}:
                    action = "rewrite"

        if action == "allow" and is_egress and hard_blocked:
            # Ruling 3: default_action is an egress-only policy. An ingress
            # observation never reaches this branch, no matter what it
            # contains — in this phase its bytes are treated as already in
            # context (a PostToolUse result, or a prompt that passed #37's
            # hold preflight).
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

        if obs.accounting is not None:
            return self._observe_v2(
                obs, scan, action=action, blocked_origin=blocked_origin,
                read_block=read_block, notice=notice)

        if dest_kind == "local":
            # Ruling 1: local always classifies as local_access, overriding
            # whatever `direction` the caller supplied -- except for #36's
            # amendment: a local read the read guard above denied classifies
            # as `prevented`, through the same `PreToolUse/blocked` taxonomy
            # entry an egress deny uses, not as `local_access`. Without this
            # a blocked read and an ordinary one would write the same ledger
            # row, and the audit could never show that anything was stopped.
            classify_direction = "blocked" if action == "deny" else "local"
        elif action == "deny":
            classify_direction = "blocked"
        elif action == "rewrite":
            classify_direction = "rewritten"
        else:
            classify_direction = obs.direction

        kind = self.matrix.classify(obs.hook_event, classify_direction)
        protection = {"deny": "blocked", "rewrite": "masked"}.get(action)

        # Legacy markers identify a policy rule, never a file or its bytes.
        # The namespace prevents collision with prior detector values.
        for index in scan.network_file_rules or ():
            self.ledger.record(
                obs.session_id, turn_id=obs.turn_id, kind=kind,
                data_type="path", source="tool input",
                destination=dest_kind,
                value_hash=value_hash(
                    self.salt, "network-file-rule:" + PATH_RULES[index]),
                masked_example=None, tool_name=obs.tool_name,
                protection=protection, source_kind=None)

        for f in findings:
            if network_block and f.data_type == "path":
                continue
            self.ledger.record(
                obs.session_id, turn_id=obs.turn_id, kind=kind,
                data_type=f.data_type, source=obs.source,
                destination=dest_kind,
                value_hash=value_hash(self.salt, f.value),
                masked_example=mask(f.data_type, f.value),
                tool_name=obs.tool_name,
                protection=protection,
                source_kind=obs.origin.kind.value if obs.origin else None)

        # Display only; a decision never reads it.
        summary = self.ledger.summary(obs.session_id)
        pct = getattr(summary, "legacy_percent", None)
        return self._decision(
            obs, findings, action=action,
            blocked_origin=blocked_origin,
            read_block=read_block, notice=notice, pct=pct,
            degraded=degraded, dest_kind=dest_kind,
            network_block=network_block)

    def _decision(self, obs: Observation, findings: Sequence[Finding], *,
                  action: str, blocked_origin: Origin | None,
                  read_block: str | None, notice: str | None,
                  pct: int | None, degraded: bool, dest_kind: str,
                  network_block: bool = False,
                  updated_input: str | dict | None = None,
                  prompt_reason: str | None = None) -> Decision:
        """The hook decision for a ruled observation: the same templates and
        shapes for either accounting. `updated_input` is passed in when the
        caller has already constructed the rewrite (version 2 builds it
        before recording that a rewrite was issued). A prompt hold (#37)
        carries its own fixed reason and no `system_message`: a hold's
        output must be exactly decision and reason."""
        if action == "deny" and prompt_reason is not None:
            return Decision(action, reason=prompt_reason, budget_percent=pct,
                            degraded=degraded)
        if action == "deny" and network_block:
            return Decision(
                action, reason=NETWORK_FILE_BLOCK_TEMPLATE,
                system_message=NETWORK_FILE_BLOCK_TEMPLATE,
                budget_percent=pct, degraded=degraded)

        if action == "deny" and read_block is not None:
            # #36: the read guard's own template -- takes `tool`/`path`, not
            # the egress templates' `label`/`destination`/`origin_phrase`.
            msg = READ_BLOCK_TEMPLATE.format(tool=obs.tool_name or "tool",
                                              path=read_block)
            return Decision(action, reason=msg, system_message=msg,
                             budget_percent=pct, degraded=degraded)

        if action in ("deny", "rewrite"):
            label = ", ".join(sorted({f.data_type for f in findings})) or "sensitive data"
            if action == "deny":
                template = ORIGIN_BLOCK_TEMPLATE if blocked_origin else BLOCK_TEMPLATE
            else:
                template = REWRITE_TEMPLATE
            phrase = (origin_phrase(blocked_origin.value, blocked_origin.kind)
                      if blocked_origin else "")
            msg = template.format(
                tool=obs.tool_name or "tool", label=label,
                source=obs.source, destination=dest_kind,
                origin_phrase=phrase)
            if action == "rewrite" and updated_input is None:
                # Task 12: every "rewrite" Decision returned by this engine
                # must carry a real, non-None updated_input — see the
                # caveat on Decision.updated_input above. Reached from
                # three places: the policy-table "mask" branch above, the
                # policy_defaults "mask" branch below it, and the
                # "minimize" token-consumption branch further below; all
                # three leave `findings` non-empty (either a policy mask
                # rule matched an existing finding's data_type, or
                # `hard_blocked` was required to reach the other two), so
                # there is always something to rewrite.
                ti = obs.tool_input if obs.tool_input is not None else obs.text
                # fix-round-1: pass obs.text straight through as the exact
                # blob findings were scanned against, rather than letting
                # minimize_tool_input re-derive json.dumps(tool_input)
                # itself and hope it byte-matches. See minimize.py's
                # minimize_tool_input docstring for the full rationale.
                updated_input = minimize_tool_input(self.salt, obs.tool_name or "",
                                                     ti, findings, text=obs.text)
            if action != "rewrite":
                updated_input = None
            return Decision(action, reason=msg, system_message=msg,
                             budget_percent=pct, updated_input=updated_input,
                             degraded=degraded)

        return Decision("allow", system_message=notice, budget_percent=pct,
                         degraded=degraded)

    # -- #54 Phase 4: version-2 accounting --------------------------------

    def _observe_v2(self, obs: Observation, scan: ScanResult, *, action: str,
                    blocked_origin: Origin | None, read_block: str | None,
                    notice: str | None,
                    prompt_reason: str | None = None) -> Decision:
        """Record one version-2 observation and return the unchanged hook
        decision.

        Everything this delivery establishes -- the observation, one event
        per identified value or guarded file and supported kind, the
        identities, first disclosures, score increment and scan gap -- goes
        to the ledger in exactly one `record_observation` call. An issued
        rewrite is constructed before that call, so a rewrite that cannot
        be built leaves no record of having been issued.

        Evidence is what happened here and nothing more: the decision this
        engine issued (PreToolUse only), local detection where scanning
        found a value, the adapter's hook evidence, and pair receipts
        merged only into the event of the pair they name. Identities are
        hashed only with this engine's accounting key while the session is
        open and available; otherwise every subject and recipient is
        unresolved and no substitute key is used."""
        acc = obs.accounting
        assert acc is not None
        findings = scan.findings
        updated_input = None
        if action == "rewrite":
            ti = obs.tool_input if obs.tool_input is not None else obs.text
            updated_input = minimize_tool_input(
                self.salt, obs.tool_name or "", ti, findings, text=obs.text)

        # PreToolUse issues a permission decision; a prompt hold (#37) issues
        # a denial. Every other hook's decision is "none".
        decision: AccountingDecision = (
            action
            if (obs.hook_event == "PreToolUse"
                or (obs.hook_event == "UserPromptSubmit" and action == "deny"))
            else "none")  # type: ignore[assignment]
        issued = _ISSUED.get(decision, Evidence(0))

        session = self.ledger.conn.execute(
            "SELECT accounting_status, ended_at FROM sessions"
            " WHERE session_id=?", (obs.session_id,)).fetchone()
        key = self.accounting_key
        if (session is None or session["ended_at"] is not None
                or session["accounting_status"] != "available"):
            key = None
        profile = self.ledger.profile_for_session(obs.session_id)

        recipient = acc.recipient
        if key is None and recipient.identity_hash is not None:
            recipient = RecipientInput(
                destination_kind=recipient.destination_kind,
                identity_hash=None)

        guarded = (obs.hook_event == "PreToolUse" and obs.direction == "local"
                   and obs.origin is not None
                   and is_sensitive_path(obs.origin.value))
        # A guarded read's path findings are matches against the command's
        # own text -- the detector pattern, not a file. The file is the
        # guarded subject below.
        network_block = scan.network_file_rules is not None
        values = [
            f for f in findings
            if not ((guarded or network_block) and f.data_type == "path")
        ]
        value_findings = (coalesce_value_findings(profile, key, values)
                          if key is not None
                          else _unresolved_value_findings(profile, values))

        source = _source_label(obs, guarded)
        drafts: list[_Draft] = []
        for vf in value_findings:
            drafts.append(_Draft(
                subject=vf.subject, recipient=recipient,
                evidence=issued | Evidence.LOCAL_DETECTION,
                data_type=vf.data_type, rule_id=None,
                occurrences=vf.occurrences, source_label=source,
                masked_example=vf.masked_example))
        if guarded:
            assert obs.origin is not None
            drafts.append(_Draft(
                subject=_file_subject(key, obs.evaluated_path, obs.cwd),
                recipient=recipient, evidence=issued, data_type="path",
                rule_id=_path_rule_id(obs.origin.value), occurrences=1,
                source_label="local file", masked_example=None))

        # One unresolved reference group per matched rule, not per file.
        # Shell text supplies neither file identity nor execution evidence.
        for index in scan.network_file_rules or ():
            drafts.append(_Draft(
                subject=SubjectInput(
                    subject_kind="file", identity_hash=None),
                recipient=recipient, evidence=issued, data_type="path",
                rule_id=PATH_RULES[index], occurrences=1,
                source_label="tool input", masked_example=None))
        for receipt in acc.receipt_events:
            if key is None and (receipt.subject.identity_hash is not None
                                or receipt.recipient.identity_hash
                                is not None):
                continue
            matched = False
            for draft in drafts:
                if _same_pair(draft, receipt):
                    draft.evidence |= receipt.evidence
                    matched = True
            if not matched:
                drafts.append(_Draft(
                    subject=receipt.subject, recipient=receipt.recipient,
                    evidence=receipt.evidence, data_type=receipt.data_type,
                    rule_id=receipt.rule_id,
                    occurrences=receipt.occurrences,
                    source_label=receipt.source_label,
                    masked_example=receipt.masked_example))

        events: list[EventRecord] = []
        observed = acc.evidence | issued
        for draft in drafts:
            observed |= draft.evidence
            for kind in classify_evidence(boundary=acc.boundary,
                                          evidence=draft.evidence):
                events.append(EventRecord(
                    subject=draft.subject, recipient=draft.recipient,
                    kind=kind, evidence=draft.evidence,
                    data_type=draft.data_type,  # type: ignore[arg-type]
                    rule_id=draft.rule_id, occurrences=draft.occurrences,
                    source_label=draft.source_label, boundary=acc.boundary,
                    masked_example=draft.masked_example))

        # A resolution scope needs resolving evidence to act on. Receipts
        # dropped above (no key: their identities cannot be recorded) leave
        # nothing for it to resolve.
        scope = acc.resolution_scope
        if not observed & _RESOLVING:
            scope = "none"
        gap = scan.degraded_reason if acc.phase != "lifecycle" else None
        self.ledger.record_observation(ObservationRecord(
            session_id=obs.session_id, delivery_key=acc.delivery_key,
            action_id=acc.action_id, turn_id=acc.turn_id,
            ts=int(time.time()), hook_event=acc.hook_event, phase=acc.phase,
            action_kind=acc.action_kind, boundary=acc.boundary,
            decision=decision, evidence=observed,
            resolution_scope=scope,
            potential_crossing=acc.potential_crossing,
            scan_gap=gap),  # type: ignore[arg-type]
            events)

        # Display only; a decision never reads it.
        summary = self.ledger.summary(obs.session_id)
        pct = getattr(summary, "percent", None)
        return self._decision(
            obs, findings, action=action,
            blocked_origin=blocked_origin,
            read_block=read_block, notice=notice, pct=pct,
            degraded=scan.degraded, dest_kind=scan.dest_kind,
            network_block=network_block, updated_input=updated_input,
            prompt_reason=prompt_reason)


# --------------------------------------------------------------------- #
# version-2 helpers (#54 Phase 4)
# --------------------------------------------------------------------- #

#: The evidence a PreToolUse decision issues. Only PreToolUse returns a
#: permission decision, and a UserPromptSubmit hold (#37) a denial; every
#: other hook's decision is "none".
_ISSUED: dict[str, Evidence] = {
    "allow": Evidence.PERMISSION_ISSUED,
    "deny": Evidence.DENY_ISSUED,
    "rewrite": Evidence.PERMISSION_ISSUED | Evidence.REWRITE_ISSUED,
}

#: `detect.paths.PATTERNS`, in order, as the allowlisted rule IDs an event
#: may carry. `tests/test_accounting_dispatch.py` pins the two together.
PATH_RULES: tuple[str, ...] = (
    "path.env", "path.ssh_private_key", "path.key_container",
    "path.aws_credentials", "path.credentials_json", "path.ssh_config",
)

_SAFE_SUFFIXES: tuple[str, ...] = get_args(SafeSuffix)

#: Evidence that can resolve an action's outcome (the ledger requires one of
#: these before an observation may claim a resolution scope).
_RESOLVING = (Evidence.DENY_ENFORCED | Evidence.REWRITE_ENFORCED
              | Evidence.CROSSING_CONFIRMED
              | Evidence.REJECTED_BEFORE_CROSSING)


@dataclass
class _Draft:
    """One finding event before classification: its evidence can still
    gain the bits of a receipt naming its pair."""

    subject: SubjectInput
    recipient: RecipientInput
    evidence: Evidence
    data_type: str
    rule_id: str | None
    occurrences: int
    source_label: str
    masked_example: str | None


def _same_pair(draft: _Draft, receipt: EventRecord) -> bool:
    """Whether a receipt names this draft's pair: both identities resolved
    and equal. An unresolved identity matches nothing."""
    return (draft.subject.identity_hash is not None
            and draft.recipient.identity_hash is not None
            and draft.subject.subject_kind == receipt.subject.subject_kind
            and draft.subject.identity_hash == receipt.subject.identity_hash
            and draft.recipient.destination_kind
            == receipt.recipient.destination_kind
            and draft.recipient.identity_hash
            == receipt.recipient.identity_hash)


def _path_rule_id(path: str) -> str | None:
    for pattern, rule_id in zip(PATTERNS, PATH_RULES, strict=True):
        if pattern.search(path):
            return rule_id
    return None


def _file_subject(key: bytes | None, evaluated_path: str | None,
                  cwd: str) -> SubjectInput:
    """The guarded file's subject: its lexical identity when the guard
    evaluated one literal path and the key is available, else unresolved.
    The allowlisted suffix comes from the evaluated path only."""
    suffix = None
    if evaluated_path:
        ext = posixpath.splitext(posixpath.basename(evaluated_path))[1]
        if ext.lower() in _SAFE_SUFFIXES:
            suffix = ext.lower()
    identity = None
    if key is not None and evaluated_path:
        try:
            identity = file_identity(key, evaluated_path, cwd)
        except ValueError:
            identity = None
    return SubjectInput(subject_kind="file", identity_hash=identity,
                        safe_suffix=suffix)  # type: ignore[arg-type]


def _unresolved_value_findings(profile, findings: Sequence[Finding]
                               ) -> tuple[ValueFinding, ...]:
    """`coalesce_value_findings` without a key: one unresolved subject per
    exact value within this observation, grouped in memory only. No value
    is hashed."""
    groups: dict[str, tuple[set[str], set[tuple[int, int]]]] = {}
    for f in findings:
        if f.data_type not in profile.severity:
            raise ValueError("invalid accounting observation")
        types, spans = groups.setdefault(f.value, (set(), set()))
        types.add(f.data_type)
        spans.add((f.start, f.end))
    out = []
    for value, (types, spans) in groups.items():
        data_type = min(types, key=lambda t: (-profile.severity[t], t))
        out.append(ValueFinding(
            subject=SubjectInput(subject_kind="value", identity_hash=None),
            data_type=data_type,  # type: ignore[arg-type]
            occurrences=len(spans),
            masked_example=safe_masked_example(
                data_type, value)))  # type: ignore[arg-type]
    return tuple(out)


def _source_label(obs: Observation, guarded: bool) -> str:
    if obs.hook_event == "UserPromptSubmit":
        return "user prompt"
    if obs.hook_event == "PostToolUse":
        return "tool result"
    if obs.hook_event == "PreToolUse":
        return "local file" if guarded else "tool input"
    if obs.hook_event in ("SubagentStart", "SubagentStop"):
        return "main agent"
    return "lifecycle"
