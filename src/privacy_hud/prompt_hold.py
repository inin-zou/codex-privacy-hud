"""#37: hold a user prompt that contains a well-formed credential, and let
the user confirm it by submitting it again.

This module owns three things and nothing else: the reviewed copy, the
allowlist of credential-format labels that copy may name, and the
per-session confirmation state machine. It touches no filesystem, ledger,
environment, model or network.

**Memory only (I1).** `PromptGate` keeps salted, domain-separated HMACs of
the credentials it has seen, their hold timestamps, the hashes the user has
confirmed and the verdict each delivery received. It never keeps a value,
a prefix or a prompt. Nothing here is persisted, so a replacement daemon
starts empty and holds again: losing this state fails safe.

**The confirmation hash is not `mask.value_hash`.** That one lowercases
before hashing so legacy dedupe folds case variants together; a
confirmation must not, because two credentials that differ only in case are
two credentials. The input is the exact UTF-8 value, with no case folding
or whitespace normalization.

**Timing.** A hold starts a window. A later submission of the same
credential confirms it once at least `MIN_GAP` seconds have passed since
the hold (measured against when that submission arrived, so a queued
accidental double Enter cannot confirm) and no more than `WINDOW` seconds
(measured against the gate's clock). Both boundaries are inclusive. An
early repeat stays held and does not restart the window. Every credential
in a submission that is not already confirmed must be pending and eligible
before any of them is confirmed; a new or expired one holds the whole
submission and restarts the window for all of its unconfirmed credentials.
A confirmed credential is never held again by this gate.
"""
from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

#: Seconds that must pass between a hold and the submission confirming it.
MIN_GAP = 2.0
#: Seconds after a hold within which a resubmission can confirm it.
WINDOW = 300.0

_DOMAIN = b"privacy-hud/prompt-confirmation/v1\0"

#: The labels the copy may name. `detect.secrets.KEY_PATTERN_LABELS`'
#: hold-eligible entries; anything else -- a value, a detector's arbitrary
#: label, model text -- is refused by the renderers below.
ALLOWED_LABELS: frozenset[str] = frozenset({
    "API key format",
    "AWS access key ID format",
    "GitHub token format",
    "JSON Web Token format",
    "Database connection string with password",
})

# Reviewed, fixed English copy. Never model-written, never carrying a value.
# It states the decision Privacy HUD issued, not what the host did with it:
# another hook, a lost reply or a host failure can each change the outcome.
# "paste or type the message again" because the inspected Codex TUI clears
# the composer on submit and does not restore it after a hook hold.
HELD_TEMPLATE = (
    "PRIVACY HUD requested a hold for this message\n\n"
    "  Credential format detected: {kinds}.\n"
    "  This hold requests that Codex keep this submission out of model context.\n"
    "  Host enforcement is not confirmed.\n\n"
    "  To allow it, wait at least 2 seconds, then paste or type the message again\n"
    "  and submit it within 5 minutes. Editing the surrounding text is allowed.\n"
    "  Every new credential requires a hold before confirmation.\n"
    "  Confirmed credentials are allowed for this session while this daemon runs.\n\n"
    "  Only supported well-formed credential formats in prompt text can trigger a hold.\n"
    "  Images and attachments are not scanned."
)

CONFIRMED_TEMPLATE = (
    "PRIVACY HUD: allowed this submission with credentials you confirmed "
    "({kinds}).\n"
    "Admission to model context is not confirmed.\n"
    "Already disclosed data cannot be recalled from this session."
)


def _kinds(labels: Iterable[str]) -> str:
    unique = sorted(set(labels))
    if not unique or any(label not in ALLOWED_LABELS for label in unique):
        raise ValueError("not an allowlisted credential format label")
    return "; ".join(unique)


def held_reason(labels: Iterable[str]) -> str:
    """The hold's `reason`: fixed copy naming only allowlisted formats."""
    return HELD_TEMPLATE.format(kinds=_kinds(labels))


def confirmed_message(labels: Iterable[str]) -> str:
    """The `systemMessage` for a submission that newly confirmed
    credentials."""
    return CONFIRMED_TEMPLATE.format(kinds=_kinds(labels))


def credential_hash(salt: bytes, value: str) -> bytes:
    """Exact-value, salted, domain-separated confirmation hash."""
    return hmac.new(salt, _DOMAIN + value.encode("utf-8"),
                    hashlib.sha256).digest()


@dataclass(frozen=True)
class Verdict:
    """`hold`: return a block. `confirmed`: the sorted labels this
    submission newly confirmed (empty when nothing new was confirmed)."""

    hold: bool
    confirmed: tuple[str, ...] = ()


class PromptGate:
    """One session's confirmation state, in daemon memory only."""

    def __init__(self, *, salt: bytes, clock: Callable[[], float]):
        self._salt = salt
        self._clock = clock
        #: credential hash -> when its current hold started (clock time).
        self.pending: dict[bytes, float] = {}
        #: credential hashes the user confirmed this session.
        self.allowed: set[bytes] = set()
        #: delivery key -> the verdict that delivery received.
        self.deliveries: dict[str, Verdict] = {}
        #: Unrecorded confirmations, reserved by delivery; never reusable.
        self._confirmations: dict[str, frozenset[bytes]] = {}

    def decide(self, values: Mapping[str, str], *, delivery_key: str,
               submitted_at: float, defer_confirmation: bool = False) -> Verdict:
        """Rule on one submission. `values` maps each eligible credential
        found in it to its fixed label; it is hashed at once and not kept.
        `submitted_at` is when the submission arrived, on the gate's clock,
        captured before any lock wait.

        With defer_confirmation, consume the eligible pending hashes but
        reserve them for this delivery instead of adding them to allowed.
        The caller must finish_confirmation under the same external lock
        after recording succeeds or fails. Other deliveries cannot borrow
        this unrecorded authorization."""
        previous = self.deliveries.get(delivery_key)
        if previous is not None:
            return previous
        labels = {credential_hash(self._salt, value): label
                  for value, label in values.items()}
        now = self._clock()
        for key in [k for k, at in self.pending.items() if now > at + WINDOW]:
            del self.pending[key]

        unapproved = set(labels) - self.allowed
        if not unapproved:
            verdict = Verdict(hold=False)
        elif any(key not in self.pending for key in unapproved):
            for key in unapproved:
                self.pending[key] = now
            verdict = Verdict(hold=True)
        elif any(submitted_at < self.pending[key] + MIN_GAP
                 for key in unapproved):
            verdict = Verdict(hold=True)
        else:
            for key in unapproved:
                del self.pending[key]
            if defer_confirmation:
                self._confirmations[delivery_key] = frozenset(unapproved)
            else:
                self.allowed |= unapproved
            verdict = Verdict(hold=False, confirmed=tuple(
                sorted({labels[key] for key in unapproved})))
        self.deliveries[delivery_key] = verdict
        return verdict

    def finish_confirmation(self, delivery_key: str, verdict: Verdict, *,
                            recorded: bool) -> tuple[str, ...]:
        """Finish only this delivery's provisional confirmation.

        Caller holds the external state lock. Success makes the reserved
        hashes reusable; failure forgets the reservation and replay verdict
        without restoring consumed pending windows or touching other
        deliveries. A concurrent hold therefore survives failure. Verdict
        identity rejects stale completions after an abort, replacement or
        clear. Once a duplicate has recorded successfully, another
        duplicate's failure cannot revoke that authorization.

        Return notice labels only for a successfully recorded, still-live
        confirmation. No values or hashes leave the gate.
        """
        if self.deliveries.get(delivery_key) is not verdict:
            return ()
        keys = self._confirmations.pop(delivery_key, None)
        if keys is not None:
            if not recorded:
                del self.deliveries[delivery_key]
                return ()
            self.allowed.update(keys)
            for key in keys:
                self.pending.pop(key, None)
        return verdict.confirmed if recorded else ()

    def snapshot(self) -> tuple[dict[bytes, float], set[bytes],
                                dict[str, Verdict]]:
        """Snapshot the collections a held decision can change.

        Take, decide, record and restore within one external lock hold.
        Held decisions do not change provisional confirmations. Never use
        this snapshot to roll back across an unlocked scan.
        """
        return dict(self.pending), set(self.allowed), dict(self.deliveries)

    def restore(self, saved: tuple[dict[bytes, float], set[bytes],
                                   dict[str, Verdict]]) -> None:
        pending, allowed, deliveries = saved
        self.pending = dict(pending)
        self.allowed = set(allowed)
        self.deliveries = dict(deliveries)

    def clear(self) -> None:
        """Discard every hash, timestamp and verdict, and the salt
        reference (session end). Drops references; does not promise that
        Python memory is wiped."""
        self.pending.clear()
        self.allowed.clear()
        self.deliveries.clear()
        self._confirmations.clear()
        self._salt = b""
