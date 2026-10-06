# src/privacy_hud/policy_services.py
"""Shared policy validation, writes and confirmation conditions.

Transport-neutral: the daemon calls `apply_policy` under its own state lock,
and `runtime_client.update_policy` calls `validate_policy_rule` before it
transmits. Nothing here imports the daemon or a surface
(`tests/test_runtime_layers.py`). `mcp_tools` re-exports the public names.

**`apply_policy` and enforcement — read before wiring UI actions to this.**
`apply_policy` writes a row to the `policy` table (schema from ledger.py /
architecture.md §5) exactly as `Engine.observe` needs to read it to make
"Mask detected <type> in future calls" real. `Engine.observe`
(src/privacy_hud/engine.py) queries the `policy` table on every egress
observation, before falling back to `Matrix.default_action()` (the static
mask/block table in tables.toml): a user-written `mask` rule forces a
rewrite of a later outbound call carrying a finding of that data type.
This does not apply retroactively (design.md P4): data already disclosed
before the rule was written stays disclosed, and no caller of this module
should claim otherwise.

That ordering — policy first, matrix defaults second — has one exception,
and it is what lets every caller say "tighten-only" and mean it: the mask
branch is skipped entirely when the observation carries a finding of a
`HARD_BLOCKED_DATA_TYPES` type, so no rule this function writes can stand in
front of the plugin's one unconditional deny. The guard is in the engine
rather than in the rules this function accepts because the branch's
selector test looked at *every* finding on the observation: a mask rule on
any innocuous type that co-occurred with a credential used to skip the block
for the whole call, and no refusal keyed on a selector can reach that.
`_MASK_WOULD_DOWNGRADE` still refuses `mask` on a hard-blocked selector —
now because such a rule is inert, and as defence in depth. Read that
constant and `Engine.observe`'s mask branch together; neither is the whole
argument on its own.

"Block this source" (`block_source`) is withdrawn (#38): `apply_policy`
refuses it and `Engine.observe` ignores any such row an older ledger still
holds. It matched a rule's selector against the *outbound* observation's
`source` at enforcement time, which is always the fixed label `"tool
input"` -- never the file or command a value came from -- so no selector
could target a source at all. `block_path`/`block_command` (#40) are the
replacement: they match a rule's selector against the `Origin` a finding's
value was first seen with (Task 2/3's `source_kind`/`source` on the
*ingress* row), independent of what the later outbound call's own `source`
says.
"""
from __future__ import annotations

from .matrix.loader import HARD_BLOCKED_DATA_TYPES

_POLICY_RULE_TYPES = {"mask", "block_path", "block_command"}

#: Why `block_source` is refused rather than written (#38). The rule compared
#: its selector with an observation's `source`, and `dispatch` only ever puts
#: fixed labels there ("tool input" on every outbound call, the tool name or
#: "user prompt" on the way in). No selector could mean "this source": one
#: taken from a tool-output row matched nothing, one taken from an outbound
#: row denied every outbound call. That is still true today and is why the
#: type stays refused permanently, not just until origins existed: the type
#: itself names a label, not a source, regardless of what the ledger now
#: records. `block_path`/`block_command` (#40) are the real replacement --
#: matched against `Origin` values the ledger records since Task 2/3 --
#: rather than a repair of `block_source`, because reviving the name would
#: revive the confusion it caused the first time.
_BLOCK_SOURCE_WITHDRAWN = (
    "block_source is not available: it names a label, not a source, so no "
    "rule written that way could ever match an origin (#38) — use "
    "block_path or block_command, which name a real origin (#40)")

#: Why `allow_dest` is refused rather than written. It named a destination
#: to stop treating as sensitive, and nothing ever enforced it: `Engine.observe`
#: reads `mask` (its own matrix defaults behind it) and the two origin rule
#: types, and compares `rule_type` against nothing else. So a row went in, the
#: caller was told `{"applied": True}`, and every later call was decided
#: exactly as if the rule did not exist. `2026-09-03-decisions.md` recorded it
#: as a placeholder -- "untouched because nothing mints it yet" -- and wiring
#: the MCP server is what would have started minting it. Refused for #38's
#: reason, in #38's words: a policy row the engine can never match is worse
#: than an error, because it looks like protection was applied when nothing
#: was. An allow rule failing to apply is the safe direction; saying it
#: applied is not.
_ALLOW_DEST_WITHDRAWN = (
    "allow_dest is not available: no code path has ever enforced it, so a "
    "rule written that way decides nothing while reporting success (#38's "
    "reason) — there is no replacement, because nothing minted it")

#: Why a `mask` rule on a hard-blocked data type is refused: the rule cannot
#: do anything, and an unremovable rule that decides nothing is #38's defect.
#:
#: **This refusal is no longer what keeps the hard block safe.** It was, or
#: was believed to be: `Engine.observe` applied a user `mask` rule ahead of
#: its matrix defaults and the default deny only ran while the action was
#: still "allow", so a mask rule on a hard-blocked type replaced the deny
#: with an executed, masked call. The argument for closing that here was
#: that `mask` + a hard-blocked selector was the only combination that could
#: loosen anything, so refusing it at the mint site was provably complete.
#: **That argument was wrong.** The engine intersected its mask selectors
#: with *every* finding on the observation, not with the finding that
#: triggered the block, so a mask rule on any type that merely co-occurred
#: with a hard-blocked one — a path on the same command line, the selector
#: one click of the audit UI's mask action writes — skipped
#: the block for the whole call. Those selectors are innocuous and this
#: function accepts them, so no refusal keyed on a selector could ever have
#: covered that case.
#:
#: The precedence now lives where the decision is made: the mask branch in
#: `Engine.observe` does not run at all when the observation carries a
#: hard-blocked finding, whatever the rule's selector says. Read that branch's
#: comment for what it costs (the observation falls through to
#: `Matrix.default_action`, which is never weaker than the mask the rule
#: asked for).
#:
#: What this refusal still does, and why it stays: with the engine holding
#: the line, a `mask` rule on a hard-blocked type is *inert*. Writing it
#: would tell the caller protection was applied, record a rule no path
#: removes (known limit 13), and change no decision — which is exactly the
#: reason `block_source` and `allow_dest` are refused above. It is defence
#: in depth for the same reason: if the branch's guard is ever lost, this
#: keeps the rule that would exploit it from being written in the first
#: place. Refused here rather than in one caller because both callers need
#: it — the model-callable `privacy.update_policy` tool and the local audit
#: UI's button, which called this function and, on a credential exposure,
#: was *downgrading* the user's protection when clicked.
_MASK_WOULD_DOWNGRADE = (
    "mask is not available for {selector!r}: a value of that type on an "
    "outbound call is already denied, and that deny takes precedence over "
    "every mask rule, so this rule would decide nothing while reporting "
    "that protection was applied — and no path removes a rule once written "
    "(known limit 13). Nothing to do: the block is already the stronger "
    "outcome.")

#: The data types the always-on cheap tiers can produce, and therefore the
#: only ones a rule can match without an accepted deep-scan result: `path` from
#: `detect/paths.py` and `credential` from `detect/secrets.py`. Everything
#: else in `detect/model.py`'s LABEL_MAP — person, address, email, phone,
#: url, date, account — exists only in an accepted deep-scan result.
#:
#: This distinction is why `rule_enforcement_note` does not give every rule
#: the same caveat. Telling a user that a `path` rule might not fire because
#: of a scan gap would be its own false statement, in the opposite
#: direction: the path detector runs on every observation, at every
#: boundary, at any size.
CHEAP_DATA_TYPES = frozenset({"path", "credential"})

#: What a saved rule can and cannot promise, appended to every confirmation.
#:
#: Saving a rule is not enforcing it, and the gap between the two is not a
#: detail: a user who reads "enforced" and goes on to send the data has made
#: a decision this plugin then cannot honour and cannot reverse (I5). Each
#: clause below is a way a written rule leaves a value unchanged, and none
#: of them is visible to the person clicking the button.
#:
#: Three strings rather than one, because the caveat is not uniform and a
#: uniform one would be its own false statement. The first draft of this
#: had exactly that bug: it keyed only on `selector`, so a `block_path` rule
#: on `/home/u/.env` — whose selector is a file path, not a data type —
#: fell through to the deep-scan text and was told its matching "needs the
#: deep scan", while an origin that happened to be named `path` got the
#: cheap text. An origin rule matches on where a value came from, which is
#: a different question from which tier found it.
_RULE_CONDITIONS_DEEP = (
    " Matching {selector} requires an accepted deep-scan result. A scan gap "
    "means an applicable deep scan supplied no accepted result (known limit "
    "21); on that call this rule has no matching deep-scan finding. "
    "Detection can also miss values, and hosted tools never reach this "
    "plugin at all.")

_RULE_CONDITIONS_CHEAP = (
    " Detection is heuristic and can miss values, and hosted tools never "
    "reach this plugin at all — on a call where nothing is detected the "
    "rule matches nothing.")

_RULE_CONDITIONS_ORIGIN = (
    " The value must be detected on ingress and again on egress. When "
    "either detection depends on the deep scan, a scan gap can prevent this "
    "rule from matching (known limit 21). Detection is heuristic and can "
    "miss values, and hosted tools never reach this plugin at all.")


#: The common final sentence of every rule note. A denial or rewritten input
#: is what Privacy HUD returns to the host; no current hook reports whether
#: the host applied it (#54's evidence baseline).
_RULE_HOST_CAVEAT = (
    "Host application of a denial or rewritten input is not confirmed by "
    "these hooks.")


def rule_enforcement_note(rule_type: str, selector: str) -> str:
    """The conditions clause for one saved rule.

    `rule_type` decides the shape of the question and `selector` only
    refines it: an origin rule's selector is a path or a command, and
    asking whether *that* is a cheap data type is a category error.
    """
    if rule_type in ("block_path", "block_command"):
        conditions = _RULE_CONDITIONS_ORIGIN
    elif selector in CHEAP_DATA_TYPES:
        conditions = _RULE_CONDITIONS_CHEAP
    else:
        conditions = _RULE_CONDITIONS_DEEP.format(selector=selector)
    return conditions + " " + _RULE_HOST_CAVEAT



def apply_policy(ledger, session_id: str, *, rule_type: str, selector: str) -> None:
    """Save a policy rule scoped to this session. The mask action is
    "Mask detected <type> in future calls" (design.md §6).

    `rule_type` must be one of the schema's own documented values
    (ledger.py SCHEMA's `policy.rule_type` comment) -- an unrecognized
    rule_type raises `ValueError` rather than being written silently, since
    a policy row the engine can never match is worse than an error: it looks
    like protection was applied when nothing was. `block_source` is refused
    for exactly that reason (`_BLOCK_SOURCE_WITHDRAWN`, #38).

    A `mask` rule whose selector is a hard-blocked data type is refused too,
    for the same reason rather than the opposite one: since C1, the engine
    keeps its hard block ahead of every mask rule, so such a rule matches
    nothing it could change. What makes "this call can only tighten
    enforcement" true of every caller — the MCP tool the model can call and
    the local audit UI's button alike — is that precedence in
    `Engine.observe`, not this refusal; the refusal additionally stops a rule
    that would be silently inert, and stands as defence in depth if the
    precedence is ever lost. See `_MASK_WOULD_DOWNGRADE`.

    See this module's top-level docstring: `Engine.observe` consults `mask`
    rules (ahead of its own matrix defaults) on every later egress
    observation that has a finding of that data type. It does not apply
    retroactively: data already disclosed before the rule was written stays
    disclosed (design.md P4).
    """
    validate_policy_rule(rule_type=rule_type, selector=selector)
    ledger.add_policy(session_id, rule_type=rule_type, selector=selector)


def validate_policy_rule(*, rule_type: str, selector: str) -> None:
    """Refuse a rule no engine could ever match, without a ledger.

    Split out of `apply_policy` for #66 Pair 6: a policy mutation now
    travels to the daemon, and a rule that is wrong on its face must be
    refused *before* the request is transmitted. Otherwise the caller
    learns about it from a reply — and a reply that never arrives is an
    unknown outcome, which is a much worse thing to say about a request
    that was never valid.

    `apply_policy` still calls it, so the daemon validates again on its
    own side: the client's check is about honest reporting, not about
    being the only gate.
    """
    if rule_type == "block_source":
        raise ValueError(_BLOCK_SOURCE_WITHDRAWN)
    if rule_type == "allow_dest":
        raise ValueError(_ALLOW_DEST_WITHDRAWN)
    if rule_type == "mask" and selector in HARD_BLOCKED_DATA_TYPES:
        raise ValueError(_MASK_WOULD_DOWNGRADE.format(selector=selector))
    if rule_type not in _POLICY_RULE_TYPES:
        raise ValueError(
            f"unknown rule_type {rule_type!r}; expected one of "
            f"{sorted(_POLICY_RULE_TYPES)}")
