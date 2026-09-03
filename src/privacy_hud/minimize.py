"""Outbound payload minimization and single-use consent tokens.

Two independent pieces that together close the gap Task 8's reviewer
flagged: `Decision(action="rewrite")` used to always carry
`updated_input=None`. This module gives the engine something real to put
there.

1. **Span rewriting** (`minimize_text` / `minimize_tool_input`) replaces a
   sensitive span with its stable pseudonym (`mask.pseudonym`), never with a
   generic redaction marker — the same input value always maps to the same
   pseudonym within a session, so an agent's cross-references (e.g. "email
   X" mentioned twice) survive the rewrite.

2. **Single-use consent tokens** (`mint_token` / `consume_token`) implement
   architecture.md §8's token binding: a token authorizes exactly one call
   with exactly those arguments, for 120 seconds, once.

Global constraint: nothing here ever writes a raw sensitive value to disk,
logs, or stdout. `minimize_text`/`minimize_tool_input` operate purely on
values already resident in memory from detection (the `Finding.value`
strings passed in), and return rewritten text/structures — they persist
nothing. `mint_token`/`consume_token` persist only a hash of the canonical
JSON of `tool_input` (`args_hash`), never the tool_input itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import time

from .detect.base import Finding
from .mask import pseudonym

TOKEN_TTL_SECONDS = 120

# Tool names whose `updatedInput` Codex requires to be a plain string
# `command` — Bash and apply_patch, per architecture.md §8's "Rewrite path".
_STRING_COMMAND_TOOLS = {"Bash", "apply_patch"}


def canonical_json(obj) -> str:
    """Key-sorted, separator-tight JSON so semantically identical `tool_input`
    dicts (regardless of key order) hash identically."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _args_hash(tool_input) -> bytes:
    return hashlib.sha256(canonical_json(tool_input).encode()).digest()


# ---------------------------------------------------------------------------
# Span rewriting
# ---------------------------------------------------------------------------

def minimize_text(salt: bytes, text: str, findings: list[Finding]) -> str:
    """Replace each finding's span with its pseudonym.

    Findings are applied right-to-left by offset (`start` descending) so
    that replacing a later span never invalidates the offsets of an earlier
    one still waiting to be applied. Pseudonyms come from
    `mask.pseudonym(salt, data_type, value)`, which is deterministic per
    (salt, data_type, value) — so the same sensitive value appearing twice
    in `text` is replaced with the identical pseudonym both times.
    """
    out = text
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        # Trust but verify: three earlier tasks shipped offset bugs where
        # text[start:end] != value. A mismatched span here would silently
        # rewrite the wrong slice of outbound text — fail loud instead.
        if out[f.start:f.end] != f.value:
            raise ValueError(
                f"Finding offset mismatch: text[{f.start}:{f.end}]="
                f"{out[f.start:f.end]!r} != finding.value={f.value!r}")
        replacement = pseudonym(salt, f.data_type, f.value)
        out = out[:f.start] + replacement + out[f.end:]
    return out


def _matching_findings(value: str, findings: list[Finding]) -> list[Finding]:
    """Findings whose recorded span is valid *within this particular string*.

    A dict-shaped tool_input can have several string fields; a flat list of
    `Finding`s (offsets relative to whatever single text was scanned) is
    only meaningful against the one field it was computed from. A finding
    is attributed to a field when its span both fits inside the field's
    length and slices out exactly `finding.value` — the same invariant
    `minimize_text` enforces, used here to route each finding to its field.
    """
    return [f for f in findings
            if 0 <= f.start <= f.end <= len(value) and value[f.start:f.end] == f.value]


def minimize_tool_input(salt: bytes, tool_name: str, tool_input, findings: list[Finding], *,
                         text: str | None = None):
    """Rewrite a tool call's arguments for outbound delivery.

    Returns a **string** for `Bash`/`apply_patch` (Codex requires a string
    `command` in `updatedInput` for these tools) and a **dict** for every
    other (MCP) tool name. Getting the return type wrong here is not just a
    test failure: Task 9's hook client forwards whatever this returns as
    `updatedInput` verbatim to Codex.

    `text`, when supplied, is the exact string the caller already scanned
    to produce `findings` — pass it whenever you have it (the engine
    always does: it's `Observation.text`). This is the fix-round-1 design
    decision (documented in task-12-report.md): rather than trusting a
    second, independent `json.dumps(tool_input)` call here to happen to
    byte-match whatever produced `text` upstream, the caller's own text is
    threaded straight through. `text` is used only for the MCP/dict
    branch below; a caller that doesn't have it (e.g. a standalone test)
    may omit it, and this function derives `json.dumps(tool_input)` (the
    same default-argument call Task 10's documented contract for a
    PreToolUse MCP event uses) as a fallback — correct only insofar as
    that fallback call matches what actually produced `findings`.

    MCP/dict findings are offsets into the *whole serialized tool_input*,
    not into any individual field's own string. fix-round-1 found that
    re-mapping those blob-relative offsets onto individual dict field
    values (matching each finding to whichever field's slice happened to
    equal `finding.value`) silently failed to attribute real findings
    whenever a span crossed a JSON structural character or the
    field-splitting didn't line up with the blob — so the credential and
    email shipped completely unredacted while the engine still reported
    `action="rewrite"`. The fix: never split. Minimize the JSON blob
    itself with the exact same right-to-left `minimize_text` primitive
    already proven correct for the Bash/string case, then parse the
    result back into a dict. This eliminates the field-attribution
    problem instead of working around it.
    """
    is_string_tool = tool_name in _STRING_COMMAND_TOOLS

    if isinstance(tool_input, str):
        # Already a bare string (no structured tool_input was available to
        # the caller — see Engine.observe's obs.text fallback). Findings
        # here may come from a detector fixture/text pairing the caller
        # doesn't fully control (e.g. a stub detector in a test double
        # returning a canned span for arbitrary input); silently dropping
        # a non-validating finding is the deliberately lenient case,
        # confined to this one fallback path.
        rewritten = minimize_text(salt, tool_input, _matching_findings(tool_input, findings))
        return rewritten if is_string_tool else {"text": rewritten}

    if is_string_tool:
        # Bash / apply_patch: architecture.md §8's Bash rewrite example
        # scans the command's own text directly, not a JSON-serialized
        # blob of the whole tool_input — so findings are relative to the
        # "command" field's own string, and minimize_text is used
        # directly and strictly (raises on a genuine mismatch, same as
        # the MCP blob path below).
        command = tool_input.get("command")
        if isinstance(command, str):
            return minimize_text(salt, command, findings)
        # No "command" field to anchor to (shouldn't happen for real
        # Bash/apply_patch payloads, but never return None here — an
        # unpopulated updated_input on a rewrite decision must never be
        # forwarded to Codex as safe): fall back to a minimized canonical
        # rendering, tolerant of non-validating findings since this
        # rendering's offset domain isn't the one findings were computed
        # against.
        blob = canonical_json(tool_input)
        return minimize_text(salt, blob, _matching_findings(blob, findings))

    # MCP tools: minimize the exact serialized blob findings were scanned
    # against — never distribute offsets across fields. `minimize_text`
    # is used strictly here (no _matching_findings tolerance): once text
    # and findings are genuinely in the same offset domain, a mismatch
    # means a real bug (wrong `text` passed, or a detector reporting bad
    # offsets against real input) worth surfacing loudly, not swallowing.
    blob = text if text is not None else json.dumps(tool_input)
    rewritten_blob = minimize_text(salt, blob, findings)
    return json.loads(rewritten_blob)


# ---------------------------------------------------------------------------
# Single-use consent tokens (architecture.md §8)
# ---------------------------------------------------------------------------

def mint_token(ledger, session_id: str, tool_name: str, tool_input, mode: str) -> str:
    """Write a one-shot consent token row into `policy_tokens`.

    `args_hash = sha256(canonical_json(tool_input))` binds the token to
    exactly these arguments — see `consume_token`. TTL is
    `TOKEN_TTL_SECONDS` (120s) from mint time.
    """
    token = os.urandom(16).hex()
    ledger.conn.execute(
        "INSERT INTO policy_tokens(token,session_id,tool_name,args_hash,mode,"
        "expires_at,consumed) VALUES(?,?,?,?,?,?,0)",
        (token, session_id, tool_name, _args_hash(tool_input), mode,
         int(time.time()) + TOKEN_TTL_SECONDS))
    return token


def consume_token(ledger, session_id: str, tool_name: str, tool_input) -> str | None:
    """Look up an unexpired, unconsumed token minted for this exact
    (session, tool_name, args_hash), consume it, and return its `mode`.

    Returns None when no such token exists — including when `tool_input`
    hashes differently than what was minted (a token never authorizes a
    call with different arguments than it was minted for), when the token
    is expired, or when it was already consumed. Consumption is a delete:
    a second call with identical arguments finds nothing and returns None.
    """
    args_hash = _args_hash(tool_input)
    row = ledger.conn.execute(
        "SELECT token, mode FROM policy_tokens WHERE session_id=? AND tool_name=?"
        " AND args_hash=? AND consumed=0 AND expires_at>?",
        (session_id, tool_name, args_hash, int(time.time()))).fetchone()
    if row is None:
        return None
    ledger.conn.execute("DELETE FROM policy_tokens WHERE token=?", (row["token"],))
    return row["mode"]
