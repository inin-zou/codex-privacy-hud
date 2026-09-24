# tests/test_copy_promises.py
"""Copy that tells a user to run something must name something that exists.

The block message shipped for six weeks ending `Run $privacy to review,
minimize, or allow once.` `$privacy` has never had either. It was in the
2026-09-03 plan verbatim, so every task review compared the code against a
brief that already contained the defect.

This catches the mechanical half: a `$privacy <subcommand>` that
`skills/privacy/SKILL.md` does not document. It cannot catch the half that
bit us -- "minimize" was a verb in a sentence, not a subcommand, and no
pattern reads what a sentence promises. `.claude/CLAUDE.md` §5 carries that
half as a review rule.
"""
from __future__ import annotations

import re
from pathlib import Path

from privacy_hud import engine

REPO = Path(__file__).resolve().parent.parent
SKILL = REPO / "skills" / "privacy" / "SKILL.md"

#: `$privacy` followed by a word, in or out of backticks. The bare form
#: (`Run $privacy to review.`) names no subcommand and is not a claim about
#: one, so `to` and friends are filtered out before the documented-set check
#: below -- see `_PROSE`.
_MENTION = re.compile(r"\$privacy\s+([a-z][a-z-]*)")

#: Prose connectives that follow a bare `$privacy`, not subcommands.
_PROSE = {"to", "and", "or", "in", "for", "again", "itself", "prints"}


def _documented_subcommands() -> set[str]:
    """The first word of every `### `$privacy <...>`` heading in SKILL.md."""
    found = set()
    for line in SKILL.read_text(encoding="utf-8").splitlines():
        match = re.match(r"###\s+`\$privacy\s+([a-z][a-z-]*)", line)
        if match:
            found.add(match.group(1))
    return found


def _templates() -> dict[str, str]:
    return {name: value for name, value in vars(engine).items()
            if name.endswith("_TEMPLATE") and isinstance(value, str)}


def test_every_privacy_subcommand_named_in_copy_exists():
    documented = _documented_subcommands()
    assert documented, "SKILL.md no longer declares subcommands the way this parses"
    offenders = []
    for name, text in _templates().items():
        for word in _MENTION.findall(text):
            if word in _PROSE or word in documented:
                continue
            offenders.append(f"{name}: `$privacy {word}`")
    assert not offenders, (
        "user-facing copy names a $privacy subcommand SKILL.md does not "
        "document:\n  " + "\n  ".join(offenders))


def test_the_block_templates_promise_no_action_without_a_surface():
    """The two words that shipped false. `minimize` has no surface at all;
    `allow once` has `mcp_tools.allow_once`, deliberately exposed nowhere
    (see the design doc) -- and it could not work through MCP even if it
    were, because the consent call would carry the credential that caused
    the block and be blocked itself."""
    for name in ("BLOCK_TEMPLATE", "ORIGIN_BLOCK_TEMPLATE"):
        text = _templates()[name]
        assert "minimize" not in text, f"{name} still offers minimize"
        assert "allow once" not in text, f"{name} still names allow once"


#: The sections that describe the consent workflow (#47 item 12), each with
#: the heading that names it. The workflow is withdrawn; these sections
#: exist to say so.
_CONSENT_SECTIONS = {
    ".claude/docs/design.md":
        "## 8. Consent flow — historical proposal, not shipped",
    ".claude/docs/PRD.md":
        "### 7.6 Consent flow — historical proposal, not shipped",
    ".claude/docs/architecture.md":
        "## 8. Enforcement and the unshipped consent workflow",
}

#: The consent actions a user cannot take on any shipped surface.
_CONSENT_ACTIONS = ("`Allow once`", "`Minimize & retry`")

#: A sentence naming a consent action must also deny that it ships.
_DENIAL = re.compile(r"\b(Neither|No|not)\b")


def _section_text(rel: str, heading: str) -> str:
    lines = (REPO / rel).read_text(encoding="utf-8").split("\n")
    found = [i for i, line in enumerate(lines) if line == heading]
    assert len(found) == 1, f"{rel}: expected one {heading!r}"
    level = len(heading) - len(heading.lstrip("#"))
    body = []
    for line in lines[found[0] + 1:]:
        match = re.match(r"(#+) ", line)
        if line.strip() == "---" or (match and len(match.group(1)) <= level):
            break
        body.append(line)
    return "\n".join(body)


def test_documented_consent_actions_are_explicitly_unavailable():
    """#47 item 12: `mcp_tools.allow_once` existing was mistaken for the
    action being available (CLAUDE.md §5). Every current description of the
    consent workflow names it as unshipped, and every sentence that names a
    consent action says no shipped surface offers it."""
    for rel, heading in _CONSENT_SECTIONS.items():
        assert "not shipped" in heading or "unshipped" in heading, rel
        text = _section_text(rel, heading)
        assert "not shipped" in text or "not available in the shipped product" in text, rel
        assert "No shipped user-facing surface" in text or (
            "no shipped user-facing surface" in text), rel
        named = 0
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            if any(action in sentence for action in _CONSENT_ACTIONS):
                named += 1
                assert _DENIAL.search(sentence), (
                    f"{rel}: names a consent action without denying it "
                    f"ships: {sentence!r}")
        assert named, f"{rel}: the section no longer names what is unavailable"

    # The denial templates still point only at the ledger review.
    for name in ("BLOCK_TEMPLATE", "ORIGIN_BLOCK_TEMPLATE"):
        text = _templates()[name]
        assert text.rstrip().endswith("Run $privacy to review the ledger."), name
        for word in ("minimize", "allow once", "retry", "consent"):
            assert word not in text.lower(), f"{name} offers {word}"
