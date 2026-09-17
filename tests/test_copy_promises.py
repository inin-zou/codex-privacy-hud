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
#: one, so `to` and friends are filtered by the documented-set check below
#: only when they look like subcommands -- see `_SUBCOMMANDS`.
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
