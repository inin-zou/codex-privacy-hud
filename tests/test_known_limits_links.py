# tests/test_known_limits_links.py
"""Both READMEs' limit lists agree with `docs/known-limits.md`.

The limits are load-bearing (CLAUDE.md section 5), and both READMEs summarise
them and link into the full text. Three things could drift silently, and all
three did:

- A link pointing at a heading that no longer exists. Renaming a limit's
  heading changes its GitHub anchor, and nothing here or in CI noticed. Two
  were dead in `README.zh-CN.md` and one in `README.md` while #49's copy
  work was in progress.
- A README summarising a limit the document does not have. The first draft
  of that work told readers to "see limits 19 and 20" before either existed
  — a dangling reference to a limit nobody had written.
- The documentation table naming a count. `README.md` said "All eighteen
  limits" after two more were added; `README.zh-CN.md` said the same until
  the translation pass caught it.

None of these is a defect in the plugin. Each is the README claiming
something the repository does not contain, which is the class of thing #49
exists to stop.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LIMITS = REPO / "docs" / "known-limits.md"
READMES = (REPO / "README.md", REPO / "README.zh-CN.md")

#: The count as each README's documentation table states it, in words.
WORD_COUNTS = {
    "eighteen": 18, "nineteen": 19, "twenty": 20, "twenty-one": 21,
    "十八": 18, "十九": 19, "二十": 20, "二十一": 21,
}


def _slug(heading: str) -> str:
    """GitHub's anchor for a Markdown heading.

    Punctuation is dropped and each remaining space becomes one hyphen — so
    an em dash surrounded by spaces leaves two. Collapsing runs of
    whitespace instead reports working links as broken, which is how the
    first version of this check produced two false positives.
    """
    s = re.sub(r"[^\w\s-]", "", heading.strip().lower())
    return s.replace(" ", "-")


def _limit_headings() -> list[str]:
    return re.findall(r"^## (\d+\..+)$", LIMITS.read_text(encoding="utf-8"), re.M)


def test_every_limit_is_numbered_in_order():
    numbers = [int(h.split(".", 1)[0]) for h in _limit_headings()]
    assert numbers == list(range(1, len(numbers) + 1)), numbers


@pytest.mark.parametrize("readme", READMES, ids=lambda p: p.name)
def test_every_link_into_known_limits_resolves(readme):
    anchors = {_slug(h) for h in _limit_headings()}
    text = readme.read_text(encoding="utf-8")
    links = re.findall(r"docs/known-limits\.md#([a-z0-9-]+)", text)
    assert links, f"{readme.name} links into known-limits.md nowhere"
    dead = sorted({link for link in links if link not in anchors})
    assert not dead, (
        f"{readme.name} links to headings that do not exist:\n  #"
        + "\n  #".join(dead))


@pytest.mark.parametrize("readme", READMES, ids=lambda p: p.name)
def test_the_readme_lists_exactly_the_limits_that_exist(readme):
    listed = re.findall(r"^(\d+)\. \*\*", readme.read_text(encoding="utf-8"), re.M)
    assert [int(n) for n in listed] == list(range(1, len(_limit_headings()) + 1)), (
        f"{readme.name} summarises {len(listed)} limits; "
        f"known-limits.md has {len(_limit_headings())}")


@pytest.mark.parametrize("readme", READMES, ids=lambda p: p.name)
def test_the_documentation_table_states_the_right_count(readme):
    """The one place the number is written out in words rather than derived."""
    row = next(line for line in readme.read_text(encoding="utf-8").splitlines()
               if "docs/known-limits.md`](docs/known-limits.md)" in line)
    stated = [n for word, n in WORD_COUNTS.items() if word in row]
    assert stated, f"{readme.name}: no count found in {row!r}"
    assert set(stated) == {len(_limit_headings())}, (
        f"{readme.name} says {stated} limits; there are {len(_limit_headings())}")
