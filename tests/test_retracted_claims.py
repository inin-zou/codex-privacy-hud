"""Retracted policy claims stay retracted (#49 item 2).

A saved rule is saved, with conditional enforcement: whether it changes a
later call depends on detection (`mcp_tools.rule_enforcement_note`). Several
sentences said otherwise and were withdrawn, and some came back, or were
never removed everywhere, because nothing checked a sentence -- only links
and counts were checked (`tests/test_known_limits_links.py`).

This scans every tracked text file for the withdrawn forms. It normalises
case, whitespace, Markdown emphasis, comment prefixes on wrapped lines and
identifier underscores, and it also reads decoded Python string constants,
so line wrapping or adjacent string literals cannot hide a phrase.

A historical quotation is allowed only by an exact passage in `ALLOWED`:
the passage must occur exactly once in its file, must contain the claim it
excuses, and carries a written justification. There are no whole-file or
line-number exemptions, and no guessing from words like "used to". A second
copy of an allowed passage is reported like any other occurrence.

This pins known retracted claims. It cannot recognise a new synonym for
one; review still has to.

Run as a script, `--active-text` prints the normalised text of every
scanned file with the validated allowed passages removed, so the zero-hit
greps can run against it. It exits non-zero if any allowance is invalid.
"""
from __future__ import annotations

import ast
import asyncio
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from runtime_helpers import writer_ledger

REPO = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()

# Declarations below are data, not claims; the scan skips their AST spans in
# this file only (`_without_self_declarations`).
RETRACTED = [
    "Protect future occurrences",
    "Protection applied",
    "protection was applied",
    "now enforced, not merely recorded",
    "Applies from the next tool call",
    "genuinely enforced on the next matching call",
    "enforces any of these starting with the next matching call",
    "a rule only changes what happens on the next call",
    "the engine honours them on the next call",
    "this value does not leave unchanged",
    "Could not apply rule",
    "规则保证的是“这个值不会原样传出”",
    "applied: true",
    '"applied": True',
    "test_block_this_source_writes_an_enforceable_rule",
]

LEGACY_NOTICE = (
    "\n"
    "> Historical implementation snapshot. The policy labels, confirmations,\n"
    "> enforcement wording and response examples below predate #49 item 2.\n"
    "> They are retained as history, not current implementation instructions.\n"
    "> Current behavior reports a saved rule with conditional enforcement;\n"
    "> `mcp_tools.rule_enforcement_note` supplies its conditions."
)


@dataclass(frozen=True)
class Allowed:
    path: str
    passage: str
    claim: str
    why: str
    legacy: bool = False


ALLOWED: list[Allowed] = [
    Allowed('.claude/docs/design.md',
            "- `Save mask rule for detected <type>` — the browser POSTs a `mask` rule to `/api/policy`. The rule selects a data type, not a source. The former label `Protect future occurrences` claimed an outcome that saving a rule cannot guarantee. Matching requires detection; types other than `path` and `credential` require an accepted deep-scan result. Host application is not confirmed.",
            'Protect future occurrences',
            'Explicit historical-label correction; current browser action saves a conditional rule.'),
    Allowed('.claude/docs/plans/2026-09-03-decisions.md',
            'Two of the three L3 actions — "Block this source" and "Protect future occurrences" — wrote',
            'Protect future occurrences',
            'Decision record: the buttons previously wrote rows nothing read.'),
    Allowed('.claude/docs/plans/2026-09-03-implementation.md',
            'def test_block_this_source_writes_an_enforceable_rule(led):',
            'test_block_this_source_writes_an_enforceable_rule',
            'Historical implementation snapshot, marked superseded by the legacy notice.', legacy=True),
    Allowed('.claude/docs/plans/2026-09-03-implementation.md',
            'def test_protect_future_occurrences_writes_a_mask_rule(led):',
            'Protect future occurrences',
            'Historical implementation snapshot, marked superseded by the legacy notice.', legacy=True),
    Allowed('.claude/docs/plans/2026-09-03-implementation.md',
            '`src/privacy_hud/mcp_tools.py` holds the pure functions the tests import; `mcp/server.py` is the stdio MCP wrapper around them. The UI is static HTML + vanilla JS served by the daemon on `127.0.0.1` at an ephemeral port, using the `design.md` §3 tokens, the three tabs, and keyboard row navigation. `apply_policy(ledger, session_id, *, rule_type, selector)` writes to the `policy` table from `architecture.md` §5, and `Engine.observe` consults it before its own default rules — a `block_source` rule denies any egress whose `source` matches, and a `mask` rule forces `rewrite` on egress carrying that data type. The L3 actions in `design.md` §6 are only real if the engine honours them on the next call; the test above is that gate.',
            'the engine honours them on the next call',
            'Historical implementation snapshot, marked superseded by the legacy notice.', legacy=True),
    Allowed('docs/superpowers/plans/2026-09-16-origin-tracking.md',
            '`[ Block values read from .env ]` after `[ Protect future occurrences ]`.',
            'Protect future occurrences',
            'Historical implementation snapshot, marked superseded by the legacy notice.', legacy=True),
    Allowed('docs/superpowers/plans/2026-09-16-origin-tracking.md',
            '`render.detail()`, after the `Protect future occurrences` line:',
            'Protect future occurrences',
            'Historical implementation snapshot, marked superseded by the legacy notice.', legacy=True),
    Allowed('docs/superpowers/plans/2026-09-16-origin-tracking.md',
            '    lines = ["", "[ Protect future occurrences ]"]',
            'Protect future occurrences',
            'Historical implementation snapshot, marked superseded by the legacy notice.', legacy=True),
    Allowed('docs/superpowers/plans/2026-09-16-origin-tracking.md',
            '      { text: "Protect future occurrences", rule_type: "mask", selector: row.data_type },',
            'Protect future occurrences',
            'Historical implementation snapshot, marked superseded by the legacy notice.', legacy=True),
    Allowed('docs/superpowers/plans/2026-09-16-origin-tracking.md',
            '            "Applies from the next tool call.")',
            'Applies from the next tool call',
            'Historical implementation snapshot, marked superseded by the legacy notice.', legacy=True),
    Allowed('docs/superpowers/plans/2026-09-16-origin-tracking.md',
            '1. **A source rule matches only byte-identical values.** A model that summarizes, rewrites, or quotes part of what it read defeats it, and that is a likely path rather than an exotic one. The rule\'s promise is "this value does not leave unchanged", not "nothing about this file leaves".',
            'this value does not leave unchanged',
            'Historical draft known-limits entry, superseded by the legacy notice; retained as a record, not current matching semantics or an enforcement promise.', legacy=True),
    Allowed('docs/superpowers/plans/2026-09-16-origin-tracking.md',
            '**Level 3 — Exposure detail.** One flow, its masked evidence, and forward-looking remedies (`Protect future occurrences`; on a row that names a real origin, `Block values read from <file>`). Never an undo — already disclosed data cannot be recalled, and a source rule only matches values that leave unchanged.',
            'Protect future occurrences',
            'Historical implementation snapshot, marked superseded by the legacy notice.', legacy=True),
    Allowed('docs/superpowers/plans/2026-09-17-mcp-server.md',
            '    row decided nothing while `{"applied": True}` said otherwise. That is',
            '"applied": True',
            'Embedded historical regression explanation (past allow_dest false success).'),
    Allowed('docs/superpowers/plans/2026-09-17-mcp-server.md',
            '#: caller was told `{"applied": True}`, and every later call was decided',
            '"applied": True',
            'Embedded historical regression explanation (past allow_dest false success).'),
    Allowed('docs/superpowers/plans/2026-09-17-mcp-server.md',
            '#: than an error, because it looks like protection was applied when nothing',
            'protection was applied',
            'Embedded historical regression explanation (past allow_dest false success).'),
    Allowed('docs/superpowers/specs/2026-09-17-mcp-server-design.md',
            '3. **`allow_dest`.** `apply_policy` accepts it, writes a row, and the server returns `{"applied": True}`. The engine never reads it: it compares `rule_type` against exactly `mask`, `block_path` and `block_command`. `apply_policy`\'s own docstring calls a rule the engine cannot match worse than an error. `2026-09-03-decisions.md:280` records it as a placeholder ("untouched because nothing mints it yet"). It is latent today only because the server is not wired.',
            '"applied": True',
            'Historical design spec, marked superseded by the legacy notice.', legacy=True),
    Allowed('docs/superpowers/specs/2026-09-17-mcp-server-design.md',
            '`REWRITE_TEMPLATE`\'s `Run $privacy to review or adjust policy.` stays. It was traced, not assumed: `$privacy` step 3 starts the local audit UI, whose "Protect future occurrences" writes a `mask` rule. `READ_BLOCK_TEMPLATE` and `READ_NOTICE_TEMPLATE` name `$privacy read off` and `$privacy read on`, which exist.',
            'Protect future occurrences',
            'Historical design spec, marked superseded by the legacy notice.', legacy=True),
    Allowed('src/privacy_hud/local_ui_server.py',
            '    being conflated** (#49 item 2). It used to end "Applies from the next\n    tool call.", which reads as a promise about every later call. It is not',
            'Applies from the next tool call',
            "Explicit 'it used to end' retraction note."),
    Allowed('src/privacy_hud/mcp_tools.py',
            '#: caller was told `{"applied": True}`, and every later call was decided',
            '"applied": True',
            'Describes the rejected false success (allow_dest / inert mask), not an enforcement claim.'),
    Allowed('src/privacy_hud/mcp_tools.py',
            '#: than an error, because it looks like protection was applied when nothing',
            'protection was applied',
            'Describes the rejected false success (allow_dest / inert mask), not an enforcement claim.'),
    Allowed('src/privacy_hud/mcp_tools.py',
            '#: would tell the caller protection was applied, record a rule no path',
            'protection was applied',
            'Describes the rejected false success (allow_dest / inert mask), not an enforcement claim.'),
    Allowed('src/privacy_hud/mcp_tools.py',
            '    "that protection was applied — and no path removes a rule once written "',
            'protection was applied',
            'Describes the rejected false success (allow_dest / inert mask), not an enforcement claim.'),
    Allowed('src/privacy_hud/mcp_tools.py',
            '    like protection was applied when nothing was. `block_source` is refused',
            'protection was applied',
            'Describes the rejected false success (allow_dest / inert mask), not an enforcement claim.'),
    Allowed('tests/test_mcp.py',
            '    row decided nothing while `{"applied": True}` said otherwise. That is',
            '"applied": True',
            'Documents the past {"applied": True} failure.'),
    Allowed('tests/test_origin_rules_e2e.py',
            '    while the ledger still recorded `prevented`. Clicking "Protect future\n    occurrences" on a credential exposure did that.',
            'Protect future occurrences',
            'Documents a past failure or asserts the claim is absent.'),
    Allowed('tests/test_origin_rules_e2e.py',
            '    """`applied: true` was the wire format\'s version of the overclaim.',
            'applied: true',
            'Documents a past failure or asserts the claim is absent.'),
    Allowed('tests/test_origin_rules_e2e.py',
            '    assert "Applies from the next tool call" not in message',
            'Applies from the next tool call',
            'Documents a past failure or asserts the claim is absent.'),
    Allowed('tests/test_skill_snippets.py',
            '    rule is now enforced, not merely recorded." — a direct instruction to',
            'now enforced, not merely recorded',
            'Quotes the withdrawn instruction, or asserts it is absent.'),
    Allowed('tests/test_skill_snippets.py',
            '    assert "now enforced, not merely recorded" not in text',
            'now enforced, not merely recorded',
            'Quotes the withdrawn instruction, or asserts it is absent.'),
]

_SELF_EXEMPT_NAMES = {"RETRACTED", "LEGACY_NOTICE", "ALLOWED"}


# --------------------------------------------------------------------- #
# normalisation
# --------------------------------------------------------------------- #

_LINE_PREFIX = re.compile(r"[ \t]*(?:#:?|//|\*|>)?[ \t]*")


def _normalize_with_lines(text: str, *, offsets: bool = False
                          ) -> tuple[str, list[int]]:
    """Normalised text and, for each output character, its 1-based source
    line. Lowercases; drops `*` and backticks; reads `_` as a space; strips
    a comment or quote prefix at the start of every line so a wrapped
    comment reads as one sentence; collapses whitespace."""
    out: list[str] = []
    lines: list[int] = []
    position = 0
    for number, raw in enumerate(text.split("\n"), start=1):
        prefix = _LINE_PREFIX.match(raw)
        begin = prefix.end() if prefix else 0
        for column, ch in enumerate(raw[begin:], start=begin):
            if ch in "*`":
                continue
            ch = " " if ch == "_" or ch.isspace() else ch.lower()
            if ch == " " and (not out or out[-1] == " "):
                continue
            out.extend(ch)
            lines.extend([position + column if offsets else number] * len(ch))
        if out and out[-1] != " ":
            out.append(" ")
            lines.append(position + len(raw) if offsets else number)
        position += len(raw) + 1
    normalized = "".join(out)
    # Chinese prose can wrap between characters without a word separator.
    # Retain the original positions for the characters that survive.
    gaps = {match.start() for match in re.finditer(
        r"(?<=[\u3400-\u9fff“”]) (?=[\u3400-\u9fff“”])", normalized)}
    return ("".join(ch for i, ch in enumerate(normalized) if i not in gaps),
            [line for i, line in enumerate(lines) if i not in gaps])


def _normalize(text: str) -> str:
    return _normalize_with_lines(text)[0].strip()


NORMALIZED_CLAIMS = {_normalize(c): c for c in RETRACTED}


# --------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------- #

@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    claim: str


def _string_constants(text: str) -> list[tuple[int, int, str]]:
    """(first line, last line, value) of every string constant in a Python
    source. Adjacent literals arrive already joined by the parser."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append((node.lineno, node.end_lineno or node.lineno,
                        node.value))
        elif isinstance(node, ast.JoinedStr):
            joined = "".join(v.value for v in node.values
                             if isinstance(v, ast.Constant)
                             and isinstance(v.value, str))
            out.append((node.lineno, node.end_lineno or node.lineno, joined))
    return out


def _without_self_declarations(text: str) -> str:
    tree = ast.parse(text)
    rows = text.encode("utf-8").splitlines(keepends=True)
    starts = [0]
    for row in rows:
        starts.append(starts[-1] + len(row))
    source = bytearray(text.encode("utf-8"))
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        if any(isinstance(t, ast.Name) and t.id in _SELF_EXEMPT_NAMES
               for t in targets):
            first = starts[node.lineno - 1] + node.col_offset
            last = starts[node.end_lineno - 1] + node.end_col_offset
            source[first:last] = bytes(
                ch if ch in (10, 13) else 32 for ch in source[first:last])
            source[first:first + 4] = b"pass"
    return source.decode("utf-8")


def _without_allowed_claims(path: str, text: str) -> str:
    # Break only identified claims inside validated exact passages.
    # Keep Python syntax intact so decoded strings remain inspectable.
    source = list(text)
    for _first, _last, entry in _allowed_spans(path, text):
        start = text.index(entry.passage)
        normalized, positions = _normalize_with_lines(
            entry.passage, offsets=True)
        pattern = re.escape(_normalize(entry.claim))
        for match in re.finditer(pattern, normalized):
            index = next(i for i in range(match.start(), match.end())
                         if normalized[i].isalpha())
            source[start + positions[index]] = "X"
    return "".join(source)


def scan_text(path: str, text: str) -> list[Hit]:
    """Every retracted-claim occurrence in one file, before allowances."""
    if Path(REPO / path).resolve() == SELF:
        text = _without_self_declarations(text)
    hits: set[Hit] = set()
    normalized, line_of = _normalize_with_lines(text)
    for claim_norm, claim in NORMALIZED_CLAIMS.items():
        for match in re.finditer(re.escape(claim_norm), normalized):
            hits.add(Hit(path, line_of[match.start()], claim))
    if path.endswith(".py"):
        for first, _last, value in _string_constants(text):
            value_norm = _normalize(value)
            for claim_norm, claim in NORMALIZED_CLAIMS.items():
                if claim_norm in value_norm:
                    already = any(h.claim == claim and h.path == path
                                  and first <= h.line <= _last for h in hits)
                    if not already:
                        hits.add(Hit(path, first, claim))
    return sorted(hits, key=lambda h: (h.path, h.line, h.claim))


def _allowed_spans(path: str, text: str) -> list[tuple[int, int, Allowed]]:
    """(first line, last line, entry) for every entry of `path` whose
    passage occurs exactly once. A passage occurring twice excuses nothing."""
    spans = []
    for entry in ALLOWED:
        if entry.path != path or text.count(entry.passage) != 1:
            continue
        if entry.legacy and LEGACY_NOTICE not in text:
            continue
        start = text.index(entry.passage)
        first = text.count("\n", 0, start) + 1
        last = first + entry.passage.count("\n")
        spans.append((first, last, entry))
    return spans


def violations_in(path: str, text: str) -> list[Hit]:
    return scan_text(path, _without_allowed_claims(path, text))


def tracked_files() -> list[str]:
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=REPO,
                            capture_output=True, check=True).stdout
    files = [p for p in listed.decode().split("\0") if p]
    own = str(SELF.relative_to(REPO))
    if own not in files:
        files.append(own)
    return sorted(files)


def _read(path: str) -> str | None:
    try:
        return (REPO / path).read_text(encoding="utf-8")
    except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
        return None


def all_violations() -> list[Hit]:
    out = []
    for path in tracked_files():
        text = _read(path)
        if text is not None:
            out.extend(violations_in(path, text))
    return out


def allowlist_problems() -> list[str]:
    problems = []
    for entry in ALLOWED:
        text = _read(entry.path)
        if text is None:
            problems.append(f"{entry.path}: file missing")
            continue
        count = text.count(entry.passage)
        if count != 1:
            problems.append(f"{entry.path}: passage occurs {count} times: "
                            f"{entry.passage[:60]!r}")
        if entry.claim not in RETRACTED:
            problems.append(f"{entry.path}: unknown claim {entry.claim!r}")
        elif NORMALIZED_CLAIMS and _normalize(entry.claim) not in \
                _normalize(entry.passage):
            problems.append(f"{entry.path}: passage does not contain "
                            f"{entry.claim!r}")
        if not entry.why.strip():
            problems.append(f"{entry.path}: no justification")
        if entry.legacy and LEGACY_NOTICE not in text:
            problems.append(f"{entry.path}: legacy entry without the notice")
        if count == 1 and not any(
                h.claim == entry.claim for h in scan_text(entry.path, text)
                if text.count("\n", 0, text.index(entry.passage)) + 1
                <= h.line <= text.count("\n", 0, text.index(entry.passage))
                + 1 + entry.passage.count("\n")):
            problems.append(f"{entry.path}: allowance excuses no hit")
    return problems


# --------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------- #

def test_no_active_retracted_policy_claims():
    violations = all_violations()
    assert violations == [], "\n".join(
        f"{v.path}:{v.line}: {v.claim}" for v in violations)


def test_retracted_claim_allowlist_is_exact_and_used():
    assert allowlist_problems() == []


def _forms(claim: str) -> list[str]:
    words = claim.split(" ")
    middle = max(1, len(words) // 2)
    wrapped = (" ".join(words[:middle]) + "\n    # "
               + " ".join(words[middle:]))
    forms = [claim, wrapped, claim.replace(" ", "_"), claim.upper()]
    if any("\u3400" <= ch <= "\u9fff" for ch in claim):
        forms.extend(claim[:i] + "\n    # " + claim[i:]
                     for i in range(1, len(claim)))
    return forms


@pytest.mark.parametrize("claim", RETRACTED)
def test_retracted_claim_scanner_detects_active_reintroduction(claim):
    for form in _forms(claim):
        text = f"x = 1\n# {form}\n"
        found = violations_in("src/privacy_hud/injected.py", text)
        assert any(h.claim == claim and h.line == 2 for h in found), form
    half = len(claim) // 2
    literal = (f"MESSAGE = ({claim[:half]!r}\n"
               f"           {claim[half:]!r})\n")
    ast.parse(literal)  # the injection must be valid Python to prove anything
    found = violations_in("src/privacy_hud/injected.py", literal)
    assert any(h.claim == claim for h in found), "adjacent literals"


def test_historical_exception_does_not_allow_a_second_occurrence(monkeypatch):
    for entry in ALLOWED:
        text = _read(entry.path)
        assert text is not None
        mutations = [
            text + "\n" + entry.passage + "\n",
            text.replace(entry.passage, entry.passage + " " + entry.claim),
        ]
        for mutated in mutations:
            found = violations_in(entry.path, mutated)
            assert any(h.claim == entry.claim for h in found), entry.path

    entry = next(e for e in ALLOWED
                 if e.path == "src/privacy_hud/local_ui_server.py")
    escaped = entry.claim.replace(" ", r"\x20", 1)
    source = ('def example():\n    """\n' + entry.passage
              + "\n    " + escaped + '\n    """\n')
    assert source.count(entry.passage) == 1
    assert any(h.claim == entry.claim
               for h in violations_in(entry.path, source))

    own = str(SELF.relative_to(REPO))
    same_line = "ALLOWED = []; message = " + repr(RETRACTED[0]) + "\n"
    assert any(h.claim == RETRACTED[0]
               for h in violations_in(own, same_line))

    monkeypatch.setattr(sys.modules[__name__], "tracked_files",
                        lambda: [entry.path, own])
    monkeypatch.setattr(sys.modules[__name__], "_read",
                        lambda path: source if path == entry.path else same_line)
    active = active_text()
    assert _normalize(entry.claim) in active
    assert _normalize(RETRACTED[0]) in active


def _registered_tools(app):
    for get in (lambda: app.list_tools(),
                lambda: app._tool_manager.list_tools()):
        try:
            tools = get()
        except (AttributeError, TypeError):
            continue
        if hasattr(tools, "__await__"):
            tools = asyncio.run(tools)
        return {t.name: t for t in tools}
    raise AssertionError("no accessor for the registered tools on this SDK")


@pytest.fixture
def mcp_app(tmp_path, monkeypatch):
    sys.path.insert(0, str(REPO / "mcp"))
    import server
    from privacy_hud.matrix.loader import load_matrix

    led = writer_ledger(tmp_path / "ledger.db", load_matrix())
    led.start_session("s1", cwd="/r", model="gpt-5")
    led.conn.close()
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    opened = []
    real_open = server._open_ledger

    def capture():
        ledger = real_open()
        opened.append(ledger)
        return ledger

    monkeypatch.setattr(server, "_open_ledger", capture)
    app = server.build_app()
    try:
        yield app
    finally:
        for ledger in opened:
            ledger.conn.close()


def test_policy_tool_registered_description_is_conditional(mcp_app):
    """The description the model actually reads: the registered metadata,
    not the source."""
    tool = _registered_tools(mcp_app)["privacy.update_policy"]
    description = tool.description or ""
    assert violations_in("mcp/server.py#update_policy",
                         description) == []
    assert "saved=true" in description
    assert 'enforcement="conditional"' in description
    assert "require detection on ingress and again on egress" in description
    assert "hosted tools bypass these hooks" in description


@pytest.mark.parametrize("rule_type,selector", [
    ("mask", "email"), ("mask", "path"),
    ("block_path", "/etc/hosts"), ("block_command", "curl"),
])
def test_policy_save_reply_preserves_conditions(mcp_app, rule_type,
                                                selector):
    import json

    from privacy_hud import mcp_tools
    result = asyncio.run(mcp_app.call_tool(
        "privacy.update_policy",
        {"session_id": "s1", "rule_type": rule_type, "selector": selector}))
    assert result.is_error is False
    reply = json.loads(result.content[0].text)
    assert reply["saved"] is True
    assert reply["enforcement"] == "conditional"
    assert "applied" not in reply
    assert reply["conditions"] == mcp_tools.rule_enforcement_note(
        rule_type, selector).strip()


# --------------------------------------------------------------------- #
# script mode
# --------------------------------------------------------------------- #

def active_text() -> str:
    chunks = []
    for path in tracked_files():
        text = _read(path)
        if text is None:
            continue
        decoded_source = _without_allowed_claims(path, text)
        for _first, _last, entry in _allowed_spans(path, text):
            text = text.replace(entry.passage, "")
        if (REPO / path).resolve() == SELF:
            text = _without_self_declarations(text)
            decoded_source = _without_self_declarations(decoded_source)
        chunks.append(f"== {path}\n{_normalize(text)}")
        if path.endswith(".py"):
            for first, _last, value in _string_constants(decoded_source):
                chunks.append(f"== {path}:{first} decoded\n{_normalize(value)}")
    return "\n".join(chunks)


if __name__ == "__main__":
    if sys.argv[1:] != ["--active-text"]:
        sys.exit("usage: test_retracted_claims.py --active-text")
    problems = allowlist_problems()
    if problems:
        sys.stderr.write("\n".join(problems) + "\n")
        sys.exit(2)
    sys.stdout.write(active_text() + "\n")
