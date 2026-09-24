# tests/test_issue47_docs_contract.py
"""#47 items 10 and 12-18: the design documents describe what ships.

Each of these rows was a sentence in `.claude/docs/` (or the READMEs, or
the skill's prose) describing an action or mechanism the plugin does not
provide: a consent loop with no surface, a Presidio detector that was
never built, a chunk cache, a manual-start daemon, compaction markers, a
Markdown receipt, a native HUD "in the future", and a `$privacy <id>`
event deep link. They were corrected by documenting the shipped behavior,
not by building the withdrawn features.

The expected text below is written out independently of the documents
under test, so a later edit that reintroduces a withdrawn claim, or
quietly rewords a qualification away, fails here. Replacements are
compared for equality with the anchored section, paragraph, list item or
table row; insertions must occur exactly once, at their anchor.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PRD = ".claude/docs/PRD.md"
DESIGN = ".claude/docs/design.md"
ARCH = ".claude/docs/architecture.md"
README = "README.md"
README_ZH = "README.zh-CN.md"
KNOWN_LIMITS = "docs/known-limits.md"


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def _section(rel: str, heading: str) -> str:
    """`heading` through the line before the next heading of the same or a
    higher level, or the next `---` rule, stripped. Fenced code is skipped
    when looking for the end, so a `#` comment inside a fence is not a
    heading."""
    lines = _read(rel).split("\n")
    found = [i for i, line in enumerate(lines) if line == heading]
    assert len(found) == 1, f"{rel}: expected one {heading!r}, found {len(found)}"
    level = len(heading) - len(heading.lstrip("#"))
    body: list[str] = []
    fenced = False
    for line in lines[found[0] + 1:]:
        if line.startswith("```"):
            fenced = not fenced
        if not fenced:
            if line.strip() == "---":
                break
            match = re.match(r"(#+) ", line)
            if match and len(match.group(1)) <= level:
                break
        body.append(line)
    return "\n".join([heading, *body]).strip()


def _line(text: str, prefix: str) -> str:
    """The one line of `text` starting with `prefix`."""
    found = [line for line in text.split("\n") if line.startswith(prefix)]
    assert len(found) == 1, f"expected one line starting {prefix!r}, found {len(found)}"
    return found[0]


def _inserted(rel: str, before: str, block: str, after: str) -> None:
    """`block` occurs exactly once in `rel`, as its own paragraph between
    `before` and `after`."""
    text = _read(rel)
    assert text.count(block) == 1, f"{rel}: expected one occurrence of the block"
    assert f"{before}\n\n{block}\n\n{after}" in text, (
        f"{rel}: block is not at its anchor")


# --- B10: mask scope ------------------------------------------------------

B10 = (
    "Mask scope is session-wide by detected data type, without a source "
    "restriction. If a matching mask rule selects an otherwise eligible "
    "outbound call, the rewriter receives all findings from that call, "
    "including findings of other types; it does not restrict rewriting to "
    "the selected type. An origin-rule denial takes precedence, and a mask "
    "rule does not weaken the built-in handling of hard-blocked types. "
    "Saving a rule does not confirm detection on a later call or host "
    "application of rewritten input. Already disclosed data cannot be "
    "recalled from this session."
)

#: The mask-action bullet B10 follows. Its text is pinned, byte for byte, by
#: `tests/test_retracted_claims.py`'s allowlist (it quotes a withdrawn
#: label), so it is located here by its opening words rather than restated.
DESIGN_MASK_BULLET_START = "- `Save mask rule for detected <type>` — the browser POSTs"
DESIGN_ORIGIN_BULLET_START = (
    "- Where a row names a real origin, `Save block rule for values read "
    "from {source}`"
)

PRD_POLICY_WRITING = (
    "The terminal detail view does not save policy rules. The local audit "
    "browser has buttons that POST to `/api/policy`; the MCP "
    "`privacy.update_policy` tool is a separate policy-writing surface. "
    "Report a rule as saved only after that surface returns success, and "
    "include its returned conditions. Host application of a later denial "
    "or rewritten input is not confirmed."
)
PRD_REQUIRED_COPY = (
    "`Already disclosed data cannot be recalled from this session.` remains "
    "required copy."
)


def test_issue47_mask_scope_is_exact():
    _inserted(DESIGN, _line(_read(DESIGN), DESIGN_MASK_BULLET_START), B10,
              DESIGN_ORIGIN_BULLET_START)
    _inserted(PRD, PRD_POLICY_WRITING, B10, PRD_REQUIRED_COPY)
    assert B10 in _section(DESIGN, "## 6. Level 3 — Exposure Detail")
    assert B10 in _section(PRD, "### Level 3 — Exposure Detail")
    for claim in ("session-wide by detected data type",
                  "without a source restriction",
                  "the rewriter receives all findings from that call",
                  "An origin-rule denial takes precedence",
                  "does not weaken the built-in handling of hard-blocked types"):
        assert claim in B10


# --- B12: consent and actual rewriting -----------------------------------

B12_BODY = (
    "The proposed deny → review → consent token → retry workflow is not "
    "available in the shipped product. Neither the audit browser, the "
    "`$privacy` skill nor the exposed MCP tools offer `Allow once`, "
    "`Minimize & retry`, a minimization preview or a consent-driven retry."
    "\n\n"
    "Internal token primitives exist: `mcp_tools.allow_once` can mint a "
    "token, and `Engine.observe` can consume one. These functions do not "
    "establish a reachable consent workflow. No shipped user-facing surface "
    "issues the token, and a saved origin-rule denial is evaluated before "
    "the token-consumption branch."
    "\n\n"
    "The available actions are those in the Level 3 policy section: the "
    "browser and `privacy.update_policy` can save conditional policy rules. "
    "They do not authorize a blocked call once, replay it or establish that "
    "the host applied a later denial or rewrite. `$privacy` opens the "
    "session audit; it does not deep-link a denial to an event."
    "\n\n"
    "Already disclosed data cannot be recalled from this session."
)

DESIGN_CONSENT_HEADING = "## 8. Consent flow — historical proposal, not shipped"
PRD_CONSENT_HEADING = "### 7.6 Consent flow — historical proposal, not shipped"

ARCH_ENFORCEMENT_HEADING = "## 8. Enforcement and the unshipped consent workflow"
ARCH_ENFORCEMENT = ARCH_ENFORCEMENT_HEADING + "\n\n" + (
    "The engine can return an allow decision, a denial, or rewritten tool "
    "input. Dispatch translates these into the host's hook output. A denial "
    "is returned in `hookSpecificOutput.permissionDecision`; a rewrite is "
    "returned through `updatedInput`. Neither response confirms that the "
    "host applied it."
    "\n\n"
    "A saved mask rule selects an outbound call by detected data type, "
    "without a source restriction. When that rule selects an otherwise "
    "eligible call, the rewriter receives all findings from the call, "
    "including other detected types. Origin-rule denials take precedence, "
    "and mask rules do not weaken the built-in handling of hard-blocked "
    "types."
    "\n\n"
    "`minimize_tool_input` rewrites detected spans in the supplied tool "
    "arguments. For supported string-command tools it returns rewritten "
    "command text; for structured MCP arguments it rewrites the scanned "
    "JSON text and parses the result. It does not read files named by a "
    "command. No `privacy-minimize` executable is shipped, and no "
    "file-upload rewrite through such a helper is implemented."
    "\n\n"
    "Pseudonyms are stable within a session for the same data type and "
    "value. This describes the returned input, not confirmed delivery or "
    "successful completion of the original task."
    "\n\n"
    "The proposed deny → review → consent token → retry workflow is not "
    "shipped. No browser button, `$privacy` branch or exposed MCP tool "
    "offers `Allow once`, `Minimize & retry`, a before/after preview or a "
    "consent-driven retry."
    "\n\n"
    "Internal token primitives remain implemented and tested. Tokens bind "
    "the session, tool and hash of canonical tool arguments, expire after "
    "120 seconds and are single-use. `Engine.observe` can consume them in "
    "its built-in block branch, but no shipped user-facing surface mints "
    "them. Origin-rule denials are decided before that branch."
    "\n\n"
    "Already disclosed data cannot be recalled from this session."
)

PRD_MINIMIZATION_HEADING = "### 7.7 What minimization rewrites"
PRD_MINIMIZATION = PRD_MINIMIZATION_HEADING + "\n\n" + (
    "Minimization operates on detected spans in the tool arguments "
    "supplied to the hook. It can return rewritten command text or "
    "structured MCP arguments. It does not open files referenced by shell "
    "commands, rewrite an upload through a helper executable, or offer a "
    "preview-and-retry action."
    "\n\n"
    "For example, a detected email in an MCP argument can be replaced with "
    "a session-stable pseudonym when the engine selects a rewrite. The "
    "returned `updatedInput` is not evidence that the host applied it or "
    "that the recipient received it. See `architecture.md` §8."
)

PRD_LIMIT_2 = (
    "2. **No interactive consent surface.** The proposed consent workflow "
    "is not shipped. Internal token primitives exist, but no browser "
    "button, `$privacy` branch or exposed MCP tool issues consent tokens "
    "(§7.6)."
)

README_LIMIT_4 = (
    "4. **No `ask` decision in Codex hooks, and no interactive consent "
    "surface.** Internal token primitives exist, but no browser button, "
    "`$privacy` branch or exposed MCP tool issues consent tokens or offers "
    "a consent-driven retry. ([details](docs/known-limits.md"
    "#4-no-ask-decision-in-codex-hooks-and-no-interactive-consent-at-all))"
)

README_ZH_LIMIT_4 = (
    "4. **Codex hook 不支持 `ask` 决策，插件也没有交互式授权入口。** "
    "内部已实现令牌的签发和消费逻辑，但浏览器按钮、`$privacy` 分支和已公开的 "
    "MCP 工具都不能签发授权令牌，也不提供授权后重试的操作。"
    "（[详情](docs/known-limits.md"
    "#4-no-ask-decision-in-codex-hooks-and-no-interactive-consent-at-all)）"
)

README_ARCH_CONTENTS = (
    "Component map, process model, ledger schema, hook dispatch, and the "
    "limits of the unshipped consent workflow."
)
README_ZH_ARCH_CONTENTS = "组件关系、进程模型、账本结构、hook 分发，以及尚未提供的交互式授权流程及其限制。"


def _doc_table_row(rel: str) -> list[str]:
    row = _line(_read(rel), "| [`.claude/docs/architecture.md`]")
    return [cell.strip() for cell in row.strip("|").split("|")]


def test_issue47_consent_sections_match_reachable_surfaces():
    assert _section(DESIGN, DESIGN_CONSENT_HEADING) == (
        DESIGN_CONSENT_HEADING + "\n\n" + B12_BODY)
    assert _section(PRD, PRD_CONSENT_HEADING) == (
        PRD_CONSENT_HEADING + "\n\n" + B12_BODY)
    assert _section(ARCH, ARCH_ENFORCEMENT_HEADING) == ARCH_ENFORCEMENT
    assert _section(PRD, PRD_MINIMIZATION_HEADING) == PRD_MINIMIZATION

    limits = _section(PRD, "## 9. Platform limitations (state these in the demo)")
    assert _line(limits, "2. ") == PRD_LIMIT_2

    assert _line(_read(README), "4. **No `ask` decision") == README_LIMIT_4
    assert _line(_read(README_ZH), "4. **Codex hook 不支持") == README_ZH_LIMIT_4
    # The Chinese limit used to claim every denied call stays denied for the
    # whole session; a later mask or policy change can decide otherwise.
    assert "一直被拒绝" not in _read(README_ZH)

    assert _doc_table_row(README)[1] == README_ARCH_CONTENTS
    assert _doc_table_row(README_ZH)[1] == README_ZH_ARCH_CONTENTS

    for rel in (PRD, ARCH):
        assert "privacy-minimize support.log" not in _read(rel)
