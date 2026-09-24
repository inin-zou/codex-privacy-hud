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


# --- B13: detector choice and scheduling ---------------------------------

PRD_ENGINE_HEADING = "### 7.3 Local privacy engine"
PRD_ENGINE = PRD_ENGINE_HEADING + "\n\n" + (
    "The shipped detector stack is `PathDetector`, `SecretDetector` and "
    "`ModelDetector`. Paths and credentials use cheap local checks. Shell "
    "destination classification is a separate heuristic step. Presidio and "
    "a separate contextual entity-resolution stage are not shipped."
    "\n\n"
    "`ModelDetector` uses `openai/privacy-filter` through `transformers`. "
    "Installing its dependencies and weights is optional, but detection is "
    "reduced without them: the model-owned categories, including names, "
    "addresses and email addresses, are unavailable. Runtime loads only "
    "local weights and never downloads replacements."
    "\n\n"
    "Cheap detectors scan the observation text. Deep scanning applies to "
    "non-local destinations, including outbound B3/B4 calls, without "
    "requiring a cheap-detector hit or a PII-shaped prefilter. Payloads "
    "above 8192 characters skip the deep scan entirely. An applicable deep "
    "scan that supplies no accepted result records a scan gap; that is not "
    "a clean scan."
    "\n\n"
    "Outbound deep scanning uses the admission and deadline rules in "
    "`architecture.md` §4. Those rules do not guarantee wall-clock "
    "completion. The hook client separately applies its shared request "
    "deadline: unchecked ingress receives an unverified warning, and "
    "unchecked outbound calls receive a denial. These are plugin responses, "
    "not confirmation of host enforcement."
)

PRD_MUST_DETECTOR = (
    "- [x] Local detector stack: path and credential checks, with "
    "`openai/privacy-filter` as the optional installed deep detector; "
    "missing dependencies or weights leave deep detection unavailable."
)
PRD_WONT = (
    "- Presidio integration, org policy presets, App Server native client, "
    "multi-user/team sync"
)

ARCH_DETECTOR_TABLE = (
    "The shipped stack contains two cheap detectors and one expensive "
    "detector:\n"
    "\n"
    "| Component | Role |\n"
    "|---|---|\n"
    "| `PathDetector` | Tier 0: sensitive path patterns |\n"
    "| `SecretDetector` | Tier 1: credential patterns and entropy checks |\n"
    "| Shell destination classification | Tier 2: heuristics over command "
    "text, outside the detector list |\n"
    "| `ModelDetector` | Tier 3: local `openai/privacy-filter` token "
    "classification |\n"
    "\n"
    "Presidio is not shipped. Cheap detectors scan each observation's text. "
    "Deep scanning applies to non-local destinations, including B3/B4, "
    "without a cheap-hit or PII-shape prerequisite. It is skipped entirely "
    "above `MAX_TIER3_CHARS` (8192 characters). Missing weights or an "
    "unsuccessful applicable scan produce a scan gap, not evidence of a "
    "clean payload."
)
ARCH_OUTBOUND = (
    "**Outbound deep scanning.** Before #47 items 1 and 6, the engine "
    "excluded B3/B4 from deep scanning. It now attempts the applicable scan "
    "under the admission and acceptance rules below. The hook client "
    "separately uses one 2.0-second deadline across connection, hello, "
    "event transmission and reply; an outbound call that cannot be checked "
    "receives a denial."
)
ARCH_INTERFACES = (
    "**Interfaces.** Detectors implement `Detector.scan(text, ctx) -> "
    "list[Finding]` and declare a `DetectorProfile` containing tier and "
    "cost. The engine schedules cheap and expensive detectors by that "
    "declaration; availability is separate runtime state. `ModelDetector` "
    "implements the expensive local `openai/privacy-filter` detector, and "
    "tests can substitute a detector with the same declared profile."
)
ARCH_POSTTOOLUSE = (
    "**`PostToolUse` is synchronous.** The host behavior recorded in §7 is "
    "why these hooks are not configured as asynchronous. Tool results can "
    "contain large payloads, and an applicable `openai/privacy-filter` scan "
    "can exceed the hook client's waiting budget. A size cap limits the "
    "input offered to the model; it does not establish a latency guarantee. "
    "If the client cannot obtain a usable ingress reply, it reports the "
    "observation as unverified."
)
ARCH_CAP = (
    "**Why the current cap is stated in characters.** `MAX_TIER3_CHARS` is "
    "8192 characters, not a byte limit. Above it, the entire deep scan is "
    "skipped and an applicable observation records an `oversize` scan gap. "
    "The cap does not establish a 40 ms scan time, a 150 ms completion "
    "bound or complete detection. Cheap detectors still inspect the full "
    "observation text."
)
PRD_LANGUAGE = (
    "1. **Language decision:** Python with a persistent daemon and a "
    "stdlib-only hook client. The shipped deep detector is local "
    "`openai/privacy-filter` through `transformers`; Presidio is not part "
    "of the runtime."
)

ARCH_DETECTION_HEADING = "## 4. Detection engine"
ARCH_PERFORMANCE_HEADING = "## 10. Concurrency and performance"


def _paragraph(text: str, start: str) -> str:
    """The one blank-line-delimited paragraph of `text` starting `start`."""
    found = [p for p in text.split("\n\n") if p.startswith(start)]
    assert len(found) == 1, f"expected one paragraph starting {start!r}, found {len(found)}"
    return found[0]


def test_issue47_detector_choice_and_schedule_are_exact():
    assert _section(PRD, PRD_ENGINE_HEADING) == PRD_ENGINE
    scope = _section(PRD, "## 11. Scope")
    assert _line(scope, "- [x] Local detector stack") == PRD_MUST_DETECTOR
    assert _line(scope, "- Presidio integration") == PRD_WONT
    assert "Presidio PII detection" not in scope
    assert "Hugging Face `privacy-filter` model" not in scope

    detection = _section(ARCH, ARCH_DETECTION_HEADING)
    assert detection.startswith(
        ARCH_DETECTION_HEADING + "\n\n" + ARCH_DETECTOR_TABLE + "\n\n"
        + ARCH_OUTBOUND + "\n\n")
    assert _paragraph(detection, "**Interfaces.**") == ARCH_INTERFACES
    assert "Presidio NER" not in detection
    assert "2.0 s per socket operation" not in detection

    performance = _section(ARCH, ARCH_PERFORMANCE_HEADING)
    assert _paragraph(performance, "**`PostToolUse` is synchronous") == ARCH_POSTTOOLUSE
    assert _paragraph(performance, "**Why the current cap") == ARCH_CAP
    assert "**Why 8 KB.**" not in performance

    questions = _section(PRD, "## 13. Open questions")
    assert _line(questions, "1. ") == PRD_LANGUAGE

    _assert_no_affirmative_presidio(_read(PRD), PRD)
    for heading in (ARCH_DETECTION_HEADING, ARCH_PERFORMANCE_HEADING):
        _assert_no_affirmative_presidio(_section(ARCH, heading), ARCH)


def _assert_no_affirmative_presidio(text: str, rel: str) -> None:
    for line in text.split("\n"):
        if "Presidio" in line:
            assert "not" in line or line.startswith("- Presidio integration"), (
                f"{rel}: affirmative Presidio claim: {line!r}")


# --- B14: no chunk cache --------------------------------------------------

ARCH_INCREMENTAL_HEADING = "### 3.3 Incremental processing without a chunk cache"
ARCH_INCREMENTAL = ARCH_INCREMENTAL_HEADING + "\n\n" + (
    "Each observation is scanned from its own text. There is no "
    "content-hash findings cache and no shared 64 MB LRU. Re-reading "
    "unchanged content can repeat detector work."
    "\n\n"
    "Dispatch separates scanning from policy and ledger work. It computes "
    "one `ScanResult` outside the ledger lock and passes that result into "
    "`Engine.observe` while holding the lock. This avoids scanning the same "
    "observation twice; it does not reuse results from earlier observations "
    "or other sessions."
    "\n\n"
    "Production sessions still use legacy accounting. Legacy deduplication "
    "uses `(session_id, value_hash, destination)` and can increment an "
    "existing row's repetition count instead of adding a new contribution. "
    "That accounting deduplication happens after detection and is not a "
    "computational cache. It can also collapse different outcomes; this "
    "section does not resolve #47 items 3, 4 or 8."
    "\n\n"
    "Processing is incremental over observed payloads rather than a rescan "
    "of the full conversation. There is no O(1) unchanged-file reread "
    "guarantee. Detection misses and recorded scan gaps remain possible."
)
ARCH_NO_CACHE_BULLET = (
    "- **No chunk cache.** Findings are not reused across observations or "
    "sessions. Legacy ledger deduplication can avoid another score "
    "contribution, but it does not avoid scanning an unchanged payload "
    "again."
)


def test_issue47_repeated_reads_are_not_cached():
    assert _section(ARCH, ARCH_INCREMENTAL_HEADING) == ARCH_INCREMENTAL
    performance = _section(ARCH, ARCH_PERFORMANCE_HEADING)
    assert _line(performance, "- **No chunk cache.**") == ARCH_NO_CACHE_BULLET
    for rel in (PRD, DESIGN, ARCH, README, README_ZH, KNOWN_LIMITS):
        text = _read(rel)
        assert "chunk_cache.get" not in text, rel
        assert "chunk_cache.put" not in text, rel
        for line in text.split("\n"):
            if "LRU" in line or "O(1)" in line:
                assert line.count("no ") + line.count("No ") >= 1, (
                    f"{rel}: affirmative cache promise: {line!r}")
    assert "re-reading an unchanged file is `O(1)`" not in _read(ARCH)
    assert "**Chunk cache** is content-hash keyed" not in _read(ARCH)


# --- B-history: historical build orders -----------------------------------

PRD_BUILD_ORDER_HEADING = "### Historical build order"
PRD_BUILD_ORDER = PRD_BUILD_ORDER_HEADING + "\n\n" + (
    "The original build sequence is historical, not an implementation plan "
    "for the current release:\n"
    "\n"
    "1. Legacy ledger and budget functions.\n"
    "2. Cheap detectors and the local `openai/privacy-filter` detector.\n"
    "3. Hook client, plugin packaging and daemon integration.\n"
    "4. Session audit and conditional policy-writing surfaces.\n"
    "5. Tool-argument rewriting and internal token primitives. No "
    "interactive consent workflow was delivered.\n"
    "6. Patched-Codex status item, companion pane and text receipt.\n"
    "\n"
    "Current production accounting remains legacy. The inactive accounting "
    "core and its activation work are governed by the current contract at "
    "the top of this document."
)
ARCH_BUILD_ORDER_HEADING = "## 13. Historical build order"
ARCH_BUILD_ORDER = ARCH_BUILD_ORDER_HEADING + "\n\n" + (
    "The original implementation sequence was ledger and budget functions, "
    "detection, hooks and daemon integration, audit surfaces, tool-argument "
    "rewriting, and ambient displays."
    "\n\n"
    "The shipped deep detector is local `openai/privacy-filter`, not "
    "Presidio. Internal consent-token primitives exist, but no shipped "
    "surface issues consent tokens. Both the patched-Codex status item and "
    "the companion pane exist. Session receipts are text returned through "
    "hook `systemMessage`, not Markdown exports."
    "\n\n"
    "This historical sequence is not the release plan for accounting "
    "activation. Production sessions remain legacy-accounted under the "
    "current contract at the top of this document."
)
DESIGN_PREVIEW_QUESTION = (
    "4. **Unshipped minimization preview:** a future preview would need a "
    "design for long payloads. No preview or preview-and-retry action is "
    "available today."
)


def test_issue47_historical_build_orders_do_not_offer_unshipped_features():
    assert _section(PRD, PRD_BUILD_ORDER_HEADING) == PRD_BUILD_ORDER
    assert _section(ARCH, ARCH_BUILD_ORDER_HEADING) == ARCH_BUILD_ORDER
    assert "### Build order" not in _read(PRD)
    assert "## 13. Build order" not in _read(ARCH)
    assert "the demo's centerpiece" not in _read(ARCH)

    questions = _section(DESIGN, "## 13. Open design questions")
    assert _line(questions, "4. ") == DESIGN_PREVIEW_QUESTION
    assert _line(_section(PRD, "## 13. Open questions"), "1. ") == PRD_LANGUAGE
