"""#54 Phase 3 (0.8.1): the inactive release contract and its exact copy.

The documentation says the version-2 accounting core ships inactive, in the
exact words the Phase 3 outline fixes; the release declarations move to
0.8.1 together; and the wire and schema versions do not move.

`test_phase3_does_not_retire_production_limits`,
`test_phase3_wire_and_schema_versions_are_unchanged` and
`test_phase3_summary_and_refusal_copy_is_exact` are ALREADY-GREEN guards
(the refusal constants landed with the version-2 readers), not new RED
claims.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from privacy_hud import accounting, hud_snapshot, ledger, ledger_schema
from privacy_hud.matrix.loader import load_matrix

REPO = Path(__file__).resolve().parents[1]

CONTRACT_BLOCK = (
    '**Current contract — #54 Phase 3 (0.8.1).**\n'
    '\n'
    'The new accounting core is implemented and tested but is not active for production sessions. Production session creation still selects legacy accounting. Prepared-schema migration remains unchanged. No historical rows are backfilled or rescored. Runtime selection, writer ownership, and the fenced ledger layout introduced in 0.8.0 remain required. #43, #44, and the related #47 accounting limitations remain unresolved in production.'
)

README_INTRO = (
    'A local-first Codex plugin that records hook observations in a session ledger and can return denials or rewritten input before tool execution.\n'
    '\n'
    'The HUD currently shows a legacy permitted-crossing score. Historical accounting includes permitted crossings and may collapse different outcomes; it does not establish confirmed disclosure. The badge counts legacy prevented rows, not denied calls or confirmed host-enforced interventions. An unrecorded session shows “No session on record” with no percentage or numeric counts.\n'
    '\n'
    'Version 0.8.1 includes the new accounting core, but production sessions still use legacy accounting. The new evidence, identity, and distinct-disclosure calculations are implemented and tested; they are not yet active.\n'
    '\n'
    'Version 0.8.0 checks runtime alignment and fences the active ledger from historical entry points. The daemon still prepares the accounting schema at a genuine new-session boundary, and production sessions still use legacy accounting. Historical records and stored scores are not backfilled or rescored.\n'
    '\n'
    'A denial or rewritten input returned by Privacy HUD is not confirmation that the host applied it. Current hooks do not establish that a denied call did not run or that rewritten input reached its intended recipient.\n'
    '\n'
    'Boundary, not recipient: a second MCP server is not a second destination today, and what a subagent inherited is not recorded at all (limits 19 and 20).\n'
    '\n'
    'Detection runs locally; the plugin sends no prompt, file, or secret to a remote scanner. Runtime communication is limited to Unix-domain sockets and the local browser UI on `127.0.0.1`.'
)

README_ZH_INTRO = (
    'Codex Privacy HUD 是一个本地优先的 Codex 插件，在会话账本中记录 hook 观测，并可在工具执行前返回拒绝决定或改写后的输入。\n'
    '\n'
    'HUD 当前显示旧版许可跨界评分（legacy permitted-crossing score）。旧版记账包含获准的跨界操作，也可能将不同结果合并到同一行；它不能证明数据已实际披露。计数标记统计旧版 prevented 行数，不是被拒绝的调用次数，也不是已确认由宿主执行的干预次数。未记录的会话显示“No session on record”，不显示百分比或数字计数。\n'
    '\n'
    '0.8.1 已包含新的记账核心，但实际会话仍使用旧版记账。证据、主体身份和不同披露的计算已实现并经过测试，尚未用于实际会话。\n'
    '\n'
    '0.8.0 会检查运行时一致性，并阻止旧版入口通过原路径访问当前账本。守护进程仍只在真正的新会话开始时准备记账结构，实际会话仍采用旧版记账。历史记录和已存分数不会被回填或重新计算。\n'
    '\n'
    'Privacy HUD 返回拒绝决定或改写后的输入，并不能证明宿主实际应用了它。当前 hook 无法证明被拒绝的调用没有执行，也无法证明改写后的输入到达了预期接收方。\n'
    '\n'
    '这里的“目的地”指边界类别，不代表具体接收方：目前，第二个 MCP 服务器不算新的目的地，子智能体启动时继承了什么则完全没有记录，见已知限制第 19、20 条。\n'
    '\n'
    '检测在本机执行；插件不会将提示词、文件或秘密信息发送到远程扫描服务。运行时通信仅使用 Unix 域套接字，以及绑定到 `127.0.0.1` 的本地浏览器界面。'
)

#: The version-bearing compatibility paragraph. #66 replaced the Phase 2
#: wording wholesale; this release keeps that replacement and moves the
#: release number onto it. The remaining #66 paragraphs beside it are
#: pinned by `tests/test_issue66_contract.py`.
COMPATIBILITY = (
    'Privacy HUD 0.8.3 retains snapshot version 2. Production sessions still use legacy accounting. Snapshot-v2 readers accept version 1 as explicitly legacy and version 2 with nullable accounting fields. Older snapshot-v1-only readers reject version 2 and show no Privacy item. Matching Codex version numbers do not establish snapshot compatibility.'
)

COMPATIBILITY_ZH = (
    'Privacy HUD 0.8.3 继续使用 snapshot v2，实际会话仍采用旧版记账。支持 v2 的读取器会将 v1 明确标为旧版记账，并支持带可空记账字段的 v2。仅支持 v1 的旧读取器会拒绝 v2，不显示 Privacy 状态项。Codex 版本号相同并不代表快照兼容。'
)

LEDGER_DOCSTRING = (
    '"""Versioned session accounting and legacy ledger access.\n'
    '\n'
    'Production sessions use legacy accounting. Phase 3 also implements an\n'
    'inactive version-2 core for isolated synthetic tests and the private-copy\n'
    'rehearsal.\n'
    '\n'
    'Legacy records retain their stored scores, counts and classifications.\n'
    'Version-2 observations, events and disclosures are separate immutable\n'
    'records. Only a new chargeable disclosure increases a version-2 score.\n'
    '\n'
    'Version-2 identity inputs are hashed before persistence. Labels and\n'
    'exemplars use explicit allowlists; the absence of a raw-content column\n'
    'alone does not establish that arbitrary metadata is safe.\n'
    '\n'
    "Readers select the session's accounting version inside a read transaction\n"
    'and never initialize, migrate or activate a ledger. SessionEnd erases\n'
    'matching hashes while retaining opaque identities and accounting joins;\n'
    'this is logical erasure, not a secure-deletion guarantee.\n'
    '"""'
)

SCHEMA_5401 = (
    '- 5401: prepared. The legacy events table is preserved as\n'
    '  `events_legacy_v1`. Production sessions remain legacy-accounted;\n'
    '  isolated synthetic tests and the private-copy rehearsal may exercise\n'
    '  version-2 accounting without activating production session creation.'
)

CONTRACT_DOCS = (".claude/docs/architecture.md", ".claude/docs/design.md",
                 ".claude/docs/PRD.md")
COMPATIBILITY_DOCS = ("README.md", "docs/installing-by-hand.md",
                      "patches/README.md")


def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


def test_phase3_versions_are_0_8_3():
    plugin = json.loads(_read(".codex-plugin/plugin.json"))
    marketplace = json.loads(_read(".agents/plugins/marketplace.json"))
    project = tomllib.loads(_read("pyproject.toml"))
    assert plugin["version"] == "0.8.3"
    assert [p["version"] for p in marketplace["plugins"]
            if p["name"] == plugin["name"]] == ["0.8.3"]
    assert project["project"]["version"] == "0.8.3"


def test_phase3_contract_blocks_match_verbatim():
    for relative in CONTRACT_DOCS:
        text = _read(relative)
        assert text.count(CONTRACT_BLOCK) == 1, relative
        assert "Current contract — #54 Phase 2" not in text, relative
        lines = text.split("\n")
        assert lines[4] == CONTRACT_BLOCK.split("\n")[0], relative
        assert lines[0].startswith("# Codex Privacy HUD"), relative
        assert lines[2].startswith("**Status:**"), relative


def test_phase3_readme_introductions_match_verbatim():
    english, chinese = _read("README.md"), _read("README.zh-CN.md")
    assert english.count(README_INTRO) == 1
    assert chinese.count(README_ZH_INTRO) == 1
    assert "Version 0.7.9 prepares" not in english
    assert "0.7.9 会在新会话开始时" not in chinese


def test_phase3_install_notes_match_verbatim():
    for relative in COMPATIBILITY_DOCS:
        text = _read(relative)
        assert text.count(COMPATIBILITY) == 1, relative
        assert "Privacy HUD 0.7.9 retains" not in text, relative
    chinese = _read("README.zh-CN.md")
    assert chinese.count(COMPATIBILITY_ZH) == 1
    assert "Privacy HUD 0.7.9 继续使用" not in chinese
    assert "0.7.10" not in "".join(_read(r) for r in COMPATIBILITY_DOCS)


def test_phase3_does_not_retire_production_limits():
    readme = _read("README.md")
    limits = _read("docs/known-limits.md")
    for number in (17, 18, 19, 20):
        assert re.search(rf"^{number}\. \*\*", readme, re.M), number
        assert f"#{number}-" in readme, number
        assert re.search(rf"^#+ {number}\.", limits, re.M), number
    assert "still use legacy accounting" in readme
    assert "仍采用旧版记账" in _read("README.zh-CN.md")


def test_phase3_wire_and_schema_versions_are_unchanged():
    assert ledger_schema.PREPARED_VERSION == 5401
    assert ledger_schema.ACTIVATED_VERSION == 5402
    assert hud_snapshot.SNAPSHOT_VERSION == 2
    matrix = load_matrix()
    assert matrix.version == "1"
    assert matrix.budget_cap == 120.0
    # No production path can reach the private version-2 constructor, and
    # nothing reads a switch that could.
    sources = [p for p in (REPO / "src" / "privacy_hud").rglob("*.py")]
    sources += [REPO / "mcp" / "server.py", REPO / "hooks" / "handler.py"]
    for path in sources:
        text = path.read_text(encoding="utf-8")
        if path.name != "ledger.py":
            assert "_start_v2_session" not in text, path.name
        assert not re.search(r"environ[^\n]*(?i:accounting)", text), path.name
        assert not re.search(r"getenv\([^)]*(?i:accounting)", text), path.name


def test_phase3_summary_and_refusal_copy_is_exact():
    assert accounting.ACCOUNTING_SCORE_LABEL == "confirmed disclosure points"
    assert accounting.ACCOUNTING_NOTE == (
        "This score is a versioned policy index over evidenced disclosures, "
        "not a measurement of harm. Permission, a returned denial, a returned "
        "rewrite, and a successful tool result do not by themselves confirm "
        "disclosure or host enforcement.")
    assert accounting.PHASE3_SURFACE_UNSUPPORTED == (
        "This Privacy HUD surface does not support version-2 accounting "
        "in 0.8.3.")
    assert json.dumps({"error": accounting.PHASE3_SURFACE_UNSUPPORTED},
                      separators=(",", ":")) == (
        '{"error":"This Privacy HUD surface does not support version-2 '
        'accounting in 0.8.3."}')


def test_phase3_source_module_documentation_matches_verbatim():
    source = _read("src/privacy_hud/ledger.py")
    assert source.startswith(LEDGER_DOCSTRING + "\n")
    assert ledger.__doc__ is not None
    schema = _read("src/privacy_hud/ledger_schema.py")
    assert SCHEMA_5401 in schema
    assert "- 5402: activated" in schema
