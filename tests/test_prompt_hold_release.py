from __future__ import annotations

import json
import tomllib
from pathlib import Path

from privacy_hud import ledger_schema, runtime_contract
from privacy_hud.matrix.loader import load_matrix


ROOT = Path(__file__).resolve().parents[1]


def test_prompt_hold_release_and_schema():
    plugin = json.loads((ROOT / ".codex-plugin/plugin.json").read_text())
    market = json.loads((ROOT / ".agents/plugins/marketplace.json").read_text())
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert plugin["version"] == "0.9.2"
    assert [
        p["version"] for p in market["plugins"] if p["name"] == plugin["name"]
    ] == ["0.9.2"]
    assert project["project"]["version"] == "0.9.2"
    assert runtime_contract.RELEASE == "0.9.2"
    assert ledger_schema.ACTIVATED_VERSION == 5402
    assert load_matrix().classify("UserPromptSubmit", "blocked") == "prevented"
    assert load_matrix().classify("UserPromptSubmit", "ingress") == "exposed"


def test_prompt_limit_and_reviewed_chinese_are_present():
    limits = (ROOT / "docs/known-limits.md").read_text()
    english = (ROOT / "README.md").read_text()
    chinese = (ROOT / "README.zh-CN.md").read_text()
    assert "## 22. Credential prompt holds have a narrow scope." in limits
    for phrase in (
        "ASSIGNMENT", "GENERIC_QUOTED", "private-key headers",
        "2 seconds", "300 seconds", "case-sensitive",
        "Images and attachments are not scanned",
        "fail open", "not a live TUI test",
    ):
        assert phrase in limits
    assert "All twenty-two limits" in english
    assert "二十二条限制" in chinese
    assert (
        "守护进程没有响应时，包括冷启动期间，提示词仍会放行，并显示未经验证的提示。"
    ) in chinese
    assert (
        "第三级 NER 检测结果、熵检测结果和单独的私钥头部不会触发提示词暂缓。"
    ) in chinese
    assert "## 0.9.1\n" in (ROOT / "CHANGELOG.md").read_text()
