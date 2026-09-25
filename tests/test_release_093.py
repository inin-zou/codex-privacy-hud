"""Current release identity and the issue 74 follow-up changelog."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from privacy_hud import runtime_contract as contract

REPO = Path(__file__).resolve().parents[1]


def test_current_release_declarations():
    plugin = json.loads((REPO / ".codex-plugin/plugin.json").read_text())
    marketplace = json.loads(
        (REPO / ".agents/plugins/marketplace.json").read_text())
    project = tomllib.loads((REPO / "pyproject.toml").read_text())
    manifest = json.loads((REPO / contract.MANIFEST_NAME).read_text())

    assert re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\."
                        r"(0|[1-9][0-9]*)", contract.RELEASE)
    assert plugin["version"] == contract.RELEASE
    assert [entry["version"] for entry in marketplace["plugins"]
            if entry["name"] == plugin["name"]] == [contract.RELEASE]
    assert project["project"]["version"] == contract.RELEASE
    assert manifest["release"] == contract.RELEASE


def test_release_093_changelog():
    text = (REPO / "CHANGELOG.md").read_text()
    section = text.split("## 0.9.3\n", 1)[1].split("\n## ", 1)[0]
    assert text.index("## 0.9.3\n") < text.index("## 0.9.0\n")
    assert re.search(r"^Refs #74\.$", section, re.M)
    assert len([line for line in section.splitlines()
                if line.startswith("- ")]) == 4
    assert not re.search(
        r"\b(close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved)"
        r" #\d+", section, re.I)


def test_current_release_documents_explicit_upgrade_recovery():
    text = (REPO / "CHANGELOG.md").read_text()
    heading = f"## {contract.RELEASE}\n"
    assert text.startswith("# Changelog\n\n" + heading)
    section = text.split(heading, 1)[1].split("\n## ", 1)[0]

    assert "any canonical N.N.N sibling path" in section
    assert "whether the version directory is present or absent" in section
    assert "need never have existed or been installed" in section
    assert "no record of prior selection is required" in section
    assert "Existing version directories must contain a canonical scripts/runtime.py file" in section
    assert "MCP and daemon" in section
    assert "Keep runtime repair explicit" in section
    assert "external-terminal repair command" in section
    assert re.search(r"^Refs #74\.$", section, re.M)
    assert not re.search(
        r"\b(close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved)"
        r" #\d+", section, re.I)
