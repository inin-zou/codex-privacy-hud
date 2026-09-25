"""0.8.3: MCP repair and plugin-data diagnostics; accounting unchanged."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from privacy_hud import accounting
from privacy_hud import runtime_contract as contract

REPO = Path(__file__).resolve().parent.parent
#: 0.8.3 is history since #54 Phase 4 (0.9.0): the declarations must agree
#: on whatever release is current, and 0.8.3's CHANGELOG section survives.
RELEASE = contract.RELEASE


def _json(relative: str) -> dict:
    return json.loads((REPO / relative).read_text(encoding="utf-8"))


def test_every_declaration_names_the_current_release():
    plugin = _json(".codex-plugin/plugin.json")
    assert plugin["version"] == RELEASE
    entries = [
        entry for entry in _json(".agents/plugins/marketplace.json")["plugins"]
        if entry["name"] == plugin["name"]
    ]
    assert [entry["version"] for entry in entries] == [RELEASE]
    with (REPO / "pyproject.toml").open("rb") as handle:
        assert tomllib.load(handle)["project"]["version"] == RELEASE
    assert contract.RELEASE == RELEASE
    assert _json(contract.MANIFEST_NAME)["release"] == RELEASE


def test_what_0_8_3_does_not_move():
    assert contract.PROTOCOL_VERSION == 2
    assert contract.STORAGE_GENERATION == 1
    # #54 Phase 4 deliberately adds generation 5402 to both capabilities.
    assert contract.READABLE_SCHEMAS == (0, 5401, 5402)
    assert contract.WRITABLE_SCHEMAS == (0, 5401, 5402)
    assert contract.SNAPSHOT_VERSIONS == (2,)


def test_surface_refusal_is_retired():
    """#54 Phase 4 replaced the Phase 3 surface refusal with real version-2
    surfaces; the refusal constant is gone from production code."""
    assert not hasattr(accounting, "PHASE3_SURFACE_UNSUPPORTED")


def test_changelog_has_a_0_8_3_section_above_0_8_2():
    text = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    assert text.startswith("# Changelog\n\n## ")
    assert "\n## 0.8.3\n" in text
    section = text.split("\n## 0.8.3\n", 1)[1].split("\n## 0.8.2\n", 1)[0]
    assert "\n## 0.8.2\n" in text
    assert re.search(r"^Refs #74\.$", section, re.M)
    assert not re.search(
        r"\b(close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved)"
        r" #\d+",
        section,
        re.I,
    )
    assert len([
        line for line in section.splitlines() if line.startswith("- ")
    ]) == 5
