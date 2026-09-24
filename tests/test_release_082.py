# tests/test_release_082.py
"""0.8.2: the recovery release for #70 and the diagnostics for #71.

Four declarations and the build manifest name one release, the surface
refusal names the release it is shipped in, and the changelog carries a
0.8.2 section above 0.8.1 that refers to both issues without closing
either. Nothing about accounting, the schema or the snapshot moves.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from privacy_hud import accounting
from privacy_hud import runtime_contract as contract

REPO = Path(__file__).resolve().parent.parent
RELEASE = "0.8.2"


def _json(rel: str) -> dict:
    return json.loads((REPO / rel).read_text(encoding="utf-8"))


def test_every_declaration_is_0_8_2():
    plugin = _json(".codex-plugin/plugin.json")
    assert plugin["version"] == RELEASE
    entries = [p for p in _json(".agents/plugins/marketplace.json")["plugins"]
               if p["name"] == plugin["name"]]
    assert [p["version"] for p in entries] == [RELEASE]
    with (REPO / "pyproject.toml").open("rb") as handle:
        assert tomllib.load(handle)["project"]["version"] == RELEASE
    assert contract.RELEASE == RELEASE
    assert _json(contract.MANIFEST_NAME)["release"] == RELEASE


def test_what_0_8_2_does_not_move():
    assert contract.PROTOCOL_VERSION == 2
    assert contract.STORAGE_GENERATION == 1
    assert contract.READABLE_SCHEMAS == (0, 5401)
    assert contract.WRITABLE_SCHEMAS == (0, 5401)
    assert contract.SNAPSHOT_VERSIONS == (2,)


def test_surface_refusal_names_this_release():
    assert accounting.PHASE3_SURFACE_UNSUPPORTED == (
        "This Privacy HUD surface does not support version-2 accounting "
        "in 0.8.2.")


def test_changelog_has_a_0_8_2_section_above_0_8_1():
    text = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    assert text.startswith("# Changelog\n\n## 0.8.2\n")
    section = text.split("\n## 0.8.2\n", 1)[1].split("\n## 0.8.1\n", 1)[0]
    assert "\n## 0.8.1\n" in text
    assert re.search(r"^Refs #70, #71\.$", section, re.M)
    assert not re.search(r"\b(close|closes|closed|fix|fixes|fixed|resolve|"
                         r"resolves|resolved) #\d+", section, re.I)
    bullets = [line for line in section.splitlines() if line.startswith("- ")]
    assert len(bullets) >= 4
