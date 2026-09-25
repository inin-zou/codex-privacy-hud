# tests/test_versions.py
"""The three places that declare this package's version agree.

`.codex-plugin/plugin.json` is the one that matters at runtime: Codex caches
an installed plugin under `<marketplace>/<plugin>/<version>/`, so a change
shipped without a bump has no new directory to land in, and users who already
have the plugin keep running the old hooks and skills. `doctor` compares against the
same field. `.agents/plugins/marketplace.json` is what the marketplace
advertises, and `pyproject.toml` is what `pip` installs. A bump that reaches
one or two of them and not the third is the easy mistake, so the three are
compared instead of trusted.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PLUGIN_JSON = REPO / ".codex-plugin" / "plugin.json"
MARKETPLACE_JSON = REPO / ".agents" / "plugins" / "marketplace.json"
PYPROJECT = REPO / "pyproject.toml"


def _plugin_version() -> str:
    return json.loads(PLUGIN_JSON.read_text(encoding="utf-8"))["version"]


def _marketplace_version() -> str:
    marketplace = json.loads(MARKETPLACE_JSON.read_text(encoding="utf-8"))
    name = json.loads(PLUGIN_JSON.read_text(encoding="utf-8"))["name"]
    entries = [p for p in marketplace["plugins"] if p["name"] == name]
    assert len(entries) == 1, f"expected one {name!r} entry in {MARKETPLACE_JSON}"
    return entries[0]["version"]


def _pyproject_version() -> str:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_declared_versions_agree():
    versions = {
        str(PLUGIN_JSON.relative_to(REPO)): _plugin_version(),
        str(MARKETPLACE_JSON.relative_to(REPO)): _marketplace_version(),
        str(PYPROJECT.relative_to(REPO)): _pyproject_version(),
    }
    assert len(set(versions.values())) == 1, (
        f"version declarations disagree: {versions}; bump all three together")


def test_version_is_plain_semver():
    """Codex uses the version as a cache directory name, and `doctor`
    compares it as a string; a suffix like `-dev` or a leading `v` would
    make that comparison miss a copy that is really the same release."""
    assert re.fullmatch(r"\d+\.\d+\.\d+", _plugin_version())


def test_network_file_send_release_is_0_9_2():
    from privacy_hud import runtime_contract

    assert _plugin_version() == "0.9.2"
    assert _marketplace_version() == "0.9.2"
    assert _pyproject_version() == "0.9.2"
    assert runtime_contract.RELEASE == "0.9.2"
    manifest = json.loads(
        (REPO / runtime_contract.MANIFEST_NAME).read_text(encoding="utf-8")
    )
    assert manifest["release"] == "0.9.2"
