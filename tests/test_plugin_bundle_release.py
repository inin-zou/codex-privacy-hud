"""Offline producer/consumer contract for the plugin source release."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_plugin_release_workflow_publishes_the_pinned_pair():
    path = ROOT / ".github/workflows/release-plugin.yml"
    workflow = yaml.safe_load(path.read_text())
    # PyYAML's YAML 1.1 loader interprets unquoted "on" as True.
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["push"]["tags"] == ["v*"]

    steps = workflow["jobs"]["publish"]["steps"]
    build = next(step["run"] for step in steps
                 if step.get("name") == "Build complete bundle")
    publish = next(step["run"] for step in steps
                   if step.get("name") == "Publish complete pair")
    verify = next(step["run"] for step in steps
                  if step.get("name") == "Verify anonymous downloads")

    assert "build-runtime-manifest.py --check" in build
    assert 'git archive --format=tar --prefix="$prefix/" HEAD' in build
    assert 'ART="codex-privacy-hud-$RELEASE.tar.gz"' in build
    assert 'sha256sum "$ART" > "$ART.sha256"' in build
    assert '"dist/$ART" "dist/$ART.sha256"' in publish
    assert "--draft" in publish
    assert publish.index("release upload") < publish.index("--draft=false")
    assert "--clobber" not in publish
    assert 'sha256sum -c "$ART.sha256"' in verify

    installer = (ROOT / "install.sh").read_text()
    assert 'BUNDLE_ART="codex-privacy-hud-$RELEASE.tar.gz"' in installer
    assert '$BASE_URL/v$RELEASE/$BUNDLE_ART' in installer
