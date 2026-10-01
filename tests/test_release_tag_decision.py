"""Offline release-tag decisions using synthetic repositories only."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/release-tag-decision.py"
VERSION = "0.10.7"


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args],
        text=True,
        stderr=subprocess.PIPE,
    ).strip()


def write_release(root, version=VERSION):
    files = {
        "install.sh": f'RELEASE="{version}"\n',
        "runtime-build.json": json.dumps({"release": version}),
        ".codex-plugin/plugin.json": json.dumps({
            "name": "codex-privacy-hud",
            "version": version,
        }),
        ".agents/plugins/marketplace.json": json.dumps({
            "plugins": [{
                "name": "codex-privacy-hud",
                "version": version,
            }],
        }),
        "pyproject.toml": f'[project]\nversion = "{version}"\n',
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    # Do not inherit Git configuration, identities, hooks, or repository paths.
    for name in tuple(os.environ):
        if name.startswith("GIT_"):
            monkeypatch.delenv(name)
    for name, value in {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "Synthetic Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Synthetic Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    }.items():
        monkeypatch.setenv(name, value)

    root = tmp_path / "repo"
    root.mkdir()
    git(root, "-c", "init.templateDir=", "init", "-b", "main")
    write_release(root)
    git(root, "add", ".")
    git(root, "commit", "-m", "Synthetic initial release")
    first = git(root, "rev-parse", "HEAD")
    git(root, "commit", "--allow-empty", "-m", "Synthetic later commit")
    second = git(root, "rev-parse", "HEAD")
    return root, first, second


@pytest.fixture
def decision():
    # Loading inside a fixture makes the missing implementation a test failure,
    # rather than preventing collection of the other RED tests.
    spec = importlib.util.spec_from_file_location("release_tag_decision", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_create_uses_pushed_commit_and_numeric_version_order(repo, decision):
    root, first, pushed = repo
    tags = [
        {"name": "v0.9.99", "commit": first},
        {"name": "codex-99.0.0-hud", "commit": first},
        {"name": "latest", "commit": first},
    ]
    result = decision.decide(root, tags, pushed)
    assert result["action"] == "create"
    assert result["tag"] == "v0.10.7"
    assert result["commit"] == pushed
    assert result["reason"]


@pytest.mark.parametrize("use_ancestor", [False, True])
def test_existing_tag_is_preserved(repo, decision, use_ancestor):
    root, first, pushed = repo
    tagged = first if use_ancestor else pushed
    result = decision.decide(
        root, [{"name": "v0.10.7", "commit": tagged}], pushed
    )
    assert result["action"] == "already-released"
    assert result["commit"] == tagged
    assert "release state not checked" in result["reason"]


def test_existing_version_can_be_revisited_after_a_newer_release(repo, decision):
    root, first, pushed = repo
    result = decision.decide(root, [
        {"name": "v0.10.7", "commit": first},
        {"name": "v0.10.8", "commit": pushed},
    ], pushed)
    assert result["action"] == "already-released"
    assert result["commit"] == first


def test_missing_older_version_is_refused(repo, decision):
    root, first, pushed = repo
    result = decision.decide(
        root, [{"name": "v0.10.8", "commit": first}], pushed
    )
    assert result["action"] == "refuse"
    assert "newer" in result["reason"]


@pytest.mark.parametrize("name", ["v0.010.7", "v0.10.7-rc1", "vbroken"])
def test_noncanonical_plugin_tag_is_refused(repo, decision, name):
    root, first, pushed = repo
    result = decision.decide(root, [{"name": name, "commit": first}], pushed)
    assert result["action"] == "refuse"
    assert "noncanonical" in result["reason"]


@pytest.mark.parametrize("version", [
    "0.010.7", "v0.10.7", "0.10.7-rc1", "0.10", "０.10.7",
])
def test_noncanonical_declared_version_is_refused(repo, decision, version):
    root, _, pushed = repo
    write_release(root, version)
    assert decision.decide(root, [], pushed)["action"] == "refuse"


@pytest.mark.parametrize("relative", [
    "install.sh",
    "runtime-build.json",
    ".codex-plugin/plugin.json",
    ".agents/plugins/marketplace.json",
    "pyproject.toml",
])
def test_each_disagreeing_declaration_is_refused(repo, decision, relative):
    root, _, pushed = repo
    path = root / relative
    path.write_text(
        path.read_text(encoding="utf-8").replace(VERSION, "0.10.8"),
        encoding="utf-8",
    )
    # Disagreement must fail even when the matching tag already exists.
    result = decision.decide(
        root, [{"name": "v0.10.7", "commit": pushed}], pushed
    )
    assert result["action"] == "refuse"


@pytest.mark.parametrize("kind", ["installer", "marketplace"])
def test_duplicate_declaration_is_refused(repo, decision, kind):
    root, _, pushed = repo
    if kind == "installer":
        path = root / "install.sh"
        path.write_text(f'RELEASE="{VERSION}"\n' * 2, encoding="utf-8")
    else:
        path = root / ".agents/plugins/marketplace.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["plugins"] *= 2
        path.write_text(json.dumps(value), encoding="utf-8")
    assert decision.decide(root, [], pushed)["action"] == "refuse"


def test_descendant_tag_is_refused(repo, decision):
    root, first, second = repo
    git(root, "checkout", "--detach", first)
    result = decision.decide(
        root, [{"name": "v0.10.7", "commit": second}], first
    )
    assert result["action"] == "refuse"
    assert "ancestor" in result["reason"]


def test_unrelated_tag_is_refused(repo, decision):
    root, _, pushed = repo
    git(root, "checkout", "--orphan", "unrelated")
    git(root, "commit", "-m", "Synthetic unrelated history")
    unrelated = git(root, "rev-parse", "HEAD")
    git(root, "checkout", "--detach", pushed)
    result = decision.decide(
        root, [{"name": "v0.10.7", "commit": unrelated}], pushed
    )
    assert result["action"] == "refuse"
    assert "ancestor" in result["reason"]


def test_checkout_must_match_pushed_commit(repo, decision):
    root, first, _ = repo
    result = decision.decide(root, [], first)
    assert result["action"] == "refuse"
    assert "checkout" in result["reason"]


def test_local_annotated_tags_are_peeled(repo, decision):
    root, first, _ = repo
    git(root, "tag", "-a", "v0.10.6", first, "-m", "Synthetic tag")
    assert decision.local_tags(root) == [
        {"name": "v0.10.6", "commit": first},
    ]


def test_duplicate_tag_input_is_refused(repo, decision):
    root, first, pushed = repo
    tags = [
        {"name": "v0.10.7", "commit": first},
        {"name": "v0.10.7", "commit": pushed},
    ]
    assert decision.decide(root, tags, pushed)["action"] == "refuse"


@pytest.mark.parametrize("refuse", [False, True])
def test_cli_json_and_exit_status(repo, tmp_path, refuse):
    root, first, pushed = repo
    tags_path = tmp_path / "tags.json"
    tags_path.write_text(json.dumps(
        [{"name": "v0.10.8", "commit": first}] if refuse else []
    ), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable, str(SCRIPT),
            "--repo", str(root),
            "--sha", pushed,
            "--tags-json", str(tags_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == (1 if refuse else 0), result.stderr
    value = json.loads(result.stdout)
    assert value["action"] == ("refuse" if refuse else "create")
