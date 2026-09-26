"""Repository metadata and immutable GitHub Action references."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/inin-zou/codex-privacy-hud"


def test_security_policy_exists_without_recall_or_guarantee_copy():
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert text.strip()
    for phrase in (
        "undo",
        "revoke",
        "remove from context",
        "your data is protected",
        "100% secure",
    ):
        assert phrase not in text.casefold(), phrase


def test_plugin_metadata_matches_project_identity():
    manifest = json.loads(
        (ROOT / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
    )
    project = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")

    assert manifest["author"] == {"name": "Yongkang Zou"}
    assert manifest["homepage"] == REPOSITORY
    assert manifest["repository"] == REPOSITORY
    assert manifest["license"] == project["project"]["license"] == "MIT"
    assert license_text.startswith(
        "MIT License\n\nCopyright (c) 2026 Yongkang Zou\n"
    )
    keywords = manifest["keywords"]
    assert isinstance(keywords, list) and keywords
    assert all(isinstance(word, str) and word.strip() for word in keywords)
    assert len(keywords) == len(set(keywords))


def test_remote_actions_and_reusable_workflows_use_full_commit_shas():
    workflows = sorted(
        path
        for path in (ROOT / ".github/workflows").iterdir()
        if path.suffix in {".yml", ".yaml"}
    )
    assert workflows
    remote_count = 0
    for path in workflows:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in workflow["jobs"].items():
            references = []
            if "uses" in job:
                references.append(job["uses"])
            references.extend(
                step["uses"]
                for step in job.get("steps", [])
                if "uses" in step
            )
            for reference in references:
                assert isinstance(reference, str), (path, job_name)
                if reference.startswith("./"):
                    continue
                remote_count += 1
                assert re.fullmatch(
                    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}",
                    reference,
                ), (path.name, job_name, reference)
    assert remote_count > 0
