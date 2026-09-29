#!/usr/bin/env python3
"""Decide whether an immutable plugin release tag may be created.

No network calls or Git mutations.

Input tags contain names and peeled commit IDs. "already-released" means
the tag exists; publication state must still be checked by the workflow.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tomllib
from pathlib import Path

VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
SHA = r"[0-9a-f]{40}"


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args],
        text=True,
        stderr=subprocess.PIPE,
    ).strip()


def declared_version(root: Path) -> str:
    plugin = json.loads(
        (root / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
    )
    market = json.loads(
        (root / ".agents/plugins/marketplace.json").read_text(encoding="utf-8")
    )
    release = tomllib.loads(
        (root / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    manifest = json.loads(
        (root / "runtime-build.json").read_text(encoding="utf-8")
    )

    if not isinstance(release, str) or not re.fullmatch(VERSION, release):
        raise ValueError("noncanonical declared release version")
    if plugin["version"] != release or manifest["release"] != release:
        raise ValueError("declared versions disagree")
    if [
        item["version"] for item in market["plugins"]
        if item["name"] == plugin["name"]
    ] != [release]:
        raise ValueError("marketplace version disagrees or is not unique")
    if re.findall(
        r'^RELEASE="([^"]+)"$',
        (root / "install.sh").read_text(encoding="utf-8"),
        re.M,
    ) != [release]:
        raise ValueError("installer version disagrees or is not unique")
    return release


def local_tags(root: Path) -> list[dict[str, str]]:
    """Read freshly fetched local refs, peeling annotated tags to commits."""
    names = git(root, "for-each-ref", "--format=%(refname:strip=2)", "refs/tags")
    return [
        {
            "name": name,
            "commit": git(root, "rev-parse", f"refs/tags/{name}^{{commit}}"),
        }
        for name in names.splitlines()
        if name.startswith("v")
    ]


def decide(root: Path, tags: list[dict[str, str]], pushed_sha: str) -> dict:
    try:
        release = declared_version(root)
        if not re.fullmatch(SHA, pushed_sha):
            raise ValueError("invalid pushed commit ID")
        if git(root, "rev-parse", "HEAD") != pushed_sha:
            raise ValueError("checkout does not match pushed commit")

        existing = {}
        for item in tags:
            name = item["name"]
            if not isinstance(name, str):
                raise ValueError("invalid tag name")
            if not name.startswith("v"):
                continue
            if not re.fullmatch("v" + VERSION, name):
                raise ValueError(f"noncanonical plugin tag: {name}")
            commit = item["commit"]
            if not isinstance(commit, str) or not re.fullmatch(SHA, commit):
                raise ValueError(f"invalid peeled commit for {name}")
            if name in existing:
                raise ValueError(f"duplicate tag input: {name}")
            existing[name] = commit

        tag = "v" + release
        if tag in existing:
            commit = existing[tag]
            ancestry = subprocess.run(
                [
                    "git", "-C", str(root), "merge-base", "--is-ancestor",
                    commit, pushed_sha,
                ],
                capture_output=True,
                check=False,
            )
            if ancestry.returncode != 0:
                raise ValueError(
                    "existing tag is not a verified ancestor of pushed commit"
                )
            return {
                "action": "already-released",
                "tag": tag,
                "commit": commit,
                "reason": "existing tag preserved; release state not checked",
            }

        version = tuple(map(int, release.split(".")))
        if any(
            tuple(map(int, name[1:].split("."))) >= version
            for name in existing
        ):
            raise ValueError("missing release tag is not newer than existing tags")

        return {
            "action": "create",
            "tag": tag,
            "commit": pushed_sha,
            "reason": "consistent new release at pushed commit",
        }
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        return {"action": "refuse", "reason": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--sha", required=True)
    parser.add_argument("--tags-json", type=Path)
    args = parser.parse_args()

    try:
        tags = (
            json.loads(args.tags_json.read_text(encoding="utf-8"))
            if args.tags_json else local_tags(args.repo)
        )
        if not isinstance(tags, list):
            raise ValueError("tags input must be a list")
        result = decide(args.repo, tags, args.sha)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        result = {"action": "refuse", "reason": str(exc)}

    print(json.dumps(result, sort_keys=True))
    return 1 if result["action"] == "refuse" else 0


if __name__ == "__main__":
    raise SystemExit(main())
