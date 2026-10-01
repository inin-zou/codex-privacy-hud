"""Offline YAML contracts for automatic plugin tagging and publication."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow():
    return yaml.safe_load(
        (ROOT / ".github/workflows/release-plugin.yml").read_text(
            encoding="utf-8"
        )
    )


def step(name):
    return next(
        item for item in workflow()["jobs"]["publish"]["steps"]
        if item.get("name") == name
    )


def test_main_and_manual_tags_share_one_serialized_workflow():
    value = workflow()
    triggers = value.get("on", value.get(True))
    assert triggers["push"] == {"branches": ["main"], "tags": ["v*"]}
    assert value["permissions"] == {"contents": "read"}
    assert value["jobs"]["publish"]["permissions"] == {"contents": "write"}
    assert value["concurrency"] == {
        "group": "release-plugin-publish",
        "cancel-in-progress": False,
        "queue": "max",
    }
    assert set(value["jobs"]) == {"publish"}


def test_checkout_and_decision_use_the_triggering_commit():
    steps = workflow()["jobs"]["publish"]["steps"]
    checkout = next(
        item for item in steps
        if item.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert checkout["with"]["fetch-depth"] == 0

    select = step("Select immutable release source")["run"]
    assert "git fetch --tags origin" in select
    assert 'git rev-parse "$GITHUB_SHA^{commit}"' in select
    assert 'release-tag-decision.py --sha "$pushed"' in select
    assert 'test "$GITHUB_REF_NAME" = "$tag"' in select
    assert 'git checkout --detach "$commit"' in select


def test_validation_precedes_tag_creation_and_publication():
    steps = workflow()["jobs"]["publish"]["steps"]
    names = [item.get("name") for item in steps]
    assert (
        names.index("Select immutable release source")
        < names.index("Build complete bundle")
        < names.index("Ensure immutable release tag")
        < names.index("Publish complete pair")
        < names.index("Verify anonymous downloads")
    )

    build = step("Build complete bundle")["run"]
    assert 'test "$RELEASE_TAG" = "v$RELEASE"' in build
    assert 'test "$(git rev-parse HEAD)" = "$RELEASE_COMMIT"' in build
    assert 'test "$GITHUB_REF_NAME" = "v$RELEASE"' not in build

    tag = step("Ensure immutable release tag")["run"]
    assert 'test "$RELEASE_COMMIT" = "$(git rev-parse "$GITHUB_SHA^{commit}")"' in tag
    assert 'gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs"' in tag
    assert '-f "ref=refs/tags/$RELEASE_TAG"' in tag
    assert '-f "sha=$RELEASE_COMMIT"' in tag
    assert 'git fetch --no-tags origin "refs/tags/$RELEASE_TAG"' in tag
    assert 'test "$(git rev-parse FETCH_HEAD^{commit})" = "$RELEASE_COMMIT"' in tag
    assert "--force" not in tag
    assert "--method PATCH" not in tag


def test_published_releases_are_preserved_and_drafts_resume():
    publish = step("Publish complete pair")["run"]
    assert "--json isDraft,assets" in publish
    assert 'if [ "$draft" = false ]; then' in publish
    assert publish.index('if [ "$draft" = false ]; then') < publish.index(
        "release upload"
    )
    assert "Published release preserved" in publish
    assert "exit 0" in publish
    assert "--verify-tag --draft" in publish
    assert 'asset["name"] == sys.argv[1]' in publish
    assert 'cmp "$artifact" "existing/$name"' in publish
    assert 'gh release upload "$tag"' in publish
    assert "--clobber" not in publish
    assert "release delete" not in publish
    assert publish.index('cmp "dist/$ART.sha256"') < publish.index(
        "--draft=false"
    )

    verify = step("Verify anonymous downloads")
    assert verify["env"] == {"GH_TOKEN": ""}
    assert 'sha256sum -c "$ART.sha256"' in verify["run"]


def test_release_helper_is_outside_runtime_manifest_scope():
    from privacy_hud import runtime_contract

    assert "scripts/release-tag-decision.py" not in (
        runtime_contract.covered_files(ROOT)
    )
