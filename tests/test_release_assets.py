# tests/test_release_assets.py
"""The four files a released version must carry, pinned across the four
places that name them.

`install.sh` downloads `codex-privacy-<ver>-<triple>.tar.gz` and its
`.sha256` for the triple it derives from `uname`.
`scripts/build-patched-codex.sh` produces that pair. `release-codex.yml`
builds one pair per matrix target and refuses to publish without all four.
`track-upstream.yml` calls a version done only when all four are on a
published release.

They agree today by hand. Add a third target to the matrix, or rename the
archive, and the two workflows would be checking for files nobody builds --
a check that cannot fail, which is the shape of the gap these two workflows
were just changed to close (#45).
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
INSTALL = ROOT / "install.sh"
BUILD = ROOT / "scripts" / "build-patched-codex.sh"
RELEASE = ROOT / ".github" / "workflows" / "release-codex.yml"
TRACK = ROOT / ".github" / "workflows" / "track-upstream.yml"

# codex-privacy-<version>-<triple>.tar.gz, however the two variables happen
# to be spelled by the file doing the naming ($VER/$TRIPLE, $VER/$TARGET,
# $VER/$triple).
ARCHIVE = re.compile(r"codex-privacy-\$\{?\w+\}?-\$\{?\w+\}?\.tar\.gz")
VARIABLE = re.compile(r"\$\{?\w+\}?")

# Both workflows walk the targets the same way; the loop is where a new
# target would have to be added and is the thing that silently would not be.
TRIPLE_LOOP = re.compile(r"for triple in ([^\n;]+); do")

# `for name in "<archive>" "<archive>.sha256"` -- the backreference is the
# point: it pins the checksum to the archive beside it, not merely to the
# file existing somewhere in the workflow.
NAME_LOOP = re.compile(r'for name in "(codex-privacy-[^"]+\.tar\.gz)" "\1\.sha256"; do')


def matrix_triples():
    yaml = pytest.importorskip("yaml")
    matrix = yaml.safe_load(RELEASE.read_text())["jobs"]["build"]["strategy"]["matrix"]
    return sorted(entry["target"] for entry in matrix["include"])


def test_install_sh_asks_for_exactly_the_targets_we_build():
    body = INSTALL.read_text()
    fn = body[body.index("target() {"):body.index("first_codex_on_path")]
    emitted = sorted(re.findall(r"^\s*\S+\)\s+echo (\S+) ;;", fn, re.M))
    assert emitted == matrix_triples(), fn


def test_both_workflows_check_exactly_the_targets_we_build():
    want = matrix_triples()
    for path in (RELEASE, TRACK):
        loops = TRIPLE_LOOP.findall(path.read_text())
        assert loops, f"{path.name} checks no targets at all"
        for loop in loops:
            assert sorted(loop.split()) == want, (path.name, loop)


def test_every_file_spells_the_archive_the_same_way():
    spellings = {}
    for path in (INSTALL, BUILD, RELEASE, TRACK):
        names = {VARIABLE.sub("<>", m) for m in ARCHIVE.findall(path.read_text())}
        assert names, f"{path.name} never names the archive"
        spellings[path.name] = names
    assert set().union(*spellings.values()) == {"codex-privacy-<>-<>.tar.gz"}, spellings


def test_no_workflow_checks_for_an_archive_without_its_checksum():
    """install.sh dies -- `checksum file for $ART not found; not installing`
    -- rather than install an archive whose .sha256 is absent. So publishing
    the archives alone is worse than publishing nothing: it bypasses the
    graceful `no patched build published` path and breaks the install
    outright. Neither workflow may treat an archive as sufficient on its
    own."""
    for path in (RELEASE, TRACK):
        text = path.read_text()
        pairs, triples = len(NAME_LOOP.findall(text)), len(TRIPLE_LOOP.findall(text))
        # Both counts zero would satisfy the equality while meaning the
        # workflow checks nothing at all -- the vacuous pass this file exists
        # to refuse.
        assert pairs > 0, f"{path.name} names no archive/checksum pair"
        assert pairs == triples, (path.name, pairs, triples)
