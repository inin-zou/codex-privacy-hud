# tests/test_build_script.py
"""The build script's contract, minus cargo. `--dry-run` runs every step up
to the compile and prints the plan, so argument handling and file naming are
testable in CI without a Rust toolchain or a 20-minute build."""
import os
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "build-patched-codex.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "release-codex.yml"


def run(*args):
    return subprocess.run(["sh", str(SCRIPT), *args], capture_output=True, text=True)


def test_requires_a_version():
    r = run()
    assert r.returncode == 2 and "usage" in r.stderr.lower()


def test_rejects_a_non_version():
    r = run("latest")
    assert r.returncode == 2


def test_dry_run_names_tag_target_and_artifact(tmp_path):
    r = run("0.154.0", "--dry-run", "--out", str(tmp_path), "--target", "aarch64-apple-darwin")
    assert r.returncode == 0, r.stderr
    assert "rust-v0.154.0" in r.stdout
    assert "codex-privacy-0.154.0-aarch64-apple-darwin.tar.gz" in r.stdout
    assert "patches/privacy-status-line.patch" in r.stdout


def test_dry_run_does_not_call_rustc_when_target_is_given(tmp_path):
    """CI may call this before rustup is on PATH, so the host triple must be
    computed lazily: with `--target` given, `rustc` is never run. A shim that
    leaves a sentinel behind is the evidence."""
    shim = tmp_path / "bin"
    shim.mkdir()
    sentinel = tmp_path / "rustc-was-called"
    rustc = shim / "rustc"
    rustc.write_text(f'#!/bin/sh\n: > "{sentinel}"\necho "host: wrong-triple"\n')
    rustc.chmod(0o755)
    env = dict(os.environ, PATH=f"{shim}:{os.environ['PATH']}")
    r = subprocess.run(
        ["sh", str(SCRIPT), "0.154.0", "--dry-run", "--target", "x86_64-unknown-linux-gnu"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stderr
    assert not sentinel.exists(), "the script ran rustc although --target was given"
    assert "codex-privacy-0.154.0-x86_64-unknown-linux-gnu.tar.gz" in r.stdout


def test_refuses_to_reset_a_dirty_source_tree(tmp_path):
    """`--src` can name a checkout somebody is working in, and the script
    resets it before applying the patch. Uncommitted work must stop the build,
    not be discarded -- this runs before any clone or cargo."""
    src = tmp_path / "codex-src"
    src.mkdir()

    def git(*args):
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-C", str(src), *args],
            check=True, capture_output=True, text=True,
        )

    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "test")
    keep = src / "keep.txt"
    keep.write_text("committed\n")
    git("add", "keep.txt")
    git("commit", "-qm", "seed")
    keep.write_text("local work\n")

    r = run("0.154.0", "--target", "aarch64-apple-darwin",
            "--src", str(src), "--out", str(tmp_path / "out"))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "refusing" in r.stderr, r.stderr
    assert keep.read_text() == "local work\n", "the script clobbered uncommitted work"


def test_the_release_workflow_clones_before_it_warms_the_cache():
    """`Swatinem/rust-cache` keys on the Cargo.lock inside the workspace it
    is given. Pointed at a directory the build step creates later, it found
    no lockfile, fell back to a weaker key, and every release build was a
    cold one -- an invisible failure, since the build still succeeded."""
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["build"]["steps"]
    names = [s.get("name") or s.get("uses") for s in steps]
    clone = next(i for i, s in enumerate(steps)
                 if "git clone" in (s.get("run") or ""))
    cache = next(i for i, s in enumerate(steps)
                 if "rust-cache" in (s.get("uses") or ""))
    assert clone < cache, names
    # ...and at the same directory, or the cache still misses.
    workspace = steps[cache]["with"]["workspaces"]
    src = workspace[: -len("/codex-rs")]
    assert steps[clone]["run"].rstrip().endswith(f'"{src}"'), steps[clone]["run"]
