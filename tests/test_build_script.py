# tests/test_build_script.py
"""The build script's contract, minus cargo. `--dry-run` runs every step up
to the compile and prints the plan, so argument handling and file naming are
testable in CI without a Rust toolchain or a 20-minute build."""
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "build-patched-codex.sh"


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
