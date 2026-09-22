"""The patched Codex reader, executed.

`privacy_status.rs` is a new file in `patches/privacy-status-line.patch`.
These tests take it out of the patch and run its own unit tests in a
scratch crate, with the two goldens it embeds beside it. That runs the
reader's parsing and rendering against `tests/matrix/hud_reading_golden.json`
in Rust, not only Python assertions about the patch text. It does not build
or test `codex-tui`, and it does not check that the patch applies upstream
(`patch-health.yml` does).

Compiling needs `cargo` and the `serde_json` and `tempfile` crates, so it
runs when `PRIVACY_HUD_RUST_TESTS=1`; CI's `rust-status` job sets it.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PATCH = (ROOT / "patches" / "privacy-status-line.patch").read_text(
    encoding="utf-8")
MATRIX = ROOT / "tests" / "matrix"


def added_file(name: str) -> str:
    """The full text of a file the patch adds, reconstructed from its hunk."""
    lines = PATCH.splitlines()
    starts = [i for i, line in enumerate(lines)
              if line.startswith("+++ ") and line.endswith("/" + name)]
    assert len(starts) == 1, f"patch must add {name} exactly once"
    body = lines[starts[0] + 1:]
    end = next((i for i, line in enumerate(body)
                if line.startswith("diff --git")), len(body))
    return "\n".join(line[1:] for line in body[:end]
                     if line.startswith("+")) + "\n"


def test_patch_embeds_the_reading_golden():
    assert added_file("privacy_status_reading_golden.json") == \
        (MATRIX / "hud_reading_golden.json").read_text(encoding="utf-8")


def test_the_reader_runs_the_reading_golden():
    source = added_file("privacy_status.rs")
    assert 'include_str!("privacy_status_reading_golden.json")' in source
    assert "fn every_reading_golden_case_renders" in source


needs_rust = pytest.mark.skipif(
    os.environ.get("PRIVACY_HUD_RUST_TESTS") != "1"
    or shutil.which("cargo") is None,
    reason="set PRIVACY_HUD_RUST_TESTS=1 with cargo installed")

_CARGO_TOML = """\
[package]
name = "privacy_status_scratch"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
path = "src/lib.rs"

[dependencies]
serde_json = "1"

[dev-dependencies]
tempfile = "3"
"""


@needs_rust
def test_rust_reader_unit_tests_pass(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (tmp_path / "Cargo.toml").write_text(_CARGO_TOML, encoding="utf-8")
    (src / "lib.rs").write_text("#![allow(dead_code)]\nmod privacy_status;\n",
                                encoding="utf-8")
    for name in ("privacy_status.rs", "privacy_status_golden.json",
                 "privacy_status_reading_golden.json"):
        (src / name).write_text(added_file(name), encoding="utf-8")
    proc = subprocess.run(
        ["cargo", "test", "--quiet"], cwd=tmp_path, capture_output=True,
        text=True, timeout=900,
        env={**os.environ, "CARGO_TARGET_DIR": str(tmp_path / "target")})
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-4000:]
