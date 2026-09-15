# tests/test_install_sh.py
"""install.sh and --uninstall in a throwaway HOME (spec §5.6).

A fake `codex` on PATH reports a version; a fake release directory served
over file:// carries a tarball for that version. PRIVACY_HUD_FAKE=1 skips the
venv, model, plugin and setup steps -- they need the network and a real
Codex -- so what is tested here is the part that touches the user's
filesystem: the forwarder, the manifest, config.toml, PATH, and that
uninstall restores the tree exactly.

The tarball and its .sha256 live under rel/"latest" -- the installer tries
"$BASE_URL/codex-<ver>-hud/<artifact>" first (the version-pinned release,
not present in this fixture) and falls back to "$BASE_URL/latest/<artifact>"
(the rolling release Task 11 publishes), so the fixture only serves the
second URL.
"""
import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

INSTALL = Path(__file__).parents[1] / "install.sh"
VER = "0.154.0"
TRIPLE = "aarch64-apple-darwin"


def _tree(root: Path):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "home"; home.mkdir()
    bin_ = tmp_path / "officialbin"; bin_.mkdir()
    fake = bin_ / "codex"
    fake.write_text(f'#!/bin/sh\n[ "$1" = --version ] && echo "codex-cli {VER}" && exit 0\necho official "$@"\n')
    fake.chmod(0o755)
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text('model = "gpt-5.4"\n')
    (home / ".zshrc").write_text("# user rc\n")
    # a "release" the installer can download -- served under rel/"latest"
    rel = tmp_path / "release"; rel.mkdir()
    latest = rel / "latest"; latest.mkdir()
    patched = tmp_path / "codex-patched"
    patched.write_text('#!/bin/sh\necho patched "$@"\n'); patched.chmod(0o755)
    tgz = latest / f"codex-privacy-{VER}-{TRIPLE}.tar.gz"
    with tarfile.open(tgz, "w:gz") as t:
        t.add(patched, arcname="codex")
    (latest / f"{tgz.name}.sha256").write_text(f"{hashlib.sha256(tgz.read_bytes()).hexdigest()}  {tgz.name}\n")
    env = {"HOME": str(home), "PATH": f"{bin_}:/usr/bin:/bin", "SHELL": "/bin/zsh",
           "PRIVACY_HUD_FAKE": "1", "PRIVACY_HUD_TARGET": TRIPLE}
    return home, env, rel


def run(env, *args):
    return subprocess.run(["sh", str(INSTALL), *args], capture_output=True, text=True, env=env)


def test_install_then_uninstall_restores_the_tree(home):
    home, env, rel = home
    before = _tree(home)
    r = run(env, "--yes", "--release-base-url", rel.as_uri())
    assert r.returncode == 0, r.stderr
    fwd = home / ".local/bin/codex"
    assert fwd.exists() and "codex-privacy-hud forwarder" in fwd.read_text()
    assert (home / f".local/share/codex-privacy-hud/{VER}/codex").exists()
    m = json.loads((home / ".local/share/codex-privacy-hud/manifest.json").read_text())
    assert m["codex_version"] == VER and str(fwd) in m["created"]
    assert "privacy" in (home / ".codex/config.toml").read_text()
    assert "# codex-privacy-hud" in (home / ".zshrc").read_text()

    r = run(env, "--uninstall")
    assert r.returncode == 0, r.stderr
    assert _tree(home) == before
    assert (home / ".codex/config.toml").read_text() == 'model = "gpt-5.4"\n'
    assert (home / ".zshrc").read_text() == "# user rc\n"


def test_existing_tui_table_gets_only_the_key(home):
    home, env, rel = home
    cfg = home / ".codex/config.toml"
    cfg.write_text('[tui]\ntheme = "dark"\n')
    run(env, "--yes", "--release-base-url", rel.as_uri())
    assert cfg.read_text().count("[tui]") == 1 and "privacy" in cfg.read_text()
    run(env, "--uninstall")
    assert cfg.read_text() == '[tui]\ntheme = "dark"\n'


def test_forwarder_runs_patched_when_versions_match(home):
    home, env, rel = home
    run(env, "--yes", "--release-base-url", rel.as_uri())
    out = subprocess.run([str(home / ".local/bin/codex"), "hello"], capture_output=True, text=True, env=env)
    assert out.stdout.strip() == "patched hello"


def test_forwarder_falls_through_when_no_build_matches(home):
    home, env, rel = home
    run(env, "--yes", "--release-base-url", rel.as_uri())
    # simulate `brew upgrade codex`: the official binary now reports a newer version
    official = Path(env["PATH"].split(":")[0]) / "codex"
    official.write_text('#!/bin/sh\n[ "$1" = --version ] && echo "codex-cli 0.155.0" && exit 0\necho official "$@"\n')
    out = subprocess.run([str(home / ".local/bin/codex"), "hello"], capture_output=True, text=True, env=env)
    assert out.stdout.strip() == "official hello"


def test_uninstall_refuses_a_forwarder_it_did_not_write(home):
    home, env, rel = home
    run(env, "--yes", "--release-base-url", rel.as_uri())
    (home / ".local/bin/codex").write_text("#!/bin/sh\necho mine\n")
    r = run(env, "--uninstall")
    assert r.returncode != 0 and "not ours" in r.stderr
    assert (home / ".local/bin/codex").read_text() == "#!/bin/sh\necho mine\n"


def test_checksum_mismatch_aborts_before_installing(home):
    home, env, rel = home
    (rel / "latest" / f"codex-privacy-{VER}-{TRIPLE}.tar.gz.sha256").write_text("0" * 64 + "  x\n")
    r = run(env, "--yes", "--release-base-url", rel.as_uri())
    assert r.returncode != 0 and "checksum" in r.stderr.lower()
    assert not (home / ".local/bin/codex").exists()


def test_missing_release_continues_without_forwarder(home):
    home, env, rel = home
    for p in (rel / "latest").iterdir():
        p.unlink()
    r = run(env, "--yes", "--release-base-url", rel.as_uri())
    assert r.returncode == 0, r.stderr
    assert "no patched build" in r.stdout.lower()
    assert not (home / ".local/bin/codex").exists()


def test_missing_sha256_aborts_before_installing(home):
    # The tarball is there but its .sha256 is not (a partial/broken release
    # publish) -- the OR-chain of both .sha256 fetch attempts must not be
    # allowed to fail bare under `set -e`; it has to be caught and reported.
    home, env, rel = home
    (rel / "latest" / f"codex-privacy-{VER}-{TRIPLE}.tar.gz.sha256").unlink()
    r = run(env, "--yes", "--release-base-url", rel.as_uri())
    assert r.returncode != 0 and "checksum" in r.stderr.lower()
    assert not (home / ".local/bin/codex").exists()


def test_second_install_preserves_created_table_marker_for_uninstall(home):
    # Installing twice (e.g. re-running after a codex point release with the
    # same version) must not lose track of the fact that WE created the
    # [tui] table the first time -- uninstall still has to be able to
    # reverse it.
    home, env, rel = home
    run(env, "--yes", "--release-base-url", rel.as_uri())
    r = run(env, "--yes", "--release-base-url", rel.as_uri())
    assert r.returncode == 0, r.stderr
    r = run(env, "--uninstall")
    assert r.returncode == 0, r.stderr
    assert (home / ".codex/config.toml").read_text() == 'model = "gpt-5.4"\n'


def test_uninstall_leaves_preexisting_privacy_config_untouched(home):
    # If the user's config.toml already listed "privacy" before we ever
    # touched it, install must not claim credit for that edit, and uninstall
    # must leave it exactly as the user wrote it.
    home, env, rel = home
    cfg = home / ".codex/config.toml"
    cfg.write_text('[tui]\nstatus_line = ["model-with-reasoning", "privacy"]\n')
    r = run(env, "--yes", "--release-base-url", rel.as_uri())
    assert r.returncode == 0, r.stderr
    r = run(env, "--uninstall")
    assert r.returncode == 0, r.stderr
    assert cfg.read_text() == '[tui]\nstatus_line = ["model-with-reasoning", "privacy"]\n'


def test_uninstall_keeps_tui_header_when_user_added_a_key(home):
    # We created the [tui] table; the user later added their own key under
    # it. Uninstall must drop only our status_line line, not the header the
    # user's own key now depends on.
    home, env, rel = home
    r = run(env, "--yes", "--release-base-url", rel.as_uri())
    assert r.returncode == 0, r.stderr
    cfg = home / ".codex/config.toml"
    cfg.write_text(cfg.read_text().rstrip("\n") + '\ntheme = "dark"\n')
    r = run(env, "--uninstall")
    assert r.returncode == 0, r.stderr
    assert cfg.read_text() == 'model = "gpt-5.4"\n[tui]\ntheme = "dark"\n'


def test_purge_without_uninstall_is_a_usage_error(home):
    home, env, rel = home
    r = run(env, "--purge")
    assert r.returncode == 2
