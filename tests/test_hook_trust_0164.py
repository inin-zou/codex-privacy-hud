from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from privacy_hud import codex, doctor
from hook_trust_helpers import (
    HOOKS_ONLY_CONTENT,
    LEGACY_FILENAME,
    TREE_CONTENT,
    copy_hooks,
    expected_trust,
    reference_content_hash,
    reference_legacy_path,
    write_trust,
)


@pytest.fixture
def installed(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    config_home = tmp_path / "config-home"
    config_home.mkdir()
    bundle = tmp_path / "bundle"
    copy_hooks(bundle)
    config = config_home / "config.toml"

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CODEX_HOME", str(config_home))
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    monkeypatch.setattr(
        codex, "official_codex_version", lambda: "0.164.0",
        raising=False,
    )
    entry = (codex.MARKETPLACE_NAME, "0.10.12", bundle)
    monkeypatch.setattr(
        doctor, "_installed_plugin_dirs", lambda: [entry],
    )
    monkeypatch.setattr(
        doctor, "_installed_plugin_entry", lambda entries: entries[0],
    )
    return bundle, config


def snapshot(root):
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize(
    "case,expected_status,ready",
    [
        ("modern-match", doctor.OK, 8),
        ("modern-mismatch", doctor.FAIL, 0),
        ("modern-old-baseline", doctor.OK, 8),
        ("legacy-match", doctor.OK, 8),
        ("legacy-mismatch", doctor.FAIL, 0),
        ("legacy-absent", doctor.WARN, 0),
        ("legacy-newline", doctor.FAIL, 0),
        ("declaration-mismatch", doctor.FAIL, 7),
        ("disabled", doctor.FAIL, 7),
    ],
)
def test_persisted_trust_matrix(
    installed, case, expected_status, ready,
):
    bundle, config = installed
    assert reference_content_hash(bundle) == HOOKS_ONLY_CONTENT
    hashes = expected_trust()
    key = next(iter(hashes))
    disabled = ()
    content = None if case.startswith("legacy-") else HOOKS_ONLY_CONTENT
    if case == "modern-mismatch":
        content = "sha256:" + "0" * 64
    if case == "declaration-mismatch":
        hashes[key] = "sha256:" + "1" * 64
    if case == "disabled":
        disabled = (key,)

    write_trust(
        config, hashes, disabled=disabled, content_hash=content,
    )
    baseline = reference_legacy_path(config)
    if case in {
        "legacy-match", "legacy-mismatch",
        "legacy-newline", "modern-old-baseline",
    }:
        baseline.parent.mkdir()
        value = HOOKS_ONLY_CONTENT
        if case in {"legacy-mismatch", "modern-old-baseline"}:
            value = "sha256:" + "2" * 64
        if case == "legacy-newline":
            value += "\n"
        baseline.write_bytes(value.encode("ascii"))

    before = snapshot(config.parent)
    baseline_existed = baseline.parent.exists()
    check = doctor.check_hook_trust()
    report = doctor.format_report([check])

    assert check.status == expected_status
    assert f"{ready}/8" in check.summary
    assert doctor.exit_code([check]) == (
        1 if expected_status == doctor.FAIL else 0
    )
    assert snapshot(config.parent) == before
    assert baseline.parent.exists() == baseline_existed
    if expected_status != doctor.OK:
        assert "Trust all and continue" in report
    if expected_status == doctor.WARN:
        assert "Setup is usable" not in report
        assert "Setup is healthy" not in report
    for value in (*hashes, *hashes.values(), HOOKS_ONLY_CONTENT):
        assert value not in report


def test_bundle_change_invalidates_every_content_approval(installed):
    bundle, config = installed
    write_trust(config, content_hash=HOOKS_ONLY_CONTENT)
    (bundle / "handler.py").write_text("changed\n")
    check = doctor.check_hook_trust()
    assert check.status == doctor.FAIL
    assert "0/8" in check.summary


@pytest.mark.parametrize("version", [
    "0.154.0", "0.155.1", "0.163.0", "0.164.1", "0.165.0", None,
])
def test_unimplemented_or_undetermined_version_warns(
    installed, monkeypatch, version,
):
    _, config = installed
    write_trust(config, content_hash=HOOKS_ONLY_CONTENT)
    monkeypatch.setattr(codex, "official_codex_version", lambda: version)

    def forbidden(*args, **kwargs):
        raise AssertionError("unsupported scheme must not inspect trust")

    monkeypatch.setattr(codex, "read_hook_states", forbidden)
    check = doctor.check_hook_trust()
    report = doctor.format_report([check])
    assert check.status == doctor.WARN
    assert "hook trust cannot be verified" in check.summary
    if version:
        assert f"Codex {version}" in check.summary
    assert "Trust all and continue" in report
    assert not (config.parent / ".hook-trust").exists()


def test_only_own_state_and_baseline_are_used(installed, monkeypatch):
    _, config = installed
    other_key = "OTHER-PRIVATE-PLUGIN:hooks/hooks.json:pre_tool_use:0:0"
    config.write_text(
        'api_key = "PRIVATE-API-KEY"\n'
        f'[hooks.state."{other_key}"]\n'
        'trusted_hash = "PRIVATE-DECLARATION"\n'
        'trusted_content_hash = "PRIVATE-CONTENT"\n'
        'path = "/PRIVATE/OTHER/PLUGIN"\n'
    )
    write_trust(config, content_hash=HOOKS_ONLY_CONTENT)
    directory = config.parent / ".hook-trust"
    directory.mkdir()
    other = directory / "PRIVATE-OTHER-BASELINE"
    other.write_text("PRIVATE-OTHER-BASELINE-CONTENT")
    before = snapshot(config.parent)

    original_open = Path.open

    def guarded_open(path, *args, **kwargs):
        if path == other:
            raise AssertionError("another plugin baseline was read")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    selected = codex.read_hook_states(set(expected_trust()))
    assert set(selected) == set(expected_trust())
    check = doctor.check_hook_trust()
    assert check.status == doctor.OK
    report = doctor.format_report([check])
    for secret in (
        other_key, "PRIVATE-API-KEY", "PRIVATE-DECLARATION",
        "PRIVATE-CONTENT", "/PRIVATE/OTHER/PLUGIN",
        str(other), "PRIVATE-OTHER-BASELINE-CONTENT",
        HOOKS_ONLY_CONTENT, *expected_trust(),
        *expected_trust().values(),
    ):
        assert secret not in report
    monkeypatch.setattr(Path, "open", original_open)
    assert snapshot(config.parent) == before


@pytest.mark.parametrize("field", [
    'trusted_content_hash = 123',
    'trusted_content_hash = false',
])
def test_invalid_content_field_is_redacted_failure(installed, field):
    _, config = installed
    key = next(iter(expected_trust()))
    config.write_text(
        f'[hooks.state."{key}"]\n'
        f'trusted_hash = "{expected_trust()[key]}"\n{field}\n'
    )
    check = doctor.check_hook_trust()
    assert check.status == doctor.FAIL
    assert key not in doctor.format_report([check])


@pytest.mark.parametrize("modern", [False, True])
def test_baseline_read_error_is_failure(installed, monkeypatch, modern):
    _, config = installed
    write_trust(
        config, content_hash=HOOKS_ONLY_CONTENT if modern else None,
    )
    baseline = reference_legacy_path(config)
    original_open = Path.open

    def guarded_open(path, *args, **kwargs):
        if path == baseline:
            raise PermissionError("PRIVATE-BASELINE-PATH")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    check = doctor.check_hook_trust()
    assert check.status == doctor.FAIL
    assert "PRIVATE-BASELINE-PATH" not in doctor.format_report([check])


def test_scan_timeout_is_unverified(installed, monkeypatch):
    _, config = installed
    write_trust(config, content_hash=HOOKS_ONLY_CONTENT)

    def expired(*args, **kwargs):
        raise TimeoutError("PRIVATE-BUNDLE")

    monkeypatch.setattr(
        codex, "plugin_content_hash", expired, raising=False,
    )
    check = doctor.check_hook_trust()
    assert check.status == doctor.WARN
    assert "PRIVATE-BUNDLE" not in doctor.format_report([check])


def test_content_golden_and_exclusions(tmp_path):
    (tmp_path / "a").write_bytes(b"A\n")
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "z").write_bytes(b"\x00\xff")
    (tmp_path / "é").write_bytes(b"")
    assert reference_content_hash(tmp_path) == TREE_CONTENT
    assert codex.plugin_content_hash(tmp_path) == TREE_CONTENT
    for parent in (tmp_path, tmp_path / "d"):
        for name in ("__pycache__", ".venv", "x.pyc", "x.egg-info"):
            excluded = parent / name
            excluded.mkdir()
            (excluded / "ignored").write_bytes(b"not fingerprinted")
    assert codex.plugin_content_hash(tmp_path) == TREE_CONTENT


def test_sorted_dfs_not_breadth_first(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "z").write_bytes(b"nested")
    (tmp_path / "a.txt").write_bytes(b"sibling")
    assert codex.plugin_content_hash(tmp_path) == reference_content_hash(
        tmp_path
    )


def test_non_utf8_filename_is_not_excluded_by_suffix(tmp_path):
    path = tmp_path / os.fsdecode(b"\xff.pyc")
    path.write_bytes(b"one")
    first = codex.plugin_content_hash(tmp_path)
    path.write_bytes(b"two")
    assert codex.plugin_content_hash(tmp_path) != first


@pytest.mark.parametrize("kind", ["symlink", "fifo", "root-symlink"])
def test_unsupported_entries_fail(tmp_path, kind):
    root = tmp_path / "root"
    root.mkdir()
    if kind == "symlink":
        (root / "link").symlink_to(tmp_path / "missing")
    elif kind == "fifo":
        os.mkfifo(root / "pipe")
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        root = alias
    with pytest.raises((OSError, ValueError)):
        codex.plugin_content_hash(root)


def test_legacy_filename_golden():
    config = Path("/synthetic/codex/config.toml")
    plugin_id = "codex-privacy-hud@codex-privacy-hud"
    assert codex.legacy_trust_path(config, plugin_id) == (
        config.parent / ".hook-trust" / LEGACY_FILENAME
    )


def test_explicit_home_canonicalizes_but_config_symlink_does_not(
    tmp_path, monkeypatch,
):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    target = tmp_path / "other.toml"
    target.write_text("")
    (real / "config.toml").symlink_to(target)
    monkeypatch.setenv("CODEX_HOME", str(alias))
    assert codex.trust_config_path() == real / "config.toml"


def test_default_home_is_not_canonicalized(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    real = tmp_path / "real"
    real.mkdir()
    (home / ".codex").symlink_to(real, target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    assert codex.trust_config_path() == home / ".codex" / "config.toml"


@pytest.mark.parametrize("bad_home", ["missing", "file"])
def test_invalid_explicit_home_cannot_be_used(
    tmp_path, monkeypatch, bad_home,
):
    path = tmp_path / bad_home
    if bad_home == "file":
        path.write_text("")
    monkeypatch.setenv("CODEX_HOME", str(path))
    with pytest.raises((OSError, ValueError)):
        codex.trust_config_path()


def executable(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    path.chmod(0o700)
    return path


def test_forwarders_and_aliases_are_never_executed(tmp_path, monkeypatch):
    forwarder = executable(
        tmp_path / "fwd" / "codex",
        b"#!/bin/sh\n# codex-privacy-hud forwarder\nexit 99\n",
    )
    alias = tmp_path / "alias" / "codex"
    alias.parent.mkdir()
    alias.symlink_to(forwarder)
    official = executable(
        tmp_path / "official" / "codex", b"synthetic executable\n",
    )
    monkeypatch.setenv(
        "PATH", os.pathsep.join(map(str, [
            forwarder.parent, alias.parent, official.parent,
        ])),
    )
    monkeypatch.setenv("PRIVATE_TOKEN", "must not reach child")
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        assert args == [str(official.resolve()), "--version"]
        assert kwargs == {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
            "timeout": 2.0,
            "check": False,
            "cwd": "/",
            "env": {
                "PATH": "/usr/bin:/bin",
                "HOME": "/dev/null",
                "CODEX_HOME": "/dev/null",
                "LC_ALL": "C",
                "LANG": "C",
            },
        }
        return SimpleNamespace(
            returncode=0, stdout=b"codex-cli 0.164.0\n",
        )

    monkeypatch.setattr(subprocess, "run", run)
    assert codex._probe_official_codex_version() == "0.164.0"
    assert len(calls) == 1


@pytest.mark.parametrize("mode", [
    "timeout", "failure", "malformed", "prerelease", "patched",
])
def test_version_probe_failure_is_undetermined(
    tmp_path, monkeypatch, mode,
):
    candidate = executable(tmp_path / "bin" / "codex", b"synthetic\n")
    monkeypatch.setenv("PATH", str(candidate.parent))

    def run(args, **kwargs):
        if mode == "timeout":
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        output = {
            "failure": b"codex-cli 0.164.0\n",
            "malformed": b"PRIVATE OUTPUT",
            "prerelease": b"codex-cli 0.164.0-alpha.1\n",
            "patched": b"codex-cli 0.164.0-hud\n",
        }[mode]
        return SimpleNamespace(
            returncode=1 if mode == "failure" else 0,
            stdout=output,
        )

    monkeypatch.setattr(subprocess, "run", run)
    assert codex._probe_official_codex_version() is None


def test_only_forwarder_means_no_subprocess(tmp_path, monkeypatch):
    candidate = executable(
        tmp_path / "bin" / "codex",
        b"#!/bin/sh\n# codex-privacy-hud forwarder\n",
    )
    monkeypatch.setenv("PATH", str(candidate.parent))

    def forbidden(*args, **kwargs):
        raise AssertionError("forwarder must never execute")

    monkeypatch.setattr(subprocess, "run", forbidden)
    assert codex._probe_official_codex_version() is None
