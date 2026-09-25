from __future__ import annotations

import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]

FAST_REQUIRED = {
    "tests/test_issue47_docs_contract.py",
    "tests/test_versions.py",
    "tests/test_copy_promises.py",
    "tests/test_release_093.py",
    "tests/test_origin.py",
    "tests/test_accounting_identity.py",
    "tests/test_accounting_profile.py",
    "tests/test_accounting_ledger.py",
    "tests/test_accounting_sequences.py",
    "tests/test_shell_identity_unresolved.py",
    "tests/test_utest_infrastructure.py",
}

CLOSING = (
    r"(^|[^[:alnum:]_])"
    r"(close[sd]?|fix(e[sd])?|resolve[sd]?):?[[:space:]]+"
    r"([[:alnum:]_.-]+/[[:alnum:]_.-]+)?"
    r"#[0-9]+([^[:alnum:]_]|$)"
)


def load_script(relative):
    return runpy.run_path(str(ROOT / relative))


def patterns(text):
    return re.findall(r"grep -qiE '([^']+)'", text)


def test_message_patterns_match_ci_exactly():
    hook = (ROOT / ".githooks/commit-msg").read_text()
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    assert patterns(hook) == patterns(ci)
    assert len(patterns(hook)) == 2
    assert patterns(hook)[1] == CLOSING
    assert 'git rev-list --no-merges "$base..$HEAD_SHA"' not in ci


@pytest.mark.parametrize(
    ("message", "rejected"),
    [
        ("chore: add test tiers\n", False),
        ("fixes a race\n", False),
        ("resolve parser ambiguity\n", False),
        ("Refs #123.\n", False),
        ("discloses #123\n", False),
        ("prefix_fixes #123\n", False),
        ("fix #123suffix\n", False),
        ("close #1\n", True),
        ("CLOSES #12\n", True),
        ("closed owner/repo#123\n", True),
        ("fix #1\n", True),
        ("Fixes: owner/repo#123\n", True),
        ("fixed #1\n", True),
        ("resolve #1\n", True),
        ("resolves #1\n", True),
        ("resolved #1\n", True),
        ("subject\n\nThis resolves owner/repo#42.\n", True),
        ("subject\n\nAssisted-By: tool\n", True),
        ("subject\n\nGenerated-By: tool\n", True),
        ("subject\n\nCo-authored-by: Codex <bot@example.test>\n", True),
        ("subject\n\nClaude-Session: example\n", True),
    ],
)
def test_commit_message_behavior(tmp_path, message, rejected):
    path = tmp_path / "message"
    path.write_text(message)
    result = subprocess.run(
        ["sh", str(ROOT / ".githooks/commit-msg"), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == int(rejected), result.stderr


@pytest.mark.parametrize("name", ["pre-commit", "commit-msg"])
def test_hooks_are_executable_posix_shell(name):
    path = ROOT / ".githooks" / name
    assert path.stat().st_mode & 0o111
    assert path.read_text().startswith("#!/bin/sh\n")
    subprocess.run(["sh", "-n", str(path)], check=True)


def test_slow_manifest_and_required_fast_files():
    policy = load_script("tests/tier_policy.py")
    slow = policy["load_slow_files"]()
    assert not FAST_REQUIRED.intersection(slow)
    assert "tests/test_daemon.py" in slow
    assert "tests/test_issue54_dry_run.py" in slow
    assert "tests/test_codex_integration.py" in slow
    assert "tests/detect/test_model.py" in slow

    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    options = config["tool"]["pytest"]["ini_options"]
    assert any(m.startswith("slow:") for m in options["markers"])
    assert "addopts" not in options


def test_slow_manifest_rejects_duplicates_and_stale_paths(tmp_path):
    policy = load_script("tests/tier_policy.py")
    manifest = tmp_path / "slow.json"
    existing = "tests/test_daemon.py"
    for entries in ([existing, existing], ["tests/not_present_utest.py"]):
        manifest.write_text(json.dumps(entries))
        with pytest.raises(pytest.UsageError):
            policy["load_slow_files"](manifest)


def test_collection_marks_every_parameter_and_keeps_fast_items():
    policy = load_script("tests/tier_policy.py")
    items = []
    for nodeid in (
        "tests/test_daemon.py::test_example[a]",
        "tests/test_daemon.py::test_example[b]",
        "tests/test_origin.py::test_example",
    ):
        marks = []
        items.append(SimpleNamespace(nodeid=nodeid, add_marker=marks.append, marks=marks))
    policy["mark_slow_items"](items)
    assert [len(item.marks) for item in items] == [1, 1, 0]
    assert items[0].marks[0].name == "slow"


def test_fast_runner_selection_and_budget():
    runner = load_script("scripts/test-fast.py")
    assert runner["PYTEST_ARGS"] == [
        "-q", "-p", "no:cacheprovider", "-m", "not slow",
        "--durations=10", "tests",
    ]

    for elapsed, initial, expected in (
        (119.0, 0, 0),
        (121.0, 0, 1),
        (121.0, 2, 2),
    ):
        times = iter([0.0, elapsed])
        budget = runner["FastBudget"](clock=lambda: next(times))
        lines = []
        reporter = SimpleNamespace(write_line=lines.append)
        manager = SimpleNamespace(get_plugin=lambda name: reporter)
        session = SimpleNamespace(
            exitstatus=initial,
            config=SimpleNamespace(pluginmanager=manager),
        )
        budget.pytest_sessionfinish(session, initial)
        assert session.exitstatus == expected
        assert lines
        assert ("exceeded" in lines[0]) == (elapsed > 120)


def test_fast_runner_rejects_inherited_selection(monkeypatch):
    runner = load_script("scripts/test-fast.py")
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k nonexistent")
    with pytest.raises(SystemExit, match="PYTEST_ADDOPTS"):
        runner["main"]([])


@pytest.fixture
def staged_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    tooling = tmp_path / "tooling"
    tooling.mkdir()
    ruff = tooling / "ruff"
    ruff.mkdir()
    (ruff / "__init__.py").write_text("")
    (ruff / "__main__.py").write_text(
        "import json, os, pathlib, sys\n"
        "if '--version' in sys.argv:\n"
        "    print(os.environ.get('UTEST_RUFF_VERSION', 'ruff 0.16.7'))\n"
        "    raise SystemExit(0)\n"
        "pathlib.Path(os.environ['UTEST_RUFF_LOG']).write_text("
        "json.dumps(sys.argv[1:]))\n"
        "paths = sys.argv[sys.argv.index('--') + 1:]\n"
        "for name in paths:\n"
        "    path = pathlib.Path(name)\n"
        "    if path.is_file() and 'BAD_RUFF' in path.read_text():\n"
        "        raise SystemExit(1)\n"
    )
    log = tmp_path / "ruff.json"
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_"):
            del env[key]
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        PYTHONPATH=str(tooling),
        PYTHONDONTWRITEBYTECODE="1",
        UTEST_RUFF_LOG=str(log),
    )

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=repo, env=env,
            capture_output=True, text=True, check=True,
        )

    git("init", "-q")
    for relative in (
        "src/privacy_hud/runtime_contract.py",
        "scripts/build-runtime-manifest.py",
    ):
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    (repo / "install.sh").write_text("#!/bin/sh\nexit 0\n")
    (repo / "pyproject.toml").write_text(
        '[tool.ruff]\ntarget-version = "py311"\n'
    )
    (repo / "example with spaces.py").write_text("value = 1\n")

    def manifest():
        subprocess.run(
            [sys.executable, "-B", "scripts/build-runtime-manifest.py"],
            cwd=repo, env=env, capture_output=True, text=True, check=True,
        )

    def check():
        return subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/check-staged.py")],
            cwd=repo, env=env, capture_output=True, text=True, check=False,
        )

    manifest()
    git("add", ".")
    return SimpleNamespace(
        root=repo, env=env, log=log, git=git, manifest=manifest, check=check,
    )


def test_staged_snapshot_not_working_tree(staged_repo):
    case = staged_repo
    source = case.root / "src/privacy_hud/runtime_contract.py"
    source.write_text(source.read_text() + "\n# staged change\n")
    case.git("add", "src/privacy_hud/runtime_contract.py")
    case.manifest()
    result = case.check()
    assert result.returncode != 0
    assert "runtime-build.json is stale" in result.stderr

    case.git("add", "runtime-build.json")
    source.write_text(source.read_text() + "\n# unstaged change\n")
    assert case.check().returncode == 0


def test_staged_lint_handles_spaces_and_unstaged_fixes(staged_repo):
    case = staged_repo
    source = case.root / "example with spaces.py"
    source.write_text("BAD_RUFF\n")
    case.git("add", source.name)
    source.write_text("value = 2\n")
    assert case.check().returncode != 0
    args = json.loads(case.log.read_text())
    assert source.name in args

    case.git("add", source.name)
    source.write_text("BAD_RUFF\n")
    assert case.check().returncode == 0


def test_staged_shell_syntax_not_unstaged_fix(staged_repo):
    case = staged_repo
    script = case.root / "install.sh"
    script.write_text("if then\n")
    case.manifest()
    case.git("add", "install.sh", "runtime-build.json")
    script.write_text("#!/bin/sh\nexit 0\n")
    assert case.check().returncode != 0


def test_staged_configuration_lints_snapshot(staged_repo):
    case = staged_repo
    assert case.check().returncode == 0
    assert json.loads(case.log.read_text())[-1] == "."


def test_wrong_or_missing_ruff_fails(staged_repo):
    case = staged_repo
    case.env["UTEST_RUFF_VERSION"] = "ruff 0.14.11"
    result = case.check()
    assert result.returncode != 0
    assert "ruff==0.16.7" in result.stderr

    ruff_main = Path(case.env["PYTHONPATH"]) / "ruff/__main__.py"
    ruff_main.write_text("raise SystemExit(1)\n")
    result = case.check()
    assert result.returncode != 0
    assert "ruff==0.16.7" in result.stderr


def test_deleted_and_renamed_staged_files(staged_repo):
    case = staged_repo
    case.git("mv", "example with spaces.py", "renamed file.py")
    assert case.check().returncode == 0
    case.git("rm", "renamed file.py")
    assert case.check().returncode == 0


def test_no_runtime_identity_or_release_edit():
    contract = load_script("src/privacy_hud/runtime_contract.py")
    touched = {
        ".githooks/pre-commit",
        ".githooks/commit-msg",
        ".github/workflows/ci.yml",
        ".claude/CLAUDE.md",
        "scripts/check-staged.py",
        "scripts/test-fast.py",
        "tests/conftest.py",
        "tests/tier_policy.py",
        "tests/slow-files.json",
        "tests/test_utest_infrastructure.py",
    }
    assert not touched.intersection(contract["COVERED_FILES"])
    for path in touched:
        assert not any(
            path.startswith(tree + "/") for tree in contract["COVERED_TREES"]
        )
