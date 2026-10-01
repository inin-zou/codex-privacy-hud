from __future__ import annotations

import os
import signal
import subprocess
from types import SimpleNamespace

import pytest

from forwarder_helpers import (
    FUSE,
    INSTALL,
    bounded_run,
    executable,
    forwarder,
)

GUARD = "PRIVACY_HUD_FORWARDER_PROBE"
REFUSAL = "codex-privacy-hud: recursive forwarder entry refused\n"
MISSING = "codex-privacy-hud: official codex not found\n"


@pytest.mark.parametrize("shell", ["/bin/sh", "/bin/dash"])
def test_fuse_kills_its_process_group_under_available_shells(shell):
    if not os.path.isfile(shell):
        pytest.skip(f"{shell} is unavailable")
    result = subprocess.run(
        [
            shell, "-c",
            "PH_TEST_PGID=$$; export PH_TEST_PGID;\n" + FUSE,
        ],
        env={"PATH": "/usr/bin:/bin", "PH_TEST_DEPTH": "3"},
        capture_output=True,
        text=True,
        start_new_session=True,
        timeout=3,
    )
    assert result.returncode == -signal.SIGKILL, result.stderr
    assert result.stderr == "TEST forwarder entry limit reached\n"


@pytest.fixture
def case(tmp_path):
    home_a = tmp_path / "homeA"
    home_b = tmp_path / "homeB"
    third = tmp_path / "third"
    for home in (home_a, home_b, third):
        home.mkdir()

    a = forwarder(home_a / ".local/bin/codex")
    b = forwarder(home_b / ".local/bin/codex")
    official = executable(
        tmp_path / "official/codex",
        '#!/bin/sh\n'
        'if [ "${1-}" = --version ]; then\n'
        '  printf "%s\\n" "codex-cli 0.154.0"\n'
        '  exit 0\n'
        'fi\n'
        'printf "official"\n'
        'printf " <%s>" "$@"\n'
        'printf "\\n"\n',
    )
    env = {
        "HOME": str(third),
        "PATH": f"{a.parent}:{b.parent}:{official.parent}:/usr/bin:/bin",
        "SHELL": "/bin/sh",
        "TMPDIR": str(tmp_path),
        "LC_ALL": "C",
    }
    return SimpleNamespace(
        root=tmp_path, a=a, b=b, official=official,
        home_a=home_a, home_b=home_b, third=third, env=env,
    )


def invoke(case, *args, env=None, argv=None, cwd=None, extra=()):
    return bounded_run(
        case.root,
        argv or [str(case.a), *args],
        env or case.env,
        forwarders=(case.a, case.b, *extra),
        cwd=cwd,
    )


def test_harness_kills_recursive_fixture_group(case):
    recursive = executable(
        case.root / "recursive/codex",
        "#!/bin/sh\n"
        "# codex-privacy-hud forwarder synthetic containment test\n"
        'value="$("$0" --version)"\n'
        'exec "$0" "$@"\n',
    )
    result = bounded_run(
        case.root, [str(recursive)], case.env,
        forwarders=(recursive,),
    )
    assert result.returncode == -signal.SIGKILL
    assert "TEST forwarder entry limit reached" in result.stderr


@pytest.mark.parametrize("home_name", ["home_a", "third"])
def test_two_forwarders_with_changed_home(case, home_name):
    env = dict(case.env, HOME=str(getattr(case, home_name)))
    result = invoke(case, "hello", "two words", "*", env=env)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "official <hello> <two words> <*>\n"
    assert "TEST forwarder entry limit reached" not in result.stderr


def test_self_only_with_changed_home(case):
    env = dict(case.env, PATH=f"{case.a.parent}:/usr/bin:/bin")
    result = invoke(case, env=env)
    assert result.returncode == 127
    assert result.stderr == MISSING


def test_two_forwarders_without_official(case):
    env = dict(
        case.env, PATH=f"{case.a.parent}:{case.b.parent}:/usr/bin:/bin"
    )
    result = invoke(case, env=env)
    assert result.returncode == 127
    assert result.stderr == MISSING


@pytest.mark.parametrize("value", ["", "1", "unexpected"])
def test_guard_refuses_any_set_value(case, value):
    env = dict(case.env)
    env[GUARD] = value
    result = invoke(case, env=env)
    assert result.returncode == 126
    assert result.stderr == REFUSAL


def test_probe_reentry_is_refused(case):
    # This deliberately unmarked trampoline tests the guard independently
    # of marker classification. It has no recursive version logic itself.
    case.official.write_text(
        '#!/bin/sh\nexec "$TEST_FORWARDER" "$@"\n',
        encoding="utf-8",
    )
    env = dict(case.env, TEST_FORWARDER=str(case.a))
    result = invoke(case, env=env)
    assert result.returncode == 126
    assert REFUSAL in result.stderr
    assert "TEST forwarder entry limit reached" not in result.stderr


def test_probe_guard_is_absent_from_normal_and_nested_execution(case):
    case.official.write_text(
        '#!/bin/sh\n'
        'if [ "${1-}" = --version ]; then\n'
        f'  [ "${{{GUARD}+set}}" = set ] || exit 81\n'
        '  printf "%s\\n" "codex-cli 0.154.0"\n'
        '  exit 0\n'
        'fi\n'
        f'[ "${{{GUARD}+set}}" != set ] || exit 82\n'
        'if [ "${1-}" = outer ]; then exec codex inner; fi\n'
        'printf "%s\\n" "$1"\n',
        encoding="utf-8",
    )
    result = invoke(case, "outer")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "inner\n"


def test_patched_build_belongs_to_resolved_forwarder(case):
    executable(
        case.home_a / ".local/share/codex-privacy-hud/0.154.0/codex",
        '#!/bin/sh\n'
        f'[ "${{{GUARD}+set}}" != set ] || exit 82\n'
        'printf "%s\\n" "patched A"\n',
    )
    executable(
        case.third / ".local/share/codex-privacy-hud/0.154.0/codex",
        '#!/bin/sh\nprintf "%s\\n" "wrong HOME build"\n',
    )
    result = invoke(case)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "patched A\n"


def test_marked_patched_target_is_not_executed(case):
    patched = (
        case.home_a / ".local/share/codex-privacy-hud/0.154.0/codex"
    )
    patched.parent.mkdir(parents=True)
    patched.symlink_to(case.b)
    result = invoke(case, "hello", extra=(patched,))
    assert result.returncode == 0, result.stderr
    assert result.stdout == "official <hello>\n"


@pytest.mark.parametrize("mode", ["absolute", "relative", "path"])
def test_invocation_forms_and_relative_symlink_chain(case, mode):
    links = case.root / "links"
    links.mkdir()
    (links / "next").symlink_to(
        os.path.relpath(case.a, links)
    )
    alias = links / "codex"
    alias.symlink_to("next")
    env = dict(
        case.env, PATH=f"{links}:{case.env['PATH']}"
    )
    commands = {
        "absolute": [str(alias), "hello"],
        "relative": ["./links/codex", "hello"],
        "path": ["codex", "hello"],
    }
    result = invoke(
        case, env=env, argv=commands[mode],
        cwd=case.root, extra=(alias,),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "official <hello>\n"


def test_empty_relative_and_glob_path_entries(case):
    # Empty PATH component means cwd. A literal '*' directory must not
    # expand into its sibling directories.
    literal = case.root / "*"
    literal.mkdir()
    (literal / "codex").symlink_to(case.b)
    (case.root / "codex").symlink_to(case.a)
    env = dict(
        case.env,
        PATH=f":*:{case.official.parent}:/usr/bin:/bin",
    )
    result = invoke(case, "hello", env=env, cwd=case.root)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "official <hello>\n"


def test_symlink_cycle_and_fifo_are_skipped(case):
    cycle = case.root / "cycle"
    cycle.mkdir()
    (cycle / "codex").symlink_to("other")
    (cycle / "other").symlink_to("codex")
    fifo_dir = case.root / "fifo"
    fifo_dir.mkdir()
    fifo = fifo_dir / "codex"
    os.mkfifo(fifo, 0o700)
    env = dict(
        case.env,
        PATH=f"{cycle}:{fifo_dir}:{case.env['PATH']}",
    )
    result = invoke(case, "hello", env=env)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "official <hello>\n"


def test_installer_discovery_skips_foreign_forwarders(case):
    source = INSTALL.read_text(encoding="utf-8")
    functions = "first_codex_on_path() {" + source.split(
        "first_codex_on_path() {", 1
    )[1].split("# The patched tarball", 1)[0]
    probe = executable(
        case.root / "discovery.sh",
        "#!/bin/sh\nset -eu\n"
        'FWD="$HOME/.local/bin/codex"\n'
        + functions
        + '\nofficial="$(official_codex)" || exit 127\n'
        + 'printf "%s\\n" "$official"\n'
        + '"$official" --version\n',
    )
    result = invoke(case, argv=[str(probe)])
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        str(case.official.resolve()), "codex-cli 0.154.0",
    ]


def test_bare_name_resolution_uses_path(case):
    source = INSTALL.read_text(encoding="utf-8")
    functions = "first_codex_on_path() {" + source.split(
        "first_codex_on_path() {", 1
    )[1].split("# The patched tarball", 1)[0]
    probe = executable(
        case.root / "resolve.sh",
        "#!/bin/sh\n" + functions + '\nreal_path codex\n',
    )
    result = invoke(case, argv=[str(probe)])
    assert result.returncode == 0
    assert result.stdout.strip() == str(case.a.resolve())


def test_spec_forwarder_listing_matches_installer():
    from forwarder_helpers import REPO, forwarder_source

    spec = (
        REPO
        / "docs/superpowers/specs/"
        "2026-09-15-patched-codex-status-line-design.md"
    ).read_text(encoding="utf-8")
    listing = spec.split("**Forwarding script**", 1)[1].split(
        "```sh\n", 1
    )[1].split("\n```", 1)[0] + "\n"
    assert listing == forwarder_source()
