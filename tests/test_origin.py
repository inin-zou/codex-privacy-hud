import pytest

from privacy_hud.origin import Origin, OriginKind, extract_origin


def _bash(command: str):
    return extract_origin("Bash", {"command": command})


# --- paths -------------------------------------------------------------

@pytest.mark.parametrize("command,expected", [
    ("cat .env", ".env"),
    ("cat ./.env", "./.env"),
    ("head -n5 config/.env", "config/.env"),
    ("tail -f /var/log/app.log", "/var/log/app.log"),
    ("grep KEY .env", ".env"),
])
def test_a_read_command_yields_the_path_it_reads(command, expected):
    assert _bash(command) == Origin(value=expected, kind=OriginKind.PATH)


def test_a_file_tool_yields_its_own_path_argument():
    assert extract_origin("Read", {"file_path": "/repo/support.log"}) == \
        Origin(value="/repo/support.log", kind=OriginKind.PATH)


def test_an_example_file_is_not_the_file_it_is_an_example_of():
    # `.env.example` is a different origin from `.env`; a rule on one must
    # not match the other.
    assert _bash("cat .env.example") == \
        Origin(value=".env.example", kind=OriginKind.PATH)


# --- commands ----------------------------------------------------------

@pytest.mark.parametrize("command,expected", [
    ("env", "env"),
    ("git log --oneline", "git log"),
    ("gh pr list --state open", "gh pr"),
    ("ls -la", "ls"),
    ("cp .env.example .env", "cp"),
])
def test_a_non_read_command_yields_its_program_name(command, expected):
    assert _bash(command) == Origin(value=expected, kind=OriginKind.COMMAND)


# --- no origin ---------------------------------------------------------

@pytest.mark.parametrize("tool_name,tool_input", [
    ("Bash", {"command": ""}),
    ("Bash", {}),
    ("Bash", {"command": "echo 'unbalanced"}),
    ("mcp__github__create_issue", {"title": "x"}),
    ("Read", {}),
])
def test_no_origin_rather_than_a_guess(tool_name, tool_input):
    assert extract_origin(tool_name, tool_input) is None


# --- I1: arguments are never part of an origin -------------------------

SECRET_COMMANDS = [
    "curl -u admin:hunter2 https://api.internal/v1/users",
    "psql postgres://app:s3cr3t@db.internal:5432/prod -c 'select 1'",
    "export GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "ssh -i /Users/jordan/.ssh/id_rsa deploy@10.0.0.9",
    "mysql --password=hunter2 -e 'show databases'",
]


@pytest.mark.parametrize("command", SECRET_COMMANDS)
def test_an_origin_never_carries_argument_text(command):
    """The gatekeeper for "program name only" (I1). `events.source` is
    persisted and rendered, and command lines carry credentials; if anyone
    later widens extraction to arguments, this fails first."""
    origin = extract_origin("Bash", {"command": command})
    assert origin is not None
    program, _, _ = command.partition(" ")
    for argument in command.split()[1:]:
        assert argument not in origin.value
    assert origin.value in {program, f"{program} {command.split()[1]}"}
