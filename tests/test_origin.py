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
    ("egrep ERROR /var/log/app.log", "/var/log/app.log"),
    ("rg TODO src/main.py", "src/main.py"),
    ("jq . a.json", "a.json"),
    ("yq .foo config.yaml", "config.yaml"),
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


# --- option values are not paths ---------------------------------------

@pytest.mark.parametrize("command,expected", [
    # A separated option value is the option's, not a positional: it must
    # neither be taken for the path nor shift the pattern/path window.
    ("head -n 5 /etc/passwd", "/etc/passwd"),
    ("tail -n 20 app.log", "app.log"),
    ("tail -c 100 /var/log/app.log", "/var/log/app.log"),
    ("grep -A 3 KEY .env", ".env"),
    ("grep -m 1 --color always KEY .env", ".env"),
    ("rg -C 2 KEY .env", ".env"),
    ("jq --arg name value . conf.json", "conf.json"),   # --arg takes TWO
    ("bat --theme ansi src/main.py", "src/main.py"),
    # An interleaved boolean flag does not shift it either.
    ("grep -i KEY .env", ".env"),
    ("grep KEY -i .env", ".env"),
    # `-e`/`-f` supply the pattern, so the first positional IS the file.
    ("grep -e KEY .env", ".env"),
    ("rg --regexp KEY .env", ".env"),
    # An attached `--opt=value` consumes nothing after it.
    ("grep --regexp=KEY .env", ".env"),
    ("head --lines=5 config/.env", "config/.env"),
])
def test_an_option_value_is_never_mistaken_for_the_path(command, expected):
    assert _bash(command) == Origin(value=expected, kind=OriginKind.PATH)


@pytest.mark.parametrize("command,expected", [
    # A candidate that does not look like a path is never returned as one:
    # a doubtful read yields the program name, per the spec's "never guess".
    ("grep --unknown-option value KEY .env", "grep"),
    ("head -n 5 passwd", "head"),
    ("cat Makefile", "cat"),
])
def test_a_candidate_that_is_not_path_shaped_falls_back_to_the_command(
        command, expected):
    assert _bash(command) == Origin(value=expected, kind=OriginKind.COMMAND)


@pytest.mark.parametrize("command,expected", [
    # The subcommand window shifts on a separated option value too, and a
    # path or a URL is never a subcommand.
    ("git -C /srv/repo log --oneline", "git log"),
    ("kubectl -n prod get pods", "kubectl get"),
    ("gh --repo owner/name pr list", "gh pr"),
])
def test_an_option_value_is_never_mistaken_for_the_subcommand(command, expected):
    assert _bash(command) == Origin(value=expected, kind=OriginKind.COMMAND)


# --- I1: arguments are never part of an origin -------------------------

#: Credential-shaped fragments planted in the corpus below. None may appear
#: anywhere in an extracted origin, whichever branch produced it.
SECRET_FRAGMENTS = (
    "hunter2", "s3cr3t", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "ghp_XXXXXXXXXXXXXXXX", "sk-proj-LIVEKEY123", "id_rsa",
    "admin:hunter2", "AKIAIOSFODNN7EXAMPLE",
)

#: (command, the origin it must yield). The list deliberately spans BOTH
#: branches: the program-name one AND the PATH one, which is the branch that
#: can return an argument and so the one an I1 gatekeeper has to exercise.
SECRET_COMMANDS = [
    # -- program-name branch --------------------------------------------
    ("curl -u admin:hunter2 https://api.internal/v1/users",
     Origin("curl", OriginKind.COMMAND)),
    ("psql postgres://app:s3cr3t@db.internal:5432/prod -c 'select 1'",
     Origin("psql", OriginKind.COMMAND)),
    ("export GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     Origin("export", OriginKind.COMMAND)),
    ("ssh -i /Users/jordan/.ssh/id_rsa deploy@10.0.0.9",
     Origin("ssh", OriginKind.COMMAND)),
    ("mysql --password=hunter2 -e 'show databases'",
     Origin("mysql", OriginKind.COMMAND)),
    ("aws --profile AKIAIOSFODNN7EXAMPLE s3 ls",
     Origin("aws s3", OriginKind.COMMAND)),
    # -- PATH branch: a read verb whose SECRET rides in an option value --
    ("grep -A 3 sk-proj-LIVEKEY123 .env", Origin(".env", OriginKind.PATH)),
    ("grep -e hunter2 -C 2 .env", Origin(".env", OriginKind.PATH)),
    ("rg -C 2 hunter2 .env", Origin(".env", OriginKind.PATH)),
    ("rg --replace hunter2 s3cr3t /var/log/app.log",
     Origin("/var/log/app.log", OriginKind.PATH)),
    ("jq --arg tok ghp_XXXXXXXXXXXXXXXX . conf.json",
     Origin("conf.json", OriginKind.PATH)),
    ("head -n 5 /etc/passwd", Origin("/etc/passwd", OriginKind.PATH)),
    ("tail -n 20 app.log", Origin("app.log", OriginKind.PATH)),
    ("grep -i hunter2 config/.env", Origin("config/.env", OriginKind.PATH)),
]


@pytest.mark.parametrize("command,expected", SECRET_COMMANDS)
def test_an_origin_never_carries_argument_text(command, expected):
    """The gatekeeper for "no argument text in the ledger" (I1).

    `events.source` is persisted to SQLite, served unmasked by the local UI
    API and rendered in the audit, and command lines routinely carry
    credentials. The corpus covers both branches on purpose: an earlier
    version of it held only commands that fell through to the program name,
    so the one branch that CAN return an argument -- the read-verb path --
    was never exercised, and `grep -A 3 <secret> .env` returned the secret.
    """
    origin = extract_origin("Bash", {"command": command})
    assert origin == expected
    for secret in SECRET_FRAGMENTS:
        assert secret not in origin.value
