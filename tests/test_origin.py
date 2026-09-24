import pytest

from privacy_hud.origin import Origin, OriginKind, extract_origin


@pytest.mark.parametrize("command", [
    "grep -eKEY /r/other .env",
    "grep -eKEY -- /r/other .env",
    "grep /r/other -eKEY .env",
    "egrep -eKEY /r/other .env",
    'bat --pager="cat /r/other" --paging=always .env',
    'bat --pager "cat /r/other" --paging always .env',
    'bat --pager="/bin/cat /r/other" --paging=always .env',
    'bat --paging=always --pager="head -n5 /r/other" .env',
])
def test_hidden_additional_operands_leave_accounting_path_unresolved(command):
    origin = extract_origin("Bash", {"command": command})
    assert origin is not None
    assert origin.kind is OriginKind.PATH
    assert origin.value == ".env"
    assert origin.evaluated_path is None


@pytest.mark.parametrize("command", [
    "grep --regexp=KEY .env",
    "egrep -e KEY .env",
    "bat --paging=never .env",
    "bat --language=json .env",
])
def test_unambiguous_option_forms_keep_accounting_path_resolved(command):
    origin = extract_origin("Bash", {"command": command})
    assert origin is not None
    assert origin.evaluated_path == ".env"


@pytest.mark.parametrize("command", [
    "grep -f/r/patterns -e KEY .env",
    "grep -f /r/patterns -e KEY .env",
    "less -k/r/keys .env",
    "less -k /r/keys .env",
    "less -T/r/tags .env",
    "less -T /r/tags .env",
])
def test_additional_file_options_leave_accounting_path_unresolved(command):
    origin = extract_origin("Bash", {"command": command})
    assert origin is not None
    assert origin.kind is OriginKind.PATH
    assert origin.value == ".env"
    assert origin.evaluated_path is None


@pytest.mark.parametrize("command", [
    "cat .env",
    "head -n5 .env",
    "grep -e KEY .env",
    "less -N .env",
])
def test_single_file_options_keep_accounting_path_resolved(command):
    origin = extract_origin("Bash", {"command": command})
    assert origin is not None
    assert origin.evaluated_path == ".env"


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
    # Secrets shaped like paths, which is what makes them dangerous here:
    # `_looks_like_a_path` accepts a token carrying `/` or `.`, so a secret
    # that happens to carry one defeats it on its own. Only knowing that the
    # token arrived as an UNRECOGNIZED option's value keeps it out.
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123",
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
    # -- PATH branch: the secret rides in an option the table does NOT know,
    #    and is itself shaped like a path. The table cannot list every option
    #    of every program, so a candidate that arrived straight after an
    #    unrecognized option is doubtful, and the spec's "never guess" rule
    #    makes a doubtful candidate a COMMAND origin rather than a wrong path.
    ("tail --format wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY /var/log/app.log",
     Origin("tail", OriginKind.COMMAND)),
    ("head --unknown eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123 app.log",
     Origin("head", OriginKind.COMMAND)),
    ("less --opt s3cr3t/key /etc/hosts", Origin("less", OriginKind.COMMAND)),
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


# --- a flag the table does not know must not shift the file window -------

def test_a_zero_arity_flag_before_the_pattern_still_finds_the_file():
    """The other half of the doubt rule: an unrecognized flag that takes no
    value leaves the file exactly where it was, and the file is NOT the
    token that followed the flag, so it stays trustworthy."""
    assert _bash("grep -i KEY .env") == Origin(".env", OriginKind.PATH)


def test_end_of_options_restores_positional_reading():
    """`--` says "no more options". Without that case the marker was read as
    an unknown option, and the file right after it became doubtful."""
    assert _bash("cat -- .env") == Origin(".env", OriginKind.PATH)
    assert _bash("cat -- -weird-name.log") == \
        Origin("-weird-name.log", OriginKind.PATH)


# --- the account name never reaches the ledger ---------------------------

def test_a_path_under_your_home_is_collapsed(monkeypatch):
    """`events.source` is persisted, served by the local API and rendered in
    the audit, so the account name must not ride into it on a path.

    The project already holds this line twice — `runtime.display_path`
    collapses `$HOME` "to keep the account name out of a report", and a
    masked path exemplar reads `/Users/•••/app.log` — so an origin that kept
    `/Users/jordan/...` verbatim would be the one place it leaked.
    """
    monkeypatch.setenv("HOME", "/Users/jordan")
    assert extract_origin("Read", {"file_path": "/Users/jordan/.ssh/id_rsa"}) == \
        Origin("~/.ssh/id_rsa", OriginKind.PATH)
    assert _bash("cat /Users/jordan/project/.env") == \
        Origin("~/project/.env", OriginKind.PATH)


def test_another_persons_home_is_left_alone(monkeypatch):
    """Only YOUR home collapses. `/Users/someone-else/...` is exactly the row
    known limit 7 says you want to see, so it stays readable."""
    monkeypatch.setenv("HOME", "/Users/jordan")
    assert _bash("cat /Users/alice/Downloads/patient-intake-2026.csv") == \
        Origin("/Users/alice/Downloads/patient-intake-2026.csv", OriginKind.PATH)


def test_a_path_outside_home_is_unchanged(monkeypatch):
    monkeypatch.setenv("HOME", "/Users/jordan")
    assert _bash("head -n 5 /etc/passwd") == \
        Origin("/etc/passwd", OriginKind.PATH)


# --- #54 Phase 4: the evaluated path, separate from the display value ----

def test_evaluated_path_survives_home_display_collapse(monkeypatch):
    """`Origin.value` collapses your home for display; the transient
    `evaluated_path` keeps the literal the guard evaluated, so a file
    identity is hashed from the path and never from the display text."""
    from privacy_hud.identity import file_identity

    key = bytes(range(32))
    monkeypatch.setenv("HOME", "/Users/jordan")
    for origin in (
            extract_origin("Read", {"file_path": "/Users/jordan/p/.env"}),
            _bash("cat /Users/jordan/p/.env")):
        assert origin is not None
        assert origin.value == "~/p/.env"
        assert origin.evaluated_path == "/Users/jordan/p/.env"
        assert "/Users/jordan" not in repr(origin)
        assert file_identity(key, origin.evaluated_path, "/elsewhere") == \
            file_identity(key, "/Users/jordan/p/.env", "/")
        with pytest.raises(ValueError):
            file_identity(key, origin.value, "/elsewhere")
    # Display equality and enforcement semantics are unchanged.
    assert _bash("cat /Users/jordan/p/.env") == \
        Origin("~/p/.env", OriginKind.PATH)
    assert _bash("cat config/.env").evaluated_path == "config/.env"


@pytest.mark.parametrize("command", [
    "cat $HOME/.env",
    "cat ${HOME}/.env",
    "cat `pwd`/.env",
    "cat $(pwd)/.env",
    "cat ~/.env",
    "cat *.pem",
    "cat key?.pem",
    "cat [ab].pem",
    "cat {a,b}.pem",
    "cat a.pem b.pem",
    "grep KEY a.env b.env",
    "grep -r KEY config/",
    "grep -f patterns.txt secret.env",
    "cat a.pem; cat b.pem",
    "cat a.pem && cat b.pem",
    "cat a.pem | tee b.pem",
    "cat < a.pem",
    "cat a.pem > b.pem",
    "cat a.pem # b.pem",
    "cat 'a.pem",
    "rg KEY config/.env",
    "tail --format x /var/log/app.log",
    "cat a\\ b.pem",
])
def test_ambiguous_shell_path_is_unresolved(command):
    origin = _bash(command)
    assert origin is None or origin.evaluated_path is None, command
    # The literal, unambiguous forms are resolved, which is what makes the
    # refusals above meaningful.
    for literal, path in (("cat a.pem", "a.pem"),
                          ("head -n 5 /etc/passwd", "/etc/passwd"),
                          ("grep -i KEY config/.env", "config/.env"),
                          ("cat -- .env", ".env"),
                          ("cat 'dir with space/k.pem'",
                           "dir with space/k.pem")):
        assert _bash(literal).evaluated_path == path, literal
    for tool_input in ({"file_path": "~/k.pem"}, {"file_path": "$HOME/k"},
                       {"file_path": "a\x00b"}, {"path": "*.pem"}):
        origin = extract_origin("Read", tool_input)
        assert origin is not None and origin.evaluated_path is None
