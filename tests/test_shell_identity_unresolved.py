import shlex

import pytest

from privacy_hud.origin import (
    BOOLEAN_OPTIONS,
    PATTERN_THEN_PATH_VERBS,
    READ_VERBS,
    VALUE_OPTIONS,
    OriginKind,
    extract_origin,
)


def _shell_cases():
    cases = set()
    for program in sorted(READ_VERBS):
        operands = (["KEY"] if program in {"grep", "egrep", "rg"}
                    else ["."] if program in PATTERN_THEN_PATH_VERBS
                    else []) + [".env"]
        for executable in (program, "/usr/bin/" + program,
                           "/r/bin/" + program):
            for suffix in (operands, ["--"] + operands,
                           operands + ["/r/other"],
                           ["--"] + operands + ["/r/other"],
                           ["@/r/args"], ["--", "@/r/args"]):
                cases.add(shlex.join([executable] + suffix))
        for option, arity in VALUE_OPTIONS.get(program, {}).items():
            values = ["KEY", "/r/other"][:arity]
            forms = [[option] + values, [option], [option, "--"]]
            if arity:
                forms.append([option + "=" + values[0]] + values[1:])
                if not option.startswith("--"):
                    forms.append([option + values[0]] + values[1:])
                    for flag in BOOLEAN_OPTIONS.get(program, ()):
                        if len(flag) == 2:
                            forms.append([flag + option[1:]] + values)
                            forms.append(
                                [flag + option[1:] + values[0]] + values[1:])
            for form in forms:
                for suffix in (operands, ["/r/other"] + operands):
                    cases.add(shlex.join([program] + form + suffix))
                    cases.add(shlex.join(
                        [program] + form + ["--"] + suffix))
                    cases.add(shlex.join([program] + suffix + form))
        for flag in BOOLEAN_OPTIONS.get(program, ()):
            cases.add(shlex.join([program, flag] + operands))
            cases.add(shlex.join([program, flag + "=/r/other"] + operands))
    for program in ("fgrep", "ggrep", "gcat", "batcat", "busybox",
                    "command", "env", "sudo"):
        cases.add(program + " cat .env")
        cases.add(program + " .env")
    return sorted(cases)


@pytest.mark.parametrize("command", _shell_cases())
def test_shell_text_never_attests_file_identity(command):
    # Some generated forms are invalid for a particular implementation.
    # Neither invalid syntax nor valid syntax establishes execution evidence.
    origin = extract_origin("Bash", {"command": command})
    assert origin is None or origin.evaluated_path is None, command


@pytest.mark.parametrize("command, expected", [
    ("grep --color KEY /r/other .env", ".env"),
    ("grep --colour KEY /r/other .env", ".env"),
    ("egrep --color KEY /r/other .env", ".env"),
    ("od -w /r/other .env", ".env"),
    ("od --width /r/other .env", ".env"),
    ("od --strings /r/other .env", ".env"),
    ("strings @/r/args", "@/r/args"),
    ("strings -- @/r/args", "@/r/args"),
    ("less .env", ".env"),
    ("more .env", ".env"),
    ("bat --paging=always .env", ".env"),
    ("jq . .env", ".env"),
    ("yq . .env", ".env"),
    ("/r/bin/cat .env", ".env"),
])
def test_unattested_shell_origin_keeps_legacy_display(command, expected):
    origin = extract_origin("Bash", {"command": command})
    assert origin is not None
    assert origin.kind is OriginKind.PATH
    assert origin.value == expected
    assert origin.evaluated_path is None


@pytest.mark.parametrize("name, value, command", [
    ("GREP_OPTIONS", "-f /r/patterns", "grep KEY .env"),
    ("LESSOPEN", "|cat /r/other %s", "less .env"),
    ("LESS", "-T/r/tags", "less .env"),
    ("MORE", "-T/r/tags", "more .env"),
    ("BAT_PAGER", "cat /r/other", "bat --paging=always .env"),
    ("PAGER", "cat /r/other", "bat --paging=always .env"),
    ("BAT_CONFIG_PATH", "/r/bat.conf", "bat .env"),
    ("RIPGREP_CONFIG_PATH", "/r/rg.conf", "rg KEY .env"),
    ("POSIXLY_CORRECT", "1", "grep KEY -e /r/other .env"),
])
def test_process_environment_cannot_attest_shell_identity(
        monkeypatch, name, value, command):
    monkeypatch.setenv(name, value)
    origin = extract_origin("Bash", {"command": command})
    assert origin is not None
    assert origin.evaluated_path is None
    monkeypatch.delenv(name)
    origin = extract_origin("Bash", {"command": command})
    assert origin is not None
    assert origin.evaluated_path is None


def test_structured_file_path_still_resolves():
    origin = extract_origin("Read", {"file_path": "/r/file.txt"})
    assert origin is not None
    assert origin.evaluated_path == "/r/file.txt"
