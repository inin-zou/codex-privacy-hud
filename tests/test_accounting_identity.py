"""#54 Phase 3: exact, session-keyed identity and value-finding normalization.

Version-2 accounting charges a (subject, recipient) pair once. That is only
honest if "the same subject" means the same exact value or the same evaluated
file, never "the same detector pattern" or "two things we could not resolve",
and if nothing readable about the subject or recipient survives into labels
or exemplars.
"""
from __future__ import annotations

import builtins
import hashlib
import hmac
import itertools
import os
import pathlib
import re

import pytest

from privacy_hud.accounting import (
    RecipientInput, ScoringProfile, SubjectInput, coalesce_value_findings,
)
from privacy_hud.detect.base import Finding
from privacy_hud.identity import (
    file_identity, recipient_identity, safe_file_label, safe_masked_example,
    value_identity,
)
from privacy_hud.matrix.loader import load_matrix

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
SUBJECT_ID = "0123456789abcdef0123456789abcdef"
INVALID_IDENTITY = "invalid accounting identity"
TOKEN = re.compile(r"[0-9a-f]{32}")


def _frame(*fields: str) -> bytes:
    out = b""
    for text in fields:
        raw = text.encode("utf-8")
        out += len(raw).to_bytes(8, "big") + raw
    return out


def _hmac(*fields: str) -> bytes:
    return hmac.new(KEY, _frame(*fields), hashlib.sha256).digest()


def _profile() -> ScoringProfile:
    return ScoringProfile.from_matrix(load_matrix())


def test_exact_value_identity_is_detector_and_source_independent():
    value = "alice@example.com"
    first = value_identity(KEY, value)
    assert first == value_identity(KEY, value)
    assert len(first) == 32
    assert first == _hmac("privacy-hud/54/value/v1", value)

    for variant in ("Alice@example.com", "ALICE@EXAMPLE.COM",
                    " alice@example.com", "alice@example.com\n",
                    "alice@example.com "):
        assert value_identity(KEY, variant) != first, repr(variant)

    # Two detectors, two sources, one exact value: one identity.
    findings = [Finding("email", value, 0, 17), Finding("person", value, 40, 57)]
    (group,) = coalesce_value_findings(_profile(), KEY, findings)
    assert group.subject.identity_hash == first
    assert group.subject.subject_kind == "value"

    for bad_key in (b"", b"short", "k" * 32, bytearray(KEY), None):
        with pytest.raises(ValueError, match=INVALID_IDENTITY):
            value_identity(bad_key, value)  # type: ignore[arg-type]
    for bad_value in ("", None, b"alice", "\ud800"):
        with pytest.raises(ValueError, match=INVALID_IDENTITY):
            value_identity(KEY, bad_value)  # type: ignore[arg-type]


def test_file_identity_uses_evaluated_path_not_pattern():
    one = file_identity(KEY, "/a/one.pem", "/")
    assert one != file_identity(KEY, "/a/two.pem", "/")
    assert len(one) == 32
    assert one == _hmac("privacy-hud/54/file/v1", "/a/one.pem")

    for path, cwd in (("/a/one.pem", ""), ("/a/one.pem", "/elsewhere"),
                      ("/a/./one.pem", "/"), ("/a//one.pem", "/"),
                      ("/a/b/../one.pem", "/"), ("/a/one.pem/", "/"),
                      ("one.pem", "/a"), ("./one.pem", "/a/"),
                      ("../a/one.pem", "/a"), ("b/../one.pem", "/a/./")):
        assert file_identity(KEY, path, cwd) == one, (path, cwd)

    assert file_identity(KEY, "one.pem", "/b") != one


def test_file_identity_never_uses_ambient_cwd_or_filesystem(monkeypatch):
    calls: list[str] = []

    class Forbidden(BaseException):
        """Not an `Exception`, so no `except Exception` can swallow it."""

    def forbidden(name):
        def call(*args, **kwargs):
            calls.append(name)
            raise Forbidden(name)
        return call

    invalid = (("one.pem", ""), ("one.pem", "relative/dir"),
               ("one.pem", "./a"), ("one.pem", None),
               ("", "/a"), ("/a/\x00one.pem", "/"),
               ("one.pem", "/a/\x00b"), ("~/one.pem", "/a"),
               ("~alice/one.pem", "/"), ("$HOME/one.pem", "/"),
               ("/a/${DIR}/one.pem", "/"), ("/a/`id`.pem", "/"),
               ("/a/*.pem", "/"), ("/a/one?.pem", "/"),
               ("one.pem", "~/a"), (b"/a/one.pem", "/"),
               (None, "/"))
    valid: list[object] = []
    outcomes: list[tuple[object, object]] = []

    # The filesystem and environment are unavailable only while the calls
    # under test run: pytest itself needs them to report a failure, so every
    # outcome is collected here and asserted after the patch is undone.
    with monkeypatch.context() as patch:
        for module, name in ((os, "getcwd"), (os, "stat"), (os, "lstat"),
                             (os, "readlink"), (os, "scandir"),
                             (os.path, "realpath"), (os.path, "abspath"),
                             (os.path, "expanduser"), (os.path, "expandvars"),
                             (os.path, "exists"), (builtins, "open"),
                             (pathlib.Path, "resolve"), (pathlib.Path, "stat")):
            patch.setattr(module, name,
                          forbidden(f"{module.__name__}.{name}"))
        for path, cwd in (("/a/one.pem", ""), ("one.pem", "/a")):
            try:
                valid.append(file_identity(KEY, path, cwd))
            except BaseException as exc:  # reported below
                valid.append(exc)
        for path, cwd in invalid:
            try:
                outcomes.append(((path, cwd), file_identity(
                    KEY, path, cwd)))  # type: ignore[arg-type]
            except BaseException as exc:  # reported below
                outcomes.append(((path, cwd), exc))

    assert calls == []
    assert all(isinstance(v, bytes) and len(v) == 32 for v in valid), valid
    for case, outcome in outcomes:
        assert isinstance(outcome, ValueError), (case, outcome)
        assert str(outcome) == INVALID_IDENTITY, (case, outcome)


def test_identity_domains_do_not_collide():
    text = "/a/x"
    value = value_identity(KEY, text)
    file = file_identity(KEY, text, "/")
    local = recipient_identity(KEY, "local", text)
    assert len({value, file, local}) == 3

    assert recipient_identity(KEY, "mcp_tool", "server-a") == _hmac(
        "privacy-hud/54/recipient/v1", "mcp_tool", "server-a")
    assert (recipient_identity(KEY, "mcp_tool", "x")
            != recipient_identity(KEY, "external_net", "x"))
    # Length framing, not delimiters: moving a boundary changes the hash.
    assert _frame("ab", "c") != _frame("a", "bc")

    for kind, identity in (("nowhere", "x"), ("mcp_tool", ""),
                           ("mcp_tool", None), (None, "x")):
        with pytest.raises(ValueError, match=INVALID_IDENTITY):
            recipient_identity(KEY, kind, identity)  # type: ignore[arg-type]


def test_identity_is_session_scoped():
    assert value_identity(KEY, "v") != value_identity(OTHER_KEY, "v")
    assert (file_identity(KEY, "/a/one.pem", "/")
            != file_identity(OTHER_KEY, "/a/one.pem", "/"))
    assert (recipient_identity(KEY, "external_net", "api.example.com")
            != recipient_identity(OTHER_KEY, "external_net", "api.example.com"))
    for bad_key in (b"", KEY[:31], KEY + b"\x00"):
        with pytest.raises(ValueError, match=INVALID_IDENTITY):
            file_identity(bad_key, "/a/one.pem", "/")
        with pytest.raises(ValueError, match=INVALID_IDENTITY):
            recipient_identity(bad_key, "mcp_tool", "server-a")


def test_unresolved_tokens_are_explicit_and_observation_local():
    a = SubjectInput(subject_kind="value", identity_hash=None)
    b = SubjectInput(subject_kind="value", identity_hash=None)
    assert a.unresolved_token is not None and b.unresolved_token is not None
    assert TOKEN.fullmatch(a.unresolved_token)
    assert TOKEN.fullmatch(b.unresolved_token)
    assert a.unresolved_token != b.unresolved_token
    assert a != b
    reused = SubjectInput(subject_kind="value", identity_hash=None,
                          unresolved_token=a.unresolved_token)
    assert reused == a
    assert a.unresolved_token not in repr(a)

    r1 = RecipientInput(destination_kind="mcp_tool", identity_hash=None)
    r2 = RecipientInput(destination_kind="mcp_tool", identity_hash=None)
    assert r1.unresolved_token and TOKEN.fullmatch(r1.unresolved_token)
    assert r1 != r2
    assert RecipientInput(destination_kind="mcp_tool", identity_hash=None,
                          unresolved_token=r1.unresolved_token) == r1
    assert r1.unresolved_token not in repr(r1)

    digest = bytes(32)
    resolved = SubjectInput(subject_kind="file", identity_hash=digest,
                            safe_suffix=".pem")
    assert resolved.unresolved_token is None
    assert RecipientInput(destination_kind="local",
                          identity_hash=digest).unresolved_token is None

    invalid = (
        lambda: SubjectInput(subject_kind="value", identity_hash=digest,
                             unresolved_token="0" * 32),
        lambda: SubjectInput(subject_kind="value", identity_hash=bytes(16)),
        lambda: SubjectInput(subject_kind="value",
                             identity_hash=bytearray(32)),  # type: ignore[arg-type]
        lambda: SubjectInput(subject_kind="value", identity_hash=None,
                             unresolved_token="not-a-token"),
        lambda: SubjectInput(subject_kind="value", identity_hash=None,
                             unresolved_token="A" * 32),
        lambda: SubjectInput(subject_kind="value", identity_hash=digest,
                             safe_suffix=".pem"),
        lambda: SubjectInput(subject_kind="file", identity_hash=digest,
                             safe_suffix=".txt"),  # type: ignore[arg-type]
        lambda: SubjectInput(subject_kind="row",  # type: ignore[arg-type]
                             identity_hash=digest),
        lambda: RecipientInput(destination_kind="nowhere",  # type: ignore[arg-type]
                               identity_hash=digest),
        lambda: RecipientInput(destination_kind="local", identity_hash=digest,
                               unresolved_token="0" * 32),
        lambda: RecipientInput(destination_kind="local",
                               identity_hash=b"\x00" * 31),
    )
    for build in invalid:
        with pytest.raises(ValueError, match=INVALID_IDENTITY):
            build()


def test_unsafe_file_and_recipient_labels_are_opaque():
    planted = "/home/alice/secret-project/prod-db-password.pem"
    label = safe_file_label(SUBJECT_ID, planted)
    assert label == f"file {SUBJECT_ID} (.pem)"
    for component in ("home", "alice", "secret-project", "prod-db-password"):
        assert component not in label

    assert safe_file_label(SUBJECT_ID, "/x/Y.KEYSTORE") == (
        f"file {SUBJECT_ID} (.keystore)")
    assert safe_file_label(SUBJECT_ID, "rel/cert.p12") == (
        f"file {SUBJECT_ID} (.p12)")
    assert safe_file_label(SUBJECT_ID, "/x/bundle.pfx") == (
        f"file {SUBJECT_ID} (.pfx)")
    for other in ("/etc/app/config.yaml", "/srv/app/.env",
                  "/a/archive.pem.bak", "/home/alice/.ssh/id_rsa"):
        label = safe_file_label(SUBJECT_ID, other)
        assert label == f"file {SUBJECT_ID}", other

    for bad_id in ("alice", "/home/alice", SUBJECT_ID.upper(),
                   SUBJECT_ID[:-1], SUBJECT_ID + "0", ""):
        with pytest.raises(ValueError, match=INVALID_IDENTITY):
            safe_file_label(bad_id, planted)
    for bad_path in ("", "/a/\x00.pem", None):
        with pytest.raises(ValueError, match=INVALID_IDENTITY):
            safe_file_label(SUBJECT_ID, bad_path)  # type: ignore[arg-type]

    # Recipients are keyed by an opaque digest; the concrete host, URL or
    # server configuration is an input to the HMAC, never a stored part.
    for kind, concrete in (
            ("external_net", "https://api.planted-host.example/v1?token=abc"),
            ("mcp_tool", '{"command":"planted-server","args":["--secret"]}')):
        digest = recipient_identity(KEY, kind, concrete)  # type: ignore[arg-type]
        assert len(digest) == 32
        for planted_part in (b"planted", b"example", b"https", b"secret"):
            assert planted_part not in digest
        recipient = RecipientInput(destination_kind=kind,  # type: ignore[arg-type]
                                   identity_hash=digest)
        assert "planted" not in repr(recipient)


def test_v2_exemplars_do_not_keep_email_domains_or_paths():
    assert safe_masked_example("credential", "sk-live-abcdef123456") is None
    assert safe_masked_example("path", "/home/alice/.ssh/id_rsa") is None

    email = safe_masked_example("email", "alice@planted-domain.example")
    assert email == "al•••e"
    assert "planted" not in email and "@" not in email

    assert safe_masked_example("account", "a") == "••••"
    assert safe_masked_example("account", "abcd") == "••••"
    assert safe_masked_example("phone", "+1 415 555 0100") == "+1•••0"

    # An output that would contain the whole input shows nothing instead.
    assert safe_masked_example("person", "••••") is None
    assert safe_masked_example("person", "ab•••c") is None
    # Retained characters never carry control characters.
    assert safe_masked_example("person", "\x1b[31mhello") is None
    assert safe_masked_example("person", "hello\n") is None
    assert safe_masked_example("person", "a\x07cdef") is None

    for bad_type in ("zipcode", None):
        with pytest.raises(ValueError):
            safe_masked_example(bad_type, "value")  # type: ignore[arg-type]


def test_coalescing_uses_exact_identity_and_distinct_spans():
    profile = _profile()
    lower, upper = "alice@example.com", "Alice@example.com"
    findings = [
        Finding("email", lower, 0, 17),
        Finding("email", lower, 0, 17),       # a second detector, same span
        Finding("email", upper, 36, 53),
        Finding("email", lower, 18, 35),
    ]
    groups = coalesce_value_findings(profile, KEY, findings)
    assert len(groups) == 2
    first, second = groups
    assert first.subject.identity_hash == value_identity(KEY, lower)
    assert first.subject.subject_kind == "value"
    assert first.subject.unresolved_token is None
    assert first.data_type == "email"
    assert first.occurrences == 2
    assert first.masked_example == "al•••m"
    assert second.subject.identity_hash == value_identity(KEY, upper)
    assert second.occurrences == 1
    assert second.masked_example == "Al•••m"
    assert lower not in repr(groups) and upper not in repr(groups)
    assert "example.com" not in repr(groups)

    assert coalesce_value_findings(profile, KEY, []) == ()

    for bad in (Finding("email", lower, -1, 16), Finding("email", lower, 5, 5),
                Finding("email", lower, 0, 16), Finding("email", "", 0, 0),
                Finding("email", lower, True, 17),  # type: ignore[arg-type]
                Finding("email", lower, 0.0, 17),  # type: ignore[arg-type]
                Finding("zipcode", lower, 0, 17)):
        with pytest.raises(ValueError, match="invalid accounting observation"):
            coalesce_value_findings(profile, KEY, [bad])
    with pytest.raises(ValueError, match=INVALID_IDENTITY):
        coalesce_value_findings(profile, b"short", findings)


def test_coalescing_selects_highest_severity_then_name():
    profile = _profile()
    card = "4111111111111111"
    cases = (
        ([Finding("account", card, 0, 16), Finding("financial", card, 0, 16),
          Finding("url", card, 20, 36)], "financial"),
        ([Finding("person", "Jordan Lee", 0, 10),
          Finding("phone", "Jordan Lee", 0, 10),
          Finding("email", "Jordan Lee", 0, 10)], "email"),
        ([Finding("url", "sk-live-abcdef", 0, 14),
          Finding("credential", "sk-live-abcdef", 0, 14)], "credential"),
    )
    for findings, expected in cases:
        for order in itertools.permutations(findings):
            (group,) = coalesce_value_findings(profile, KEY, list(order))
            assert group.data_type == expected, order
            assert group.masked_example == safe_masked_example(
                expected, order[0].value)
    (credential,) = coalesce_value_findings(profile, KEY, cases[2][0])
    assert credential.masked_example is None
    assert credential.occurrences == 1
    (card_group,) = coalesce_value_findings(profile, KEY, cases[0][0])
    assert card_group.occurrences == 2
