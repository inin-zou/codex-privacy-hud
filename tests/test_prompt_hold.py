from __future__ import annotations

import pytest

from privacy_hud.detect.base import Finding
from privacy_hud.detect.secrets import SecretDetector


A = "ghp_" + "Ab12" * 9
B = "ghp_" + "Cd34" * 9

CASES = [
    ("sk-" + "Ab12" * 6, "API key format"),
    ("AKIA" + "AB12" * 4, "AWS access key ID format"),
    (A, "GitHub token format"),
    (
        "eyJ" + "Ab12" * 3 + "." + "Cd34" * 3 + "." + "Ef56" * 3,
        "JSON Web Token format",
    ),
    (
        "postgres://demo:synthetic_password@db.example.invalid/app",
        "Database connection string with password",
    ),
]

HELD = (
    "PRIVACY HUD requested a hold for this message\n\n"
    "  Credential format detected: GitHub token format.\n"
    "  This hold requests that Codex keep this submission out of model context.\n"
    "  Host enforcement is not confirmed.\n\n"
    "  To allow it, wait at least 2 seconds, then paste or type the message again\n"
    "  and submit it within 5 minutes. Editing the surrounding text is allowed.\n"
    "  Every new credential requires a hold before confirmation.\n"
    "  Confirmed credentials are allowed for this session while this daemon runs.\n\n"
    "  Only supported well-formed credential formats in prompt text can trigger a hold.\n"
    "  Images and attachments are not scanned."
)

CONFIRMED = (
    "PRIVACY HUD: allowed this submission with credentials you confirmed "
    "(GitHub token format).\n"
    "Admission to model context is not confirmed.\n"
    "Already disclosed data cannot be recalled from this session."
)


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


@pytest.mark.parametrize(("value", "label"), CASES)
def test_supported_formats_have_fixed_labels_and_keep_finding_contract(
    value, label
):
    detector = SecretDetector()
    text = "before " + value + " after"
    labeled = detector.scan_labeled(text, {})
    eligible = [m for m in labeled if m.hold_eligible]
    assert len(eligible) == 1
    match = eligible[0]
    assert match.kind == label
    assert match.finding == Finding("credential", value, 7, 7 + len(value))
    assert detector.scan(text, {}) == [m.finding for m in labeled]


@pytest.mark.parametrize(
    ("text", "label"),
    [
        (
            'password="aB3dE5gH7jK9mN2pQ4sT6vW8"',
            "High-entropy secret assignment",
        ),
        (
            '"aB3dE5gH7jK9mN2pQ4sT6vW8"',
            "High-entropy quoted string",
        ),
        ("-----BEGIN RSA PRIVATE KEY-----", "Private key header"),
        ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "Private key header"),
    ],
)
def test_entropy_and_key_headers_remain_detectable_but_cannot_hold(text, label):
    detector = SecretDetector()
    matches = detector.scan_labeled(text, {})
    assert matches
    assert label in {m.kind for m in matches}
    assert not any(m.hold_eligible for m in matches)
    assert detector.scan(text, {}) == [m.finding for m in matches]


def test_confirmation_hash_is_exact_salted_and_domain_separated():
    from privacy_hud.mask import value_hash
    from privacy_hud.prompt_hold import credential_hash

    salt = b"a" * 32
    first = credential_hash(salt, A)
    assert isinstance(first, bytes)
    assert len(first) == 32
    assert first == credential_hash(salt, A)
    assert first != credential_hash(b"b" * 32, A)
    assert first != credential_hash(salt, A.swapcase())
    assert first != credential_hash(salt, " " + A)
    assert first != value_hash(salt, A)


def test_gap_window_and_allowed_lifetime():
    from privacy_hud.prompt_hold import PromptGate

    clock = Clock()
    gate = PromptGate(salt=b"a" * 32, clock=clock)

    def submit(key):
        return gate.decide(
            {A: "GitHub token format"},
            delivery_key=key,
            submitted_at=clock(),
        )

    assert submit("1").hold
    clock.now = 101.999
    assert submit("2").hold
    clock.now = 102.0
    result = submit("3")
    assert not result.hold
    assert result.confirmed == ("GitHub token format",)
    clock.now = 10000.0
    result = submit("4")
    assert not result.hold
    assert result.confirmed == ()


@pytest.mark.parametrize(("elapsed", "held"), [(300.0, False), (300.001, True)])
def test_window_boundary(elapsed, held):
    from privacy_hud.prompt_hold import PromptGate

    clock = Clock()
    gate = PromptGate(salt=b"a" * 32, clock=clock)
    values = {A: "GitHub token format"}
    assert gate.decide(values, delivery_key="1", submitted_at=clock()).hold
    clock.now += elapsed
    assert gate.decide(
        values, delivery_key="2", submitted_at=clock()
    ).hold is held


def test_expiration_reholds_then_can_be_confirmed():
    from privacy_hud.prompt_hold import PromptGate

    clock = Clock()
    gate = PromptGate(salt=b"a" * 32, clock=clock)
    values = {A: "GitHub token format"}
    assert gate.decide(values, delivery_key="1", submitted_at=clock()).hold
    clock.now = 401.0
    assert gate.decide(values, delivery_key="2", submitted_at=clock()).hold
    clock.now = 403.0
    assert not gate.decide(
        values, delivery_key="3", submitted_at=clock()
    ).hold


def test_new_credential_reholds_whole_group_without_partial_authorization():
    from privacy_hud.prompt_hold import PromptGate

    clock = Clock()
    gate = PromptGate(salt=b"a" * 32, clock=clock)
    assert gate.decide(
        {A: "GitHub token format"}, delivery_key="1", submitted_at=clock()
    ).hold
    clock.now = 102.0
    both = {A: "GitHub token format", B: "GitHub token format"}
    assert gate.decide(both, delivery_key="2", submitted_at=clock()).hold
    assert gate.allowed == set()
    clock.now = 103.999
    assert gate.decide(both, delivery_key="3", submitted_at=clock()).hold
    clock.now = 104.0
    assert not gate.decide(both, delivery_key="4", submitted_at=clock()).hold
    assert len(gate.allowed) == 2


def test_queued_early_submission_does_not_become_confirmation():
    from privacy_hud.prompt_hold import PromptGate

    clock = Clock()
    gate = PromptGate(salt=b"a" * 32, clock=clock)
    values = {A: "GitHub token format"}
    assert gate.decide(values, delivery_key="1", submitted_at=100.0).hold
    clock.now = 110.0
    assert gate.decide(values, delivery_key="2", submitted_at=100.1).hold
    assert not gate.decide(values, delivery_key="3", submitted_at=110.0).hold


def test_replayed_delivery_cannot_confirm_and_keeps_original_decision():
    from privacy_hud.prompt_hold import PromptGate

    clock = Clock()
    gate = PromptGate(salt=b"a" * 32, clock=clock)
    values = {A: "GitHub token format"}
    first = gate.decide(values, delivery_key="1", submitted_at=clock())
    clock.now = 102.0
    assert gate.decide(values, delivery_key="1", submitted_at=clock()) == first
    assert not gate.decide(values, delivery_key="2", submitted_at=clock()).hold
    assert gate.decide(values, delivery_key="1", submitted_at=clock()) == first


def test_gate_keeps_no_raw_values_and_restart_loses_authorization():
    from privacy_hud.prompt_hold import PromptGate

    clock = Clock()
    gate = PromptGate(salt=b"a" * 32, clock=clock)
    values = {A: "GitHub token format"}
    gate.decide(values, delivery_key="1", submitted_at=clock())
    assert all(isinstance(key, bytes) for key in gate.pending)
    clock.now += 2
    gate.decide(values, delivery_key="2", submitted_at=clock())
    assert all(isinstance(key, bytes) for key in gate.allowed)
    assert A not in repr(vars(gate))
    replacement = PromptGate(salt=b"b" * 32, clock=clock)
    assert replacement.decide(
        values, delivery_key="3", submitted_at=clock()
    ).hold


def test_exact_copy_and_label_allowlist():
    from privacy_hud.prompt_hold import confirmed_message, held_reason

    assert held_reason(["GitHub token format"]) == HELD
    assert confirmed_message(["GitHub token format"]) == CONFIRMED
    assert held_reason(["GitHub token format"] * 2) == HELD
    text = held_reason(["GitHub token format", "API key format"])
    assert "API key format; GitHub token format" in text
    for render in (held_reason, confirmed_message):
        with pytest.raises(ValueError):
            render([A])
    for text in (HELD, CONFIRMED):
        assert A not in text
        for phrase in (
            "undo", "revoke", "remove from context",
            "your data is protected", "100% secure",
        ):
            assert phrase not in text.lower()
