from privacy_hud.mask import new_salt, value_hash, mask, pseudonym


def test_value_hash_is_stable_within_a_salt():
    s = new_salt()
    assert value_hash(s, "a@b.com") == value_hash(s, "a@b.com")


def test_value_hash_differs_across_salts():
    assert value_hash(new_salt(), "a@b.com") != value_hash(new_salt(), "a@b.com")


def test_credentials_are_never_exemplified():
    assert mask("credential", "sk-live-abcdef123456") is None


def test_email_mask_keeps_two_chars_and_domain():
    assert mask("email", "jordan@acme.com") == "jo•••@acme.com"


def test_mask_does_not_leak_the_local_part():
    masked = mask("email", "jordan@acme.com")
    assert "rdan" not in masked


def test_short_values_are_indistinguishable_by_length():
    assert mask("account", "1") == mask("account", "1234")


def test_pseudonym_is_stable_within_session_and_typed():
    s = new_salt()
    a = pseudonym(s, "email", "jordan@acme.com")
    b = pseudonym(s, "email", "jordan@acme.com")
    assert a == b
    assert a.endswith("@example.invalid")
    assert pseudonym(s, "email", "other@acme.com") != a
