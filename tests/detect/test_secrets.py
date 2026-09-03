import pytest

from privacy_hud.detect.secrets import SecretDetector

D = SecretDetector()


def test_detects_openai_style_key():
    found = D.scan("OPENAI_API_KEY=sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm", {})
    assert [f.data_type for f in found] == ["credential"]


def test_detects_aws_access_key_id():
    assert D.scan("AKIAIOSFODNN7EXAMPLE", {})


def test_detects_high_entropy_assignment():
    assert D.scan('token = "hR7dQ2mZ9pXvL4tK8sN1bW6yE3cA5uJ0"', {})


def test_ignores_low_entropy_prose():
    assert D.scan("the quick brown fox jumps over the lazy dog", {}) == []


def test_ignores_obvious_placeholders():
    assert D.scan('api_key = "your-api-key-here"', {}) == []


def test_high_entropy_value_reachable_without_a_recognized_keyword():
    # The entropy backstop must not require api_key/secret/token/... — a
    # credential assigned to any other name is exactly what it exists to
    # catch. Regression test for fix round 1, Finding 2.
    found = D.scan('session_seed = "hR7dQ2mZ9pXvL4tK8sN1bW6yE3cA5uJ0"', {})
    assert [f.data_type for f in found] == ["credential"]


def test_detects_pem_private_key_headers():
    for header in [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ]:
        found = D.scan(header, {})
        assert [f.data_type for f in found] == ["credential"], header


# --- Fix round 2: pure-hex digests are excluded from the name-agnostic
# GENERIC_QUOTED path (they read as git SHAs/checksums, not credentials, at
# these exact digest lengths), but NOT from the keyword-gated ASSIGNMENT
# path, where an explicit api_key/secret/token/... name outweighs shape. ---

_SHA1_HEX = "b6632199159d0b375414a80164f189e001241b1e"  # 40 hex chars
_SHA256_HEX = "6d96702f97cfdf794beddf9874f2d706da71edf839fcf4e9d3c45f54c8be77e2"  # 64 hex chars
assert len(_SHA1_HEX) == 40
assert len(_SHA256_HEX) == 64


def test_bare_quoted_git_sha_is_not_flagged():
    # A 40-char pure-hex string with no assignment context reads as a git
    # SHA, not a credential — must NOT be flagged.
    found = D.scan(f'"{_SHA1_HEX}"', {})
    assert found == []


def test_bare_quoted_sha256_is_not_flagged():
    # Same reasoning at the sha256 digest length (64 hex chars).
    found = D.scan(f'"{_SHA256_HEX}"', {})
    assert found == []


def test_named_key_with_hex_value_is_still_flagged():
    # Keyword beats shape: an explicit api_key/secret/token/... name is
    # strong enough evidence that the hex-digest exclusion must NOT apply
    # here, even though the value happens to be pure hex at digest length.
    found = D.scan(f'api_key = "{_SHA1_HEX}"', {})
    assert [f.data_type for f in found] == ["credential"]


def test_quoted_base64_blob_is_still_flagged():
    # Base64 blobs are NOT exempted (accepted trade-off, documented in
    # fix round 2 of task-5-report.md): a base64 blob can genuinely be an
    # encoded key, and missing one is a silent leak, so this must still
    # flag despite the risk of catching non-secret base64 data too.
    found = D.scan('payload = "aB3+xY9/zQw1Er5Ty7Ui0OpAs2Df4Gh6"', {})
    assert [f.data_type for f in found] == ["credential"]


def test_high_entropy_alphanumeric_secret_still_flagged_no_regression():
    # No regression on the original entropy-backstop case from the brief.
    found = D.scan('token = "hR7dQ2mZ9pXvL4tK8sN1bW6yE3cA5uJ0"', {})
    assert [f.data_type for f in found] == ["credential"]


@pytest.mark.parametrize(
    "text",
    [
        "OPENAI_API_KEY=sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "a" * 36,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ",
        "postgres://user:pass12345@db.example.com:5432/mydb",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        'token = "hR7dQ2mZ9pXvL4tK8sN1bW6yE3cA5uJ0"',
        'api_key: "AbCdEfGhIjKlMnOpQrSt1234567890XYZ"',
        'session_seed = "hR7dQ2mZ9pXvL4tK8sN1bW6yE3cA5uJ0"',
        'headers["X-Random"] = "zQ8pL2vN6mK9xR3tY7uI1oP5aS4dF0gH"',
        'api_key = "your-api-key-here"',
        "the quick brown fox jumps over the lazy dog",
        f'"{_SHA1_HEX}"',
        f'"{_SHA256_HEX}"',
        f'api_key = "{_SHA1_HEX}"',
        'payload = "aB3+xY9/zQw1Er5Ty7Ui0OpAs2Df4Gh6"',
    ],
)
def test_offsets_always_slice_back_to_the_value(text):
    for f in SecretDetector().scan(text, {}):
        assert text[f.start : f.end] == f.value
