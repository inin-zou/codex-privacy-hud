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
    ],
)
def test_offsets_always_slice_back_to_the_value(text):
    for f in SecretDetector().scan(text, {}):
        assert text[f.start : f.end] == f.value
