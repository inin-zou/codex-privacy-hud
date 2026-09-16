import pytest

from privacy_hud.detect.paths import PathDetector, is_sensitive_path

D = PathDetector()


def test_flags_dotenv():
    assert [f.data_type for f in D.scan("cat /repo/.env", {})] == ["path"]


def test_flags_private_key_and_aws_credentials():
    assert D.scan("~/.aws/credentials", {})
    assert D.scan("./deploy/id_rsa", {})


def test_ignores_ordinary_source_paths():
    assert D.scan("src/app/main.py", {}) == []


@pytest.mark.parametrize(
    "text",
    [
        "cat .env",
        "the .env file has secrets",
        "/repo/.env",
        'load("/app/.env.production")',
        "~/.aws/credentials",
        "./deploy/id_rsa",
        "cert.pem",
        "credentials.json",
        ".ssh/config",
    ],
)
def test_offsets_always_slice_back_to_the_value(text):
    for f in PathDetector().scan(text, {}):
        assert text[f.start : f.end] == f.value


@pytest.mark.parametrize("path", [
    ".env",
    "./.env",
    "config/.env",
    ".env.local",
    ".env.production",
    "~/.ssh/id_rsa",
    "deploy/id_ed25519",
    "certs/server.pem",
    "keystore.p12",
    "~/.aws/credentials",
    "credentials.json",
    "~/.ssh/config",
])
def test_a_known_sensitive_path_is_recognised(path):
    assert is_sensitive_path(path) is True


@pytest.mark.parametrize("path", [
    # Templates are committed to repositories to be read. Blocking one stops
    # ordinary work, and the user's only escape is turning the whole guard
    # off -- so the guard is narrower than the detector here, on purpose.
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    "config/.env.example",
    # Ordinary files.
    "src/main.py",
    "README.md",
    "Makefile",
    "",
])
def test_an_ordinary_or_template_path_is_not(path):
    assert is_sensitive_path(path) is False


def test_the_detector_still_flags_a_template():
    """The guard being narrower than tier 0 is deliberate, not a gap.

    A `.env.example` that really does hold a key must still be NOTICED --
    noticing costs 2.0 budget points, while blocking costs a command that
    does not run. If someone later "fixes" the asymmetry by narrowing
    PATTERNS, this fails first.
    """
    assert D.scan("cat .env.example", {}) != []
