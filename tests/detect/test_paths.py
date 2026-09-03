import pytest

from privacy_hud.detect.paths import PathDetector

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
