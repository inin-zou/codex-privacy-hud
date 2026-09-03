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
