import pytest
from privacy_hud.matrix.loader import load_matrix
from privacy_hud.detect.model import LABEL_MAP, ModelDetector, StubModelDetector

M = load_matrix()


def test_every_model_label_maps_to_a_known_matrix_type():
    for data_type in LABEL_MAP.values():
        assert M.severity(data_type) > 0


def test_stub_detector_returns_findings_without_loading_weights():
    d = StubModelDetector([("email", "jordan@acme.com", 8, 23)])
    found = d.scan("contact jordan@acme.com now", {})
    assert found[0].data_type == "email"


def test_detector_reports_unavailable_rather_than_raising_when_weights_absent():
    d = ModelDetector(model_id="does-not-exist/nope")
    assert d.available is False
    # I6: unavailable deep scan degrades, it does not crash the daemon.
    assert d.scan("contact jordan@acme.com", {}) == []


@pytest.mark.slow
def test_real_model_finds_an_email():
    d = ModelDetector()
    if not d.available:
        pytest.skip("privacy-filter weights not present in local cache")
    assert any(f.data_type == "email"
               for f in d.scan("contact jordan@acme.com now", {}))
