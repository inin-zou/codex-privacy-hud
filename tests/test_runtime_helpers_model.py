from __future__ import annotations

import pytest

from privacy_hud import dispatch as dispatch_mod
from privacy_hud.detect.model import ModelDetector, StubModelDetector
from runtime_helpers import (
    close_writer,
    writer_state,
    writer_state_with_detectors,
)


@pytest.mark.parametrize("available", [False, True])
def test_explicit_stack_preserves_detector_identity_and_availability(
        tmp_path, monkeypatch, available):
    def forbidden_init(self, *args, **kwargs):
        pytest.fail("explicit detector stack constructed the real model")

    monkeypatch.setattr(ModelDetector, "__init__", forbidden_init)
    original_constructor = dispatch_mod.ModelDetector
    detector = StubModelDetector([])
    detector.available = available
    detectors = [detector]

    state = writer_state_with_detectors(tmp_path, detectors=detectors)
    try:
        assert state.detectors is detectors
        assert state.detectors[0] is detector
        assert detector.available is available
        assert dispatch_mod.ModelDetector is original_constructor
    finally:
        close_writer(state.ledger)


def test_plain_writer_state_still_constructs_the_production_model(
        tmp_path, monkeypatch):
    class ConstructorReached(Exception):
        pass

    def intercepted_init(self, *args, **kwargs):
        raise ConstructorReached

    monkeypatch.setattr(ModelDetector, "__init__", intercepted_init)
    with pytest.raises(ConstructorReached):
        writer_state(tmp_path)


def test_explicit_stack_restores_an_existing_patch_after_failure(
        tmp_path, monkeypatch):
    sentinel = object()

    def existing_constructor():
        return sentinel

    class ConstructionFailed(Exception):
        pass

    def failed_new_state(*args, **kwargs):
        raise ConstructionFailed

    monkeypatch.setattr(dispatch_mod, "ModelDetector", existing_constructor)
    monkeypatch.setattr(dispatch_mod, "new_state", failed_new_state)

    with pytest.raises(ConstructionFailed):
        writer_state_with_detectors(tmp_path, detectors=[])

    assert dispatch_mod.ModelDetector is existing_constructor
