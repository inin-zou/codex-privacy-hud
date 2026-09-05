"""The detector stack, and the one place that says what the default stack is.

`default_detectors()` exists so the answer to "which detectors does this
plugin run?" lives next to the detectors themselves rather than inline in
`dispatch.new_state`. Detection is the most-likely-to-change part of this
codebase (the model has been swapped once and its label taxonomy shifted
under us), so the list belongs on the same seam as the `Detector` contract:
a new detector is added by writing the class and adding one line here, and
its tier/cost declaration is checked the moment an `Engine` is built with it.

Deliberately a plain function returning a fresh list, not a registry with
decorators and entry points. There is no third-party detector story here (I2:
no dependencies, nothing loaded from outside the package), so a discovery
mechanism would add indirection and an import-order failure mode in exchange
for nothing. What was actually missing was a *named* construction site, and a
function is that.

Imports are inside the function on purpose: importing `privacy_hud.detect`
must stay free of side effects, and constructing a `ModelDetector` is the
opposite of free — it tries to load 1.5B parameters from the local
HuggingFace cache. `tests/test_network_isolation.py` imports every module in
the package to prove nothing reaches the network at import time, and this
keeps that cheap and true.
"""
from __future__ import annotations


def default_detectors() -> list:
    """Construct the plugin's default detector stack, cheapest tier first.

    Order is the order findings are produced in, which is the order the
    ledger records them in, so it is user-visible: tier 0, then tier 1, then
    the expensive tier 3. `Engine` re-groups by declared cost regardless, so
    this ordering is for readers and for stable ledger rows, not for
    correctness.

    Constructing the returned `ModelDetector` is where tier 3's weight load
    happens (and where it silently fails to happen, setting
    `available=False`, on a machine with no weights). Call this once per
    process — `dispatch.new_state` does — and share the result; the engine's
    `_TIER3_LOCK` assumes one shared pipeline, not one per session.
    """
    from .model import ModelDetector
    from .paths import PathDetector
    from .secrets import SecretDetector

    return [PathDetector(), SecretDetector(), ModelDetector()]
