# tests/test_browser_honesty.py
"""The browser must not show a clean bill of health the ledger cannot sign.

Two halves of issue #49:

**1a.** `local_ui_server` already sends `coverage` on `/api/summary`, and the
guarded ASCII block on `/api/exposures`. The HTML view -- the one visible by
default, since `ui/index.html` hides the ASCII region -- reads neither, and
picks the reassuring empty state unconditionally. So the protection is
computed, served, and not what the user sees.

**3.** The reassuring strings themselves claim more than the evidence
supports, and `SessionCoverage`'s own docstring is what proves it:

    `verified` means "nothing on record contradicts a complete account",
    which is the strongest claim the evidence supports and deliberately
    weaker than "complete".

So "No sensitive data has crossed a trust boundary this session" is not
supportable on the verified path either -- the type that gates the claim
documents that it cannot carry it.

That docstring also lists examples, and one of them is wrong: it names "a
hook whose 2 s client timeout expired against a busy daemon" as an event
that leaves no trace, which `daemon.py`'s own probe disproves -- 10
concurrent ingress calls at the real timeout, 7 clients gave up, all 10 rows
in the ledger once the daemon drained. The first draft of the replacement
copy repeated that example and had to be corrected. The lesson is in the
copy now: it reports what the coverage check found and names no examples at
all, because enumerating is how a caveat acquires a claim of its own.

The fix both halves share: **one function decides which empty line applies,
and every surface calls it.** Two surfaces each deciding is how they came to
disagree.
"""
import json
import re
import urllib.parse
import urllib.request

import pytest

from privacy_hud import dispatch as dispatch_mod
from privacy_hud import local_ui_server, render
from privacy_hud.ledger import SessionCoverage

SID = "0199e2e0-b10c-4000-8000-0000000049aa"

VERIFIED = SessionCoverage(recorded=True, observers=1, attached=False,
                           unobserved_hooks=False)
UNVERIFIED = SessionCoverage(recorded=True, observers=1, attached=True,
                             unobserved_hooks=False)

TABS = ("Exposed", "Prevented", "All events")

#: Sentences no empty state may contain, on any coverage reading, because
#: nothing the ledger holds can support them. Exact strings: this cannot
#: catch an equivalent claim phrased differently, which is why CLAUDE.md
#: section 5's tracing rule is the real check and this is the tripwire.
UNSUPPORTABLE = (
    "No sensitive data has crossed",
    "The engine is running",
)


def _get(base, path):
    with urllib.request.urlopen(f"{base}{path}") as r:
        return json.load(r)


def _exposures(base, tab):
    q = urllib.parse.urlencode({"session_id": SID, "tab": tab})
    return _get(base, f"/api/exposures?{q}")


@pytest.fixture
def ui(state):
    server = local_ui_server.serve(SID, print_url=False)
    host, port = server.socket.getsockname()[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


# --- half 3: the strings themselves -----------------------------------

@pytest.mark.parametrize("tab", TABS)
@pytest.mark.parametrize("coverage", [None, VERIFIED, UNVERIFIED],
                         ids=["not-asked", "verified", "unverified"])
def test_no_empty_state_asserts_what_the_ledger_cannot_show(tab, coverage):
    line = render.empty_message(tab, coverage)
    for claim in UNSUPPORTABLE:
        assert claim not in line, (tab, coverage, line)


@pytest.mark.parametrize("tab", TABS)
def test_every_empty_state_says_what_was_recorded(tab):
    """Stating the ledger fact is the whole replacement for claiming the
    world fact, so the word has to actually be there."""
    assert "record" in render.empty_message(tab, VERIFIED).lower()


def test_an_unverified_session_gets_the_same_line_on_every_tab():
    """design.md section 5: an incomplete record is a session-scope caveat,
    so it replaces all three tab-scope lines rather than qualifying one."""
    lines = {render.empty_message(tab, UNVERIFIED) for tab in TABS}
    assert len(lines) == 1, lines


def test_a_verified_session_still_gets_a_line_per_tab():
    lines = {render.empty_message(tab, VERIFIED) for tab in TABS}
    assert len(lines) == len(TABS), lines


# --- half 1a: the browser is given the decision, and takes it ----------

def test_the_exposures_endpoint_sends_an_empty_message_at_all(ui):
    """The browser cannot pick the right line without being told which one,
    and `/api/copy` cannot tell it: that endpoint is session-independent and
    fetched once, while coverage is per session."""
    for tab in TABS:
        payload = _exposures(ui, tab)
        assert payload["empty_message"], (tab, payload)


def test_an_unrecorded_session_is_not_served_a_reassuring_empty_state(ui):
    """Nothing has been dispatched for SID, so its record is not verified.
    Every tab must be served the unverified line, not the clean one."""
    served = {
        _exposures(ui, tab)["empty_message"] for tab in TABS
    }
    assert len(served) == 1, served
    assert served == {render.empty_message("Exposed", UNVERIFIED)}


def test_the_banner_travels_as_its_own_field_for_an_unverified_session(ui):
    """The ASCII block carries the banner inside `text`, which the default
    view hides. The HTML needs it as a field it can render."""
    payload = _exposures(ui, "Exposed")
    assert payload["coverage_banner"], payload


def test_a_verified_session_carries_no_banner(state):
    """The banner is a caveat. A caveat shown unconditionally is noise, and
    noise is how a warning gets trained away (ledger.coverage's own words)."""
    dispatch_mod.dispatch(state, {
        "hook_event_name": "SessionStart", "session_id": SID,
        "cwd": "/w", "model": "gpt-5", "turn_id": "t1"})
    server = local_ui_server.serve(SID, print_url=False)
    host, port = server.socket.getsockname()[:2]
    try:
        payload = _exposures(f"http://{host}:{port}", "Exposed")
    finally:
        server.shutdown()
        server.server_close()
    assert payload["coverage_banner"] is None, payload
    assert payload["empty_message"] == render.empty_message("Exposed", VERIFIED)


def test_the_browser_reads_the_servers_empty_message_and_banner():
    """`ui/app.js` is an IIFE with no exports and this suite has no JS
    runtime, so this pins the two reads rather than the rendering. It is a
    tripwire, not a proof, and the page itself is looked at during the
    reinstall acceptance run.

    Comments are stripped first. The version of this test that did not strip
    them passed on a file whose assignments had been deleted, because both
    field names also appear in the comments explaining them — a check that
    survives the defect it names, which is the failure this whole issue is
    about.
    """
    src = (local_ui_server.__file__.rsplit("/src/", 1)[0] + "/ui/app.js")
    with open(src) as fh:
        js = fh.read()
    code = re.sub(r"^\s*//.*$", "", js, flags=re.M)
    assert "data.empty_message" in code, \
        "app.js does not read the server's empty message"
    assert "data.coverage_banner" in code, \
        "app.js does not read the server's coverage banner"
