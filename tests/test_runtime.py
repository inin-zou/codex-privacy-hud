"""Tests for the runtime receipt and `privacy-hud-setup`.

Three things are being defended.

**The pin cannot be blind.** The whole point of recording an interpreter is
that Codex's hooks run against a minimal `PATH` where `python3` is usually a
system interpreter with no `transformers` — so a daemon spawned from the
shebang would come up with tier 3 dead and report itself healthy. That makes
`setup refuses to record an interpreter without the ML stack` the single most
important assertion in this file. `--allow-degraded` exists so the degraded
choice stays a *choice*, and it is tested as such.

**The receipt holds infrastructure only (I1).** It is a file this plugin
writes into the user's plugin-data directory, and the pinned environment it
carries is a hardcoded three-name allowlist of HuggingFace cache locations. A
test plants a fake credential in the environment and asserts it does not
appear anywhere in the receipt, because "copy the environment" is the obvious
implementation and it would turn a privacy tool into a secret leak.

**The literals stay in sync.** `hooks/handler.py` is stdlib-only and never
imports this package, so it restates the receipt's filename, version, latch
name, cooldown, module and env-var names as its own constants. Those are
parsed out of the file and compared, the same way `MIN_PYTHON` is checked
against `pyproject.toml` rather than trusted.

The real interpreter probe is exercised once, against `sys.executable`, and
asserts only that this package can be imported there — nothing about
`transformers`, which CI does not have.
"""
from __future__ import annotations

import ast
import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest

from privacy_hud import runtime

HANDLER = Path(__file__).resolve().parents[1] / "hooks" / "handler.py"
SRC = Path(runtime.__file__).resolve().parent.parent


# --------------------------------------------------------------------- #
# the receipt's shape
# --------------------------------------------------------------------- #

def test_build_receipt_records_the_running_interpreter(tmp_path):
    """`sys.executable`, never a name resolved off `PATH`. This is the whole
    lesson from the prior art: the process doing the recording is the one
    known to have the stack."""
    receipt = runtime.build_receipt(tmp_path)
    assert receipt["python"] == sys.executable
    assert receipt["v"] == runtime.RECEIPT_VERSION


def test_build_receipt_records_the_path_entry_that_holds_this_package(tmp_path):
    """So a bare checkout works without the user remembering `PYTHONPATH=src`.

    Safe to force onto the spawned child because the child is the same
    interpreter that recorded it.
    """
    receipt = runtime.build_receipt(tmp_path)
    assert Path(receipt["pythonpath"]) == SRC
    assert (Path(receipt["pythonpath"]) / "privacy_hud" / "runtime.py").is_file()


def test_receipt_carries_only_infrastructure_fields(tmp_path):
    """I1, as a whitelist over the top-level keys. A `content`, `payload` or
    `session` field here would be a privacy incident in the file this plugin
    writes into the user's own data directory."""
    receipt = runtime.build_receipt(tmp_path, versions={"transformers": "5.16.1"})
    assert set(receipt) == {"v", "python", "pythonpath", "plugin_data",
                            "recorded_at", "recorded", "env"}


def test_receipt_never_copies_the_environment(tmp_path, monkeypatch):
    """The obvious implementation — snapshot `os.environ` so the daemon starts
    in the same environment — would write the user's tokens to disk. Only the
    three HuggingFace cache names are recorded, and this asserts on the whole
    serialized file rather than on `receipt["env"]`, so a leak anywhere in the
    structure fails here."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-not-a-real-key-abcdef")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI-fake")
    monkeypatch.setenv("HF_HOME", str(tmp_path / "hf"))

    receipt = runtime.build_receipt(tmp_path)
    blob = json.dumps(receipt)

    assert "sk-not-a-real-key-abcdef" not in blob
    assert "wJalrXUtnFEMI-fake" not in blob
    assert "OPENAI_API_KEY" not in blob
    assert receipt["env"] == {"HF_HOME": str(tmp_path / "hf")}
    assert set(receipt["env"]) <= set(runtime.PINNED_ENV_NAMES)


def test_write_receipt_is_owner_only(tmp_path):
    """It names an interpreter a hook process will execute. A file any local
    user could rewrite would turn auto-spawn into an arbitrary-exec hole."""
    path = runtime.write_receipt(tmp_path, runtime.build_receipt(tmp_path))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_write_receipt_leaves_no_temp_file_behind(tmp_path):
    runtime.write_receipt(tmp_path, runtime.build_receipt(tmp_path))
    assert sorted(p.name for p in tmp_path.iterdir()) == [runtime.RECEIPT_NAME]


def test_write_receipt_creates_the_directory(tmp_path):
    target = tmp_path / "not-yet"
    runtime.write_receipt(target, runtime.build_receipt(target))
    assert runtime.receipt_path(target).is_file()


# --------------------------------------------------------------------- #
# reading it back
# --------------------------------------------------------------------- #

def test_load_receipt_round_trips(tmp_path):
    written = runtime.build_receipt(tmp_path)
    runtime.write_receipt(tmp_path, written)
    receipt, problem = runtime.load_receipt(tmp_path)
    assert problem == ""
    assert receipt == written


def test_absent_receipt_is_distinguishable_from_a_damaged_one(tmp_path):
    """Different remedies: one setup was never run, the other was damaged."""
    receipt, problem = runtime.load_receipt(tmp_path)
    assert (receipt, problem) == (None, "absent")

    runtime.receipt_path(tmp_path).write_text("{oops", encoding="utf-8")
    receipt, problem = runtime.load_receipt(tmp_path)
    assert receipt is None
    assert problem not in ("", "absent")


@pytest.mark.parametrize("payload", [
    "[]",                                  # not an object
    '{"v": 99, "python": "/bin/sh"}',       # a version this code cannot read
    '{"v": 1}',                             # no interpreter
    '{"v": 1, "python": ""}',               # an empty one
    '{"v": 1, "python": 17}',               # not even a string
])
def test_unusable_receipts_are_refused_rather_than_guessed_at(tmp_path, payload):
    """Every one of these must degrade to "do not spawn". Spawning something
    plausible is the failure mode the pin exists to prevent."""
    runtime.receipt_path(tmp_path).write_text(payload, encoding="utf-8")
    receipt, problem = runtime.load_receipt(tmp_path)
    assert receipt is None and problem


def test_load_receipt_never_raises_on_a_directory(tmp_path):
    """I6: an unreadable receipt is a reason not to spawn, never a traceback
    on the hook path."""
    runtime.receipt_path(tmp_path).mkdir()
    receipt, problem = runtime.load_receipt(tmp_path)
    assert receipt is None and problem


# --------------------------------------------------------------------- #
# the environment a spawned daemon gets
# --------------------------------------------------------------------- #

def test_spawn_env_prepends_the_recorded_path_entry(tmp_path):
    receipt = runtime.build_receipt(tmp_path)
    env = runtime.spawn_env(receipt, {"PYTHONPATH": "/already/here"})
    assert env["PYTHONPATH"].split(os.pathsep) == [receipt["pythonpath"],
                                                   "/already/here"]


def test_spawn_env_lets_the_live_environment_win(tmp_path, monkeypatch):
    """The receipt describes the machine as it was at setup time; the hook's
    environment describes it now, and Codex's value is authoritative. The past
    only fills gaps."""
    monkeypatch.setenv("HF_HOME", str(tmp_path / "recorded"))
    receipt = runtime.build_receipt(tmp_path)
    env = runtime.spawn_env(receipt, {"HF_HOME": "/live/value"})
    assert env["HF_HOME"] == "/live/value"


def test_spawn_env_fills_in_a_missing_weights_location(tmp_path, monkeypatch):
    """Pinning the interpreter without pinning where it looks for weights
    leaves the same "healthy daemon, dead tier 3" hole one level down: setup
    runs in a shell where the weights are findable, and a hook's environment
    is Codex's, which usually is not that shell."""
    monkeypatch.setenv("HF_HOME", str(tmp_path / "recorded"))
    receipt = runtime.build_receipt(tmp_path)
    env = runtime.spawn_env(receipt, {})
    assert env["HF_HOME"] == str(tmp_path / "recorded")


# --------------------------------------------------------------------- #
# probing an interpreter
# --------------------------------------------------------------------- #

def test_probe_of_this_interpreter_finds_this_package():
    """The one test that runs the real probe. Asserts only what is true
    everywhere including CI: this interpreter can import `privacy_hud` when
    handed the recorded path entry."""
    result, elapsed, error = runtime.probe_interpreter(sys.executable, str(SRC),
                                                       timeout=60.0)
    assert error == ""
    assert result["privacy_hud"]
    assert result["executable"]
    assert elapsed >= 0.0


def test_probe_of_a_missing_interpreter_reports_an_error_not_a_crash(tmp_path):
    result, _elapsed, error = runtime.probe_interpreter(
        tmp_path / "deleted" / "python3", timeout=5.0)
    assert result is None and error


def test_probe_of_a_non_python_executable_reports_an_error():
    result, _elapsed, error = runtime.probe_interpreter("/bin/false", timeout=5.0)
    assert result is None and error


def test_probe_reports_a_module_it_cannot_import(tmp_path):
    """A `pythonpath` that does not contain the package: the state a receipt
    written from a checkout that has since been deleted would leave behind."""
    result, _elapsed, error = runtime.probe_interpreter(
        sys.executable, str(tmp_path / "empty"), timeout=60.0,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONNOUSERSITE": "1"})
    assert error == ""
    # Either the package is genuinely absent here, or it is installed in this
    # interpreter's site-packages -- both are honest answers; what matters is
    # that the probe reports a value rather than raising.
    assert "privacy_hud" in result


def test_probe_forbids_hub_access(monkeypatch):
    """I2. Nothing in importing `transformers` should reach the hub, and this
    makes that a property of the probe rather than a hope about a library's
    import side effects. The child reports the flag it actually saw, so this
    asserts what reached the interpreter under test and not what the parent
    intended."""
    monkeypatch.delenv("HF_HUB_OFFLINE", raising=False)
    result, _elapsed, error = runtime.probe_interpreter(
        sys.executable, str(SRC), timeout=60.0)
    assert error == ""
    assert result["hf_hub_offline"] == "1"
    assert os.environ.get("HF_HUB_OFFLINE") is None  # not leaked into ours


# --------------------------------------------------------------------- #
# resolving which plugin-data directory to record against
# --------------------------------------------------------------------- #

def test_resolve_prefers_the_directory_codex_assigns(tmp_path, monkeypatch):
    """The user should never have to know what `PLUGIN_DATA` is, and the value
    Codex assigns is the only one that can be *wrong* to disagree with — its
    hooks pass that one. A stale export in the shell is reported, not obeyed."""
    assigned = tmp_path / "codex-home" / "plugins" / "data" / \
        "codex-privacy-hud-codex-privacy-hud"
    assigned.mkdir(parents=True)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path / "stale-export"))

    chosen, notes, candidates = runtime.resolve_data_dir()

    assert chosen == assigned
    assert candidates == [assigned]
    assert notes  # the disagreement is reported rather than silently resolved


def test_resolve_falls_back_to_the_environment_without_a_codex_install(
        tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex"))
    monkeypatch.setenv("PLUGIN_DATA", str(tmp_path / "scratch"))
    chosen, notes, _candidates = runtime.resolve_data_dir()
    assert chosen == tmp_path / "scratch"
    assert notes


def test_resolve_gives_up_when_there_is_nothing_to_resolve(tmp_path,
                                                           monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex"))
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    chosen, notes, _candidates = runtime.resolve_data_dir()
    assert chosen is None and notes


def test_resolve_refuses_to_choose_between_several_candidates(tmp_path,
                                                              monkeypatch):
    root = tmp_path / "codex-home" / "plugins" / "data"
    (root / "codex-privacy-hud-codex-privacy-hud").mkdir(parents=True)
    (root / "other-codex-privacy-hud").mkdir()
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    chosen, notes, candidates = runtime.resolve_data_dir()
    assert chosen is None
    assert len(candidates) == 2
    assert any("--plugin-data" in note for note in notes)


def test_explicit_plugin_data_wins_and_says_when_codex_disagrees(tmp_path,
                                                                 monkeypatch):
    assigned = tmp_path / "codex-home" / "plugins" / "data" / \
        "codex-privacy-hud-codex-privacy-hud"
    assigned.mkdir(parents=True)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    scratch = tmp_path / "scratch"
    chosen, notes, _candidates = runtime.resolve_data_dir(str(scratch))
    assert chosen == scratch
    assert notes


# --------------------------------------------------------------------- #
# the setup command
# --------------------------------------------------------------------- #

def _no_stack(monkeypatch):
    monkeypatch.setattr(runtime, "_local_versions",
                        lambda: {"transformers": None, "torch": None})


def _full_stack(monkeypatch):
    monkeypatch.setattr(runtime, "_local_versions",
                        lambda: {"transformers": "5.16.1", "torch": "2.14.0"})


def test_setup_refuses_an_interpreter_without_the_ml_stack(tmp_path, monkeypatch,
                                                          capsys):
    """The most important test in this file.

    Running setup from Codex's PATH `python3` is exactly how a blind daemon
    gets pinned: it would start, bind, answer every probe, and detect no names
    or addresses at all. Refusing is what makes the naive setup fail loudly
    instead of quietly.
    """
    _no_stack(monkeypatch)
    code = runtime.main(["--plugin-data", str(tmp_path)])
    out = capsys.readouterr().out

    assert code == 1
    assert not runtime.receipt_path(tmp_path).exists()
    assert "FAILED" in out
    assert "transformers" in out


def test_setup_says_how_to_fix_a_missing_stack(tmp_path, monkeypatch, capsys):
    _no_stack(monkeypatch)
    runtime.main(["--plugin-data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "[detectors]" in out
    assert "--allow-degraded" in out


def test_setup_records_a_degraded_runtime_only_when_asked(tmp_path, monkeypatch,
                                                          capsys):
    """Tiers 0-2 are a real product, so choosing them must stay possible —
    as a decision, with the consequence stated, not as an accident."""
    _no_stack(monkeypatch)
    code = runtime.main(["--plugin-data", str(tmp_path), "--allow-degraded"])
    out = capsys.readouterr().out

    assert code == 0
    receipt, problem = runtime.load_receipt(tmp_path)
    assert problem == ""
    assert receipt["recorded"] == {"transformers": None, "torch": None}
    assert "names and addresses will not be detected" in out.lower()


def test_setup_writes_a_usable_receipt(tmp_path, monkeypatch, capsys):
    _full_stack(monkeypatch)
    code = runtime.main(["--plugin-data", str(tmp_path)])
    capsys.readouterr()

    assert code == 0
    receipt, problem = runtime.load_receipt(tmp_path)
    assert problem == ""
    assert receipt["python"] == sys.executable
    assert receipt["plugin_data"] == str(tmp_path)
    assert receipt["recorded"]["transformers"] == "5.16.1"


def test_setup_states_the_unmonitored_window(tmp_path, monkeypatch, capsys):
    """CLAUDE.md §5. The daemon starting itself costs the first seconds of a
    session, and the command that enables it is where the user must be told."""
    _full_stack(monkeypatch)
    runtime.main(["--plugin-data", str(tmp_path)])
    out = capsys.readouterr().out.lower()
    assert "unmonitored" in out
    assert "unverified" in out


def test_setup_fails_without_writing_when_it_cannot_resolve_a_directory(
        tmp_path, monkeypatch, capsys):
    _full_stack(monkeypatch)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex"))
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    code = runtime.main([])
    out = capsys.readouterr().out
    assert code == 1
    assert "codex plugin add" in out


def test_setup_help_returns_an_int(capsys):
    """`ambient.main`'s and `doctor.main`'s contract: the console-script
    wrapper is handed this return value."""
    assert runtime.main(["--help"]) == 0
    assert runtime.main(["--nonsense"]) == 2


def test_setup_is_idempotent(tmp_path, monkeypatch, capsys):
    _full_stack(monkeypatch)
    runtime.main(["--plugin-data", str(tmp_path)])
    first = runtime.receipt_path(tmp_path).read_text()
    time.sleep(0.01)
    runtime.main(["--plugin-data", str(tmp_path)])
    capsys.readouterr()
    second = runtime.receipt_path(tmp_path).read_text()
    assert json.loads(first)["python"] == json.loads(second)["python"]
    assert sorted(p.name for p in tmp_path.iterdir()) == [runtime.RECEIPT_NAME]


def test_console_script_is_registered():
    import tomllib
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    assert data["project"]["scripts"]["privacy-hud-setup"] == \
        "privacy_hud.runtime:main"


# --------------------------------------------------------------------- #
# the contract with the stdlib-only hook client
# --------------------------------------------------------------------- #

def _handler_constants() -> dict:
    """Module-level literal assignments in `hooks/handler.py`, by AST.

    Parsed rather than imported: that file has a `__main__` guard and reads
    stdin, and importing it to read five constants would be a worse dependency
    than parsing it.
    """
    tree = ast.parse(HANDLER.read_text(encoding="utf-8"), str(HANDLER))
    out = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        try:
            out[target.id] = ast.literal_eval(node.value)
        except ValueError:
            pass
    return out


@pytest.mark.parametrize("name", [
    "RECEIPT_NAME", "RECEIPT_VERSION", "LATCH_NAME", "SPAWN_COOLDOWN",
    "DAEMON_MODULE", "NO_SPAWN_ENV", "PINNED_ENV_NAMES",
])
def test_handler_restates_the_receipt_contract_correctly(name):
    """`hooks/handler.py` cannot import this module — it is stdlib-only so
    that a broken install cannot break Codex — so it restates these literals.
    Drift between the two would be invisible and would silently disable
    auto-spawn, so the duplication is checked rather than trusted, exactly as
    `MIN_PYTHON` is checked against `pyproject.toml`."""
    assert _handler_constants()[name] == getattr(runtime, name)
