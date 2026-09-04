# src/privacy_hud/runtime.py
"""`privacy-hud-setup` — pin the interpreter the daemon must be spawned with,
so the hook client can start the daemon itself.

**Why a receipt exists at all.** `hooks/handler.py` is invoked by Codex as
`$PLUGIN_ROOT/hooks/handler.py`, i.e. through its `#!/usr/bin/env python3`
shebang, resolved against Codex's own minimal `PATH`. On the machine this was
built on that is `/opt/homebrew/bin/python3`, which has no `transformers` at
all; the ML stack lives in a completely different interpreter
(`/opt/homebrew/Caskroom/miniforge/base/bin/python3`). A hook that spawned
`sys.executable` — or worse, a bare `python3` off `PATH` — would therefore
start a daemon that comes up *blind*: `ModelDetector.available` is `False`,
tier 3 is silently off, person / address / date detection is gone, and the
daemon looks perfectly healthy while it happens. That is strictly worse than
the honest "you forgot to start the daemon" it replaces, so the interpreter is
recorded once, at setup time, **from a process that demonstrably has the
stack**, and the hook client never guesses.

Every project that solves lazy auto-spawn arrives here. `oleksiijko/pmb` puts
the diagnosis in a code comment — *"Hooks run with a minimal PATH, so prefer
the venv-internal binary we're running from"* — and the projects that shell
out to a bare `python` on `PATH` ship exactly the bug described above.

**Why the receipt lives in `$PLUGIN_DATA`.** Because that is the one directory
whose identity the hook client already knows for certain. Codex assigns
`PLUGIN_DATA` and passes it to its hooks, so a hook reading
`$PLUGIN_DATA/runtime.json` is reading the receipt *for the exact directory it
is about to talk to*, with no derivation, no second env var, and no way for
the two to disagree. That disagreement is this project's most expensive
historical bug (see `doctor.check_plugin_data`), and locating the receipt here
makes it structurally impossible rather than merely detectable: a daemon
spawned from a hook inherits that same `PLUGIN_DATA` from the hook's own
environment. The receipt does **not** record which `PLUGIN_DATA` to use — the
hook's own value does. `plugin_data` is recorded only so a receipt that was
copied to a different directory can be reported as such.

The alternatives were rejected for concrete reasons. In the source checkout:
Codex runs a *copy* of the plugin out of its own cache, so the checkout is not
what executes and may be read-only or shared. In `~/.config` or `$CODEX_HOME`:
one receipt for several plugin-data directories, which reintroduces the
mismatch. As an env var: the user would have to keep it exported in whatever
shell Codex was launched from, which is the failure mode this whole change
exists to delete.

**Why it records an interpreter and not a command line.** The hook client
builds `[python, "-m", "privacy_hud.daemon"]` from its own literals. A receipt
that carried `argv` would be a plain JSON file in a data directory that a hook
process executes verbatim — an arbitrary-exec vector for the price of one
stray write. The receipt carries data the client validates (a path it checks
is executable, a `sys.path` entry, cache locations); it never carries code.

**I1 — infrastructure only.** Interpreter path, `sys.path` entry, data
directory, timestamp, and the versions of `transformers`/`torch` observed at
setup time. The recorded environment is a hardcoded three-name allowlist of
HuggingFace *cache locations* (`PINNED_ENV_NAMES`), never `os.environ` — an
environment dump would carry the user's tokens and credentials into a file on
disk, which is the exact opposite of this plugin's job. No session content, no
prompt, no finding, ever.

**I2 — no network.** Setup imports `transformers` to read a version number and
sets `HF_HUB_OFFLINE=1` in every interpreter it probes, so nothing here can
reach the hub even accidentally.

Stdlib only, and it imports nothing else from `privacy_hud` at module import
time. `doctor.py` imports this module at module level and must be able to
diagnose a broken package; the one import of `doctor` here is deferred into
the CLI, where a circular import cannot form.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

#: Bumped only when the meaning of an existing field changes. A receipt whose
#: `v` this code does not recognize is treated as unusable rather than
#: guessed at: spawning the wrong interpreter is the failure mode this file
#: exists to prevent, so "I do not understand this receipt" must degrade to
#: "do not spawn", never to "spawn something plausible".
RECEIPT_VERSION = 1

#: The receipt's filename inside `$PLUGIN_DATA`. Duplicated as a literal in
#: `hooks/handler.py`, which is stdlib-only and never imports this package —
#: `tests/test_runtime.py` asserts the two agree, so the duplication is
#: checked rather than trusted (the same treatment `daemon.sock` and
#: `MIN_PYTHON` already get).
RECEIPT_NAME = "runtime.json"

#: Marker written after every spawn attempt. Its *mtime* is the whole
#: mechanism: see `SPAWN_COOLDOWN`.
LATCH_NAME = "daemon.spawn-attempt"

#: How long after a spawn attempt the client refuses to make another.
#:
#: This is politeness, not correctness — correctness is `daemon.py`'s startup
#: `flock`, which lets exactly one racer win and makes every loser exit 3
#: without touching the winner's socket. What the cooldown buys is the cold
#: start: `Daemon.__init__` loads ~2.8 GB before it binds, so for those ~7
#: seconds there is no socket file, every hook in the session fails to
#: connect, and without a latch every one of them would fork another
#: interpreter that could only lose the lock and exit. 30 s comfortably
#: covers that window, and a genuinely dead setup is retried a few seconds
#: into the next tool call rather than never.
SPAWN_COOLDOWN = 30.0

#: What the client runs. `-m` rather than a path so the pinned interpreter
#: resolves the module through its own `sys.path` (plus the recorded
#: `pythonpath`), which is what makes a `pip install -e .` and a bare
#: checkout behave identically.
DAEMON_MODULE = "privacy_hud.daemon"

#: Escape hatch, honoured before anything else on the spawn path. On a
#: sandboxed or resource-capped box, paying a fork on every hook that cannot
#: possibly succeed is worse than having no HUD, and a user who has decided
#: that must be able to say so without uninstalling the plugin. Any value
#: other than empty or `0` disables auto-spawn.
NO_SPAWN_ENV = "PRIVACY_HUD_NO_SPAWN"

#: Environment names copied into the receipt and re-applied when the daemon
#: is spawned. A deliberately tiny, hardcoded allowlist of HuggingFace cache
#: *locations*: setup runs in a shell where the weights are findable, and the
#: hook's environment is Codex's, which usually is not that shell. Pinning
#: the interpreter without pinning where it looks for weights would leave the
#: same "healthy daemon, dead tier 3" hole one level down.
#:
#: It is an allowlist and not a filter for an I1 reason: `os.environ` holds
#: API keys, tokens and session state, and a privacy tool that writes the
#: environment to disk has become the leak it was built to prevent.
PINNED_ENV_NAMES = ("HF_HOME", "HF_HUB_CACHE", "TRANSFORMERS_CACHE")

#: Modules the probe asks a pinned interpreter about, in the order a failure
#: cascades. `privacy_hud` first: if that import fails the spawned daemon
#: exits 1 before anything else matters.
PROBE_MODULES = ("privacy_hud", "transformers", "torch")

#: Ceiling on the probe subprocess. `import transformers, torch` measures
#: ~1.4 s warm on the machine this was built on; the ceiling is for a cold
#: page cache or a spinning disk, and expiring it is reported as a failure
#: (an interpreter that cannot import its stack inside a minute cannot serve
#: a 2 s hook budget either).
PROBE_TIMEOUT = 60.0

#: Source of the probe child. Kept as one flat string passed to `-c` so the
#: probe needs no temp file and no importable helper: the interpreter under
#: test may not have `privacy_hud` on its path, which is precisely one of the
#: things being measured.
_PROBE_SOURCE = """
import importlib, json, os, sys
out = {"executable": sys.executable,
       "version": ".".join(str(p) for p in sys.version_info[:3]),
       "hf_hub_offline": os.environ.get("HF_HUB_OFFLINE")}
for name in %(modules)r:
    try:
        module = importlib.import_module(name)
    except BaseException:
        out[name] = None
        continue
    out[name] = str(getattr(module, "__version__", "") or "present")
sys.stdout.write(json.dumps(out))
""" % {"modules": list(PROBE_MODULES)}


# --------------------------------------------------------------------- #
# paths
# --------------------------------------------------------------------- #

def receipt_path(data_dir) -> Path:
    """`$PLUGIN_DATA/runtime.json`. See the module docstring for why here."""
    return Path(data_dir) / RECEIPT_NAME


def latch_path(data_dir) -> Path:
    """`$PLUGIN_DATA/daemon.spawn-attempt`."""
    return Path(data_dir) / LATCH_NAME


# --------------------------------------------------------------------- #
# reading
# --------------------------------------------------------------------- #

def load_receipt(data_dir) -> tuple[dict | None, str]:
    """Read the receipt. Returns `(receipt, problem)`.

    `problem` is `""` when the receipt is structurally usable, `"absent"`
    when there is no file at all, and otherwise a short reason. The three
    states are kept distinct because they have different remedies and
    different verdicts: absent is a setup that was never done, malformed is a
    setup that was damaged, and both must be told apart from a receipt that
    is fine but points at an interpreter that has since been deleted — which
    this function deliberately does not test, because it is answered by
    stat'ing the recorded path (the hook client, which cannot import this
    module) and by probing it (`doctor.check_runtime_pin`).

    Never raises. This is called from the doctor and, in spirit, from the
    hook path; a receipt that cannot be read must degrade to "do not spawn",
    not to a traceback (I6).
    """
    path = receipt_path(data_dir)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, "absent"
    except OSError as exc:
        return None, f"unreadable ({type(exc).__name__})"

    try:
        receipt = json.loads(raw)
    except ValueError:
        return None, "not valid JSON"
    if not isinstance(receipt, dict):
        return None, "not a JSON object"
    if receipt.get("v") != RECEIPT_VERSION:
        return None, f"unrecognized version {receipt.get('v')!r}"
    python = receipt.get("python")
    if not isinstance(python, str) or not python:
        return None, "no interpreter recorded"
    return receipt, ""


def spawn_env(receipt: dict, base: dict[str, str] | None = None) -> dict[str, str]:
    """The environment a spawned daemon should run in.

    Starts from the caller's own environment — for a hook that is Codex's,
    which is the authoritative source for `PLUGIN_DATA` and must stay
    untouched — and fills in only the recorded `sys.path` entry and any
    `PINNED_ENV_NAMES` the caller does not already set. Caller wins on every
    key, deliberately: the live environment describes the machine as it is
    now, while the receipt describes it as it was at setup time, and the only
    values worth taking from the past are the ones nobody has an opinion
    about in the present.
    """
    env = dict(os.environ if base is None else base)

    pythonpath = receipt.get("pythonpath")
    if isinstance(pythonpath, str) and pythonpath:
        existing = env.get("PYTHONPATH", "")
        parts = [pythonpath] + [p for p in existing.split(os.pathsep) if p]
        env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(parts))

    recorded = receipt.get("env")
    if isinstance(recorded, dict):
        for name in PINNED_ENV_NAMES:
            value = recorded.get(name)
            if isinstance(value, str) and value and not env.get(name):
                env[name] = value
    return env


def probe_interpreter(python, pythonpath: str | None = None, *,
                      timeout: float = PROBE_TIMEOUT,
                      env: dict[str, str] | None = None,
                      ) -> tuple[dict | None, float, str]:
    """Ask an interpreter, in its own process, what it can import.

    Returns `(result, elapsed_seconds, error)` where `result` maps each of
    `PROBE_MODULES` to a version string (or `"present"` for a module with no
    `__version__`) or `None` for "could not be imported", and `error` is a
    short reason when the probe itself did not run.

    A real `importlib.import_module` and not `importlib.util.find_spec`: the
    documented trap on this project is a `transformers` that is *installed*
    and fails on import — a torch/torchvision ABI mismatch surfacing as
    `operator torchvision::nms does not exist` — and `find_spec` reports that
    setup as healthy. The cost is ~1.4 s, which is what buying a true answer
    costs here.

    `HF_HUB_OFFLINE=1` is set in the child (I2). Nothing in an import of
    `transformers` should reach the hub, and this makes that a property of
    the probe rather than a hope about a library's import side effects.
    """
    child_env = dict(os.environ if env is None else env)
    if pythonpath:
        existing = child_env.get("PYTHONPATH", "")
        parts = [pythonpath] + [p for p in existing.split(os.pathsep) if p]
        child_env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(parts))
    child_env["HF_HUB_OFFLINE"] = "1"

    started = time.monotonic()
    try:
        completed = subprocess.run(
            [str(python), "-c", _PROBE_SOURCE],
            capture_output=True, text=True, timeout=timeout, env=child_env,
        )
    except subprocess.TimeoutExpired:
        return None, time.monotonic() - started, f"no answer in {timeout:g}s"
    except OSError as exc:
        return None, time.monotonic() - started, type(exc).__name__
    elapsed = time.monotonic() - started

    if completed.returncode != 0:
        return None, elapsed, f"exited {completed.returncode}"
    try:
        result = json.loads(completed.stdout)
    except ValueError:
        return None, elapsed, "unparseable answer"
    if not isinstance(result, dict):
        return None, elapsed, "unparseable answer"
    return result, elapsed, ""


# --------------------------------------------------------------------- #
# writing
# --------------------------------------------------------------------- #

def build_receipt(data_dir, *, python: str | None = None,
                  pythonpath: str | None = None,
                  versions: dict[str, str | None] | None = None,
                  environ: dict[str, str] | None = None,
                  now: float | None = None) -> dict:
    """Assemble the receipt for the interpreter currently running.

    `sys.executable` is the point of the whole exercise (prior art: record
    the interpreter you are running in, never one resolved off `PATH`), and
    the recorded `pythonpath` is the `sys.path` entry that holds *this*
    package — which is what lets a bare checkout work without the user
    remembering `PYTHONPATH=src`, and is safe to force onto the child because
    the child is the same interpreter that wrote it.
    """
    source_root = Path(__file__).resolve().parent.parent
    env = dict(os.environ if environ is None else environ)
    pinned = {name: env[name] for name in PINNED_ENV_NAMES if env.get(name)}
    return {
        "v": RECEIPT_VERSION,
        "python": python or sys.executable,
        "pythonpath": pythonpath if pythonpath is not None else str(source_root),
        "plugin_data": str(Path(data_dir)),
        "recorded_at": time.time() if now is None else now,
        "recorded": dict(versions or {}),
        "env": pinned,
    }


def write_receipt(data_dir, receipt: dict) -> Path:
    """Write the receipt atomically, 0600.

    Atomic because a hook may read this file at any moment: a torn write
    would read back as "malformed", and while that degrades safely (no
    spawn) it would do so for no reason. 0600 because it names the
    interpreter a hook will execute — a file any local user could rewrite
    would turn auto-spawn into an arbitrary-exec hole, which is also why the
    client re-checks the recorded path itself.
    """
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    final = receipt_path(directory)
    temp = final.with_name(final.name + ".tmp")
    payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            temp.unlink()
        except OSError:
            pass
        raise
    os.replace(temp, final)
    os.chmod(final, 0o600)
    return final


# --------------------------------------------------------------------- #
# the setup command
# --------------------------------------------------------------------- #

def _local_versions() -> dict[str, str | None]:
    """`transformers` and `torch` as *this* interpreter sees them.

    This is the check that makes the whole design safe. Setup must be run
    from the environment that has the ML stack, and the only way to know that
    it was is to import the stack here, in this process, and refuse to record
    an interpreter that cannot (see `main`'s `--allow-degraded`).
    """
    os.environ.setdefault("HF_HUB_OFFLINE", "1")  # I2, before transformers
    out: dict[str, str | None] = {}
    for name in ("transformers", "torch"):
        try:
            module = __import__(name)
        except BaseException:
            out[name] = None
            continue
        out[name] = str(getattr(module, "__version__", "") or "present")
    return out


def resolve_data_dir(explicit: str | None = None
                     ) -> tuple[Path | None, list[str], list[Path]]:
    """Decide which `PLUGIN_DATA` this receipt is for.

    Returns `(directory, notes, candidates)`; `directory` is `None` only when
    nothing could be resolved, in which case `notes` says why.

    Precedence is `--plugin-data`, then **Codex's own assigned directory**,
    then `$PLUGIN_DATA`. Codex outranks the environment variable on purpose:
    Codex assigns that directory and passes it to its hooks, so it is the
    only value that can be *wrong* to disagree with — and the goal of this
    command is that the user never has to learn what `PLUGIN_DATA` is, which
    a design that required them to export it correctly would not achieve. A
    disagreement is reported rather than silently resolved.

    The candidate list comes from `doctor._codex_data_candidates`, imported
    here and not reimplemented: that function is where this project's
    knowledge of Codex's layout lives, and a second derivation of it would be
    a second thing to get wrong. The import is deferred to keep `doctor`'s
    module-level import of *this* module acyclic.
    """
    notes: list[str] = []
    try:
        from .doctor import _codex_data_candidates
        candidates = _codex_data_candidates()
    except Exception:  # a broken doctor must not block setup
        candidates = []

    env_value = os.environ.get("PLUGIN_DATA")

    if explicit:
        chosen = Path(explicit).expanduser()
        if candidates and chosen.resolve() not in {c.resolve()
                                                   for c in candidates}:
            notes.append(
                "--plugin-data is not the directory Codex assigns to this "
                "plugin; nothing recorded here will apply to a real Codex "
                "session.")
        return chosen, notes, candidates

    if len(candidates) == 1:
        chosen = candidates[0]
        if env_value and Path(env_value).expanduser().resolve() != \
                chosen.resolve():
            notes.append(
                "$PLUGIN_DATA in this shell points somewhere else; using the "
                "directory Codex assigns, which is what its hooks will pass.")
        return chosen, notes, candidates

    if len(candidates) > 1:
        notes.append("Several plugin-data directories look like this "
                     "plugin's; pick one with --plugin-data.")
        return None, notes, candidates

    if env_value:
        notes.append("No Codex install found for this plugin; recording "
                     "against $PLUGIN_DATA from this shell instead.")
        return Path(env_value).expanduser(), notes, candidates

    notes.append("Codex has no plugin-data directory for this plugin and "
                 "$PLUGIN_DATA is not set.")
    return None, notes, candidates


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="privacy-hud-setup",
        description="Record which Python interpreter the privacy-hud daemon "
                    "must be started with, so Codex's hooks can start it "
                    "themselves. Run this from the environment that has "
                    "transformers and torch installed.",
        epilog="Exit code 0 when a usable runtime was recorded, 1 when "
               "nothing was written.",
    )
    parser.add_argument(
        "--plugin-data", metavar="DIR", default=None,
        help="write the receipt here instead of the directory Codex assigns "
             "(for a scratch or test setup)")
    parser.add_argument(
        "--check-model", action="store_true",
        help="also construct the tier 3 detector to prove the weights load "
             "(~2.8 GB, about 7s) instead of only checking the packages")
    parser.add_argument(
        "--allow-degraded", action="store_true",
        help="record this interpreter even though it cannot import "
             "transformers or torch, accepting a daemon with no tier 3 "
             "(names and addresses will not be detected)")
    return parser


def main(argv: list[str] | None = None, *, out=None) -> int:
    """Entry point for `privacy-hud-setup` / `python -m privacy_hud.runtime`.

    Refusing to write a receipt for an interpreter without the ML stack is
    the single most important thing this function does. The naive setup — run
    it from whatever `python3` is on `PATH` — is exactly how a blind daemon
    gets pinned, and a blind daemon that reports itself healthy is worse than
    the missing daemon this feature replaces. So that case fails loudly, with
    the remedy, and `--allow-degraded` exists only so that choosing tiers 0-2
    stays possible as a *decision* rather than an accident.
    """
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = _build_parser().parse_args(argv)
    except SystemExit as exc:  # --help (0) or a usage error (2)
        return int(exc.code or 0)
    out = sys.stdout if out is None else out

    def say(line: str = "") -> None:
        print(line, file=out)

    # Imported here, not at module level: this module is imported by
    # `doctor` and (in spirit) mirrored by the stdlib-only hook client, and
    # only this command needs the pretty-printing helpers.
    from .doctor import _display_path, _shell_path

    say("privacy-hud setup")
    say()

    data_dir, notes, _candidates = resolve_data_dir(args.plugin_data)
    for note in notes:
        say(f"  note: {note}")
    if data_dir is None:
        say("  FAILED: cannot tell which plugin-data directory to record "
            "against.")
        say()
        say("  -> Install the plugin first, then re-run this command:")
        say("       codex plugin marketplace add inin-zou/codex-privacy-hud")
        say("       codex plugin add codex-privacy-hud@codex-privacy-hud")
        say("  -> Or name a directory explicitly: "
            "privacy-hud-setup --plugin-data DIR")
        return 1

    versions = _local_versions()
    missing = [name for name, value in versions.items() if value is None]
    say(f"  interpreter    {_display_path(sys.executable)}")
    say(f"  transformers   {versions.get('transformers') or 'NOT INSTALLED'}")
    say(f"  torch          {versions.get('torch') or 'NOT INSTALLED'}")
    say(f"  plugin data    {_display_path(data_dir)}")
    say()

    if missing and not args.allow_degraded:
        say("  FAILED: nothing was recorded.")
        say()
        say(f"  This interpreter cannot import {', '.join(missing)}, so a "
            "daemon started")
        say("  from it would run tiers 0-2 only: names and addresses would "
            "not be")
        say("  detected, and nothing would say so. That is worse than no "
            "daemon at all,")
        say("  so it is not recorded.")
        say()
        say("  -> Re-run this command from the environment that has them, "
            "e.g.:")
        say("       source .venv/bin/activate && privacy-hud-setup")
        say("  -> Or install them into this one (a dedicated virtualenv; "
            "upgrading")
        say("     torch inside a shared environment breaks other ML "
            "packages):")
        say("       pip install -e \".[detectors]\"")
        say("  -> Or accept a tier-3-less daemon deliberately: "
            "privacy-hud-setup --allow-degraded")
        return 1

    if args.check_model:
        try:
            from .detect.model import ModelDetector
            started = time.monotonic()
            available = ModelDetector().available
            elapsed = time.monotonic() - started
        except Exception as exc:
            available, elapsed = False, 0.0
            say(f"  tier 3         could not be constructed "
                f"({type(exc).__name__})")
        if available:
            say(f"  tier 3         model loaded and available ({elapsed:.1f}s)")
        else:
            say("  tier 3         NOT available — names and addresses will "
                "not be detected")
            say("                 The weights are a separate ~2.8 GB "
                "download; see README.")
        say()

    receipt = build_receipt(data_dir, versions=versions)
    try:
        written = write_receipt(data_dir, receipt)
    except OSError as exc:
        say(f"  FAILED: cannot write the receipt ({type(exc).__name__}).")
        say()
        say(f"  -> Check that {_shell_path(data_dir)} exists and is "
            "writable.")
        return 1

    say(f"  recorded       {_display_path(written)}")
    say()
    if missing:
        say("  Recorded a DEGRADED runtime, as asked: tier 3 cannot run in "
            "this")
        say("  interpreter, so names and addresses will not be detected. "
            "Tiers 0-2")
        say("  (credentials, file paths, shell destinations) still run.")
        say()
    say("  Codex's hooks will now start the daemon themselves on the first "
        "tool")
    say("  call of a session. Loading the tier 3 model takes about 7 "
        "seconds, and")
    say("  hooks that fire during that window are answered without "
        "detection: the")
    say("  first few seconds of a session are unmonitored, and calls in it "
        "are")
    say("  reported as unverified rather than checked.")
    say()
    say("  Verify any time with: privacy-hud-doctor")
    return 0


if __name__ == "__main__":
    sys.exit(main())
