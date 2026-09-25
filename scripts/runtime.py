#!/usr/bin/env python3
# scripts/runtime.py
"""The bundled bootstrap (#66): the one way Privacy HUD's Python code runs.

    runtime.py --plugin-data DIR probe
    runtime.py --plugin-data DIR doctor [--load-model]
    runtime.py --plugin-data DIR setup --python ABSOLUTE_PYTHON
                                       [--allow-degraded]
    runtime.py --plugin-data DIR daemon
    runtime.py --plugin-data DIR ambient [existing ambient arguments]
    runtime.py --plugin-data DIR audit [SESSION_ID] [--tab TAB]
    runtime.py --plugin-data DIR detail SESSION_ID EVENT_ID
    runtime.py --plugin-data DIR ui [SESSION_ID]
    runtime.py --plugin-data DIR hud SESSION_ID on|off|status
    runtime.py --plugin-data DIR read on|off|status
    runtime.py --plugin-data DIR repair --print-command
    runtime.py --plugin-data DIR mcp

What it guarantees, in order:

1. **The bundle is this file's own.** The bundle root is two directories
   above this file. Nothing is taken from `cwd`, a cache listing, or an
   installed distribution's metadata.
2. **The selected runtime is this bundle.** Receipt v2 in `DIR` must select
   this bundle root, and the bundle's files must hash to the recorded build
   (`runtime_contract.load_activation`). Receipt v1 is repair input only.
3. **The receipt's interpreter runs in isolated mode.** The process
   re-executes `python -I` with inherited `PYTHONPATH` and friends removed
   and user site-packages disabled, so the dependency environment supplies
   dependencies and nothing else. The interpreter check compares the
   executable *and* the virtual-environment prefix: two environments can
   share one base executable.
4. **First-party imports come only from `<bundle>/src`,** checked after
   import (`runtime_contract.verify_import_origins`).
5. **Offline before anything optional is imported** (I2).

The re-exec marker only prevents a loop. A process that carries it but is
not the selected, isolated interpreter is refused, never trusted.

`repair --print-command` needs no receipt and imports nothing beyond the
standard library, so it works in exactly the states that need it. `setup`
and `repair --stop-runtime` also run before any selection exists — they
are how one comes to exist, and how an uninstall stops the one that does
— so they import this bundle's code by path rather than through a
receipt, and verify its origin immediately afterwards. Refusals
print fixed text (copied from `privacy_hud.runtime_messages`, pinned by
`tests/test_runtime_messages.py`) and no traceback. For `mcp`, nothing is
ever written to stdout: stdout is the JSON-RPC channel.

Stdlib only.
"""
import argparse
import importlib
import importlib.util
import json
import os
import shlex
import sys
from pathlib import Path

BUNDLE_ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAP = BUNDLE_ROOT / "scripts" / "runtime.py"

#: Set before the re-exec so the child does not exec again. Never trusted:
#: see the module docstring.
REEXEC_MARKER = "PRIVACY_HUD_BOOTSTRAP_REEXEC"

#: Removed from the environment of everything this starts. `-I` already
#: makes the selected interpreter ignore them; removing them keeps them
#: from reaching anything that interpreter starts in turn.
STRIPPED_ENV = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                "PYTHONUSERBASE", "PYTHONEXECUTABLE", "PYTHONINSPECT",
                "PRIVACY_HUD_MCP_REEXEC")

#: A copy of `privacy_hud.offline.FORCED_ENV` (I2), assigned last.
#: `tests/test_offline.py` pins the two together.
OFFLINE_ENV = {
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "HF_DATASETS_OFFLINE": "1",
    "HF_HUB_DISABLE_TELEMETRY": "1",
    "DO_NOT_TRACK": "1",
    "HF_HUB_DISABLE_UPDATE_CHECK": "1",
    "DISABLE_SAFETENSORS_CONVERSION": "1",
}

#: The existing allowlisted cache settings a receipt may pin.
PINNED_ENV_NAMES = ("HF_HOME", "HF_HUB_CACHE", "TRANSFORMERS_CACHE")

#: Dependencies `probe` reports, imported for real (an installed package
#: that fails on import is not usable).
PROBED_DEPENDENCIES = ("transformers", "torch", "mcp")

# -- fixed text: copies of privacy_hud.runtime_messages ----------------- #
RUNTIME_SETUP_FAIL = (
    "[FAIL] Runtime setup\n"
    "No usable Privacy HUD runtime is configured. "
    "An update may require explicit repair; repair is not automatic.\n"
    "Run this command in another terminal:\n"
    "  {repair_command}\n"
    "Installation may download dependencies and model weights."
)
REPAIR_COMMAND_OUTPUT = (
    "Run this command in another terminal:\n"
    "  {repair_command}\n"
    "This command may download dependencies and model weights.\n"
    "It does not install or replace a patched Codex binary."
)
MCP_BOOTSTRAP_REFUSAL = (
    "privacy-hud mcp: runtime setup is incompatible; no ledger was opened.\n"
    "Run in another terminal:\n"
    "  {repair_command}"
)
DAEMON_STARTUP_REFUSAL = (
    "privacy-hud daemon: runtime identity or ledger compatibility check "
    "failed; no writable ledger was opened.\n"
    "Run the repair command reported by the current plugin's doctor."
)
AMBIENT_RUNTIME_MISMATCH = "Privacy — runtime mismatch"
AMBIENT_NARROW_FALLBACK = "Privacy unverified"


class _Refused(Exception):
    """Internal: the bootstrap stage failed. Carries nothing."""


def format_repair_command(bundle_root, data_dir) -> str:
    """A copy of `privacy_hud.runtime_repair.format_repair_command`."""
    return shlex.join([
        "sh", str(Path(bundle_root) / "install.sh"),
        "--repair-runtime", "--plugin-data", str(data_dir), "--yes",
    ])


def _ambient_argv(argv: list) -> tuple[list, list]:
    """Split the launcher's own flags off an `ambient` invocation.

    `ambient` forwards to `privacy_hud.ambient`'s parser, which owns
    `--once`, `--watch` and `--session-id`. `argparse.REMAINDER` does not
    hold them: an option-looking token immediately after the subcommand is
    consumed by *this* parser, so the shipped wrapper's
    `privacy-hud-ambient --watch` -- and the exact ambient command the
    contract tells a user to run -- exited 2 with a usage message. The
    split is by position and nothing else, and the token is only taken as
    the subcommand where it is not the value of `--plugin-data`.
    """
    for index, token in enumerate(argv):
        if token == "ambient" and (index == 0
                                   or argv[index - 1] != "--plugin-data"):
            return argv[:index + 1], argv[index + 1:]
    return argv, []


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="runtime.py")
    parser.add_argument("--plugin-data", required=True, metavar="DIR")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("probe")
    doctor = sub.add_parser("doctor")
    doctor.add_argument("--load-model", action="store_true")
    sub.add_parser("daemon")
    ambient = sub.add_parser("ambient")
    ambient.add_argument("ambient_args", nargs=argparse.REMAINDER)
    ui = sub.add_parser("ui")
    ui.add_argument("session_id", nargs="?")
    audit = sub.add_parser("audit")
    audit.add_argument("session_id", nargs="?")
    audit.add_argument("--tab", default="Exposed")
    detail = sub.add_parser("detail")
    detail.add_argument("session_id")
    detail.add_argument("event_id")
    hud = sub.add_parser("hud")
    hud.add_argument("session_id")
    hud.add_argument("action", choices=("on", "off", "status"))
    read = sub.add_parser("read")
    read.add_argument("action", choices=("on", "off", "status"))
    setup = sub.add_parser("setup")
    setup.add_argument("--python", required=True, metavar="ABSOLUTE_PYTHON")
    setup.add_argument("--allow-degraded", action="store_true")
    repair = sub.add_parser("repair")
    # Exactly one, and required: `repair` on its own would be an
    # ambiguous verb for an operation that either prints a command or
    # stops a running runtime.
    mode = repair.add_mutually_exclusive_group(required=True)
    mode.add_argument("--print-command", action="store_true")
    mode.add_argument("--stop-runtime", action="store_true")
    mode.add_argument("--offline", action="store_true")
    repair.add_argument("--allow-degraded", action="store_true")
    sub.add_parser("mcp")
    return parser


def _refuse(command: str, data_dir: Path) -> int:
    repair = format_repair_command(BUNDLE_ROOT, data_dir)
    if command == "mcp":
        print(MCP_BOOTSTRAP_REFUSAL.format(repair_command=repair),
              file=sys.stderr)
    elif command == "daemon":
        print(DAEMON_STARTUP_REFUSAL, file=sys.stderr)
    elif command == "doctor":
        print(RUNTIME_SETUP_FAIL.format(repair_command=repair))
    elif command == "ambient":
        print(AMBIENT_RUNTIME_MISMATCH)
        print(REPAIR_COMMAND_OUTPUT.format(repair_command=repair))
    else:
        body = RUNTIME_SETUP_FAIL.split("\n", 1)[1]
        print(body.format(repair_command=repair), file=sys.stderr)
    return 1


# --------------------------------------------------------------------- #
# selection
# --------------------------------------------------------------------- #

def _enter_bundle(data_dir: Path):
    """Import this bundle's package before any selection exists.

    `setup` and `repair --stop-runtime` run in exactly the states where
    there is no receipt to verify against, so the guarantee available
    here is the weaker one: the code comes from *this file's own bundle*,
    checked with `verify_import_origins` the moment it is imported, with
    every inherited path removed first. Offline is forced before anything
    optional can be imported (I2).
    """
    src = str(BUNDLE_ROOT / "src")
    sys.path[:] = [src] + [p for p in sys.path if p != src]
    for name in STRIPPED_ENV:
        os.environ.pop(name, None)
    os.environ["PLUGIN_DATA"] = str(data_dir)
    os.environ.update(OFFLINE_ENV)
    try:
        contract = importlib.import_module("privacy_hud.runtime_contract")
        contract.verify_import_origins(BUNDLE_ROOT)
        module = importlib.import_module("privacy_hud.runtime_repair")
        contract.verify_import_origins(BUNDLE_ROOT)
    except Exception:
        raise _Refused() from None
    return module


def _standalone_contract():
    """`runtime_contract.py` from this bundle, loaded by path and without
    importing the `privacy_hud` package: which package may be imported is
    what is being decided."""
    path = BUNDLE_ROOT / "src" / "privacy_hud" / "runtime_contract.py"
    if not path.is_file():
        raise _Refused()
    name = "_privacy_hud_bootstrap_contract"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise _Refused()
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise _Refused() from None
    return module


def _select(contract, data_dir: Path):
    """The activation, if it selects this bundle; else `_Refused`."""
    try:
        activation = contract.load_activation(data_dir)
    except contract.RuntimeRefusal:
        raise _Refused() from None
    if Path(activation.bundle_root).resolve() != BUNDLE_ROOT:
        raise _Refused()
    return activation


def _pinned_env(contract, data_dir: Path) -> dict:
    try:
        recorded = contract.read_receipt(data_dir).get("env")
    except contract.RuntimeRefusal:
        return {}
    if not isinstance(recorded, dict):
        return {}
    return {name: recorded[name] for name in PINNED_ENV_NAMES
            if isinstance(recorded.get(name), str) and recorded[name]}


def _process_is_selected(activation) -> bool:
    """Is this process the selected interpreter, in isolated mode?

    The executable alone is not enough: virtual environments can share a
    base executable, so the environment prefix must match too.
    """
    if not sys.flags.isolated or not sys.executable:
        return False
    python = str(activation.python)
    if os.path.abspath(sys.executable) != os.path.abspath(python):
        try:
            if not os.path.samefile(sys.executable, python):
                return False
        except OSError:
            return False
    venv = Path(python).parent.parent
    if (venv / "pyvenv.cfg").is_file():
        return os.path.realpath(sys.prefix) == os.path.realpath(venv)
    return os.path.realpath(sys.prefix) == os.path.realpath(sys.base_prefix)


def _child_env(contract, data_dir: Path) -> dict:
    env = dict(os.environ)
    for name in STRIPPED_ENV:
        env.pop(name, None)
    env["PYTHONNOUSERSITE"] = "1"
    env["PLUGIN_DATA"] = str(data_dir)
    for name, value in _pinned_env(contract, data_dir).items():
        if not env.get(name):
            env[name] = value
    env.update(OFFLINE_ENV)
    return env


def _reexec(contract, activation, argv: list, data_dir: Path) -> None:
    env = _child_env(contract, data_dir)
    env[REEXEC_MARKER] = "1"
    python = str(activation.python)
    try:
        os.execve(python, [python, "-I", str(BOOTSTRAP), *argv], env)
    except OSError:
        raise _Refused() from None


def _enter_selected(data_dir: Path):
    """In the selected interpreter: put only this bundle's `src` in front,
    force offline, import the package and verify where it came from.
    Returns the package's `runtime_contract` and the activation."""
    src = str(BUNDLE_ROOT / "src")
    sys.path[:] = [src] + [p for p in sys.path if p != src]
    for name in STRIPPED_ENV:
        os.environ.pop(name, None)
    os.environ["PLUGIN_DATA"] = str(data_dir)
    os.environ.update(OFFLINE_ENV)
    try:
        contract = importlib.import_module("privacy_hud.runtime_contract")
    except Exception:
        raise _Refused() from None
    try:
        contract.verify_import_origins(BUNDLE_ROOT)
        for name, value in _pinned_env(contract, data_dir).items():
            os.environ.setdefault(name, value)
        activation = _select(contract, data_dir)
        offline = importlib.import_module("privacy_hud.offline")
        offline.prepare_process()
        contract.verify_import_origins(BUNDLE_ROOT)
    except _Refused:
        raise
    except Exception:
        raise _Refused() from None
    return contract, activation


# --------------------------------------------------------------------- #
# commands, run in the selected interpreter
# --------------------------------------------------------------------- #

def _probe(activation) -> int:
    import privacy_hud
    dependencies = {}
    for name in PROBED_DEPENDENCIES:
        try:
            module = importlib.import_module(name)
        except Exception:
            dependencies[name] = None
            continue
        dependencies[name] = str(getattr(module, "__version__", "")
                                 or "present")
    print(json.dumps({
        "release": activation.identity.release,
        "build_id": activation.identity.build_id,
        "activation_epoch": activation.epoch,
        "python": sys.executable,
        "isolated": bool(sys.flags.isolated),
        "first_party_origin": str(Path(privacy_hud.__file__).resolve().parent),
        "sys_path": list(sys.path),
        "dependency_probe": dependencies,
    }, sort_keys=True))
    return 0


def _load_mcp_server():
    path = BUNDLE_ROOT / "mcp" / "server.py"
    spec = importlib.util.spec_from_file_location("privacy_hud_mcp_server",
                                                  path)
    if spec is None or spec.loader is None:
        raise _Refused()
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _dispatch(args, activation) -> int:
    command = args.command
    if command == "probe":
        return _probe(activation)
    if command == "doctor":
        from privacy_hud import doctor
        return doctor.main(["--check-model"] if args.load_model else [])
    if command == "daemon":
        from privacy_hud import daemon
        return daemon.main([], activation=activation)
    if command == "ambient":
        from privacy_hud import ambient
        return ambient.main(list(args.ambient_args), activation=activation)
    if command == "ui":
        from privacy_hud import local_ui_server
        return local_ui_server.main([args.session_id] if args.session_id
                                    else [])
    if command == "audit":
        import json as _json

        from privacy_hud import runtime_commands
        result = runtime_commands.audit(
            Path(os.environ["PLUGIN_DATA"]), activation=activation,
            session_id=args.session_id, tab=args.tab)
        if result.banner:
            print(result.banner)
        print(result.text)
        # The resolution, once, so a caller that also opens the browser
        # hands it the same session rather than resolving a second time
        # and naming another one.
        print(_json.dumps({"session_id": result.resolved.session_id,
                           "basis": result.resolved.basis,
                           "also_active": list(result.resolved.also_active),
                           "runtime_mismatch": result.runtime_mismatch},
                          sort_keys=True))
        return 0
    if command == "detail":
        from privacy_hud import runtime_commands
        try:
            event_id = int(args.event_id)
        except ValueError:
            print("detail: EVENT_ID must be an integer", file=sys.stderr)
            return 2
        print(runtime_commands.detail(Path(os.environ["PLUGIN_DATA"]),
                                      session_id=args.session_id,
                                      event_id=event_id))
        return 0
    if command in ("hud", "read"):
        import json as _json

        from privacy_hud import runtime_commands
        data_dir = Path(os.environ["PLUGIN_DATA"])
        if command == "hud":
            out = runtime_commands.hud(data_dir, session_id=args.session_id,
                                       action=args.action)
        else:
            out = runtime_commands.read_guard(data_dir, action=args.action)
        print(_json.dumps(out, sort_keys=True))
        return 0
    raise _Refused()


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    # The re-exec passes the *whole* command line on, launcher flags
    # included; only this process's own parsing is given the head.
    full_argv = list(argv)
    argv, ambient_args = _ambient_argv(argv)
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    if args.command == "ambient":
        args.ambient_args = ambient_args
    data_dir = Path(os.path.abspath(os.path.expanduser(args.plugin_data)))

    if args.command == "repair" and args.print_command:
        print(REPAIR_COMMAND_OUTPUT.format(
            repair_command=format_repair_command(BUNDLE_ROOT, data_dir)))
        return 0

    if args.command in ("setup", "repair"):
        # Both run before a selection exists (`setup` creates one;
        # `repair --stop-runtime` is what an uninstall calls to stop the
        # runtime it owns before deleting the environment that runs it).
        try:
            repair_module = _enter_bundle(data_dir)
        except _Refused:
            return _refuse(args.command, data_dir)
        if args.command == "repair" and args.stop_runtime:
            return 0 if repair_module.stop_selected_runtime(data_dir) else 1
        argv_repair = ["--bundle-root", str(BUNDLE_ROOT),
                       "--plugin-data", str(data_dir)]
        if args.command == "setup":
            argv_repair.extend(["--python", args.python])
        if args.allow_degraded:
            argv_repair.append("--allow-degraded")
        return repair_module.main(argv_repair)

    forged_or_reexecuted = os.environ.pop(REEXEC_MARKER, None) is not None
    try:
        standalone = _standalone_contract()
        activation = _select(standalone, data_dir)
        if not _process_is_selected(activation):
            if forged_or_reexecuted:
                raise _Refused()
            _reexec(standalone, activation, full_argv, data_dir)
        _contract, activation = _enter_selected(data_dir)
        if args.command == "mcp":
            server = _load_mcp_server()
        else:
            server = None
    except _Refused:
        return _refuse(args.command, data_dir)
    except Exception:
        return _refuse(args.command, data_dir)
    if server is not None:
        return server.serve()
    return _dispatch(args, activation)


if __name__ == "__main__":
    sys.exit(main())
