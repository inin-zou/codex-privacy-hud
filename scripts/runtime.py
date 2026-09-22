#!/usr/bin/env python3
# scripts/runtime.py
"""Bundled bootstrap -- RED scaffold.

This placeholder reproduces the launch path the plugin uses today (the
re-exec in `mcp/server.py` and the spawn in `hooks/handler.py`): read the
receipt, prepend its recorded path entry to the inherited `PYTHONPATH`,
re-exec the recorded interpreter once (guarded by an environment marker),
and import `privacy_hud` from wherever that interpreter resolves it. It has
no digest check, no origin check and no repair command. The GREEN commit
replaces it.
"""
import json
import os
import sys

MARKER = "PRIVACY_HUD_BOOTSTRAP_REEXEC"


def _run(command, rest):
    if command == "probe":
        import privacy_hud
        print(json.dumps({
            "first_party_origin": os.path.dirname(
                os.path.realpath(privacy_hud.__file__)),
            "sys_path": list(sys.path),
            "isolated": bool(sys.flags.isolated),
        }))
        return 0
    return 2


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 3 or argv[0] != "--plugin-data":
        print("usage: runtime.py --plugin-data DIR COMMAND", file=sys.stderr)
        return 2
    data_dir, command = argv[1], argv[2]
    if os.environ.get(MARKER):
        return _run(command, argv[3:])
    with open(os.path.join(data_dir, "runtime.json")) as handle:
        receipt = json.load(handle)
    python = receipt["python"]
    entry = receipt.get("pythonpath") or ""
    if not entry and receipt.get("selected_bundle_root"):
        entry = os.path.join(receipt["selected_bundle_root"], "src")
    env = dict(os.environ)
    env[MARKER] = "1"
    env["PLUGIN_DATA"] = data_dir
    if entry:
        parts = [entry] + [p for p in env.get("PYTHONPATH", "").split(
            os.pathsep) if p]
        env["PYTHONPATH"] = os.pathsep.join(parts)
    os.execve(python, [python, os.path.abspath(__file__)] + argv, env)
    return 1


if __name__ == "__main__":
    sys.exit(main())
