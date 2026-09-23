#!/usr/bin/env python3
# scripts/build-runtime-manifest.py
"""Write or check `runtime-build.json` for a plugin bundle (#66).

    python scripts/build-runtime-manifest.py            # write
    python scripts/build-runtime-manifest.py --check    # exit 1 if stale
    python scripts/build-runtime-manifest.py --bundle DIR

The digest and the covered file set are defined once, in
`src/privacy_hud/runtime_contract.py`, which this loads by path from the
bundle being described. Run it after the covered files reach their final
contents: any later edit changes the build id.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path


def _contract(bundle: Path):
    path = bundle / "src" / "privacy_hud" / "runtime_contract.py"
    name = "_privacy_hud_manifest_contract"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build-runtime-manifest.py")
    parser.add_argument("--bundle", default=None,
                        help="bundle root (default: this checkout)")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the manifest is absent or stale")
    args = parser.parse_args(argv)
    bundle = (Path(args.bundle) if args.bundle
              else Path(__file__).resolve().parent.parent).resolve()
    contract = _contract(bundle)
    text = contract.render_manifest(contract.build_manifest(bundle))
    target = bundle / contract.MANIFEST_NAME
    if args.check:
        try:
            current = target.read_text(encoding="utf-8")
        except OSError:
            current = None
        if current != text:
            print(f"{contract.MANIFEST_NAME} is stale", file=sys.stderr)
            return 1
        return 0
    temp = target.with_name(target.name + ".tmp")
    temp.write_text(text, encoding="utf-8")
    os.replace(temp, target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
