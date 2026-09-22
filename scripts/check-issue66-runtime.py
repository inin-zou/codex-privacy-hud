#!/usr/bin/env python3
"""Rehearse #66's storage transition on a private copy of a real ledger.

Scaffolding: the interface `astra_66_plan.final` §E specifies, and the two
fixed lines it prints. No check is implemented yet.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PASS = "Issue 66 private-ledger checks: PASS. No ledger values were printed."
FAIL = "Private-ledger check failed. No ledger values were printed."


class CheckFailed(Exception):
    """A named check failed. The name is a fixed string from this file."""


def rehearse(source: Path, work_dir: Path) -> None:
    raise CheckFailed("unexpected-error")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        rehearse(args.source, args.work_dir)
    except CheckFailed as failed:
        print(FAIL)
        print(f"check: {failed.args[0]}", file=sys.stderr)
        return 1
    except Exception:
        print(FAIL)
        print("check: unexpected-error", file=sys.stderr)
        return 2
    print(PASS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
