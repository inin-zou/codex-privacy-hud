from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path(__file__).with_name("slow-files.json")


def load_slow_files(manifest=MANIFEST):
    try:
        entries = json.loads(Path(manifest).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise pytest.UsageError(f"cannot read slow-file manifest: {error}") from error

    if (
        not isinstance(entries, list)
        or not all(isinstance(entry, str) for entry in entries)
        or entries != sorted(set(entries))
    ):
        raise pytest.UsageError("slow-file manifest must be a sorted unique string list")

    for entry in entries:
        relative = Path(entry)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not entry.startswith("tests/")
            or not entry.endswith(".py")
            or not (ROOT / relative).is_file()
        ):
            raise pytest.UsageError(f"stale or invalid slow-file entry: {entry}")
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        if not any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
            for node in ast.walk(tree)
        ):
            raise pytest.UsageError(f"slow-file entry contains no tests: {entry}")
    return frozenset(entries)


def mark_slow_items(items):
    slow = load_slow_files()
    for item in items:
        if item.nodeid.split("::", 1)[0] in slow:
            item.add_marker(pytest.mark.slow)
