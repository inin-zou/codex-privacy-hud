"""Runtime layer contracts; parse source without importing the application."""

import ast
from pathlib import Path
from textwrap import dedent

REPO = Path(__file__).resolve().parents[1]
SURFACES = frozenset({
    "privacy_hud.mcp_tools",
    "privacy_hud.local_ui_server",
    "privacy_hud.runtime_commands",
    "privacy_hud.ambient",
    "mcp.server",
})
DAEMON = "privacy_hud.daemon"


def module_name(path):
    parts = list(path.with_suffix("").parts)
    if parts[0] == "src":
        parts.pop(0)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def source_files():
    return {
        module_name(path.relative_to(REPO)): path
        for root in ("src", "mcp", "scripts")
        for path in sorted((REPO / root).rglob("*.py"))
    }


def runtime_edges(source, module, modules, *, is_package=False):
    tree = ast.parse(source)
    typing_names = set()
    checking_names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            typing_names.update(
                alias.asname or alias.name
                for alias in node.names if alias.name == "typing"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "typing":
            checking_names.update(
                alias.asname or alias.name
                for alias in node.names if alias.name == "TYPE_CHECKING"
            )

    def checking(node):
        return (
            isinstance(node, ast.Name) and node.id in checking_names
        ) or (
            isinstance(node, ast.Attribute)
            and node.attr == "TYPE_CHECKING"
            and isinstance(node.value, ast.Name)
            and node.value.id in typing_names
        )

    def visit(node):
        if isinstance(node, ast.If) and checking(node.test):
            for child in node.orelse:
                yield from visit(child)
            return
        if (isinstance(node, ast.If)
                and isinstance(node.test, ast.UnaryOp)
                and isinstance(node.test.op, ast.Not)
                and checking(node.test.operand)):
            for child in node.body:
                yield from visit(child)
            return

        targets = set()
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                package = module if is_package else module.rpartition(".")[0]
                parts = package.split(".")
                keep = len(parts) - node.level + 1
                assert keep > 0, (module, node.lineno)
                base = ".".join(parts[:keep] + ([base] if base else []))
            targets.add(base)
            targets.update(
                f"{base}.{alias.name}" for alias in node.names
                if alias.name != "*"
            )
        for target in sorted(targets & modules):
            yield node.lineno, target
        for child in ast.iter_child_nodes(node):
            yield from visit(child)

    return list(visit(tree))


def forbidden(source, target):
    if source == target:
        return False
    # Scripts are composition/maintenance entry points, not shared services.
    if source.startswith("scripts."):
        return False
    # All remaining src modules are daemon/core support.
    if source == "privacy_hud" or source.startswith("privacy_hud."):
        if target in SURFACES or target == DAEMON:
            return True
    return source in SURFACES and target in SURFACES | {DAEMON}


def test_runtime_layer_contract():
    files = source_files()
    assert SURFACES | {DAEMON} <= files.keys()
    errors = []
    for module, path in sorted(files.items()):
        for line, target in runtime_edges(
            path.read_text(encoding="utf-8"), module, set(files),
            is_package=path.name == "__init__.py",
        ):
            if forbidden(module, target):
                errors.append(
                    f"{path.relative_to(REPO)}:{line}: {module} -> {target}"
                )
    assert not errors, "Forbidden runtime imports:\n" + "\n".join(errors)


def test_import_spellings_and_nested_runtime_imports_are_checked():
    modules = {"privacy_hud", DAEMON, *SURFACES}
    statements = (
        "from . import local_ui_server",
        "from .local_ui_server import resolve_data_dir",
        "import privacy_hud.local_ui_server as ui",
        "from privacy_hud import local_ui_server as ui",
        "from privacy_hud.local_ui_server import *",
    )
    wrappers = (
        "{}",
        "def f():\n    {}",
        "class C:\n    def f(self):\n        {}",
        "try:\n    {}\nexcept ImportError:\n    pass",
    )
    for statement in statements:
        for wrapper in wrappers:
            edges = runtime_edges(
                wrapper.format(statement), "privacy_hud.ambient", modules,
            )
            assert any(
                target == "privacy_hud.local_ui_server"
                and forbidden("privacy_hud.ambient", target)
                for _, target in edges
            )


def test_type_checking_only_branches_are_exempt():
    modules = {"privacy_hud", *SURFACES}
    source = dedent("""
        from typing import TYPE_CHECKING as TC
        import typing as t
        if TC:
            from . import mcp_tools
        else:
            from . import local_ui_server
        if t.TYPE_CHECKING:
            from .mcp_tools import ResolvedSession
        if not TC:
            from . import ambient
        else:
            from . import mcp_tools
    """)
    targets = {
        target for _, target in runtime_edges(
            source, "privacy_hud.render", modules,
        )
    }
    assert "privacy_hud.mcp_tools" not in targets
    assert {"privacy_hud.local_ui_server", "privacy_hud.ambient"} <= targets


def test_core_and_bootstrap_classification():
    assert forbidden(DAEMON, "privacy_hud.mcp_tools")
    assert forbidden("privacy_hud.session_services", DAEMON)
    assert forbidden("privacy_hud.policy_services", "privacy_hud.mcp_tools")
    assert forbidden("mcp.server", "privacy_hud.runtime_commands")
    assert not forbidden("scripts.runtime", DAEMON)
    assert not forbidden("scripts.runtime", "privacy_hud.ambient")
    assert not forbidden(DAEMON, "privacy_hud.policy_services")
    assert not forbidden("privacy_hud.ambient", "privacy_hud.session_services")
