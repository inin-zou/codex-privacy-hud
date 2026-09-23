# tests/test_issue66_contract.py
"""#66 Pair 9: what this release declares, and what its documents say.

Three kinds of claim are pinned here, because each has failed silently
before. A version declared in two of three places leaves Codex running
cached hooks from the third. A compatibility paragraph that survives a
release describes a product that no longer exists — and these particular
paragraphs are the ones a user reads to decide whether their native HUD
still works. And a skill that tells an agent to open a pathname the
release turned into a directory breaks `$privacy` on exactly the
installations the release repaired.

The strings below are the contract's, character for character. Where a
sentence looks redundant, it is load-bearing: "matching Codex version
numbers do not establish snapshot compatibility" is the claim this
project got wrong once already.
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from privacy_hud import runtime_contract as contract
from privacy_hud.matrix.loader import load_matrix
from runtime_helpers import shared_bundle, short_data_dir, write_receipt_v2

REPO = Path(__file__).resolve().parents[1]
RELEASE = "0.8.1"

PLUGIN_JSON = REPO / ".codex-plugin" / "plugin.json"
MARKETPLACE_JSON = REPO / ".agents" / "plugins" / "marketplace.json"
PYPROJECT = REPO / "pyproject.toml"
MANIFEST = REPO / contract.MANIFEST_NAME
SKILL = REPO / "skills" / "privacy" / "SKILL.md"
CHANGELOG = REPO / "CHANGELOG.md"

#: What the current-contract block at the top of all three design
#: documents must still say about this release's runtime, whichever issue
#: owns the block. There is one such block and each release replaces it:
#: 0.8.1 publishes #54 Phase 3's, and this is the sentence that carries
#: #66's contract into it. Deleting it is how a document comes to describe
#: a release that no longer checks runtime alignment.
CURRENT_CONTRACT_REQUIREMENT = (
    "Runtime selection, writer ownership, and the fenced ledger layout "
    "introduced in 0.8.0 remain required."
)

#: The replacement compatibility paragraphs, in order, for `README.md`,
#: `docs/installing-by-hand.md` and `patches/README.md`.
COMPATIBILITY = [
    "Privacy HUD 0.8.1 retains snapshot version 2. Production sessions still "
    "use legacy accounting. Snapshot-v2 readers accept version 1 as "
    "explicitly legacy and version 2 with nullable accounting fields. Older "
    "snapshot-v1-only readers reject version 2 and show no Privacy item. "
    "Matching Codex version numbers do not establish snapshot "
    "compatibility.",
    "The snapshot-v2 patched Codex builds for 0.154.0, 0.155.0, and 0.155.1 "
    "were re-released on 2026-09-22. An earlier installation of one of those "
    "versions may still contain the older reader. Updating the plugin does "
    "not replace that binary. No additional patched-Codex release is "
    "required for Privacy HUD 0.8.1.",
    "The native Privacy item displays accounting snapshots; it does not "
    "verify runtime alignment. Before repair, an old daemon may continue "
    "refreshing a legacy reading. Use doctor to check alignment. The bundled "
    "ambient launcher reports runtime failure instead of displaying a "
    "percentage.",
    "Privacy HUD loads its Python code from the selected plugin bundle. The "
    "recorded Python environment supplies dependencies. Run `$privacy "
    "repair` to obtain the exact recovery command for another terminal. "
    "Explicit installation may download dependencies and model weights; "
    "runtime checks and offline repair do not.",
    "Repair preserves recorded ledger values and moves the active store to "
    "`$PLUGIN_DATA/ledger/active.db`. `$PLUGIN_DATA/ledger.db` becomes a "
    "directory that fences the historical pathname. Do not replace it with "
    "a file or symlink. Repair does not perform the accounting rebuild; the "
    "compatible daemon retains the genuine new-session migration boundary. "
    "Unsupported or altered schemas are preserved and refused. No downgrade "
    "migration is provided.",
    "Runtime mismatches produce an unverified warning on ingress and a "
    "denial for outbound calls the hook cannot verify. These are plugin "
    "decisions, not confirmation of host enforcement. Monitoring gaps and "
    "lost in-memory detection state cannot be reconstructed.",
]

#: The interim review's replacement hazard paragraph. It is the only
#: description of why the fence exists that this release may publish: the
#: withdrawn one claimed 0.7.1 alters a prepared ledger's schema, and it
#: does not.
HAZARD = (
    "Privacy HUD 0.7.1 does not alter the schema of a valid prepared "
    "generation-5401 ledger during initialization: `events` already contains "
    "`source_kind`. It can nevertheless open the historical ledger pathname "
    "without participating in the selected runtime's handshake or writer "
    "lease. On a prepared ledger, historical session and coverage writes can "
    "succeed even though legacy event recording fails against the new "
    "`events` layout. On a generation-0 ledger, historical event writes "
    "remain possible, and initialization adds `source_kind` only when that "
    "column is absent. Explicit repair therefore quiesces legacy users, "
    "preserves the ledger at `$PLUGIN_DATA/ledger/active.db`, and replaces "
    "`$PLUGIN_DATA/ledger.db` with a directory fence that prevents "
    "subsequent historical-path opens. The fence does not revoke "
    "already-open connections or protect against same-user code "
    "deliberately opening the active pathname."
)

RELEASE_SENTENCE = (
    "Version 0.8.0 checks runtime alignment and fences the active ledger "
    "from historical entry points. The daemon still prepares the accounting "
    "schema at a genuine new-session boundary, and production sessions still "
    "use legacy accounting. Historical records and stored scores are not "
    "backfilled or rescored."
)

#: astra's Chinese text, published as written. It is not translated here
#: and must not be paraphrased in review.
COMPATIBILITY_ZH = [
    "Privacy HUD 0.8.1 继续使用 snapshot v2，实际会话仍采用旧版记账。支持 v2 "
    "的读取器会将 v1 明确标为旧版记账，并支持带可空记账字段的 v2。仅支持 v1 "
    "的旧读取器会拒绝 v2，不显示 Privacy 状态项。Codex 版本号相同并不代表快照"
    "兼容。",
    "支持 snapshot v2 的 Codex 0.154.0、0.155.0 和 0.155.1 补丁构建已于 "
    "2026-09-22 重新发布。如果此前安装过这些版本，本机二进制仍可能包含旧读取"
    "器。更新插件不会替换该二进制；Privacy HUD 0.8.1 本身不需要再次发布 Codex "
    "补丁构建。",
    "Codex 内的 Privacy 状态项只显示记账快照，不验证运行时是否一致。完成修复之"
    "前，旧守护进程可能仍在刷新旧版读数。请用 doctor 检查运行时一致性。插件内置"
    "的独立 HUD 启动器会在运行时检查失败时显示错误，而不显示百分比。",
    "Privacy HUD 从所选插件包加载 Python 代码，已记录的 Python 环境只提供依赖。"
    "运行 `$privacy repair` 可获取在另一个终端执行的完整修复命令。显式安装可能"
    "下载依赖和模型权重；运行时检查和离线修复不会下载。",
    "修复保留账本中已有的记录值，并将当前账本移至 "
    "`$PLUGIN_DATA/ledger/active.db`。原路径 `$PLUGIN_DATA/ledger.db` 会成为目"
    "录，阻止旧程序通过该路径打开当前账本。请勿将此目录替换为文件或符号链接。修"
    "复不执行记账结构迁移；迁移仍由兼容的守护进程在收到真正的新会话开始事件时执"
    "行。如果账本结构不受支持，或与版本标记不一致，程序会保留文件并拒绝使用，不"
    "会自动改写历史。本项目不提供降级迁移。",
    "运行时不匹配时，入站事件继续执行并显示未经验证的提示；对于 hook 无法验证的"
    "出站调用，插件会返回拒绝决定。这些决定不能证明宿主实际执行了干预。监测空档"
    "中的事件以及重启时丢失的内存检测状态无法恢复。",
]

RELEASE_SENTENCE_ZH = (
    "0.8.0 会检查运行时一致性，并阻止旧版入口通过原路径访问当前账本。守护进程仍"
    "只在真正的新会话开始时准备记账结构，实际会话仍采用旧版记账。历史记录和已存"
    "分数不会被回填或重新计算。"
)

#: The exact `$privacy repair` branch.
SKILL_REPAIR_BRANCH = (
    "`$privacy repair` prints the recovery command for another terminal. "
    "Invoke the bundled launcher with `repair --print-command` and reproduce "
    "its output verbatim. This branch does not start installation, stop "
    "processes, or request an enforcement bypass. If hook execution prevents "
    "the launcher from running, construct the same shell-quoted command from "
    "this skill's exact bundle location and the resolved plugin-data "
    "directory. Do not select another cached version."
)

WITHDRAWN = (
    "The already-published snapshot-v1 builds do not support 0.7.8 "
    "snapshots.",
    "Updated release artifacts have not been published as part of this "
    "change.",
    "The already-published builds use snapshot-v1 readers.",
    "No snapshot-v2 release has been run for this change.",
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _flowed(text: str) -> str:
    """Markdown with its hard wrapping removed, so a paragraph compares as
    the sentence it is rather than as the lines it was typed on."""
    return re.sub(r"\s+", " ", text)


# --------------------------------------------------------------------- #
# versions
# --------------------------------------------------------------------- #

def test_issue66_versions_are_0_8_1():
    """Four declarations, one release. Codex caches an installed plugin
    by version, so a bump that reaches three of them ships nothing."""
    assert json.loads(_text(PLUGIN_JSON))["version"] == RELEASE
    marketplace = json.loads(_text(MARKETPLACE_JSON))
    name = json.loads(_text(PLUGIN_JSON))["name"]
    entries = [p for p in marketplace["plugins"] if p["name"] == name]
    assert len(entries) == 1
    assert entries[0]["version"] == RELEASE
    with PYPROJECT.open("rb") as handle:
        assert tomllib.load(handle)["project"]["version"] == RELEASE
    assert json.loads(_text(MANIFEST))["release"] == RELEASE
    assert contract.RELEASE == RELEASE

    # What this release deliberately does not move (§D).
    from privacy_hud import hud_snapshot, ledger_schema

    assert ledger_schema.PREPARED_VERSION == 5401
    assert ledger_schema.ACTIVATED_VERSION == 5402
    assert hud_snapshot.SNAPSHOT_VERSION == 2
    assert hud_snapshot.DAEMON_MARKER_VERSION == 1
    assert load_matrix().version == "1"
    assert contract.PROTOCOL_VERSION == 2
    assert contract.STORAGE_GENERATION == 1
    assert contract.RECEIPT_VERSION == 2


def test_issue66_changelog_records_the_release():
    text = _text(CHANGELOG)
    assert text.startswith("# Changelog\n")
    assert "\n## 0.8.0\n" in text
    for line in ("Load first-party Python code from the selected plugin "
                 "bundle.",
                 "Require matching daemon identity before sending hook "
                 "events or policy mutations.",
                 "Retain snapshot version 2 and the existing native-reader "
                 "contract.",
                 "Provide no downgrade migration or reconstruction of "
                 "monitoring gaps."):
        assert f"- {line}" in _flowed(text) or line in _flowed(text), line
    assert "Refs #66." in text


# --------------------------------------------------------------------- #
# the documents
# --------------------------------------------------------------------- #

@pytest.mark.parametrize("name", ["PRD.md", "design.md", "architecture.md"])
def test_issue66_current_contract_blocks_match(name):
    text = _text(REPO / ".claude" / "docs" / name)
    assert _flowed(CURRENT_CONTRACT_REQUIREMENT) in _flowed(text)
    assert "#54 Phase 2 (0.7.9)" not in text, (
        "the superseded block is still at the top of this document")
    assert "#66 runtime consistency (0.8.0)" not in text, (
        "the superseded block is still at the top of this document")


@pytest.mark.parametrize("name", ["README.md", "docs/installing-by-hand.md",
                                  "patches/README.md"])
def test_issue66_compatibility_copy_matches(name):
    flowed = _flowed(_text(REPO / name))
    for paragraph in COMPATIBILITY:
        assert _flowed(paragraph) in flowed, paragraph[:60]
    assert _flowed(HAZARD) in flowed, "the replacement hazard paragraph"
    for withdrawn in WITHDRAWN:
        assert _flowed(withdrawn) not in flowed, withdrawn
    # The retracted claim, in the words the interim review withdrew it in.
    assert "0.7.1" not in flowed or _flowed(HAZARD) in flowed
    assert "alters the prepared" not in flowed


def test_issue66_release_sentences_match():
    assert _flowed(RELEASE_SENTENCE) in _flowed(_text(REPO / "README.md"))
    assert _flowed(RELEASE_SENTENCE_ZH) in _flowed(
        _text(REPO / "README.zh-CN.md"))


def test_issue66_chinese_copy_matches():
    """astra wrote these paragraphs; they are published as written."""
    flowed = _flowed(_text(REPO / "README.zh-CN.md"))
    for paragraph in COMPATIBILITY_ZH:
        assert _flowed(paragraph) in flowed, paragraph[:30]
    assert "0.7.9" not in flowed


def test_issue66_manual_commands_use_the_bundled_launcher():
    """Operational examples run the bootstrap, not a console script and
    not `PYTHONPATH=src` (§D)."""
    for name in ("README.md", "docs/installing-by-hand.md"):
        flowed = _flowed(_text(REPO / name))
        assert "scripts/runtime.py" in flowed, name
        assert "PYTHONPATH=src python3 -m privacy_hud" not in flowed, name


def test_issue66_instruction_files_name_the_resolved_ledger_path():
    """`.claude/CLAUDE.md` is read before any change is proposed, so a
    statement of fact in it that a release made false is a defect in the
    release."""
    text = _text(REPO / ".claude" / "CLAUDE.md")
    assert "codex.ledger_path" in text
    assert "ledger/active.db" in text
    assert "$PLUGIN_DATA/ledger.db`)" not in text


# --------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------- #

#: The one module that may hold the historical basename: it is where this
#: project's facts about Codex's layout live, and the fence is defined in
#: terms of it.
_NAME_OWNERS = {"src/privacy_hud/codex.py"}


def _code_literals(path: Path) -> list[str]:
    """Every string constant a module actually evaluates, docstrings
    excluded. A comment describing the fence is documentation; a literal
    in an expression is a pathname something will open."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docstrings.add(id(body[0].value))
    return [node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings]


def test_issue66_no_current_entrypoint_uses_legacy_ledger_path():
    """Nothing that runs spells the historical pathname out for itself.

    `codex.ledger_path` answers which ledger, in one place, because the
    answer is now a question about which state the installation is in.
    A second spelling is a surface that opens the fence directory on a
    repaired machine — which is what the `$privacy` skill did.
    """
    offenders = []
    for tree in ("src/privacy_hud", "hooks", "mcp", "scripts", "ui"):
        for path in sorted((REPO / tree).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            rel = path.relative_to(REPO).as_posix()
            if rel in _NAME_OWNERS:
                continue
            for literal in _code_literals(path):
                if "ledger.db" in literal:
                    offenders.append((rel, literal))
    assert offenders == [], offenders

    skill = _text(SKILL)
    for block in re.findall(r"```bash\n(.*?)```", skill, flags=re.S):
        assert "ledger.db" not in block, block[:120]
    assert "local_ui_server" not in skill, (
        "the skill must reach the browser through the bundled launcher")


# --------------------------------------------------------------------- #
# the skill
# --------------------------------------------------------------------- #

def _skill_blocks() -> list[str]:
    return re.findall(r"```bash\n(.*?)```", _text(SKILL), flags=re.S)


def test_issue66_skill_has_the_exact_repair_branch():
    assert _flowed(SKILL_REPAIR_BRANCH) in _flowed(_text(SKILL))
    assert "ls -d" not in _text(SKILL), (
        "the newest-directory fallback selects a cached version by sorting")
    assert "0.7.8" not in _text(SKILL)


def test_issue66_skill_commands_execute(tmp_path):
    """Every bash block in the skill runs, against a real installation.

    These blocks are code an agent executes verbatim in a user's session.
    Nothing else runs them, so a renamed subcommand or a changed argument
    breaks `$privacy` the first time someone types it — which is exactly
    what the ledger pathname did.
    """
    from runtime_helpers import writer_ledger

    bundle = shared_bundle()
    data = short_data_dir("phskill")
    ledger = writer_ledger(data / "ledger.db", load_matrix(), data_dir=data)
    ledger.start_session("s1", cwd="/r", model="gpt-5")
    ledger.record("s1", turn_id="t1", kind="exposed", data_type="email",
                  source="support.log", destination="model_context",
                  value_hash=b"\x01" * 16, masked_example="jo•••@acme.com",
                  tool_name="Read", protection=None)
    ledger.conn.close()
    from runtime_helpers import release_leases

    release_leases()
    write_receipt_v2(data, bundle=bundle, python=sys.executable)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").symlink_to(sys.executable)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "PLUGIN_ROOT": str(bundle),
        "PLUGIN_DATA": str(data),
        "SESSION_ID": "s1",
        "EVENT_ID": "1",
        "CODEX_HOME": str(tmp_path / "codex-home"),
    }
    env.pop("PYTHONPATH", None)

    blocks = [block for block in _skill_blocks()
              if "runtime.py" in block or "$HUD" in block]
    assert blocks, "the skill runs nothing through the bundled launcher"
    for block in blocks:
        if " ui " in block:
            # The browser block backgrounds a server that stays up until
            # it is stopped; it is run, its one line is read, and it is
            # stopped by process group so nothing outlives the test.
            _run_browser_block(block, env)
            continue
        proc = subprocess.run(["bash", "-c", block], capture_output=True,
                              text=True, env=env, timeout=300)
        assert proc.returncode == 0, (block, proc.stdout, proc.stderr)
        assert "Traceback" not in proc.stderr, (block, proc.stderr)


def _run_browser_block(block: str, env: dict) -> None:
    import signal
    import threading

    proc = subprocess.Popen(["bash", "-c", block], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env,
                            start_new_session=True)

    def stop() -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass

    watchdog = threading.Timer(120.0, stop)
    watchdog.start()
    try:
        line = proc.stdout.readline().strip()
        assert line.startswith("http://127.0.0.1:"), line
    finally:
        watchdog.cancel()
        stop()
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_issue66_runtime_manifest_is_current():
    """The manifest is the bundle's identity. A source change that does
    not reach it selects a build whose files no longer hash to it, and
    every client refuses."""
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "build-runtime-manifest.py"),
         "--check"], capture_output=True, text=True, cwd=REPO, timeout=300)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(_text(MANIFEST))["build_id"] == \
        contract.compute_build_id(REPO)
