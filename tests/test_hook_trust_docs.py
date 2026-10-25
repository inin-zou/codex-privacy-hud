from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_installer_closing_message_names_the_trust_requirement():
    script = (ROOT / "install.sh").read_text()
    closing = script[script.rfind('log "done. restart codex'):]
    assert (
        'log "      hooks run only after trust is granted in an interactive '
        'codex session: choose \\"Trust all and continue\\""' in closing
    )
    assert (
        'log "      codex exec sessions are unmonitored until then '
        '(with default hook-trust checks)"' in closing
    )


def test_hook_trust_limit_and_install_instructions_are_present():
    english = (ROOT / "README.md").read_text()
    chinese = (ROOT / "README.zh-CN.md").read_text()
    limits = (ROOT / "docs/known-limits.md").read_text()

    assert "## 23. Untrusted hooks mean no observation at all." in limits
    assert "no observation at all" in english
    assert "完全没有观测" in chinese
    for text in (english, chinese, limits):
        assert "Trust all and continue" in text
        assert "codex exec" in text
    assert "default user config" in limits
    assert "session flags" in limits
    assert "23-untrusted-hooks-mean-no-observation-at-all" in english
    assert "23-untrusted-hooks-mean-no-observation-at-all" in chinese
    assert "never `FAIL`" not in english
    assert "不应出现 `FAIL`" not in chinese


def test_bundle_trust_scope_and_read_only_copy():
    english = (ROOT / "README.md").read_text()
    chinese = (ROOT / "README.zh-CN.md").read_text()
    limits = (ROOT / "docs/known-limits.md").read_text()
    installer = (ROOT / "install.sh").read_text()
    changelog = (ROOT / "CHANGELOG.md").read_text()

    for text in (english, chinese, limits, installer):
        assert "0.164.0" in text
        assert "WARN" in text
    assert "fingerprinted bundle contents" in english
    assert "参与指纹计算的插件包内容" in chinese
    assert "从不创建或迁移 hook 信任状态" in chinese
    assert "never creates or migrates hook trust state" in installer
    assert "__pycache__" in limits
    assert ".egg-info" in limits
    assert "SessionEnd at 3 seconds" in limits
    assert "not a checksum of every external file" in limits
    assert "Trust is for the normalized hook definition, not a checksum" not in limits
    release = changelog.split("## 0.10.12", 1)[1].split("## 0.10.11", 1)[0]
    assert "legacy content baseline" in release
    assert "unsupported or undetermined" in release
