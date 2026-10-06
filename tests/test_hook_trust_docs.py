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
