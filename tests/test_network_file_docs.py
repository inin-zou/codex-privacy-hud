from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def read(relative):
    return (REPO / relative).read_text(encoding="utf-8")


def test_network_file_limit_describes_the_build_and_its_limits():
    limits = read("docs/known-limits.md")
    section = limits.split("\n## 6. ", 1)[1].split("\n## 7. ", 1)[0]
    for text in (
        "In 0.9.2, a default-on lexical network guard",
        "does not trace payload data flow",
        "127.0.0.1",
        "Tokenization failure",
        "Variables, aliases, configuration files",
        "zero additional charge",
        "no fabricated finding event",
    ):
        assert text in section
    assert "not a bug with a fix pending" not in section


def test_read_guard_and_template_limits_are_scoped():
    limits = read("docs/known-limits.md")
    assert "That guard is off by default; $privacy read status reports its setting." in limits
    assert "The network guard is on by default" in limits
    assert "The carve-out applies to path-based denial only." in limits
    assert "Network-file denials also keep shell-derived file identities unresolved." in limits
    assert "The network guard is separate from origin extraction" in limits


def test_readmes_state_the_new_default_in_both_languages():
    english = read("README.md")
    chinese = read("README.zh-CN.md")
    assert "**Network-file contents are not inspected.**" in english
    assert "16. **The optional read guard is off by default.** This setting controls recognized shell reads. Credential prompt holds, the default-on network guard, and existing credential-based egress policy operate independently of it. Returned holds and denials do not confirm host enforcement. ([details](docs/known-limits.md#16-nothing-is-blocked-until-you-turn-it-on))" in english
    assert "**不会检查网络发送所引用文件的内容。**" in chinese
    assert "16. **可选的读取防护默认关闭。** 此设置控制能够识别的 shell 读取。提示词中的凭据暂缓、默认开启的网络防护，以及现有的基于凭据的出站策略，均独立于此设置运行。返回的暂缓或拒绝决定不能证明宿主实际执行了干预。（[详情](docs/known-limits.md#16-nothing-is-blocked-until-you-turn-it-on)）" in chinese
    assert "Version 0.9.2 adds a default-on lexical network guard." in english
    assert "0.9.2 新增默认开启的网络命令词法防护。" in chinese


def test_design_documents_describe_denial_without_upload_rewriting():
    prd = read(".claude/docs/PRD.md")
    architecture = read(".claude/docs/architecture.md")
    assert "0.9.2 acceptance:" in prd
    assert "An unavailable percentage must not be rendered as 0%." in prd
    assert "## 8.1 Sensitive-path network denial (0.9.2)" in architecture
    assert "one unresolved file-reference subject per matched rule" in architecture
    assert "No `privacy-minimize` executable is shipped" in architecture
    assert "privacy-minimize support.log" not in prd + architecture


def test_changelog_has_a_separate_0_9_2_entry():
    text = read("CHANGELOG.md")
    assert text.startswith("# Changelog\n\n## ")
    assert text.count("\n## 0.9.2\n") == 1
    section = text.split("\n## 0.9.2\n", 1)[1].split("\n## 0.9.1\n", 1)[0]
    assert "shell-derived file identities unresolved" in section
    assert "No file contents are opened" in section
