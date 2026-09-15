# Codex patch

`privacy-status-line.patch` adds one status-line item, `privacy`, to Codex's
TUI. It is applied to the upstream tag named in `scripts/build-patched-codex.sh`
and nothing else is changed. See `docs/superpowers/specs/2026-09-15-patched-codex-status-line-design.md` §5.3.

Regenerate against a new tag:

    git clone --depth 1 --branch rust-v<ver> https://github.com/openai/codex /tmp/codex-src
    cd /tmp/codex-src && git apply --3way ../codex-privacy-hud/patches/privacy-status-line.patch
    # resolve, cargo test -p codex-tui, then:
    git add -A && git diff --cached > ../codex-privacy-hud/patches/privacy-status-line.patch

`privacy_status_golden.json` inside the patch must stay a byte copy of
`tests/matrix/hud_golden.json`; `tests/test_hud_contract.py` checks.
