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

## What has and has not been run (status as of 2026-09-15)

`cargo check -p codex-tui` and `cargo clippy -p codex-tui -- -D warnings`
are run against a patched 0.154.0 tree before every re-export of this patch,
and `privacy_status.rs`'s own unit tests are run through a scratch crate that
includes the module by path.

**`cargo test -p codex-tui` has never been run, and neither have the `insta`
snapshots** that cover the status-line picker this patch touches
(`status_line_setup.rs`, `status_surface_preview.rs`). Building the codex-tui
test binary does not fit on the development machine's disk, and no workflow
in `.github/workflows` runs it either — `release-codex.yml` builds
`codex-cli` and `patch-health.yml` only checks that the patch still applies.
So if a snapshot needs accepting because `privacy` now appears in the picker,
nothing here will tell you: run `cargo test -p codex-tui` against a patched
tree on a machine with room for it before trusting that UI.
