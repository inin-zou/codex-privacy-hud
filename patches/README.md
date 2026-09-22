# Codex patch

Privacy HUD 0.7.8 writes snapshot version 2. Updated readers accept version 1 as explicitly legacy and accept version 2 with nullable accounting fields. Older patched Codex readers reject version 2 and show no Privacy item. A matching Codex version alone does not establish snapshot compatibility. Use a snapshot-v2-compatible patched build, or run privacy-hud-ambient --watch in a separate terminal pane.

The already-published builds use snapshot-v1 readers. No snapshot-v2 release has been run for this change. After merge, publish compatible builds with `release-codex.yml` via `workflow_dispatch` for each supported Codex version; source compatibility does not update installed binaries.

`privacy-status-line.patch` adds one status-line item, `privacy`, to Codex's
TUI. It is applied to the upstream tag named in `scripts/build-patched-codex.sh`
and nothing else is changed. See `docs/superpowers/specs/2026-09-15-patched-codex-status-line-design.md` §5.3.

Regenerate against a new tag:

    git clone --depth 1 --branch rust-v<ver> https://github.com/openai/codex /tmp/codex-src
    cd /tmp/codex-src && git apply --3way ../codex-privacy-hud/patches/privacy-status-line.patch
    # resolve, cargo test -p codex-tui, then:
    git add -A && git diff --cached > ../codex-privacy-hud/patches/privacy-status-line.patch

`privacy_status_golden.json` must remain byte-identical to `tests/matrix/hud_golden.json`; it pins the retained numeric bar primitive, which the current HUD does not draw. `privacy_status_reading_golden.json` must remain byte-identical to `tests/matrix/hud_reading_golden.json`; it pins accounting-aware parsing and full-width text in both languages. Python selects narrower complete candidates separately.

## What has and has not been run (status as of 2026-09-22)

The author reports 15 passing Rust module tests and clean module clippy with `--all-targets -D warnings` for this change. `tests/test_rust_status.py`, enabled by `PRIVACY_HUD_RUST_TESTS=1`, extracts the module and both fixtures into a scratch crate and runs `cargo test`; CI's `rust-status` job executes it. This is not a build or test of the complete patched Codex TUI. Earlier patched-tree `cargo check` and clippy results do not validate this revision.

**`cargo test -p codex-tui` has never been run, and neither have the `insta`
snapshots** that cover the status-line picker this patch touches
(`status_line_setup.rs`, `status_surface_preview.rs`). Building the codex-tui
test binary does not fit on the development machine's disk, and no workflow
in `.github/workflows` runs it either — `release-codex.yml` builds
`codex-cli` and `patch-health.yml` only checks that the patch still applies.
So if a snapshot needs accepting because `privacy` now appears in the picker,
nothing here will tell you: run `cargo test -p codex-tui` against a patched
tree on a machine with room for it before trusting that UI.
