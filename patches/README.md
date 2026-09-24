# Codex patch

Privacy HUD 0.8.2 retains snapshot version 2. Production sessions still use legacy accounting. Snapshot-v2 readers accept version 1 as explicitly legacy and version 2 with nullable accounting fields. Older snapshot-v1-only readers reject version 2 and show no Privacy item. Matching Codex version numbers do not establish snapshot compatibility.

The snapshot-v2 patched Codex builds for 0.154.0, 0.155.0, and 0.155.1 were re-released on 2026-09-22. An earlier installation of one of those versions may still contain the older reader. Updating the plugin does not replace that binary. No additional patched-Codex release is required for Privacy HUD 0.8.1.

The native Privacy item displays accounting snapshots; it does not verify runtime alignment. Before repair, an old daemon may continue refreshing a legacy reading. Use doctor to check alignment. The bundled ambient launcher reports runtime failure instead of displaying a percentage.

Privacy HUD loads its Python code from the selected plugin bundle. The recorded Python environment supplies dependencies. Run `$privacy repair` to obtain the exact recovery command for another terminal. Explicit installation may download dependencies and model weights; runtime checks and offline repair do not.

Repair preserves recorded ledger values and moves the active store to `$PLUGIN_DATA/ledger/active.db`. `$PLUGIN_DATA/ledger.db` becomes a directory that fences the historical pathname. Do not replace it with a file or symlink. Repair does not perform the accounting rebuild; the compatible daemon retains the genuine new-session migration boundary. Unsupported or altered schemas are preserved and refused. No downgrade migration is provided.

Runtime mismatches produce an unverified warning on ingress and a denial for outbound calls the hook cannot verify. These are plugin decisions, not confirmation of host enforcement. Monitoring gaps and lost in-memory detection state cannot be reconstructed.

Privacy HUD 0.7.1 does not alter the schema of a valid prepared generation-5401 ledger during initialization: `events` already contains `source_kind`. It can nevertheless open the historical ledger pathname without participating in the selected runtime's handshake or writer lease. On a prepared ledger, historical session and coverage writes can succeed even though legacy event recording fails against the new `events` layout. On a generation-0 ledger, historical event writes remain possible, and initialization adds `source_kind` only when that column is absent. Explicit repair therefore quiesces legacy users, preserves the ledger at `$PLUGIN_DATA/ledger/active.db`, and replaces `$PLUGIN_DATA/ledger.db` with a directory fence that prevents subsequent historical-path opens. The fence does not revoke already-open connections or protect against same-user code deliberately opening the active pathname.

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
