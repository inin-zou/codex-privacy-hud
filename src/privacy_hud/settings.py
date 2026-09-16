# src/privacy_hud/settings.py
"""User preferences that outlive a session.

The first of its kind in this plugin. Everything else under `PLUGIN_DATA`
is either machine configuration written by setup (`runtime.json`), the
ledger, or per-session scratch -- so this gets its own file rather than
sharing one: a reinstall rewrites `runtime.json`, and a user's protection
setting must not be lost when the interpreter is re-recorded.

Not in Codex's `config.toml`, for three reasons. The standard library reads
TOML but cannot write it, so a toggle there means a new dependency (I2
forbids it) or `sed` against the user's own config. The setting is this
plugin's policy, not a Codex setting -- `[tui].status_line` holds a Codex
identifier we add to, while `deny_read` is a concept Codex knows nothing
about. And `install.sh --purge` already removes `PLUGIN_DATA`.

The cost is that the file is invisible, which `$privacy read status` and a
`privacy-hud-doctor` line are here to pay.
"""
from __future__ import annotations

import json
from pathlib import Path

SETTINGS_NAME = "settings.json"

#: Every setting, with the value that applies when the file does not say.
#: Defaults are the permissive answer on purpose (I6): a guard that cannot
#: read its own configuration must not start blocking on a guess.
DEFAULTS: dict[str, object] = {"deny_read": False}


class Settings:
    """`$PLUGIN_DATA/settings.json`, re-read when it changes on disk.

    The daemon builds one of these for its life, but a user flips the
    toggle from a *different* process (the `$privacy` skill, through the
    MCP server). Caching the parsed file against its `(mtime, size)` is
    what lets a change land inside a running session without a restart,
    while still not re-reading a file on every hook.

    `mtime` alone is compared together with `size` rather than by itself:
    two writes from two different processes (a live daemon's `Settings`
    plus the skill's own, as in
    `test_a_change_is_seen_without_a_restart`) can land in the same
    filesystem mtime tick, especially on filesystems with 1-second
    resolution -- and a cache keyed on mtime alone would then miss the
    second write. Adding `size` distinguishes "no change" from "changed
    within the same tick" whenever the byte count differs, which it does
    for every value this file currently holds (`true` vs `false`).
    """

    def __init__(self, data_dir) -> None:
        self.path = Path(data_dir) / SETTINGS_NAME
        self._cached: dict | None = None
        self._stamp: tuple[float, int] | None = None

    def _load(self) -> dict:
        try:
            st = self.path.stat()
        except OSError:
            self._cached, self._stamp = {}, None
            return self._cached
        stamp = (st.st_mtime, st.st_size)
        if self._cached is None or stamp != self._stamp:
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                # A malformed file is not a reason to start blocking reads.
                data = {}
            self._cached = data if isinstance(data, dict) else {}
            self._stamp = stamp
        return self._cached

    @property
    def deny_read(self) -> bool:
        return bool(self._load().get("deny_read", DEFAULTS["deny_read"]))

    def set_deny_read(self, enabled: bool) -> None:
        """Write the flag, keeping every other key the file holds."""
        data = dict(self._load())
        data["deny_read"] = bool(enabled)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2) + "\n",
                             encoding="utf-8")
        self.path.chmod(0o600)
        self._cached, self._stamp = None, None
